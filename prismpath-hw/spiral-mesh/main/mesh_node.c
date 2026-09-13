// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* spiral-mesh — step 3 of Facet-on-the-mesh: the ESP-NOW binding. Three nodes, one binary,
 * role by MAC. Each node synthesizes its channel, quantizes it through the BAKED partition
 * derived from the signed flow (replacing #101's hand-coded bands), and broadcasts Facet
 * frames; every node decodes its neighbors' streams, holds the latest symbol per slot, and
 * gossips its fused posture (the k=3 joint spiral cell) as a fleet-coherence beacon.
 *
 * ESP-NOW binding v1 (documented here, referenced by the profile text):
 *   - stream identity: transport-provided (sender MAC -> role); nothing spent in-frame
 *   - payload: a Zeckendorf stream of THREE wire ints (all value+1, MSB-first, zero-padded):
 *       [class, tick, value]
 *     class 1 = band tier (value = own field's cell symbol)   — every tick
 *     class 2 = refinement (value = raw reading)               — every 5th tick
 *     class 3 = posture    (value = joint spiral cell n)       — every tick once all slots seen
 *   - a lost frame costs freshness/fidelity, never a wrong decision: symbols hold until
 *     replaced; posture is recomputed from the latest symbols only. */
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_now.h"

#include "../../codec-bench/zeck.h"
#include "../../spiral-node/main/spiral_sidecar.h"
#include "sidecar_blob.h"
#include "roles.h"

#define TICK_MS 200
#define REFINE_EVERY 5
/* BATCH_TICKS > 1 = the batching materialization of the same binding: accumulate each tick's
 * [class, tick, value] triples in one payload and flush every BATCH_TICKS ticks as ONE ESP-NOW
 * frame. Same frames, same self-framing stream — the fixed per-frame L2 overhead is amortized,
 * which is where Facet's density becomes an airtime/energy win. Decision latency trades to
 * BATCH_TICKS * TICK_MS worst case; the band tier still rides every flush. */
#ifndef BATCH_TICKS
#define BATCH_TICKS 1
#endif

static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

typedef struct { uint8_t src[6]; uint8_t len; uint8_t data[32]; } rxmsg_t;
static QueueHandle_t rxq;

static ssc_t sidecar;
static int my_role = -1;
static int slot_sym[N_ROLES];              /* latest symbol per slot; -1 = never seen */
static int32_t peer_posture[N_ROLES];      /* latest posture n gossiped per role; -1 = none */

/* ---- decode: the receive half zeck.h deliberately omitted (front half only) ---- */
static uint64_t zeck_decode1(const uint8_t *buf, uint16_t nbits, uint16_t *pos) {
    uint64_t value = 0; uint8_t prev = 0; uint8_t fib_index = 0;
    while (*pos < nbits && fib_index < 78) {
        uint8_t bit = (buf[*pos >> 3] >> (7 - (*pos & 7))) & 1;
        (*pos)++;
        if (bit && prev) return value;           /* "11" terminator */
        if (bit) value += fib_at(fib_index);
        prev = bit; fib_index++;
    }
    return 0;                              /* malformed / padding overrun */
}

static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (len > (int)sizeof(((rxmsg_t *)0)->data)) return;
    rxmsg_t message; memcpy(message.src, info->src_addr, 6); message.len = (uint8_t)len; memcpy(message.data, data, len);
    xQueueSend(rxq, &message, 0);
}

static int role_of(const uint8_t *mac) {
    for (int role_index = 0; role_index < N_ROLES; role_index++)
        if (memcmp(mac, ROLE_MAC[role_index], 6) == 0) return role_index;
    return -1;
}

static int32_t synth(int role, uint32_t tick) {
    int32_t lo = ROLE_SYNTH[role][0], hi = ROLE_SYNTH[role][1];
    int32_t period = ROLE_SYNTH[role][2], phase = ROLE_SYNTH[role][3];
    int32_t pos = (int32_t)((tick + (uint32_t)phase) % (uint32_t)period);
    int32_t half = period / 2;
    int32_t ramp = pos <= half ? pos : period - pos;
    return lo + (ramp * (hi - lo)) / half;
}

static void print_hex(const uint8_t *bytes, uint8_t length) {
    for (uint8_t byte_index = 0; byte_index < length; byte_index++) printf("%02x", bytes[byte_index]);
}

/* ---- TX accumulator: one triple per frame at BATCH_TICKS==1 (byte identical to the unbatched
 * binding); at BATCH_TICKS>1 the triples of a whole window ride ONE frame. ---- */
static uint8_t  bat_buf[64];
static bitacc_t bat_acc = { bat_buf, 0 };

static void bat_flush(uint32_t tick) {
    if (bat_acc.bitpos == 0) return;
    uint8_t length = (uint8_t)((bat_acc.bitpos + 7u) >> 3);
    esp_now_send(BCAST, bat_buf, length);
    printf("X %lu len=%u ", (unsigned long)tick, length); print_hex(bat_buf, length); printf("\n");
    memset(bat_buf, 0, sizeof bat_buf);
    bat_acc.bitpos = 0;
}

static void tx_triple(uint8_t cls, uint32_t tick, uint32_t value) {
    (void)zeck_encode(&bat_acc, (uint64_t)cls + 1);
    (void)zeck_encode(&bat_acc, (uint64_t)tick + 1);
    (void)zeck_encode(&bat_acc, (uint64_t)value + 1);
    printf("T %lu c%u v%lu\n", (unsigned long)tick, cls, (unsigned long)value);
    if (BATCH_TICKS == 1) bat_flush(tick);     /* unbatched: identical frames to binding v1 */
}

void app_main(void) {
    rxq = xQueueCreate(24, sizeof(rxmsg_t));
    nvs_flash_init(); esp_netif_init(); esp_event_loop_create_default();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wc); esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_start();
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_STA, mac);
    esp_now_init(); esp_now_register_recv_cb(on_recv);
    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, BCAST, 6); peer.ifidx = WIFI_IF_STA; peer.encrypt = false;
    esp_now_add_peer(&peer);

    my_role = role_of(mac);
    int prc = ssc_parse(SIDECAR, sizeof SIDECAR, &sidecar);
    const ssc_node_t *node = &sidecar.nodes[0];
    printf("BOOT mac=%02x:%02x:%02x:%02x:%02x:%02x role=%d ssc=%d bands=%u size=%lu\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], my_role, prc,
           node->n_bands, (unsigned long)node->size);
    if (my_role < 0 || prc != 0) { printf("HALT\n"); return; }
    for (int slot_index = 0; slot_index < N_ROLES; slot_index++) { slot_sym[slot_index] = -1; peer_posture[slot_index] = -1; }

    for (uint32_t tick = 0;; tick++) {
        /* own channel: synthesize, quantize through the BAKED partition, band-tier TX */
        int32_t raw = synth(my_role, tick);
        int sym = ssc_quantize(&node->fields[ROLE_FIELD[my_role]], raw);
        slot_sym[my_role] = sym;
        tx_triple(1, tick, (uint32_t)sym);
        if (tick % REFINE_EVERY == 0)
            tx_triple(2, tick, (uint32_t)raw);

        /* drain RX: neighbors' band frames update slots; posture frames update the beacon view */
        rxmsg_t message;
        while (xQueueReceive(rxq, &message, 0) == pdTRUE) {
            int role_index = role_of(message.src);
            uint16_t pos = 0, nbits = (uint16_t)(message.len * 8u);
            int triples = 0;
            for (;;) {                          /* a frame carries 1..BATCH triples, self framing */
                uint64_t wire_class = zeck_decode1(message.data, nbits, &pos);
                if (wire_class == 0) break;              /* zero padding / end of stream */
                uint64_t wire_tick = zeck_decode1(message.data, nbits, &pos);
                uint64_t wire_value = zeck_decode1(message.data, nbits, &pos);
                if (role_index < 0 || wire_tick == 0 || wire_value == 0) { triples = -1; break; }
                printf("R %d c%llu t%llu v%llu ", role_index, (unsigned long long)(wire_class - 1),
                       (unsigned long long)(wire_tick - 1), (unsigned long long)(wire_value - 1));
                print_hex(message.data, message.len); printf("\n");
                if (wire_class - 1 == 1) slot_sym[role_index] = (int)(wire_value - 1);
                if (wire_class - 1 == 3) peer_posture[role_index] = (int32_t)(wire_value - 1);
                triples++;
            }
            if (triples <= 0 && role_index >= 0 && message.len > 0 && triples < 0) {
                printf("RBAD "); print_hex(message.data, message.len); printf("\n");
            } else if (triples == 0) {
                printf("RBAD "); print_hex(message.data, message.len); printf("\n");
            }
        }

        /* fused posture: the k=3 joint spiral cell over the latest symbols; gossip it */
        if (slot_sym[0] >= 0 && slot_sym[1] >= 0 && slot_sym[2] >= 0) {
            int syms[SSC_MAX_FIELDS];
            for (int role_index = 0; role_index < N_ROLES; role_index++) syms[ROLE_FIELD[role_index]] = slot_sym[role_index];
            int32_t pn = ssc_n(node, syms);
            int band = pn >= 0 ? ssc_band(node, (uint32_t)pn) : -1;
            tx_triple(3, tick, (uint32_t)pn);
            printf("P %lu n=%ld band=%d route=%s peers=%ld,%ld,%ld\n",
                   (unsigned long)tick, (long)pn, band,
                   band >= 0 ? node->bands[band].route : "?",
                   (long)peer_posture[0], (long)peer_posture[1], (long)peer_posture[2]);
        }
        if (BATCH_TICKS > 1 && tick % BATCH_TICKS == (uint32_t)(BATCH_TICKS - 1))
            bat_flush(tick);                    /* the whole window rides one frame */
        vTaskDelay(pdMS_TO_TICKS(TICK_MS));
    }
}
