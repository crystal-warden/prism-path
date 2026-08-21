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

typedef struct { uint8_t src[6]; uint8_t len; uint8_t d[32]; } rxmsg_t;
static QueueHandle_t rxq;

static ssc_t S;
static int my_role = -1;
static int slot_sym[N_ROLES];              /* latest symbol per slot; -1 = never seen */
static int32_t peer_posture[N_ROLES];      /* latest posture n gossiped per role; -1 = none */

/* ---- decode: the receive half zeck.h deliberately omitted (front half only) ---- */
static uint64_t zeck_decode1(const uint8_t *buf, uint16_t nbits, uint16_t *pos) {
    uint64_t v = 0; uint8_t prev = 0; uint8_t i = 0;
    while (*pos < nbits && i < 78) {
        uint8_t b = (buf[*pos >> 3] >> (7 - (*pos & 7))) & 1;
        (*pos)++;
        if (b && prev) return v;           /* "11" terminator */
        if (b) v += fib_at(i);
        prev = b; i++;
    }
    return 0;                              /* malformed / padding overrun */
}

static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (len > (int)sizeof(((rxmsg_t *)0)->d)) return;
    rxmsg_t m; memcpy(m.src, info->src_addr, 6); m.len = (uint8_t)len; memcpy(m.d, data, len);
    xQueueSend(rxq, &m, 0);
}

static int role_of(const uint8_t *mac) {
    for (int r = 0; r < N_ROLES; r++)
        if (memcmp(mac, ROLE_MAC[r], 6) == 0) return r;
    return -1;
}

static int32_t synth(int role, uint32_t tick) {
    int32_t lo = ROLE_SYNTH[role][0], hi = ROLE_SYNTH[role][1];
    int32_t period = ROLE_SYNTH[role][2], phase = ROLE_SYNTH[role][3];
    int32_t pos = (int32_t)((tick + (uint32_t)phase) % (uint32_t)period);
    int32_t half = period / 2;
    int32_t x = pos <= half ? pos : period - pos;
    return lo + (x * (hi - lo)) / half;
}

static void print_hex(const uint8_t *b, uint8_t n) {
    for (uint8_t i = 0; i < n; i++) printf("%02x", b[i]);
}

/* ---- TX accumulator: one triple per frame at BATCH_TICKS==1 (byte identical to the unbatched
 * binding); at BATCH_TICKS>1 the triples of a whole window ride ONE frame. ---- */
static uint8_t  bat_buf[64];
static bitacc_t bat_acc = { bat_buf, 0 };

static void bat_flush(uint32_t tick) {
    if (bat_acc.bitpos == 0) return;
    uint8_t n = (uint8_t)((bat_acc.bitpos + 7u) >> 3);
    esp_now_send(BCAST, bat_buf, n);
    printf("X %lu len=%u ", (unsigned long)tick, n); print_hex(bat_buf, n); printf("\n");
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
    int prc = ssc_parse(SIDECAR, sizeof SIDECAR, &S);
    const ssc_node_t *N = &S.nodes[0];
    printf("BOOT mac=%02x:%02x:%02x:%02x:%02x:%02x role=%d ssc=%d bands=%u size=%lu\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], my_role, prc,
           N->n_bands, (unsigned long)N->size);
    if (my_role < 0 || prc != 0) { printf("HALT\n"); return; }
    for (int i = 0; i < N_ROLES; i++) { slot_sym[i] = -1; peer_posture[i] = -1; }

    for (uint32_t tick = 0;; tick++) {
        /* own channel: synthesize, quantize through the BAKED partition, band-tier TX */
        int32_t raw = synth(my_role, tick);
        int sym = ssc_quantize(&N->fields[ROLE_FIELD[my_role]], raw);
        slot_sym[my_role] = sym;
        tx_triple(1, tick, (uint32_t)sym);
        if (tick % REFINE_EVERY == 0)
            tx_triple(2, tick, (uint32_t)raw);

        /* drain RX: neighbors' band frames update slots; posture frames update the beacon view */
        rxmsg_t m;
        while (xQueueReceive(rxq, &m, 0) == pdTRUE) {
            int r = role_of(m.src);
            uint16_t pos = 0, nbits = (uint16_t)(m.len * 8u);
            int triples = 0;
            for (;;) {                          /* a frame carries 1..BATCH triples, self framing */
                uint64_t c = zeck_decode1(m.d, nbits, &pos);
                if (c == 0) break;              /* zero padding / end of stream */
                uint64_t t = zeck_decode1(m.d, nbits, &pos);
                uint64_t v = zeck_decode1(m.d, nbits, &pos);
                if (r < 0 || t == 0 || v == 0) { triples = -1; break; }
                printf("R %d c%llu t%llu v%llu ", r, (unsigned long long)(c - 1),
                       (unsigned long long)(t - 1), (unsigned long long)(v - 1));
                print_hex(m.d, m.len); printf("\n");
                if (c - 1 == 1) slot_sym[r] = (int)(v - 1);
                if (c - 1 == 3) peer_posture[r] = (int32_t)(v - 1);
                triples++;
            }
            if (triples <= 0 && r >= 0 && m.len > 0 && triples < 0) {
                printf("RBAD "); print_hex(m.d, m.len); printf("\n");
            } else if (triples == 0) {
                printf("RBAD "); print_hex(m.d, m.len); printf("\n");
            }
        }

        /* fused posture: the k=3 joint spiral cell over the latest symbols; gossip it */
        if (slot_sym[0] >= 0 && slot_sym[1] >= 0 && slot_sym[2] >= 0) {
            int syms[SSC_MAX_FIELDS];
            for (int r = 0; r < N_ROLES; r++) syms[ROLE_FIELD[r]] = slot_sym[r];
            int32_t pn = ssc_n(N, syms);
            int band = pn >= 0 ? ssc_band(N, (uint32_t)pn) : -1;
            tx_triple(3, tick, (uint32_t)pn);
            printf("P %lu n=%ld band=%d route=%s peers=%ld,%ld,%ld\n",
                   (unsigned long)tick, (long)pn, band,
                   band >= 0 ? N->bands[band].route : "?",
                   (long)peer_posture[0], (long)peer_posture[1], (long)peer_posture[2]);
        }
        if (BATCH_TICKS > 1 && tick % BATCH_TICKS == (uint32_t)(BATCH_TICKS - 1))
            bat_flush(tick);                    /* the whole window rides one frame */
        vTaskDelay(pdMS_TO_TICKS(TICK_MS));
    }
}
