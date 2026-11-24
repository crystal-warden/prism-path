// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_mesh.c: one ESP32 node of the ESP-NOW mesh as a policy distribution enforcement point of kind `mesh`
 * (docs/design/spec-policy-distribution.md). mesh_node.c holds the node's logic over the C core in
 * prismpath-hw/dist/, and the host runs the same file in prismpath-hw/mesh/host/mesh_sim.c. This file only wires it
 * to the board: two NVS partitions keep the durable parts (`nvs`, and `nvs_copy` for the second copy IS10 asks
 * of the install parts), esp_timer is the monotonic clock, ESP-NOW and UART0 carry frames, and every decision is
 * the core's (pp_pep_ask).
 *
 * The node has no real time clock (T2). Its time is its time floor at boot plus the seconds it has run, and every
 * verified envelope's not_before raises the floor (V13), as does the first fresh controller statement of a start
 * where the anchor sets `fresh` (H16).
 *
 * UART0, 115200 baud, one line per message.
 *   in   F <frame hex>   a frame from the host: broadcast on ESP-NOW and taken here
 *        L <frame hex>   a frame taken here only
 *        B               a beat state record
 *        A <regs hex> [<ages, comma separated, - for none>]   one decision of the core
 *        Z               forget the durable state and the instance key on both partitions, then restart
 *   out  I <instance public key hex>, H <hold 0|1>, X <crystal MHz>   at boot, or E <reason> when it does not start
 *        S <state record hex>                                  each record the node signs, oldest first
 *        D <transfer> <cause code>                             a dropped frame transfer
 *        Q <outcome> <cause> <basis> <held mark>               the answer to A
 *        N mac=<mac> state=<s> held=<0|1> seq=<active seq> epoch=<epoch id> cause=<refusal cause or 0> hold=<0|1>
 *          nvs_used=<entries> nvs_free=<entries> copy_used=<entries> copy_free=<entries> nvs_written=<bytes>
 *          nvs_failures=<n>                                    each second
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/uart.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include "soc/rtc.h"

#include "mesh_node.h"
#include "tables.h"

#define UART UART_NUM_0
#ifdef CONFIG_PPT_MESH_EXPIRY_HOLD
#define EXPIRY_HOLD 1
#else
#define EXPIRY_HOLD 0
#endif
#define COPY_PARTITION "nvs_copy"
static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static mesh_node node;
static mesh_build build;
static uint8_t mac[6];
static nvs_handle_t handles[2];
static int handle_open[2];

static void emit(const char *fmt, ...) {
    char line[320];
    va_list ap;
    va_start(ap, fmt);
    int length = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (length > 0) uart_write_bytes(UART, line, length < (int)sizeof line ? length : (int)sizeof line - 1);
}

static void emit_hex(const char *tag, const uint8_t *data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    char chunk[130];
    uart_write_bytes(UART, tag, strlen(tag));
    for (size_t at = 0; at < len; at += 64) {
        size_t n = len - at < 64 ? len - at : 64, k = 0;
        for (size_t j = 0; j < n; j++) {
            chunk[k++] = digits[data[at + j] >> 4];
            chunk[k++] = digits[data[at + j] & 15];
        }
        uart_write_bytes(UART, chunk, k);
    }
    uart_write_bytes(UART, "\r\n", 2);
}

/* ---------------- the store: NVS on two partitions ---------------- */
static int store_get(void *context, int medium, const char *name, uint8_t *out, size_t *len) {
    (void)context;
    if (!handle_open[medium]) return -1;
    esp_err_t err = nvs_get_blob(handles[medium], name, out, len);
    if (err == ESP_ERR_NVS_NOT_FOUND) return 1;
    return err == ESP_OK ? 0 : -1;
}

static int store_set(void *context, int medium, const char *name, const uint8_t *data, size_t len) {
    (void)context;
    return handle_open[medium] && nvs_set_blob(handles[medium], name, data, len) == ESP_OK ? 0 : -1;
}

static int store_commit(void *context, int medium) {
    (void)context;
    return handle_open[medium] && nvs_commit(handles[medium]) == ESP_OK ? 0 : -1;
}

static void open_partitions(void) {
    const char *names[2] = {NVS_DEFAULT_PART_NAME, COPY_PARTITION};
    for (int m = 0; m < 2; m++) {
        esp_err_t err = nvs_flash_init_partition(names[m]);
        if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            nvs_flash_erase_partition(names[m]); /* a partition NVS cannot use: its parts read as absent */
            err = nvs_flash_init_partition(names[m]);
        }
        handle_open[m] = err == ESP_OK && nvs_open_from_partition(names[m], "ppt", NVS_READWRITE, &handles[m]) == ESP_OK;
    }
}

static void forget(void) {
    for (int m = 0; m < 2; m++)
        if (handle_open[m]) {
            nvs_erase_all(handles[m]);
            nvs_commit(handles[m]);
        }
    esp_restart();
}

/* ---------------- the radio and the serial report ---------------- */
static void on_radio(void *context, const uint8_t *frame, size_t len) {
    (void)context;
    esp_now_send(BCAST, frame, len);
}

static void on_record(void *context, const uint8_t *record, size_t len) {
    (void)context;
    emit_hex("S ", record, len);
}

static void on_dropped(void *context, unsigned transfer, unsigned cause) {
    (void)context;
    emit("D %u %u\r\n", transfer, cause);
}

typedef struct {
    int len;
    uint8_t data[PP_FRAME_LIMIT];
} rxmsg_t;
static QueueHandle_t rxq;

static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    (void)info;
    if (len <= 0 || len > PP_FRAME_LIMIT) return;
    rxmsg_t message;
    message.len = len;
    memcpy(message.data, data, len);
    xQueueSend(rxq, &message, 0);
}

static int unhex(const char *text, uint8_t *out, size_t room) {
    size_t n = strlen(text);
    if (n % 2 || n / 2 > room) return -1;
    for (size_t k = 0; k < n / 2; k++) {
        int hi = text[2 * k], lo = text[2 * k + 1];
        hi = hi <= '9' ? hi - '0' : (hi | 0x20) - 'a' + 10;
        lo = lo <= '9' ? lo - '0' : (lo | 0x20) - 'a' + 10;
        if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return -1;
        out[k] = (uint8_t)(hi << 4 | lo);
    }
    return (int)(n / 2);
}

static void ask(char *args) {
    static uint8_t regs[4 + 8 * PP_LAYOUT_FIELDS];
    static uint32_t ages[PP_LAYOUT_FIELDS];
    char *space = strchr(args, ' ');
    if (space) *space = 0;
    int n = unhex(args, regs, sizeof regs);
    if (n < 4) return;
    const uint32_t *given = NULL;
    if (space) {
        size_t k = 0;
        for (char *tok = strtok(space + 1, ","); tok && k < PP_LAYOUT_FIELDS; tok = strtok(NULL, ","))
            ages[k++] = strcmp(tok, "-") == 0 ? PP_AGE_NONE : (uint32_t)strtoul(tok, NULL, 10);
        for (; k < PP_LAYOUT_FIELDS; k++) ages[k] = PP_AGE_NONE;
        given = ages;
    }
    pp_decision d;
    mesh_node_ask(&node, regs, (size_t)n, given, esp_timer_get_time(), &d);
    emit("Q %u %u %u %d\r\n", d.outcome, d.cause, d.basis, d.held_mark);
}

static void command(char *line) {
    static uint8_t frame[PP_FRAME_LIMIT];
    if ((line[0] == 'F' || line[0] == 'L') && line[1] == ' ') {
        int n = unhex(line + 2, frame, sizeof frame);
        if (n <= 0) return;
        if (line[0] == 'F') esp_now_send(BCAST, frame, n); /* the mesh hears it from this node */
        mesh_node_frame(&node, frame, (size_t)n, esp_timer_get_time());
    } else if (line[0] == 'B') {
        mesh_node_beat(&node, esp_timer_get_time());
    } else if (line[0] == 'A' && line[1] == ' ') {
        ask(line + 2);
    } else if (line[0] == 'Z') {
        forget();
    }
}

static void status(void) {
    int held = 0;
    pp_pep_machine *pep = node.pep;
    uint8_t cause = pp_pep_decide(pep, &held, mesh_node_time(&node, esp_timer_get_time()));
    nvs_stats_t stats[2];
    memset(stats, 0, sizeof stats);
    nvs_get_stats(NVS_DEFAULT_PART_NAME, &stats[0]);
    nvs_get_stats(COPY_PARTITION, &stats[1]);
    emit("N mac=%02x:%02x:%02x:%02x:%02x:%02x state=%s held=%d seq=%lld epoch=%llu cause=%u hold=%d nvs_used=%u "
         "nvs_free=%u copy_used=%u copy_free=%u nvs_written=%u nvs_failures=%u\r\n",
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mesh_node_state(&node), held,
         pep->d.has_active ? pep->d.active.seq : 0LL, (unsigned long long)pep->epoch, cause, EXPIRY_HOLD,
         (unsigned)stats[0].used_entries, (unsigned)stats[0].free_entries, (unsigned)stats[1].used_entries,
         (unsigned)stats[1].free_entries, (unsigned)node.bytes_written, node.write_failures);
}

void app_main(void) {
    const uart_config_t uc = {.baud_rate = 115200,
                              .data_bits = UART_DATA_8_BITS,
                              .parity = UART_PARITY_DISABLE,
                              .stop_bits = UART_STOP_BITS_1,
                              .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
                              .source_clk = UART_SCLK_DEFAULT};
    uart_driver_install(UART, 2048, 4096, 0, NULL, 0);
    uart_param_config(UART, &uc);
    uart_set_pin(UART, 1, 3, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    open_partitions();
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wc);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    esp_wifi_get_mac(WIFI_IF_STA, mac);
    esp_now_init();
    esp_now_register_recv_cb(on_recv);
    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, BCAST, 6);
    peer.ifidx = WIFI_IF_STA;
    peer.channel = 0;
    peer.encrypt = false;
    esp_now_add_peer(&peer);
    rxq = xQueueCreate(16, sizeof(rxmsg_t));

    /* The machine, the assembler and the packing buffer are allocated once here, at boot, since the static DRAM
       has not the room the heap has. Nothing allocates after this. */
    pp_pep_machine *pep = calloc(1, sizeof *pep);
    pp_assembler *assembler = calloc(1, sizeof *assembler);
    uint8_t *packed = malloc(PP_PART_PACKED_MAX);
    if (!pep || !assembler || !packed) {
        emit("E no memory for the enforcement point\r\n");
        for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
    }
    build.anchor = &MESH_ANCHOR;
    build.expiry_hold = EXPIRY_HOLD;
    build.layout = &MESH_LAYOUT;
    build.has_domain = 1;
    memcpy(build.domain_sha256, MESH_DOMAIN, 32);
    uint8_t seed[32];
    esp_fill_random(seed, sizeof seed);
    mesh_store store = {store_get, store_set, store_commit, NULL};
    mesh_io io = {on_radio, on_record, on_dropped, NULL};
    if (mesh_node_open(&node, pep, assembler, packed, &build, &store, &io, seed, esp_timer_get_time()) != 0) {
        emit("E refused to start: an expiry response other than the one provisioned (X10), an instance key the trust "
             "store holds (K2), or an anchor whose keys are not apart (P2)\r\n");
        for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
    }
    emit_hex("I ", pep->instance_public, 32);
    emit("H %d\r\n", EXPIRY_HOLD);
    emit("X %d\r\n", (int)rtc_clk_xtal_freq_get()); /* the crystal this board runs at, as the auto setting found it */

    static char line[2 * PP_FRAME_LIMIT + 2 * (4 + 8 * PP_LAYOUT_FIELDS) + 64];
    size_t used = 0;
    int64_t next_status = 0, next_tick = 0, next_save = 3600LL * 1000000;
    for (;;) {
        uint8_t byte;
        while (uart_read_bytes(UART, &byte, 1, 0) == 1) {
            if (byte == '\n' || byte == '\r') {
                line[used] = 0;
                if (used) command(line);
                used = 0;
            } else if (used + 1 < sizeof line) {
                line[used++] = (char)byte;
            }
        }
        rxmsg_t message;
        while (xQueueReceive(rxq, &message, 0) == pdTRUE)
            mesh_node_frame(&node, message.data, (size_t)message.len, esp_timer_get_time());
        int64_t now = esp_timer_get_time();
        if (now >= next_tick) { /* X1 at least once a minute, B8 a commit's delay, T2 the time saved hourly */
            next_tick = now + 20000;
            int save = now >= next_save;
            if (save) next_save = now + 3600LL * 1000000;
            mesh_node_tick(&node, now, save);
        }
        if (now >= next_status) {
            next_status = now + 1000000;
            status();
        }
        vTaskDelay(1); /* one tick, so the idle task runs and the watchdog is fed */
    }
}
