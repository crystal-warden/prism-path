// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_mesh.c — coordinated Level M policy hot-swap across an ESP-NOW mesh of ESP32 nodes.
 *
 * The physical realization of the crypto-migration fleet model (#94): every node holds two
 * pre-vetted policies (A permissive, B tightened; tables.h). A node poked with 'R' over USB becomes
 * the COORDINATOR for one rollout and runs a two-phase commit over ESP-NOW:
 *   1. PREPARE  — broadcast the target policy bytes + its id. Followers verify the id is on the
 *                 allowlist {A,B} (the on-device "pre-vetting"), stage it, and ACK.
 *   2. COMMIT   — once all followers ACK (else ABORT — all-or-nothing), broadcast "flip in Δ ms".
 *                Every node flips its active policy at local_now+Δ, so they transition together
 *                (within ESP-NOW delivery jitter, ~ms). The flip itself is a single pointer swap.
 * Each node continuously evaluates the SAME signed .ppt every substrate certifies, on a fixed test
 * input, and reports its verdict over USB — so the host sees all three flip allow<->deny at once.
 *
 * (The id-allowlist stands in for an Ed25519 signature check — the same shape, next layer up.)
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "driver/uart.h"
#include "nvs.h"
#include "monocypher-ed25519.h"
#include "tables.h"

#define UART UART_NUM_0
#define TBL_MAX 640
#define REGS_MAX (4 + 8 * 24)
#define STACK_MAX 64
#define EXPECT_ACKS 2 /* 3-node fleet -> coordinator waits for the other two */
#define ACK_WIN_MS 500
#define FLIP_DELAY 120 /* ms from COMMIT receipt to the atomic flip */

enum {
    TY_NONE = 0,
    TY_BOOL = 1,
    TY_INT = 2,
    TY_STR = 3
};
enum {
    M_PREPARE = 1,
    M_ACK = 2,
    M_COMMIT = 3
};
static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

enum {
    OP_EQ = 0,
    OP_NE,
    OP_LT,
    OP_LE,
    OP_GT,
    OP_GE,
    OP_TRUTHY
};
enum {
    OPC_NOT = 0x8000,
    OPC_AND,
    OPC_OR,
    OPC_TRUE,
    OPC_FALSE
};
/* ---------------- evaluator core: a local copy of interp.c's core, pending conversion to ../ppt_eval.h (eval_copies_check.py) ---------------- */
static uint8_t tbl[TBL_MAX], regs[REGS_MAX];
static uint16_t n_fields, n_atoms, n_nodes, n_edges, prog_len;
static uint16_t atoms_off, nodes_off, edges_off, prog_base;
static uint16_t rd16(const uint8_t *bytes) {
    return (uint16_t)(bytes[0] | ((uint16_t)bytes[1] << 8));
}
static int32_t rd32(const uint8_t *bytes) {
    int32_t value;
    memcpy(&value, bytes, 4);
    return value;
}
static uint8_t parse_table(uint16_t len) {
    if (len < 28)
        return 3;
    if (rd32(tbl) != (int32_t)0x4D545050L || rd16(tbl + 4) != 1)
        return 1;
    n_fields = rd16(tbl + 6);
    n_atoms = rd16(tbl + 10);
    n_nodes = rd16(tbl + 12);
    n_edges = rd16(tbl + 14);
    prog_len = rd16(tbl + 16);
    atoms_off = 28;
    nodes_off = atoms_off + 8 * n_atoms;
    edges_off = nodes_off + 4 * n_nodes;
    prog_base = edges_off + 6 * n_edges;
    return (prog_base + 2 * prog_len != len) ? 3 : 0;
}
static uint8_t eval_atom(uint16_t ai) {
    const uint8_t *atom = tbl + atoms_off + 8 * (uint32_t)ai;
    uint16_t field = rd16(atom);
    uint8_t op = atom[2], aty = atom[3];
    int32_t av = rd32(atom + 4);
    const uint8_t *reg = regs + 4 + 8 * (uint32_t)field;
    int32_t rty = rd32(reg), rv = rd32(reg + 4);
    uint8_t ln = (rty == TY_BOOL || rty == TY_INT), rn = (aty == TY_BOOL || aty == TY_INT);
    switch (op) {
        case OP_EQ:
        case OP_NE: {
            uint8_t eq;
            if (ln && rn)
                eq = (rv == av);
            else if (rty == TY_STR && aty == TY_STR)
                eq = (rv == av);
            else if (rty == TY_NONE && aty == TY_NONE)
                eq = 1;
            else
                eq = 0;
            return op == OP_EQ ? eq : (uint8_t)!eq;
        }
        case OP_LT:
        case OP_LE:
        case OP_GT:
        case OP_GE:
            if (!(ln && rn))
                return 0;
            switch (op) {
                case OP_LT:
                    return rv < av;
                case OP_LE:
                    return rv <= av;
                case OP_GT:
                    return rv > av;
                default:
                    return rv >= av;
            }
        case OP_TRUTHY:
            return rty == TY_NONE ? 0 : (rv != 0);
    }
    return 0;
}
static int8_t eval_prog(uint16_t off, uint16_t cnt, uint8_t *err) {
    uint8_t st[STACK_MAX];
    int8_t sp = 0;
    for (uint16_t word_index = 0; word_index < cnt; word_index++) {
        uint16_t word = rd16(tbl + prog_base + 2 * (uint32_t)(off + word_index));
        if (word < OPC_NOT) {
            if (sp >= STACK_MAX) {
                *err = 7;
                return 0;
            }
            st[sp++] = eval_atom(word);
        } else
            switch (word) {
                case OPC_NOT:
                    st[sp - 1] = (uint8_t)!st[sp - 1];
                    break;
                case OPC_AND:
                    sp--;
                    st[sp - 1] = (uint8_t)(st[sp - 1] && st[sp]);
                    break;
                case OPC_OR:
                    sp--;
                    st[sp - 1] = (uint8_t)(st[sp - 1] || st[sp]);
                    break;
                case OPC_TRUE:
                    if (sp >= STACK_MAX) {
                        *err = 7;
                        return 0;
                    }
                    st[sp++] = 1;
                    break;
                case OPC_FALSE:
                    if (sp >= STACK_MAX) {
                        *err = 7;
                        return 0;
                    }
                    st[sp++] = 0;
                    break;
                default:
                    *err = 8;
                    return 0;
            }
    }
    return (int8_t)st[0];
}
static int8_t evaluate(uint16_t node, uint8_t *err) {
    const uint8_t *node_entry = tbl + nodes_off + 4 * (uint32_t)node;
    uint16_t eo = rd16(node_entry), ec = rd16(node_entry + 2);
    for (uint16_t edge_index = 0; edge_index < ec; edge_index++) {
        const uint8_t *edge_entry = tbl + edges_off + 6 * (uint32_t)(eo + edge_index);
        if (eval_prog(rd16(edge_entry + 2), rd16(edge_entry + 4), err))
            return (int8_t)edge_index;
        if (*err)
            return -1;
    }
    return -1;
}
/* verify a pushed pack: rebuild the domain-separated signed message and check it against the baked
   authority public key. 1 = valid. Must match gen_mesh_tables.py's signed_msg() byte for byte. */
static uint8_t vmsg[15 + TBL_MAX];
static int verify_pack(const uint8_t *table, uint16_t len, uint32_t version, const uint8_t *sig) {
    int cursor = 0;
    memcpy(vmsg + cursor, "PPTM1", 5);
    cursor += 5;
    memcpy(vmsg + cursor, KEY_ID, 4);
    cursor += 4;
    vmsg[cursor++] = version & 0xFF;
    vmsg[cursor++] = (version >> 8) & 0xFF;
    vmsg[cursor++] = (version >> 16) & 0xFF;
    vmsg[cursor++] = (version >> 24) & 0xFF;
    vmsg[cursor++] = len & 0xFF;
    vmsg[cursor++] = len >> 8;
    memcpy(vmsg + cursor, table, len);
    cursor += len;
    return crypto_ed25519_check(sig, AUTHORITY_PUBKEY, vmsg, cursor) == 0;
}

/* ---------------- state ---------------- */
static uint32_t active_id;
static uint8_t staged[TBL_MAX];
static uint16_t staged_len;
static uint32_t staged_id;
static uint16_t staged_seq;
static uint32_t staged_version;
static volatile int64_t flip_at_us = 0;
static uint32_t epoch = 0;
static uint8_t node_id;
static uint32_t version_floor = 0; /* anti-rollback: highest pushed version accepted, persisted in NVS */
/* coordinator */
static int coord = 0;
static uint16_t rollout_seq = 0;
static int64_t ack_deadline_us = 0;
static uint8_t acked[256];
static int ack_n = 0;

static void set_active(const uint8_t *table, uint16_t len, uint32_t id) {
    memcpy(tbl, table, len);
    parse_table(len);
    active_id = id;
}
static const char *pname(uint32_t id) {
    return id == POLICY_ID_A ? "A" : (id == POLICY_ID_B ? "B" : "?");
}
/* the anti-rollback floor lives in NVS so it survives reboots ('Z' resets it for a fresh cert run) */
static void floor_load(void) {
    nvs_handle_t handle;
    if (nvs_open("ppt", NVS_READONLY, &handle) == ESP_OK) {
        uint32_t stored_floor;
        if (nvs_get_u32(handle, "vfloor", &stored_floor) == ESP_OK)
            version_floor = stored_floor;
        nvs_close(handle);
    }
}
static void floor_save(uint32_t version) {
    nvs_handle_t handle;
    if (nvs_open("ppt", NVS_READWRITE, &handle) == ESP_OK) {
        nvs_set_u32(handle, "vfloor", version);
        nvs_commit(handle);
        nvs_close(handle);
    }
    version_floor = version;
}
static void floor_reset(void) {
    nvs_handle_t handle;
    if (nvs_open("ppt", NVS_READWRITE, &handle) == ESP_OK) {
        nvs_erase_key(handle, "vfloor");
        nvs_commit(handle);
        nvs_close(handle);
    }
    version_floor = 0;
}

/* ---------------- UART I/O (own UART0, console disabled) ---------------- */
static void emit(const char *fmt, ...) {
    char line[160];
    va_list ap;
    va_start(ap, fmt);
    int length = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (length > 0)
        uart_write_bytes(UART, line, length);
}
static QueueHandle_t rxq;
typedef struct {
    uint8_t src[6];
    int len;
    uint8_t data[TBL_MAX + 96];
} rxmsg_t; /* room for header + table + 64B sig */
static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (len > (int)sizeof(((rxmsg_t *)0)->data))
        return;
    rxmsg_t message;
    memcpy(message.src, info->src_addr, 6);
    message.len = len;
    memcpy(message.data, data, len);
    xQueueSend(rxq, &message, 0);
}

static void bcast(const uint8_t *data, int length) {
    esp_now_send(BCAST, data, length);
}
static void send_prepare(uint32_t id, uint32_t version, const uint8_t *table, uint16_t len, const uint8_t *sig,
                         uint16_t seq) {
    uint8_t packet[TBL_MAX + 96];
    int cursor = 0;
    packet[cursor++] = M_PREPARE;
    packet[cursor++] = seq & 0xFF;
    packet[cursor++] = seq >> 8;
    memcpy(packet + cursor, &id, 4);
    cursor += 4;
    memcpy(packet + cursor, &version, 4);
    cursor += 4;
    packet[cursor++] = len & 0xFF;
    packet[cursor++] = len >> 8;
    memcpy(packet + cursor, table, len);
    cursor += len;
    memcpy(packet + cursor, sig, 64);
    cursor += 64;
    bcast(packet, cursor);
}
static void send_ack(uint16_t seq) {
    uint8_t packet[4] = {M_ACK, seq & 0xFF, seq >> 8, node_id};
    bcast(packet, 4);
}
static void send_commit(uint16_t seq, uint16_t delay) {
    uint8_t packet[5] = {M_COMMIT, seq & 0xFF, seq >> 8, delay & 0xFF, delay >> 8};
    bcast(packet, 5);
}

static int verdict(void) {
    uint8_t err = 0;
    int8_t matched_edge = evaluate(0, &err);
    return matched_edge;
}

static void start_rollout(void) {
    uint32_t target_id = (active_id == POLICY_ID_A) ? POLICY_ID_B : POLICY_ID_A;
    const uint8_t *table;
    uint16_t len;
    uint32_t version;
    const uint8_t *sig;
    if (target_id == POLICY_ID_A) {
        table = TABLE_A;
        len = TABLE_A_LEN;
        version = VERSION_A;
        sig = SIG_A;
    } else {
        table = TABLE_B;
        len = TABLE_B_LEN;
        version = VERSION_B;
        sig = SIG_B;
    }
    rollout_seq++;
    /* stage locally (a node never hears its own broadcast) */
    memcpy(staged, table, len);
    staged_len = len;
    staged_id = target_id;
    staged_version = version;
    staged_seq = rollout_seq;
    memset(acked, 0, sizeof acked);
    ack_n = 0;
    ack_deadline_us = esp_timer_get_time() + (int64_t)ACK_WIN_MS * 1000;
    coord = 1;
    send_prepare(target_id, version, table, len, sig, rollout_seq);
    emit("[coord] PREPARE seq=%u target=%s v%lu (Ed25519-signed) — collecting ACKs\r\n", rollout_seq, pname(target_id),
         (unsigned long)version);
}

void app_main(void) {
    /* own UART0 for the binary-free status/command channel */
    const uart_config_t uc = {.baud_rate = 115200,
                              .data_bits = UART_DATA_8_BITS,
                              .parity = UART_PARITY_DISABLE,
                              .stop_bits = UART_STOP_BITS_1,
                              .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
                              .source_clk = UART_SCLK_DEFAULT};
    uart_driver_install(UART, 1024, 0, 0, NULL, 0);
    uart_param_config(UART, &uc);
    uart_set_pin(UART, 1, 3, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wc);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, mac);
    node_id = mac[5];
    esp_now_init();
    esp_now_register_recv_cb(on_recv);
    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, BCAST, 6);
    peer.ifidx = WIFI_IF_STA;
    peer.channel = 0;
    peer.encrypt = false;
    esp_now_add_peer(&peer);
    rxq = xQueueCreate(8, sizeof(rxmsg_t));

    set_active(TABLE_A, TABLE_A_LEN, POLICY_ID_A);
    floor_load();
    memset(regs, 0, sizeof regs);
    regs[4] = TY_INT;
    memcpy(regs + 8, &TEST_LEVEL, 4);
    emit(
        "node %02x up (mac %02x:%02x:%02x:%02x:%02x:%02x) — active=%s v%lu verdict=%s floor=v%lu ('R' swap, 'Z' reset "
        "floor, 'T'/'W' inject bad pack)\r\n",
        node_id, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], pname(active_id), (unsigned long)VERSION_A,
        verdict() == 0 ? "ALLOW" : "DENY", (unsigned long)version_floor);

    int64_t next_status = 0;
    for (;;) {
        int64_t now = esp_timer_get_time();
        /* USB command: 'R' -> initiate a rollout (toggle the fleet's policy) */
        uint8_t command;
        if (uart_read_bytes(UART, &command, 1, 0) == 1) {
            if (command == 'R' || command == 'r')
                start_rollout();
            else if (command == 'Z' || command == 'z') {
                floor_reset();
                emit("[test] version floor reset to v0\r\n");
            } else if (command == 'T' || command == 't') {
                uint8_t tt[TBL_MAX];
                memcpy(tt, TABLE_B, TABLE_B_LEN);
                tt[10] ^= 0xFF;
                rollout_seq++;
                send_prepare(POLICY_ID_B, VERSION_B, tt, TABLE_B_LEN, SIG_B, rollout_seq);
                emit("[test] injected TAMPERED table seq=%u (expect all REJECT bad signature)\r\n", rollout_seq);
            } else if (command == 'W' || command == 'w') {
                uint8_t ss[64];
                memcpy(ss, SIG_B, 64);
                ss[0] ^= 0xFF;
                rollout_seq++;
                send_prepare(POLICY_ID_B, VERSION_B + 10, TABLE_B, TABLE_B_LEN, ss, rollout_seq);
                emit("[test] injected WRONG-SIG pack seq=%u (expect all REJECT bad signature)\r\n", rollout_seq);
            }
        }
        /* ESP-NOW messages */
        rxmsg_t message;
        while (xQueueReceive(rxq, &message, 0) == pdTRUE) {
            uint8_t type = message.data[0];
            if (type == M_PREPARE && message.len >= 13) {
                uint16_t seq = message.data[1] | (message.data[2] << 8);
                uint32_t id;
                memcpy(&id, message.data + 3, 4);
                uint32_t version;
                memcpy(&version, message.data + 7, 4);
                uint16_t len = message.data[11] | (message.data[12] << 8);
                if (len <= TBL_MAX && 13 + (int)len + 64 <= message.len) {
                    const uint8_t *table = message.data + 13;
                    const uint8_t *sig = message.data + 13 + len;
                    if (!verify_pack(table, len, version, sig))
                        emit("  PREPARE REJECT seq=%u (bad Ed25519 signature)\r\n", seq);
                    else if (version <= version_floor)
                        emit("  PREPARE REJECT seq=%u v%lu <= floor v%lu (rollback/replay)\r\n", seq,
                             (unsigned long)version, (unsigned long)version_floor);
                    else {
                        memcpy(staged, table, len);
                        staged_len = len;
                        staged_id = id;
                        staged_version = version;
                        staged_seq = seq;
                        send_ack(seq);
                        emit("  PREPARE ok seq=%u %s v%lu (signature valid, fresh) staged — ACK\r\n", seq, pname(id),
                             (unsigned long)version);
                    }
                }
            } else if (type == M_ACK && message.len >= 4 && coord) {
                uint16_t seq = message.data[1] | (message.data[2] << 8);
                uint8_t nid = message.data[3];
                if (seq == rollout_seq && !acked[nid]) {
                    acked[nid] = 1;
                    ack_n++;
                    emit("  [coord] ACK from %02x (%d/%d)\r\n", nid, ack_n, EXPECT_ACKS);
                }
            } else if (type == M_COMMIT && message.len >= 5) {
                uint16_t seq = message.data[1] | (message.data[2] << 8);
                uint16_t delay = message.data[3] | (message.data[4] << 8);
                if (seq == staged_seq) {
                    flip_at_us = esp_timer_get_time() + (int64_t)delay * 1000;
                    emit("  COMMIT seq=%u -> flip in %ums\r\n", seq, delay);
                }
            }
        }
        /* coordinator: close the ACK window */
        if (coord && ack_deadline_us && now >= ack_deadline_us) {
            ack_deadline_us = 0;
            if (ack_n >= EXPECT_ACKS) {
                send_commit(rollout_seq, FLIP_DELAY);
                flip_at_us = esp_timer_get_time() + (int64_t)FLIP_DELAY * 1000;
                emit("[coord] %d ACKs — COMMIT seq=%u, flip in %ums\r\n", ack_n, rollout_seq, FLIP_DELAY);
            } else
                emit("[coord] ABORT seq=%u — only %d/%d staged, fleet stays on %s\r\n", rollout_seq, ack_n, EXPECT_ACKS,
                     pname(active_id));
            coord = 0;
        }
        /* the atomic flip */
        if (flip_at_us && now >= flip_at_us) {
            flip_at_us = 0;
            set_active(staged, staged_len, staged_id);
            floor_save(staged_version);
            epoch++;
            emit(">>> FLIP node=%02x -> policy %s v%lu verdict=%s epoch=%lu (floor now v%lu) <<<\r\n", node_id,
                 pname(active_id), (unsigned long)staged_version, verdict() == 0 ? "ALLOW" : "DENY",
                 (unsigned long)epoch, (unsigned long)version_floor);
        }
        /* heartbeat status */
        if (now >= next_status) {
            next_status = now + 700000;
            emit("node=%02x active=%s verdict=%s epoch=%lu\r\n", node_id, pname(active_id),
                 verdict() == 0 ? "ALLOW" : "DENY", (unsigned long)epoch);
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}
