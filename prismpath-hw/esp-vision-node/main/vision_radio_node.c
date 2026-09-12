// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// radio node: the camera node deciding live, readings over ESP-NOW instead of USB. One reading per
// frame as one ESP-NOW frame ("RDG6" record, under 90 bytes); background keyframes as fragments.
// Streams from boot; nothing on USB. The UART console carries the log.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_camera.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "mbedtls/sha256.h"
#include "monocypher-ed25519.h"
#include "authority_pubkey.h"
#include "nvs.h"
#include "driver/gpio.h"
#include "esp_random.h"
#include "esp_log.h"
#include "driver/usb_serial_jtag.h"
#include "vision_policy.h"
#include "../../codec-bench/zeck.h"
#include "vision_core.h"
#include "vision_radio.h"

static const char *TAG = "radio";
#define CAM_XCLK 15
#define CAM_SIOD 4
#define CAM_SIOC 5
#define CAM_D7 16
#define CAM_D6 17
#define CAM_D5 18
#define CAM_D4 12
#define CAM_D3 10
#define CAM_D2 8
#define CAM_D1 9
#define CAM_D0 11
#define CAM_VSYNC 6
#define CAM_HREF 7
#define CAM_PCLK 13
#define KEY_QUALITY 75
#define KEY_RESEND_US \
    60000000ULL /* Resend the background keyframe every minute for late-joining receivers (WIRE.md). */
#define CHAIN_SIGN_US 60000000ULL /* Sign chain head once per minute to bind trail sequence to camera key (WIRE.md). */
#define EVIDENCE_GAP_US 10000000ULL
#define LAYER_REFRESH 5
#define LED_GPIO 2
#define ACT_LED_US 3000000

/* Refusal cause codes from registry (prismpath/kernel/causes.py). */
enum {
    CAUSE_OK = 0,                   /* Success or clean outcome with no refusal (causes.py). */
    CAUSE_SIG_MISSING = 1,          /* Pack or action carries no signature (causes.py). */
    CAUSE_SIG_INVALID = 2,          /* Signature fails Ed25519 verification (causes.py). */
    CAUSE_MANIFEST_BAD_FORMAT = 5,  /* Manifest or payload unparseable or incomplete (causes.py). */
    CAUSE_IMAGE_VERSION_REPLAY = 9, /* Older signed policy version replayed at loader (causes.py). */
    CAUSE_IMAGE_CAPS_EXCEEDED = 16, /* Image exceeds capacity bound or fails table parse (causes.py). */
    CAUSE_ROUTE_NO_EDGE = 32,       /* No matching edge or addressed to another node (causes.py). */
    CAUSE_CONTRACT_VIOLATION = 37,  /* Action output on an unauthorized decision (causes.py). */
    CAUSE_REPLAY_DUPLICATE = 52     /* Action counter not strictly above flash floor (causes.py). */
};

/* Signed policy pack wire layout parameters (WIRE.md). */
#define PACK_MAX 16384            /* Maximum buffer size for policy pack staging. */
#define CHUNK 24                  /* Chunk payload size for policy pack transfer over hop. */
#define CHUNK_HDR_LEN 4           /* Header size for chunk transfer: 2 bytes index, 2 bytes total. */
#define PACK_CHUNK_MAX_INDEX 1024 /* Maximum allowed chunk index count for staged buffer bounds. */

#define PACK_MAGIC_LEN 5      /* Magic header length for "PPKV1" pack format. */
#define PACK_KEY_ID_OFF 5     /* Offset to 4-byte key identifier in pack header. */
#define PACK_KEY_ID_LEN 4     /* Length of key identifier field in pack header. */
#define PACK_VERSION_OFF 9    /* Offset to 32-bit policy version in pack header. */
#define PACK_IMAGE_LEN_OFF 13 /* Offset to 16-bit compiled image length in pack header. */
#define PACK_CB_LEN_OFF 15    /* Offset to 16-bit codebook length in pack header. */
#define PACK_ESC_MASK_OFF 17  /* Offset to 32-bit escalation bitmask in pack header. */
#define PACK_SIG_OFF 21       /* Offset to 64-byte Ed25519 signature in pack header. */
#define PACK_SIG_LEN 64       /* Length of Ed25519 signature in bytes. */
#define PACK_HDR_LEN 85       /* Total header length of signed policy pack before payload. */

#define CODEBOOK_FIELD_LEN 19   /* Byte length of each field entry in codebook layout. */
#define CODEBOOK_REG_OFF 0      /* Offset to 16-bit register id in codebook field entry. */
#define CODEBOOK_CUTS_OFF 2     /* Offset to cut count in codebook field entry. */
#define CODEBOOK_CUT_BASE_OFF 3 /* Base offset to 32-bit cuts in codebook field entry. */
#define CODEBOOK_CUT_BYTES 4    /* Byte size of each 32-bit cut value in codebook. */

/* Signed action wire layout parameters (WIRE.md). */
#define ACT_MAGIC_LEN 4      /* Magic header length for "ACT1" action format. */
#define ACT_TO_OFF 4         /* Offset to 16-bit target node id in action payload. */
#define ACT_ADMISSION_OFF 16 /* Offset to admission flag byte in action payload. */
#define ACT_ACTION_OFF 17    /* Offset to action byte in action payload. */
#define ACT_COUNTER_OFF 18   /* Offset to 32-bit execution counter in action payload. */
#define ACT_BODY_LEN 22      /* Total byte length of action body covered by signature. */
#define ACT_SIG_OFF 22       /* Offset to 64-byte Ed25519 signature in action payload. */
#define ACT_SIG_LEN 64       /* Length of Ed25519 signature in bytes. */
#define ACT_PACK_LEN 86      /* Expected total length of signed action payload. */

/* RDG6: the reading record containing boot epoch nonce and hash chain prev anchor (WIRE.md). */
typedef struct __attribute__((packed)) {
    char magic[4];
    uint16_t nid;
    uint16_t norm;
    uint32_t seq;
    uint64_t t_cap;
    uint64_t t_dec;
    uint16_t node;
    uint16_t steps;
    uint16_t wire_len;
    uint64_t prev;
    uint16_t pver;
    uint32_t epoch;
} rdg_hdr_t;

static uint16_t node_id;
static uint8_t cam_sk[64];
static uint8_t cam_pk[32];
static bool cam_key = false;
static uint32_t boot_epoch = 0;

/* CHN1: signed chain head record emitted periodically to attest trail sequence (WIRE.md). */
typedef struct __attribute__((packed)) {
    char magic[4];
    uint16_t nid;
    uint32_t epoch;
    uint32_t seq;
    uint64_t head;
    uint16_t pver;
    uint8_t sig[64];
} chn_t;

static void cam_key_init(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    nvs_handle_t nvs_handle;
    if (nvs_open("cam", NVS_READWRITE, &nvs_handle) != ESP_OK) {
        ESP_LOGE(TAG, "camera key: NVS open failed, readings will not be signed");
        return;
    }
    size_t sk_len = 64;
    size_t pk_len = 32;
    if (nvs_get_blob(nvs_handle, "sk", cam_sk, &sk_len) == ESP_OK && sk_len == 64 &&
        nvs_get_blob(nvs_handle, "pk", cam_pk, &pk_len) == ESP_OK && pk_len == 32) {
        cam_key = true;
    } else {
        uint8_t seed[32];
        esp_fill_random(seed, 32);
        crypto_ed25519_key_pair(cam_sk, cam_pk, seed);
        nvs_set_blob(nvs_handle, "sk", cam_sk, 64);
        nvs_set_blob(nvs_handle, "pk", cam_pk, 32);
        nvs_commit(nvs_handle);
        cam_key = true;
        ESP_LOGI(TAG, "camera signing key generated and kept in NVS");
    }
    nvs_close(nvs_handle);
}

static void publish_cam_key(void) {
    uint8_t key_msg[38];
    memcpy(key_msg, "PUB2", 4);
    key_msg[4] = node_id & 0xff;
    key_msg[5] = node_id >> 8;
    memcpy(key_msg + 6, cam_pk, 32);
    esp_now_send(BCAST, key_msg, sizeof(key_msg));
    hop_send(key_msg, sizeof(key_msg));
}

static void sign_chain_head(uint32_t seq, uint64_t head) {
    if (!cam_key) {
        return;
    }
    chn_t chain_head;
    memset(&chain_head, 0, sizeof(chain_head));
    memcpy(chain_head.magic, "CHN1", 4);
    chain_head.nid = node_id;
    chain_head.epoch = boot_epoch;
    chain_head.seq = seq;
    chain_head.head = head;
    chain_head.pver = (uint16_t)policy_version;
    crypto_ed25519_sign(chain_head.sig, cam_sk, (const uint8_t *)&chain_head, sizeof(chain_head) - 64);
    uint8_t chn_bytes[sizeof(chain_head)];
    memcpy(chn_bytes, &chain_head, sizeof(chain_head));
    esp_now_send(BCAST, chn_bytes, sizeof(chn_bytes));
    hop_send(chn_bytes, sizeof(chn_bytes));
}

static uint64_t chain_prev = 0;

typedef struct __attribute__((packed)) {
    char magic[4];
    uint16_t nid;
    uint16_t norm;
    uint32_t seq;
    uint64_t t_cap;
    uint32_t len;
} key_hdr_t;

typedef struct __attribute__((packed)) {
    char magic[4];
    uint16_t nid;
    uint16_t norm;
    uint32_t seq;
    uint64_t t_cap;
    uint16_t route;
    uint32_t len;
} evd_hdr_t;

static uint8_t *last_sent;
static uint16_t frag_id = 0;

static void send_keyframe(camera_fb_t *fb, uint32_t seq, uint64_t t_cap) {
    uint8_t *jpg = NULL;
    size_t jlen = 0;
    camera_fb_t bg = *fb;
    bg.buf = background;
    bg.len = FRAME_W * FRAME_H;
    if (!frame2jpg(&bg, KEY_QUALITY, &jpg, &jlen)) {
        ESP_LOGE(TAG, "frame2jpg failed");
        return;
    }
    uint8_t *msg = malloc(sizeof(key_hdr_t) + jlen);
    key_hdr_t kh = {{'K', 'E', 'Y', '3'}, node_id, normal_id, seq, t_cap, (uint32_t)jlen};
    memcpy(msg, &kh, sizeof(kh));
    memcpy(msg + sizeof(kh), jpg, jlen);
    free(jpg);
    radio_send_fragmented(node_id, frag_id++, msg, sizeof(kh) + jlen);
    free(msg);
    memcpy(last_sent, fb->buf, FRAME_W * FRAME_H);
    ESP_LOGI(TAG, "keyframe %lu B in %u fragments, normal %04x", (unsigned long)(sizeof(kh) + jlen),
             (unsigned)((sizeof(kh) + jlen + FRAG_DATA - 1) / FRAG_DATA), normal_id);
}

static bool escalates(uint16_t node) {
    return (esc_mask >> node) & 1u;
}

static int layer_level = 0;
static uint8_t layer_last[GRID_ROWS * GRID_COLS][32];
static bool layer_have[GRID_ROWS * GRID_COLS];
static uint32_t layer_frame = 0;
static uint32_t layer_last_full = 0;

static void layer3_cell(int row, int col, uint8_t out[32]) {
    const int sub_h = CELL_H / 8;
    const int sub_w = CELL_W / 8;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            uint32_t sum_val = 0;
            const uint8_t *base = cur + (row * CELL_H + i * sub_h) * FRAME_W + col * CELL_W + j * sub_w;
            for (int y_pos = 0; y_pos < sub_h; y_pos++) {
                for (int x_pos = 0; x_pos < sub_w; x_pos++) {
                    sum_val += base[y_pos * FRAME_W + x_pos];
                }
            }
            uint8_t band = (uint8_t)((sum_val / (sub_h * sub_w)) >> 4);
            int sub_idx = i * 8 + j;
            if (sub_idx & 1) {
                out[sub_idx >> 1] |= band << 4;
            } else {
                out[sub_idx >> 1] = band;
            }
        }
    }
}

static void send_layer3(uint32_t seq, uint16_t node, bool is_door) {
    static uint8_t rec[8 + GRID_ROWS * GRID_COLS * 33];
    int cell_count = 0;
    size_t off = 8;
    bool full = (layer_frame - layer_last_full >= LAYER_REFRESH);
    if (full) {
        layer_last_full = layer_frame;
    }
    layer_frame++;
    for (int row = 0; row < GRID_ROWS; row++) {
        for (int col = 0; col < GRID_COLS; col++) {
            bool named = motion_mad[row][col] >= MOTION_ON;
            (void)is_door;
            int idx = row * GRID_COLS + col;
            if (!named) {
                layer_have[idx] = false;
                continue;
            }
            uint8_t syms[32];
            layer3_cell(row, col, syms);
            bool changed = !layer_have[idx] || memcmp(syms, layer_last[idx], 32) != 0;
            memcpy(layer_last[idx], syms, 32);
            layer_have[idx] = true;
            if (!(full || changed)) {
                continue;
            }
            rec[off++] = (uint8_t)((row << 4) | col);
            memcpy(rec + off, syms, 32);
            off += 32;
            cell_count++;
        }
    }
    if (cell_count == 0) {
        return;
    }
    memcpy(rec, "LAY3", 4);
    rec[4] = node_id & 0xff;
    rec[5] = node_id >> 8;
    memcpy(rec + 6, &seq, 4);
    uint8_t flags = full ? 1 : 0;
    memmove(rec + 12, rec + 8, off - 8);
    rec[10] = flags;
    rec[11] = (uint8_t)cell_count;
    off += 4;
    radio_send_fragmented_ex(node_id, frag_id++, rec, off, false);
}

static uint8_t *staged;
static uint8_t *vmsg;
static uint8_t *tbl_backup;
static uint16_t staged_total = 0;
static uint8_t staged_have[128];
static uint32_t staged_len = 0;
static uint32_t staged_count = 0;

typedef struct __attribute__((packed)) {
    char magic[4];
    uint16_t nid;
    uint32_t version;
    uint16_t cause;
    uint32_t verify_us;
    uint64_t image_hash;
    uint64_t t;
} swp_t;

static void swap_reset(void) {
    staged_total = 0;
    staged_len = 0;
    staged_count = 0;
    memset(staged_have, 0, sizeof(staged_have));
}

static void swap_chunk(const uint8_t *chunk_data, int total_len) {
    uint16_t idx = chunk_data[0] | (chunk_data[1] << 8);
    uint16_t total = chunk_data[2] | (chunk_data[3] << 8);
    const uint8_t *payload = chunk_data + CHUNK_HDR_LEN;
    int payload_len = total_len - CHUNK_HDR_LEN;
    if (total != staged_total) {
        swap_reset();
        staged_total = total;
    }
    if (idx >= PACK_CHUNK_MAX_INDEX || payload_len < 0 || (uint32_t)idx * CHUNK + payload_len > PACK_MAX) {
        return;
    }
    memcpy(staged + (uint32_t)idx * CHUNK, payload, payload_len);
    if ((uint32_t)idx * CHUNK + payload_len > staged_len) {
        staged_len = (uint32_t)idx * CHUNK + payload_len;
    }
    if (!((staged_have[idx >> 3] >> (idx & 7)) & 1)) {
        staged_have[idx >> 3] |= 1 << (idx & 7);
        staged_count++;
    }
}

static uint16_t swap_execute(uint32_t *out_version, uint64_t *out_hash, uint32_t *out_us) {
    int64_t start_time = esp_timer_get_time();
    uint16_t cause = CAUSE_OK;
    uint32_t version = 0;
    uint64_t image_hash_val = 0;
    if (staged_total == 0 || staged_count != staged_total) {
        cause = CAUSE_MANIFEST_BAD_FORMAT;
    } else if (staged_len < PACK_HDR_LEN || memcmp(staged, "PPKV1", PACK_MAGIC_LEN) != 0 ||
               memcmp(staged + PACK_KEY_ID_OFF, KEY_ID, PACK_KEY_ID_LEN) != 0) {
        cause = CAUSE_MANIFEST_BAD_FORMAT;
    } else {
        version = rd32(staged + PACK_VERSION_OFF);
        uint16_t image_len = rd16b(staged + PACK_IMAGE_LEN_OFF);
        uint16_t cb_len = rd16b(staged + PACK_CB_LEN_OFF);
        uint32_t esc = (uint32_t)rd32(staged + PACK_ESC_MASK_OFF);
        if ((uint32_t)PACK_HDR_LEN + image_len + cb_len != staged_len || cb_len % CODEBOOK_FIELD_LEN != 0 ||
            cb_len / CODEBOOK_FIELD_LEN > CB_MAX_FIELDS || image_len > TBL_MAX) {
            cause = CAUSE_MANIFEST_BAD_FORMAT;
        } else {
            bool zero = true;
            for (int i = 0; i < PACK_SIG_LEN; i++) {
                if (staged[PACK_SIG_OFF + i]) {
                    zero = false;
                    break;
                }
            }
            if (zero) {
                cause = CAUSE_SIG_MISSING;
            } else {
                memcpy(vmsg, staged, PACK_SIG_OFF);
                memcpy(vmsg + PACK_SIG_OFF, staged + PACK_HDR_LEN, image_len + cb_len);
                if (crypto_ed25519_check(staged + PACK_SIG_OFF, AUTHORITY_PUBKEY, vmsg,
                                         PACK_SIG_OFF + image_len + cb_len) != 0) {
                    cause = CAUSE_SIG_INVALID;
                } else if (version <= policy_version) {
                    cause = CAUSE_IMAGE_VERSION_REPLAY;
                } else {
                    memcpy(tbl_backup, tbl, TBL_MAX);
                    memcpy(tbl, staged + PACK_HDR_LEN, image_len);
                    if (parse_table(image_len) != 0) {
                        memcpy(tbl, tbl_backup, TBL_MAX);
                        parse_table(POLICY_TABLE_LEN);
                        cause = CAUSE_IMAGE_CAPS_EXCEEDED;
                    } else {
                        const uint8_t *codebook = staged + PACK_HDR_LEN + image_len;
                        wire_n = cb_len / CODEBOOK_FIELD_LEN;
                        for (int i = 0; i < wire_n; i++) {
                            wire_fields[i].reg = rd16b(codebook + CODEBOOK_FIELD_LEN * i + CODEBOOK_REG_OFF);
                            wire_fields[i].n_cuts = codebook[CODEBOOK_FIELD_LEN * i + CODEBOOK_CUTS_OFF];
                            for (int k = 0; k < CB_MAX_CUTS; k++) {
                                wire_fields[i].cut[k] = rd32(codebook + CODEBOOK_FIELD_LEN * i + CODEBOOK_CUT_BASE_OFF +
                                                             CODEBOOK_CUT_BYTES * k);
                            }
                        }
                        esc_mask = esc;
                        policy_version = version;
                        uint8_t hash_buf[32];
                        mbedtls_sha256(staged + PACK_HDR_LEN, image_len, hash_buf, 0);
                        memcpy(&image_hash_val, hash_buf, 8);
                        nvs_handle_t nvs_handle;
                        if (nvs_open("cam", NVS_READWRITE, &nvs_handle) == ESP_OK) {
                            nvs_set_blob(nvs_handle, "pack", staged, staged_len);
                            nvs_set_u32(nvs_handle, "pver", version);
                            nvs_commit(nvs_handle);
                            nvs_close(nvs_handle);
                        }
                    }
                }
            }
        }
    }
    *out_version = version;
    *out_hash = image_hash_val;
    *out_us = (uint32_t)(esp_timer_get_time() - start_time);
    swap_reset();
    return cause;
}

static uint32_t act_counter_floor = 0;
static int64_t t_led_off = 0;
static bool led_on = false;

static void act_led(bool on) {
    gpio_set_level(LED_GPIO, on ? 1 : 0);
    led_on = on;
    if (on) {
        t_led_off = esp_timer_get_time() + ACT_LED_US;
    }
}

static uint16_t act_execute(uint32_t *out_counter) {
    uint16_t cause = CAUSE_OK;
    uint32_t counter = 0;
    if (staged_total == 0 || staged_count != staged_total || staged_len != ACT_PACK_LEN ||
        memcmp(staged, "ACT1", ACT_MAGIC_LEN) != 0) {
        cause = CAUSE_MANIFEST_BAD_FORMAT;
    } else {
        uint16_t target_node = rd16b(staged + ACT_TO_OFF);
        uint8_t admission = staged[ACT_ADMISSION_OFF];
        uint8_t action = staged[ACT_ACTION_OFF];
        memcpy(&counter, staged + ACT_COUNTER_OFF, 4);
        bool zero = true;
        for (int i = 0; i < ACT_SIG_LEN; i++) {
            if (staged[ACT_SIG_OFF + i]) {
                zero = false;
                break;
            }
        }
        if (zero) {
            cause = CAUSE_SIG_MISSING;
        } else if (crypto_ed25519_check(staged + ACT_SIG_OFF, AUTHORITY_PUBKEY, staged, ACT_BODY_LEN) != 0) {
            cause = CAUSE_SIG_INVALID;
        } else if (target_node != node_id) {
            cause = CAUSE_ROUTE_NO_EDGE;
        } else if (counter <= act_counter_floor) {
            cause = CAUSE_REPLAY_DUPLICATE;
        } else if (admission != 1) {
            cause = CAUSE_CONTRACT_VIOLATION;
        } else {
            act_counter_floor = counter;
            nvs_handle_t nvs_handle;
            if (nvs_open("cam", NVS_READWRITE, &nvs_handle) == ESP_OK) {
                nvs_set_u32(nvs_handle, "act", counter);
                nvs_commit(nvs_handle);
                nvs_close(nvs_handle);
            }
            if (action == 1) {
                act_led(true);
            }
            cause = CAUSE_OK;
        }
    }
    *out_counter = counter;
    swap_reset();
    return cause;
}

static void send_evidence(camera_fb_t *fb, uint32_t seq, uint64_t t_cap, uint16_t route) {
    uint8_t *jpg = NULL;
    size_t jlen = 0;
    if (!frame2jpg(fb, KEY_QUALITY, &jpg, &jlen)) {
        return;
    }
    uint8_t *msg = malloc(sizeof(evd_hdr_t) + jlen);
    evd_hdr_t eh = {{'E', 'V', 'D', '1'}, node_id, normal_id, seq, t_cap, route, (uint32_t)jlen};
    memcpy(msg, &eh, sizeof(eh));
    memcpy(msg + sizeof(eh), jpg, jlen);
    free(jpg);
    radio_send_fragmented(node_id, frag_id++, msg, sizeof(eh) + jlen);
    free(msg);
    ESP_LOGI(TAG, "evidence for %s: %lu B", POLICY_NODE_NAMES[route], (unsigned long)(sizeof(eh) + jlen));
}

void app_main(void) {
    vision_core_init();
    last_sent = heap_caps_malloc(FRAME_W * FRAME_H, MALLOC_CAP_SPIRAM);
    staged = heap_caps_malloc(PACK_MAX, MALLOC_CAP_SPIRAM);
    vmsg = heap_caps_malloc(PACK_MAX, MALLOC_CAP_SPIRAM);
    tbl_backup = heap_caps_malloc(TBL_MAX, MALLOC_CAP_SPIRAM);
    swap_reset();
    boot_epoch = esp_random();
    cam_key_init();
    {
        gpio_config_t g = {.pin_bit_mask = 1ULL << LED_GPIO, .mode = GPIO_MODE_OUTPUT};
        gpio_config(&g);
        gpio_set_level(LED_GPIO, 0);
        nvs_handle_t nvs_handle;
        if (nvs_open("cam", NVS_READONLY, &nvs_handle) == ESP_OK) {
            nvs_get_u32(nvs_handle, "act", &act_counter_floor);
            nvs_close(nvs_handle);
        }
    }
    {
        nvs_handle_t nh;
        if (nvs_open("cam", NVS_READONLY, &nh) == ESP_OK) {
            size_t plen = PACK_MAX;
            if (nvs_get_blob(nh, "pack", staged, &plen) == ESP_OK && plen > PACK_HDR_LEN) {
                staged_len = plen;
                staged_total = (uint16_t)((plen + CHUNK - 1) / CHUNK);
                staged_count = staged_total;
                memset(staged_have, 0xff, sizeof(staged_have));
                uint32_t ver;
                uint64_t image_hash_val;
                uint32_t us;
                uint16_t cause = swap_execute(&ver, &image_hash_val, &us);
                ESP_LOGI(TAG, "stored policy pack version %lu re-applied at boot: %s (cause %u)", (unsigned long)ver,
                         cause ? "REFUSED" : "committed", cause);
            }
            nvs_close(nh);
        }
    }
    camera_config_t cam_cfg = {
        .pin_pwdn = -1,
        .pin_reset = -1,
        .pin_xclk = CAM_XCLK,
        .pin_sccb_sda = CAM_SIOD,
        .pin_sccb_scl = CAM_SIOC,
        .pin_d7 = CAM_D7,
        .pin_d6 = CAM_D6,
        .pin_d5 = CAM_D5,
        .pin_d4 = CAM_D4,
        .pin_d3 = CAM_D3,
        .pin_d2 = CAM_D2,
        .pin_d1 = CAM_D1,
        .pin_d0 = CAM_D0,
        .pin_vsync = CAM_VSYNC,
        .pin_href = CAM_HREF,
        .pin_pclk = CAM_PCLK,
        .xclk_freq_hz = 20000000,
        .ledc_timer = LEDC_TIMER_0,
        .ledc_channel = LEDC_CHANNEL_0,
        .pixel_format = PIXFORMAT_GRAYSCALE,
        .frame_size = (FRAME_W == 640 ? FRAMESIZE_VGA : FRAMESIZE_QVGA),
        .jpeg_quality = 12,
        .fb_count = 3,
        .fb_location = CAMERA_FB_IN_PSRAM,
        .grab_mode = CAMERA_GRAB_LATEST,
    };
    ESP_ERROR_CHECK(esp_camera_init(&cam_cfg));
    radio_init(NULL);
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, mac);
    node_id = (uint16_t)((mac[4] << 8) | mac[5]);
    vTaskDelay(pdMS_TO_TICKS(3000));
    {
        sensor_t *sensor = esp_camera_sensor_get();
        if (sensor) {
            sensor->set_exposure_ctrl(sensor, 0);
            sensor->set_gain_ctrl(sensor, 0);
            ESP_LOGI(TAG, "exposure and gain locked: aec_value=%d agc_gain=%d", sensor->status.aec_value,
                     sensor->status.agc_gain);
        }
    }
    ESP_LOGI(TAG, "radio node %02x:%02x:%02x:%02x:%02x:%02x streaming over ESP-NOW", mac[0], mac[1], mac[2], mac[3],
             mac[4], mac[5]);
    uint32_t seq = 0;
    static uint8_t pkt[ESPNOW_MAX];
    uint64_t t_key = 0;
    uint64_t t_evd = 0;
    uint16_t last_normal = 0xffff;
    bool adopt_now = false;
    bool key_now = false;
    usb_serial_jtag_driver_config_t ucfg = {.tx_buffer_size = 16384, .rx_buffer_size = 256};
    bool usb_ok = usb_serial_jtag_driver_install(&ucfg) == ESP_OK;
    while (1) {
        uint8_t ch;
        if (usb_ok && usb_serial_jtag_read_bytes(&ch, 1, 0) == 1 && ch == 'n') {
            ESP_LOGI(TAG, "operator adopts the normal");
            adopt_now = true;
        }
        for (int drained = 0; hop_up && hop_sock >= 0 && drained < 8; drained++) {
            uint8_t cmd_buf[32];
            int n_read = recv(hop_sock, cmd_buf, sizeof(cmd_buf), MSG_DONTWAIT);
            if (n_read <= 0) {
                break;
            }
            if (n_read >= 4 && cmd_buf[0] == 'C') {
                uint16_t target_node = cmd_buf[1] | (cmd_buf[2] << 8);
                if (target_node == node_id || target_node == 0xffff) {
                    if (cmd_buf[3] == 'n') {
                        ESP_LOGI(TAG, "adopt over the air");
                        adopt_now = true;
                    } else if (cmd_buf[3] == 'K') {
                        publish_cam_key();
                        sign_chain_head(seq, chain_prev);
                    } else if (cmd_buf[3] == 'k') {
                        ESP_LOGI(TAG, "keyframe requested over the air");
                        key_now = true;
                    } else if (cmd_buf[3] == 'L' && n_read >= 5) {
                        layer_level = cmd_buf[4];
                        ESP_LOGI(TAG, "refinement layer %d over the air", layer_level);
                        memset(layer_have, 0, sizeof(layer_have));
                    } else if (cmd_buf[3] == 'S' && n_read >= 8) {
                        swap_chunk(cmd_buf + 4, n_read - 4);
                    } else if (cmd_buf[3] == 'Y') {
                        uint32_t ctr;
                        uint16_t cause = act_execute(&ctr);
                        uint8_t rec[17];
                        memcpy(rec, "ACT2", 4);
                        rec[4] = node_id & 0xff;
                        rec[5] = node_id >> 8;
                        memcpy(rec + 6, &ctr, 4);
                        memcpy(rec + 10, &cause, 2);
                        rec[12] = led_on ? 1 : 0;
                        uint32_t tl = (uint32_t)(esp_timer_get_time() / 1000);
                        memcpy(rec + 13, &tl, 4);
                        esp_now_send(BCAST, rec, sizeof(rec));
                        hop_send(rec, sizeof(rec));
                        ESP_LOGI(TAG, "action %lu: %s (cause %u), led %s", (unsigned long)ctr,
                                 cause ? "REFUSED" : "moved", cause, led_on ? "on" : "off");
                    } else if (cmd_buf[3] == 'X') {
                        uint32_t ver, us;
                        uint64_t image_hash_val;
                        uint16_t cause = swap_execute(&ver, &image_hash_val, &us);
                        swp_t sw = {{'S', 'W', 'P', '1'},          node_id, ver, cause, us, image_hash_val,
                                    (uint64_t)esp_timer_get_time()};
                        uint8_t sb[sizeof(sw)];
                        memcpy(sb, &sw, sizeof(sw));
                        esp_now_send(BCAST, sb, sizeof(sb));
                        hop_send(sb, sizeof(sb));
                        ESP_LOGI(TAG, "policy swap to version %lu: %s (cause %u) in %lu us; now version %lu",
                                 (unsigned long)ver, cause ? "REFUSED" : "committed", cause, (unsigned long)us,
                                 (unsigned long)policy_version);
                    } else if (cmd_buf[3] == 'r' && n_read >= 7) {
                        uint16_t id = cmd_buf[4] | (cmd_buf[5] << 8);
                        int cnt = cmd_buf[6];
                        if (cnt > n_read - 7) {
                            cnt = n_read - 7;
                        }
                        int done = radio_resend_fragments(node_id, id, cmd_buf + 7, cnt);
                        ESP_LOGI(TAG, "repair for message %u: %d fragment(s) %s", id, cnt,
                                 done < 0 ? "no longer held" : "resent");
                    }
                }
            }
        }
        if (led_on && esp_timer_get_time() > t_led_off) {
            act_led(false);
        }
        camera_fb_t *fb = esp_camera_fb_get();
        if (!fb) {
            continue;
        }
        uint64_t t_cap = (uint64_t)fb->timestamp.tv_sec * 1000000ULL + (uint64_t)fb->timestamp.tv_usec;
        cur = fb->buf;
        if (adopt_now) {
            adopt_now = false;
            adopt_normal();
        }
        int64_t t_fe0 = esp_timer_get_time();
        int32_t motion_cells, dark, step, door_hit, scene;
        front_end(&motion_cells, &dark, &step, &door_hit, &scene);
        {
            static int64_t fe_sum = 0;
            static int64_t fe_max = 0;
            static int64_t t_fe_log = 0;
            static int fe_n = 0;
            int64_t dt = esp_timer_get_time() - t_fe0;
            fe_sum += dt;
            fe_n++;
            if (dt > fe_max) {
                fe_max = dt;
            }
            if (esp_timer_get_time() - t_fe_log > 10000000) {
                ESP_LOGI(TAG, "front end %dx%d: mean %lld us, max %lld us over %d frames; free PSRAM %u B", FRAME_W,
                         FRAME_H, (long long)(fe_sum / fe_n), (long long)fe_max, fe_n,
                         (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
                fe_sum = 0;
                fe_n = 0;
                fe_max = 0;
                t_fe_log = esp_timer_get_time();
            }
        }
        uint16_t node, steps;
        decide(motion_cells, dark, step, door_hit, scene, &node, &steps);
        uint8_t wirebuf[128];
        uint16_t wire_len = encode_reading(wirebuf, sizeof(wirebuf));
        uint64_t t_dec = (uint64_t)esp_timer_get_time();
        rdg_hdr_t rh = {
            {'R', 'D', 'G', '6'},     node_id,   normal_id, seq, t_cap, t_dec, node, steps, wire_len, chain_prev,
            (uint16_t)policy_version, boot_epoch};
        memcpy(pkt, &rh, sizeof(rh));
        memcpy(pkt + sizeof(rh), wirebuf, wire_len);
        esp_now_send(BCAST, pkt, sizeof(rh) + wire_len);
        hop_send(pkt, sizeof(rh) + wire_len);
        {
            uint8_t hash_buf[32];
            mbedtls_sha256(pkt, sizeof(rh) + wire_len, hash_buf, 0);
            memcpy(&chain_prev, hash_buf, 8);
        }
        {
            static uint64_t t_chn = 0;
            if (t_dec - t_chn > CHAIN_SIGN_US) {
                publish_cam_key();
                sign_chain_head(seq, chain_prev);
                t_chn = t_dec;
            }
        }
        if (normal_set && (normal_id != last_normal || key_now || t_dec - t_key > KEY_RESEND_US)) {
            send_keyframe(fb, seq, t_cap);
            t_key = t_dec;
            last_normal = normal_id;
            key_now = false;
        }
        if (escalates(node) && t_dec - t_evd > EVIDENCE_GAP_US) {
            send_evidence(fb, seq, t_cap, node);
            t_evd = t_dec;
        }
        if (layer_level >= 3) {
            const char *nm = POLICY_NODE_NAMES[node];
            bool occ = !strcmp(nm, "occupied");
            bool door = !strcmp(nm, "door");
            if (occ || door) {
                send_layer3(seq, node, door);
            } else {
                memset(layer_have, 0, sizeof(layer_have));
            }
        }
        esp_camera_fb_return(fb);
        seq++;
    }
}
