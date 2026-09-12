// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// radio node: the camera node deciding live, readings over ESP-NOW instead of USB. One reading per
// frame as one ESP-NOW frame ("RDG1" record, under 90 bytes); background keyframes as fragments.
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
#define KEY_RESEND_US 60000000ULL   // resend the background every minute so a receiver that joins late holds a normal
// RDG4: the reading carries the first eight bytes of the SHA-256 of the previous reading record (header and wire), a hash
// chain that binds the trail to the node: a receiver can tell a lost reading (a gap in sequence) from a spliced one
typedef struct __attribute__((packed)) { char magic[4]; uint16_t nid, norm; uint32_t seq; uint64_t t_cap, t_dec; uint16_t node, steps, wire_len; uint64_t prev; uint16_t pver; } rdg_hdr_t;   // RDG5: names the policy version that decided
static uint64_t chain_prev = 0;
typedef struct __attribute__((packed)) { char magic[4]; uint16_t nid, norm; uint32_t seq; uint64_t t_cap; uint32_t len; } key_hdr_t;
typedef struct __attribute__((packed)) { char magic[4]; uint16_t nid, norm; uint32_t seq; uint64_t t_cap; uint16_t route; uint32_t len; } evd_hdr_t;
#define EVIDENCE_GAP_US 10000000ULL
static uint16_t node_id;
static uint8_t *last_sent; static uint16_t frag_id = 0;
static void send_keyframe(camera_fb_t *fb, uint32_t seq, uint64_t t_cap)
{
    // the keyframe is the normal itself, not the current frame: at adoption they are the same, at a resend or a request they are not
    uint8_t *jpg = NULL; size_t jlen = 0; camera_fb_t bg = *fb; bg.buf = background; bg.len = W * H;
    if (!frame2jpg(&bg, KEY_QUALITY, &jpg, &jlen)) { ESP_LOGE(TAG, "frame2jpg failed"); return; }
    uint8_t *msg = malloc(sizeof(key_hdr_t) + jlen); key_hdr_t kh = { {'K','E','Y','3'}, node_id, normal_id, seq, t_cap, (uint32_t)jlen };
    memcpy(msg, &kh, sizeof kh); memcpy(msg + sizeof kh, jpg, jlen); free(jpg);
    radio_send_fragmented(node_id, frag_id++, msg, sizeof kh + jlen); free(msg);
    memcpy(last_sent, fb->buf, W * H);
    ESP_LOGI(TAG, "keyframe %lu B in %u fragments, normal %04x", (unsigned long)(sizeof kh + jlen), (unsigned)((sizeof kh + jlen + FRAG_DATA - 1) / FRAG_DATA), normal_id);
}
static bool escalates(uint16_t node) { return (esc_mask >> node) & 1u; }
// ---- refinement layer 3 on the air (owner's request 2026-09-11): for the cells the reading names (motion band 2 or
// more, plus the door zone on the door route), 8 by 8 sub cells of 5 px at 16 gray bands, one nibble each; only the cells
// whose 32 bytes changed since last sent, with every named cell resent every LAYER_REFRESH frames.
//   "LAY3" | nid u16 | seq u32 | flags u8 (1 = full refresh) | n u8 | (cell u8 = r<<4|c, 32 B nibbles) x n
#define LAYER_REFRESH 5
static int layer_level = 0; static uint8_t layer_last[R * C][32]; static bool layer_have[R * C]; static uint32_t layer_frame = 0, layer_last_full = 0;
static void layer3_cell(int r, int c, uint8_t out[32])
{
    const int sh = CH / 8, sw = CW / 8;
    for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) {
        uint32_t s = 0; const uint8_t *base = cur + (r * CH + i * sh) * W + c * CW + j * sw;
        for (int y = 0; y < sh; y++) for (int x = 0; x < sw; x++) s += base[y * W + x];
        uint8_t band = (uint8_t)((s / (sh * sw)) >> 4); int k = i * 8 + j;
        if (k & 1) out[k >> 1] |= band << 4; else out[k >> 1] = band;
    }
}
static void send_layer3(uint32_t seq, uint16_t node, bool is_door)
{
    static uint8_t rec[8 + R * C * 33]; int n = 0; size_t off = 8;
    bool full = (layer_frame - layer_last_full >= LAYER_REFRESH); if (full) layer_last_full = layer_frame;
    layer_frame++;
    for (int r = 0; r < R; r++) for (int c = 0; c < C; c++) {
        bool named = m_cell[r][c] >= MOTION_ON;   // the layer follows motion only; the door zone is not refined for being a door (2026-09-11, the pane read as a pixelated photo)
        (void)is_door;
        int idx = r * C + c; if (!named) { layer_have[idx] = false; continue; }
        uint8_t syms[32]; layer3_cell(r, c, syms);
        bool changed = !layer_have[idx] || memcmp(syms, layer_last[idx], 32) != 0; memcpy(layer_last[idx], syms, 32); layer_have[idx] = true;
        if (!(full || changed)) continue;
        rec[off++] = (uint8_t)((r << 4) | c); memcpy(rec + off, syms, 32); off += 32; n++;
    }
    if (n == 0) return;
    memcpy(rec, "LAY3", 4); rec[4] = node_id & 0xff; rec[5] = node_id >> 8; memcpy(rec + 6, &seq, 4); uint8_t flags = full ? 1 : 0;
    // the header is 4 + 2 + 4 + 1 + 1 = 12 bytes: shift the cells up by four to make room (the record was built at offset 8)
    memmove(rec + 12, rec + 8, off - 8); rec[10] = flags; rec[11] = (uint8_t)n; off += 4;
    radio_send_fragmented_ex(node_id, frag_id++, rec, off, false);   // superseded by the next frame: never repaired
}
// ---- the signed policy swap: chunks arrive as 'S' | idx u16 | total u16 | data over the hop, 'X' verifies and commits.
// Pack: "PPKV1" | key_id[4] | version u32 | image_len u16 | cb_len u16 | esc_mask u32 | sig[64] | image | codebook; the
// signature covers the 21 byte header, the image and the codebook. Refusals carry the kernel's cause codes.
#define PACK_MAX 16384
#define CHUNK 24
static uint8_t *staged, *vmsg, *tbl_backup; static uint16_t staged_total = 0; static uint8_t staged_have[128]; static uint32_t staged_len = 0, staged_count = 0;
typedef struct __attribute__((packed)) { char magic[4]; uint16_t nid; uint32_t version; uint16_t cause; uint32_t verify_us; uint64_t image_hash; uint64_t t; } swp_t;
static void swap_reset(void) { staged_total = 0; staged_len = 0; staged_count = 0; memset(staged_have, 0, sizeof staged_have); }
static void swap_chunk(const uint8_t *d, int n)
{
    uint16_t idx = d[0] | (d[1] << 8), total = d[2] | (d[3] << 8); const uint8_t *data = d + 4; int dn = n - 4;
    if (total != staged_total) { swap_reset(); staged_total = total; }
    if (idx >= 1024 || dn < 0 || (uint32_t)idx * CHUNK + dn > PACK_MAX) return;
    memcpy(staged + (uint32_t)idx * CHUNK, data, dn); if ((uint32_t)idx * CHUNK + dn > staged_len) staged_len = (uint32_t)idx * CHUNK + dn;
    if (!((staged_have[idx >> 3] >> (idx & 7)) & 1)) { staged_have[idx >> 3] |= 1 << (idx & 7); staged_count++; }
}
static uint16_t swap_execute(uint32_t *out_version, uint64_t *out_hash, uint32_t *out_us)
{
    int64_t t0 = esp_timer_get_time(); uint16_t cause = 0; uint32_t version = 0; uint64_t ih = 0;
    if (staged_total == 0 || staged_count != staged_total) cause = 5;                                   // manifest:bad-format (incomplete)
    else if (staged_len < 85 || memcmp(staged, "PPKV1", 5) != 0 || memcmp(staged + 5, KEY_ID, 4) != 0) cause = 5;
    else {
        version = rd32(staged + 9); uint16_t image_len = rd16b(staged + 13), cb_len = rd16b(staged + 15); uint32_t esc = (uint32_t)rd32(staged + 17);
        if (85u + image_len + cb_len != staged_len || cb_len % 19 != 0 || cb_len / 19 > CB_MAX_FIELDS || image_len > TBL_MAX) cause = 5;
        else {
            bool zero = true; for (int i = 0; i < 64; i++) if (staged[21 + i]) { zero = false; break; }
            if (zero) cause = 1;                                                                            // sig:missing
            else {
                memcpy(vmsg, staged, 21); memcpy(vmsg + 21, staged + 85, image_len + cb_len);
                if (crypto_ed25519_check(staged + 21, AUTHORITY_PUBKEY, vmsg, 21 + image_len + cb_len) != 0) cause = 2;   // sig:invalid
                else if (version <= policy_version) cause = 9;                                              // image:version-replay
                else {
                    memcpy(tbl_backup, tbl, TBL_MAX); memcpy(tbl, staged + 85, image_len);
                    if (parse_table(image_len) != 0) { memcpy(tbl, tbl_backup, TBL_MAX); parse_table(POLICY_TABLE_LEN); cause = 16; }   // image:caps-exceeded (does not parse)
                    else {
                        const uint8_t *cb = staged + 85 + image_len; wire_n = cb_len / 19;
                        for (int i = 0; i < wire_n; i++) { wire_fields[i].reg = rd16b(cb + 19 * i); wire_fields[i].n_cuts = cb[19 * i + 2]; for (int k = 0; k < CB_MAX_CUTS; k++) wire_fields[i].cut[k] = rd32(cb + 19 * i + 3 + 4 * k); }
                        esc_mask = esc; policy_version = version;
                        uint8_t h[32]; mbedtls_sha256(staged + 85, image_len, h, 0); memcpy(&ih, h, 8);
                    }
                }
            }
        }
    }
    *out_version = version; *out_hash = ih; *out_us = (uint32_t)(esp_timer_get_time() - t0); swap_reset(); return cause;
}
static void send_evidence(camera_fb_t *fb, uint32_t seq, uint64_t t_cap, uint16_t route)
{
    uint8_t *jpg = NULL; size_t jlen = 0;
    if (!frame2jpg(fb, KEY_QUALITY, &jpg, &jlen)) return;
    uint8_t *msg = malloc(sizeof(evd_hdr_t) + jlen); evd_hdr_t eh = { {'E','V','D','1'}, node_id, normal_id, seq, t_cap, route, (uint32_t)jlen };
    memcpy(msg, &eh, sizeof eh); memcpy(msg + sizeof eh, jpg, jlen); free(jpg);
    radio_send_fragmented(node_id, frag_id++, msg, sizeof eh + jlen); free(msg);
    ESP_LOGI(TAG, "evidence for %s: %lu B", POLICY_NODE_NAMES[route], (unsigned long)(sizeof eh + jlen));
}
void app_main(void)
{
    vision_core_init(); last_sent = heap_caps_malloc(W * H, MALLOC_CAP_SPIRAM);
    staged = heap_caps_malloc(PACK_MAX, MALLOC_CAP_SPIRAM); vmsg = heap_caps_malloc(PACK_MAX, MALLOC_CAP_SPIRAM); tbl_backup = heap_caps_malloc(TBL_MAX, MALLOC_CAP_SPIRAM); swap_reset();
    camera_config_t c = {
        .pin_pwdn = -1, .pin_reset = -1, .pin_xclk = CAM_XCLK, .pin_sccb_sda = CAM_SIOD, .pin_sccb_scl = CAM_SIOC,
        .pin_d7 = CAM_D7, .pin_d6 = CAM_D6, .pin_d5 = CAM_D5, .pin_d4 = CAM_D4, .pin_d3 = CAM_D3, .pin_d2 = CAM_D2,
        .pin_d1 = CAM_D1, .pin_d0 = CAM_D0, .pin_vsync = CAM_VSYNC, .pin_href = CAM_HREF, .pin_pclk = CAM_PCLK,
        .xclk_freq_hz = 20000000, .ledc_timer = LEDC_TIMER_0, .ledc_channel = LEDC_CHANNEL_0,
        .pixel_format = PIXFORMAT_GRAYSCALE, .frame_size = (W == 640 ? FRAMESIZE_VGA : FRAMESIZE_QVGA), .jpeg_quality = 12,
        .fb_count = 3, .fb_location = CAMERA_FB_IN_PSRAM, .grab_mode = CAMERA_GRAB_LATEST,
    };
    ESP_ERROR_CHECK(esp_camera_init(&c));
    radio_init(NULL);
    uint8_t mac[6]; esp_wifi_get_mac(WIFI_IF_STA, mac); node_id = (uint16_t)((mac[4] << 8) | mac[5]);
    // exposure lock (T2): the bands were tuned on a locked sensor; let auto exposure and gain settle on the scene, then
    // freeze them, and only then start the front end, so the anchored normal is a settled frame
    vTaskDelay(pdMS_TO_TICKS(3000));
    { sensor_t *sen = esp_camera_sensor_get(); if (sen) { sen->set_exposure_ctrl(sen, 0); sen->set_gain_ctrl(sen, 0); ESP_LOGI(TAG, "exposure and gain locked: aec_value=%d agc_gain=%d", sen->status.aec_value, sen->status.agc_gain); } }
    ESP_LOGI(TAG, "radio node %02x:%02x:%02x:%02x:%02x:%02x streaming over ESP-NOW", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    uint32_t seq = 0; static uint8_t pkt[ESPNOW_MAX]; uint64_t t_key = 0, t_evd = 0; uint16_t last_normal = 0xffff; bool adopt_now = false, key_now = false;
    usb_serial_jtag_driver_config_t ucfg = { .tx_buffer_size = 16384, .rx_buffer_size = 256 }; bool usb_ok = usb_serial_jtag_driver_install(&ucfg) == ESP_OK;   // the operator sends n to adopt the current frame as the normal
    while (1) {
        uint8_t ch; if (usb_ok && usb_serial_jtag_read_bytes(&ch, 1, 0) == 1 && ch == 'n') { ESP_LOGI(TAG, "operator adopts the normal"); adopt_now = true; }
        // the same command over the air: the relay forwards 'C' | nid | data to the camera it names (0xffff = all)
        for (int drained = 0; hop_up && hop_sock >= 0 && drained < 8; drained++) {   // drain every command that arrived since the last frame (pack chunks come faster than frames)
            uint8_t cb[32]; int r = recv(hop_sock, cb, sizeof cb, MSG_DONTWAIT); if (r <= 0) break;
            if (r >= 4 && cb[0] == 'C') {
                uint16_t to = cb[1] | (cb[2] << 8);
                if (to == node_id || to == 0xffff) {
                    if (cb[3] == 'n') { ESP_LOGI(TAG, "adopt over the air"); adopt_now = true; }
                    else if (cb[3] == 'k') { ESP_LOGI(TAG, "keyframe requested over the air"); key_now = true; }   // a receiver that joined mid stream asks for the normal
                    else if (cb[3] == 'L' && r >= 5) { layer_level = cb[4]; ESP_LOGI(TAG, "refinement layer %d over the air", layer_level); memset(layer_have, 0, sizeof layer_have); }
                    else if (cb[3] == 'S' && r >= 8) swap_chunk(cb + 4, r - 4);
                    else if (cb[3] == 'X') {
                        uint32_t ver, us; uint64_t ih; uint16_t cause = swap_execute(&ver, &ih, &us);
                        swp_t sw = { {'S','W','P','1'}, node_id, ver, cause, us, ih, (uint64_t)esp_timer_get_time() };
                        uint8_t sb[sizeof sw]; memcpy(sb, &sw, sizeof sw); esp_now_send(BCAST, sb, sizeof sb); hop_send(sb, sizeof sb);
                        ESP_LOGI(TAG, "policy swap to version %lu: %s (cause %u) in %lu us; now version %lu", (unsigned long)ver, cause ? "REFUSED" : "committed", cause, (unsigned long)us, (unsigned long)policy_version);
                    }
                    else if (cb[3] == 'r' && r >= 7) {   // repair: 'r' | id u16 | n u8 | idx[n]
                        uint16_t id = cb[4] | (cb[5] << 8); int cnt = cb[6]; if (cnt > r - 7) cnt = r - 7;
                        int done = radio_resend_fragments(node_id, id, cb + 7, cnt);
                        ESP_LOGI(TAG, "repair for message %u: %d fragment(s) %s", id, cnt, done < 0 ? "no longer held" : "resent");
                    }
                }
            }
        }
        camera_fb_t *fb = esp_camera_fb_get(); if (!fb) continue;
        uint64_t t_cap = (uint64_t)fb->timestamp.tv_sec * 1000000ULL + (uint64_t)fb->timestamp.tv_usec;
        cur = fb->buf;
        if (adopt_now) { adopt_now = false; adopt_normal(); }
        int64_t t_fe0 = esp_timer_get_time();
        int32_t motion_cells, dark, step, door_hit, scene; front_end(&motion_cells, &dark, &step, &door_hit, &scene);
        { static int64_t fe_sum = 0, fe_max = 0, t_fe_log = 0; static int fe_n = 0; int64_t dt = esp_timer_get_time() - t_fe0; fe_sum += dt; fe_n++; if (dt > fe_max) fe_max = dt;
          if (esp_timer_get_time() - t_fe_log > 10000000) { ESP_LOGI(TAG, "front end %dx%d: mean %lld us, max %lld us over %d frames; free PSRAM %u B", W, H, (long long)(fe_sum / fe_n), (long long)fe_max, fe_n, (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM)); fe_sum = 0; fe_n = 0; fe_max = 0; t_fe_log = esp_timer_get_time(); } }
        uint16_t node, steps; decide(motion_cells, dark, step, door_hit, scene, &node, &steps);
        uint8_t wirebuf[128]; uint16_t wire_len = encode_reading(wirebuf, sizeof wirebuf);
        uint64_t t_dec = (uint64_t)esp_timer_get_time();
        rdg_hdr_t rh = { {'R','D','G','5'}, node_id, normal_id, seq, t_cap, t_dec, node, steps, wire_len, chain_prev, (uint16_t)policy_version };
        memcpy(pkt, &rh, sizeof rh); memcpy(pkt + sizeof rh, wirebuf, wire_len);
        esp_now_send(BCAST, pkt, sizeof rh + wire_len); hop_send(pkt, sizeof rh + wire_len);
        { uint8_t h[32]; mbedtls_sha256(pkt, sizeof rh + wire_len, h, 0); memcpy(&chain_prev, h, 8); }   // this record's hash is the next record's prev
        // a keyframe whenever the normal changed id (adoption, or the search for the first clean stretch ending), and every minute
        if (normal_set && (normal_id != last_normal || key_now || t_dec - t_key > KEY_RESEND_US)) { send_keyframe(fb, seq, t_cap); t_key = t_dec; last_normal = normal_id; key_now = false; }
        if (escalates(node) && t_dec - t_evd > EVIDENCE_GAP_US) { send_evidence(fb, seq, t_cap, node); t_evd = t_dec; }
        if (layer_level >= 3) { const char *nm = POLICY_NODE_NAMES[node]; bool occ = !strcmp(nm, "occupied"), door = !strcmp(nm, "door"); if (occ || door) send_layer3(seq, node, door); else memset(layer_have, 0, sizeof layer_have); }
        esp_camera_fb_return(fb); seq++;
    }
}
