/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* pp_link.h: the frames of section 8.3 on a serial line behind a relay (spec-policy-distribution.md B10), each frame
 * framed as SLIP (RFC 1055): its bytes with END and ESC escaped, then END. The link carries frames unchanged and
 * checks nothing but its own framing, so it holds no key and verifies nothing. What it drops or changes is caught by
 * the PEP behind it. A frame past the link's limit or with a bad escape is dropped whole.
 *
 * Header only, no allocation, and no dependency, so the ESP32-C6 relay, the Uno and the host tests share it. */
#ifndef PP_LINK_H
#define PP_LINK_H

#include <stddef.h>
#include <stdint.h>

#define PP_LINK_END 0xC0
#define PP_LINK_ESC 0xDB
#define PP_LINK_ESC_END 0xDC
#define PP_LINK_ESC_ESC 0xDD
#define PP_LINK_MAX 250 /* the frame limit of the link, ESP_NOW_MAX_DATA_LEN, at least the 216 B10 asks */

/* The bytes of one frame on the line, at most 2 * len + 2 of them: an END first, so a line that came up mid frame
 * starts clean, then the frame and an END. */
static inline size_t pp_link_encode(const uint8_t *frame, size_t len, uint8_t *out) {
    size_t at = 0;
    out[at++] = PP_LINK_END;
    for (size_t k = 0; k < len; k++) {
        if (frame[k] == PP_LINK_END) { out[at++] = PP_LINK_ESC; out[at++] = PP_LINK_ESC_END; }
        else if (frame[k] == PP_LINK_ESC) { out[at++] = PP_LINK_ESC; out[at++] = PP_LINK_ESC_ESC; }
        else out[at++] = frame[k];
    }
    out[at++] = PP_LINK_END;
    return at;
}

typedef struct {
    uint8_t frame[PP_LINK_MAX];
    size_t len;
    uint8_t escaped, broken; /* broken: the frame being read is past the limit or has a bad escape */
} pp_link_rx;

static inline void pp_link_rx_init(pp_link_rx *rx) {
    rx->len = 0;
    rx->escaped = rx->broken = 0;
}

/* One byte from the line. 1 when it ends a frame, which is then rx->frame[0 .. rx->len), else 0. An empty or
 * broken frame is dropped. */
static inline int pp_link_rx_byte(pp_link_rx *rx, uint8_t b) {
    if (b == PP_LINK_END) {
        int whole = rx->len > 0 && !rx->broken && !rx->escaped;
        if (!whole) pp_link_rx_init(rx);
        else rx->escaped = 0;
        return whole;
    }
    if (rx->broken) return 0;
    if (rx->escaped) {
        rx->escaped = 0;
        if (b == PP_LINK_ESC_END) b = PP_LINK_END;
        else if (b == PP_LINK_ESC_ESC) b = PP_LINK_ESC;
        else { rx->broken = 1; return 0; }
    } else if (b == PP_LINK_ESC) {
        rx->escaped = 1;
        return 0;
    }
    if (rx->len >= PP_LINK_MAX) { rx->broken = 1; return 0; }
    rx->frame[rx->len++] = b;
    return 0;
}

/* After the caller took a whole frame. */
static inline void pp_link_rx_next(pp_link_rx *rx) { pp_link_rx_init(rx); }

#endif /* PP_LINK_H */
