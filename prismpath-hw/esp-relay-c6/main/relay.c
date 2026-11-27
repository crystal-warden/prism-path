/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* relay.c: the forwarding of the ESP32-C6 relay. See relay.h. */
#include "relay.h"

void relay_init(relay *r, relay_bytes_fn to_uart, relay_bytes_fn to_radio, void *context) {
    r->to_uart = to_uart;
    r->to_radio = to_radio;
    r->context = context;
    r->radio_frames = r->uart_frames = r->dropped = 0;
    pp_link_rx_init(&r->rx);
}

void relay_from_radio(relay *r, const uint8_t *frame, size_t len) {
    uint8_t line[2 * PP_LINK_MAX + 2];
    if (len == 0 || len > PP_LINK_MAX) { /* past what the link carries: the sender sends frames that fit it */
        r->dropped++;
        return;
    }
    r->radio_frames++;
    r->to_uart(r->context, line, pp_link_encode(frame, len, line));
}

void relay_from_uart(relay *r, const uint8_t *bytes, size_t len) {
    for (size_t k = 0; k < len; k++)
        if (pp_link_rx_byte(&r->rx, bytes[k])) {
            r->uart_frames++;
            r->to_radio(r->context, r->rx.frame, r->rx.len);
            pp_link_rx_next(&r->rx);
        }
}
