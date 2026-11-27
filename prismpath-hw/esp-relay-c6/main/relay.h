/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* relay.h: what the ESP32-C6 relay does with the frames it carries (spec-policy-distribution.md B10), apart from
 * the radio and the UART, so the host tests run the same code. A frame from the radio goes to the UART framed by
 * pp_link.h, and a frame from the UART goes to the radio, each unchanged. It reads no frame, holds no key, keeps no
 * state of the PEP and verifies nothing, so what it drops or changes is caught by the PEP behind it. */
#ifndef RELAY_H
#define RELAY_H

#include <stddef.h>
#include <stdint.h>

#include "pp_link.h"

typedef void (*relay_bytes_fn)(void *context, const uint8_t *bytes, size_t len);

typedef struct {
    relay_bytes_fn to_uart;  /* line bytes for the PEP */
    relay_bytes_fn to_radio; /* one whole frame for the medium */
    void *context;
    pp_link_rx rx;
    uint32_t radio_frames, uart_frames, dropped; /* counts, for the status the harness reads */
} relay;

void relay_init(relay *r, relay_bytes_fn to_uart, relay_bytes_fn to_radio, void *context);
/* One frame heard on the radio. */
void relay_from_radio(relay *r, const uint8_t *frame, size_t len);
/* Bytes read from the UART, in any pieces. */
void relay_from_uart(relay *r, const uint8_t *bytes, size_t len);

#endif /* RELAY_H */
