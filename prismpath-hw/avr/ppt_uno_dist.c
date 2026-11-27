// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_uno_dist.c: a constrained enforcement point (spec-policy-distribution.md B12) on an ATmega328P (Arduino Uno
 * R3), behind an ESP32-C6 relay (B10, prismpath-hw/esp-relay-c6) on its UART. It is prismpath-hw/dist/pp_dist.c
 * built with PP_DIST_PROFILE_MIN: a `mesh` PEP on one stream that checks each sealed envelope in one pass as its
 * frames arrive on the ordered link (B11), keeps one authority key and its floor in EEPROM, and sends a signed state
 * record for every transition back through the relay.
 *
 * The link is pp_link.h (SLIP) at 57600 8N1. Every frame of section 8.3 the relay hears goes to pp_min_frame, and
 * each state record goes back as a frame of type 3.
 *
 * EEPROM, written at provisioning by `avrdude -U eeprom:w:` (section 14) and then by the PEP:
 *   0     4    magic "PPU1"
 *   4     32   the instance key seed
 *   36    32   the authority public key of the anchor
 *   68    65   the stream, ended by a zero byte
 *   133   ...  the durable state (pp_min_durable), whole
 * The active table is kept in RAM beside the staging buffer when both fit, which the board measurement decides
 * (prismpath-hw/evidence/uno-dist-build-estimate.json, and PR 17c when they do not).
 *
 * Pin 13 (PB5) is high while a frame is in pp_min_frame, so the time of the signature check, which runs inside the
 * call that takes the last chunk of a sealed envelope, can be read with a logic analyser on the board. */
#include <avr/eeprom.h>
#include <avr/interrupt.h>
#include <avr/io.h>
#include <stdint.h>
#include <string.h>

#include "pp_dist.h"
#include "pp_link.h"

#define BAUD_UBRR 34 /* 16 MHz / (8 * 57600) - 1 with U2X0, 57142 baud, -0.8% */
#define EE_MAGIC 0
#define EE_SEED 4
#define EE_ANCHOR 36
#define EE_STREAM 68
#define EE_STATE 133

static uint8_t table[PP_MESH_TABLE_MAX]; /* where a table arrives and is staged */
static pp_min pep;
static pp_min_durable durable;
static pp_link_rx rx;
static volatile uint32_t ticks_ms;

ISR(TIMER0_COMPA_vect) { ticks_ms++; }

static uint32_t now_ms(void) {
    uint32_t t;
    cli();
    t = ticks_ms;
    sei();
    return t;
}

static void uart_init(void) {
    UCSR0A = _BV(U2X0);
    UBRR0 = BAUD_UBRR;
    UCSR0B = _BV(TXEN0) | _BV(RXEN0);
    UCSR0C = _BV(UCSZ01) | _BV(UCSZ00);
}

static void uart_putc(uint8_t byte) {
    while (!(UCSR0A & _BV(UDRE0))) {}
    UDR0 = byte;
}

/* A state record goes back as a frame of type 3, each byte framed as pp_link_encode frames it. */
static void send(void *context, const uint8_t *record, size_t len) {
    (void)context;
    uint8_t head[4] = {PP_FRAME_STATE, 1, 0, 0};
    uart_putc(PP_LINK_END);
    for (size_t k = 0; k < 4 + len; k++) {
        uint8_t b = k < 4 ? head[k] : record[k - 4];
        if (b == PP_LINK_END) { uart_putc(PP_LINK_ESC); uart_putc(PP_LINK_ESC_END); }
        else if (b == PP_LINK_ESC) { uart_putc(PP_LINK_ESC); uart_putc(PP_LINK_ESC_ESC); }
        else uart_putc(b);
    }
    uart_putc(PP_LINK_END);
}

/* C4: the state is written whole. The active table stays in RAM in this build (see above). */
static int persist(void *context, const pp_min_durable *d, int what) {
    (void)context;
    (void)what;
    eeprom_update_block(d, (void *)EE_STATE, sizeof *d);
    return 0;
}

/* T2: no clock, so the time is the saved time floor plus the seconds since this start. */
static long long start_floor;
static long long now_s(void) { return start_floor + (long long)(now_ms() / 1000u); }

int main(void) {
    static pp_min_config config;
    uint8_t magic[4], anchor[32];
    char stream[PP_STREAM_MAX + 1];
    DDRB |= _BV(DDB5);
    uart_init();
    TCCR0A = _BV(WGM01); /* CTC at 1 ms: 16 MHz / 64 / 250 */
    TCCR0B = _BV(CS01) | _BV(CS00);
    OCR0A = 249;
    TIMSK0 = _BV(OCIE0A);
    sei();
    eeprom_read_block(magic, (const void *)EE_MAGIC, 4);
    int provisioned_here = memcmp(magic, "PPU1", 4) == 0;
    eeprom_read_block(config.instance_seed, (const void *)EE_SEED, 32);
    eeprom_read_block(&durable, (const void *)EE_STATE, sizeof durable);
    config.has_clock = 0;
    config.table = table;
    config.table_room = sizeof table;
    config.persist = persist;
    config.send = send;
    start_floor = durable.provisioned ? durable.time_floor : 0;
    pp_min_open(&pep, &config, durable.provisioned ? &durable : NULL, 1, start_floor);
    if (provisioned_here && !pep.d.provisioned) { /* P1: the anchor written at provisioning */
        eeprom_read_block(anchor, (const void *)EE_ANCHOR, 32);
        eeprom_read_block(stream, (const void *)EE_STREAM, sizeof stream);
        stream[PP_STREAM_MAX] = 0;
        pp_min_provision(&pep, anchor, stream, now_s());
    }
    pp_link_rx_init(&rx);
    uint32_t saved_at = now_ms();
    for (;;) {
        if (UCSR0A & _BV(RXC0)) {
            if (pp_link_rx_byte(&rx, UDR0)) {
                uint8_t cause;
                PORTB |= _BV(PORTB5);
                (void)pp_min_frame(&pep, rx.frame, rx.len, now_ms(), now_s(), &cause);
                PORTB &= (uint8_t)~_BV(PORTB5);
                pp_link_rx_next(&rx);
            }
        }
        uint32_t t = now_ms();
        pp_min_tick(&pep, t, now_s()); /* B8, and a release that expires lapses (X1) */
        if (t - saved_at > 3600000u) { /* T2: the time is saved at least once an hour */
            pp_min_save_time(&pep, now_s());
            saved_at = t;
        }
    }
}
