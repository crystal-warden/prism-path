/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* host_relay.c: the relay's forwarding (main/relay.c) on the host, for prismpath/tests/test_distribution_c_min.py.
 *
 *   radio <frame hex>   a frame heard on the radio: prints "uart <line bytes hex>" or "dropped"
 *   uart <bytes hex>    bytes read from the UART: prints "radio <frame hex>" for each whole frame, then "uart-done"
 *   link <bytes hex>    bytes read from the line by the PEP behind the relay, through pp_link.h: prints "frame <hex>"
 *                       for each whole frame, then "link-done"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "relay.h"

static void print_hex(const char *word, const uint8_t *bytes, size_t len) {
    printf("%s ", word);
    for (size_t k = 0; k < len; k++) printf("%02x", bytes[k]);
    printf("\n");
}

static void to_uart(void *context, const uint8_t *bytes, size_t len) {
    (void)context;
    print_hex("uart", bytes, len);
}

static void to_radio(void *context, const uint8_t *bytes, size_t len) {
    (void)context;
    print_hex("radio", bytes, len);
}

static size_t unhex(const char *text, uint8_t *out, size_t room) {
    size_t n = strlen(text);
    if (n % 2 || n / 2 > room) exit(2);
    for (size_t k = 0; k < n / 2; k++) {
        unsigned v;
        if (sscanf(text + 2 * k, "%2x", &v) != 1) exit(2);
        out[k] = (uint8_t)v;
    }
    return n / 2;
}

int main(void) {
    static char line[1 << 17];
    static uint8_t bytes[1 << 16];
    static relay r;
    static pp_link_rx rx;
    relay_init(&r, to_uart, to_radio, NULL);
    pp_link_rx_init(&rx);
    while (fgets(line, sizeof line, stdin)) {
        char word[16], hex[sizeof line];
        line[strcspn(line, "\n")] = 0;
        if (sscanf(line, "%15s %s", word, hex) != 2) continue;
        size_t n = unhex(hex, bytes, sizeof bytes);
        if (strcmp(word, "radio") == 0) {
            uint32_t before = r.dropped;
            relay_from_radio(&r, bytes, n);
            if (r.dropped != before) printf("dropped\n");
        } else if (strcmp(word, "uart") == 0) {
            relay_from_uart(&r, bytes, n);
            printf("uart-done\n");
        } else if (strcmp(word, "link") == 0) {
            for (size_t k = 0; k < n; k++)
                if (pp_link_rx_byte(&rx, bytes[k])) {
                    print_hex("frame", rx.frame, rx.len);
                    pp_link_rx_next(&rx);
                }
            printf("link-done\n");
        } else {
            return 2;
        }
    }
    return 0;
}
