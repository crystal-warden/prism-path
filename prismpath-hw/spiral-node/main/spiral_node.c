// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* spiral-node — step 2 of Facet-on-the-mesh: the baked spiral consumer + Zeckendorf encoder,
 * proven on the ESP32 before any radio. For every test reading: quantize via the BAKED
 * partitions, look up n and band, and emit two Facet frames (band tier, then refinement n) as
 * Zeckendorf codes; print everything for the host referee, which re-derives each expectation
 * from the same signed flow via the DERIVED materialization. Device output must match the
 * reference bit-exactly — that is the "two materializations, one profile" contract on silicon. */
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "../../codec-bench/zeck.h"
#include "spiral_sidecar.h"
#include "sidecar_blob.h"
#include "test_vectors.h"

static void print_hex(const uint8_t *b, uint8_t n) {
    for (uint8_t i = 0; i < n; i++) printf("%02x", b[i]);
}

void app_main(void) {
    static ssc_t S;
    int rc = ssc_parse(SIDECAR, sizeof SIDECAR, &S);
    if (rc != 0) { printf("SSC PARSE FAIL %d\n", rc); return; }
    const ssc_node_t *N = &S.nodes[0];
    printf("SSC OK node=%s k=%u bands=%u size=%lu\n",
           N->name, N->k, N->n_bands, (unsigned long)N->size);

    for (uint32_t i = 0; i < TV_N; i++) {
        int syms[SSC_MAX_FIELDS];
        for (uint8_t f = 0; f < N->k; f++) syms[f] = ssc_quantize(&N->fields[f], TV[i][f]);
        int32_t n = ssc_n(N, syms);
        int band = n >= 0 ? ssc_band(N, (uint32_t)n) : -1;

        uint8_t fb[16], fn[16];                 /* band-tier frame, refinement frame */
        memset(fb, 0, sizeof fb); memset(fn, 0, sizeof fn);
        bitacc_t ab = { fb, 0 }, an = { fn, 0 };
        (void)zeck_encode(&ab, (uint64_t)(band + 1));   /* wire ints are 1-based */
        (void)zeck_encode(&an, (uint64_t)(n + 1));
        uint8_t lb = (uint8_t)((ab.bitpos + 7u) >> 3), ln = (uint8_t)((an.bitpos + 7u) >> 3);

        printf("V %lu band=%d n=%ld route=%s fb=", (unsigned long)i, band, (long)n,
               band >= 0 ? N->bands[band].route : "?");
        print_hex(fb, lb);
        printf(" fn=");
        print_hex(fn, ln);
        printf("\n");
        vTaskDelay(1);                          /* keep the UART drained + watchdog fed */
    }
    printf("DONE %u vectors\n", (unsigned)TV_N);
}
