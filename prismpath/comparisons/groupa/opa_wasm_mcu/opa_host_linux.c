/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Crystal Warden Supply Chain Labs LLC
 * Linux reference host for the OPA wasm glue: opa_host_linux policy.wasm '<input json>' ...
 * Prints one result line per input and the linear memory size after each, so the same glue can be
 * checked here before it is flashed to the RP2350. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opa_wasm_eval.h"

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s policy.wasm '<input json>' ...\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb"); if (!f) { perror("wasm"); return 2; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(n); if (fread(buf, 1, n, f) != (size_t)n) return 2; fclose(f);
    opa_wasm_t *w = opa_wasm_open(buf, n, 64 * 1024);
    if (!w) { fprintf(stderr, "open failed: %s\n", opa_wasm_error()); return 1; }
    printf("abi %s memory %u\n", opa_wasm_abi(w), opa_wasm_memory_bytes(w));
    for (int i = 2; i < argc; i++) {
        const char *res = opa_wasm_eval(w, argv[i], strlen(argv[i]));
        if (!res) { printf("ERROR %s\n", opa_wasm_error()); continue; }
        printf("RESULT %s memory %u\n", res, opa_wasm_memory_bytes(w));
    }
    return 0;
}
