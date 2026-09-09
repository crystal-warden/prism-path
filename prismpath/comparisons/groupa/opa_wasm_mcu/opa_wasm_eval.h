/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Crystal Warden Supply Chain Labs LLC
 *
 * OPA WebAssembly ABI glue over the wasm3 interpreter: load the module opa build -t wasm produced,
 * satisfy its six host imports, and evaluate one JSON input through the one shot opa_eval export.
 * Shared by the Linux host (opa_host_linux.c) and the RP2350 firmware (pico/opa_pico.c).
 */
#ifndef OPA_WASM_EVAL_H
#define OPA_WASM_EVAL_H
#include <stddef.h>
#include <stdint.h>

typedef struct opa_wasm opa_wasm_t;

/* Load and instantiate; stack_bytes is the wasm3 operand stack. NULL on failure (see opa_wasm_error). */
opa_wasm_t *opa_wasm_open(const uint8_t *module, size_t len, uint32_t stack_bytes);
/* Evaluate entrypoint 0 with the JSON input; returns a pointer into linear memory to the NUL terminated
 * result string (valid until the next call) or NULL on failure. */
const char *opa_wasm_eval(opa_wasm_t *w, const char *input_json, size_t input_len);
void opa_wasm_close(opa_wasm_t *w);            /* free the runtime and environment */
const char *opa_wasm_error(void);             /* last wasm3 result string, "" when none */
uint32_t opa_wasm_memory_bytes(opa_wasm_t *w);  /* current linear memory size */
const char *opa_wasm_abi(opa_wasm_t *w);        /* "major.minor" of the module's declared ABI */
#endif
