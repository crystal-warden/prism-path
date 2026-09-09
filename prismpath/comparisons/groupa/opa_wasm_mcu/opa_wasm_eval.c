/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Crystal Warden Supply Chain Labs LLC
 * See opa_wasm_eval.h. The ABI followed is the one OPA documents for its WebAssembly modules
 * (https://www.openpolicyagent.org/docs/latest/wasm/): exports opa_heap_ptr_get, opa_json_parse,
 * opa_eval(reserved, entrypoint, data_addr, input_addr, input_len, heap_ptr, format) and the six
 * imports opa_abort and opa_builtin0..4. The comparison policies use no builtins, so the builtin
 * imports trap if they are ever reached, and that trap is reported rather than hidden.
 */
#include "opa_wasm_eval.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wasm3.h"

struct opa_wasm {
    IM3Environment env;
    IM3Runtime rt;
    IM3Module mod;
    IM3Function f_heap_get, f_json_parse, f_eval;
    uint32_t data_addr;      /* parsed empty data document */
    uint32_t heap_base;      /* heap pointer after data parse; every eval restarts here */
    char abi[16];
};

static const char *g_err = "";

static m3ApiRawFunction(opa_abort_import) {
    m3ApiGetArgMem(const char *, msg)
    (void)msg;
    m3ApiTrap("opa_abort called by the module");
}
static m3ApiRawFunction(opa_builtin_import) {
    m3ApiReturnType(int32_t)
    m3ApiTrap("opa_builtin reached: the module needed a host builtin this glue does not supply");
}

static int call_i(IM3Function f, uint32_t *out, int argc, uint32_t *argv) {
    const void *args[8];
    for (int i = 0; i < argc; i++) args[i] = &argv[i];
    M3Result r = m3_Call(f, (uint32_t)argc, args);
    if (r) { g_err = r; return -1; }
    r = m3_GetResultsV(f, out);
    if (r) { g_err = r; return -1; }
    return 0;
}

static uint8_t *mem(opa_wasm_t *w, size_t *size) { return m3_GetMemory(w->mod, size, 0); }
#define FAIL(r) do { g_err = (r); opa_wasm_close(w); return NULL; } while (0)

opa_wasm_t *opa_wasm_open(const uint8_t *module, size_t len, uint32_t stack_bytes) {
    opa_wasm_t *w = (opa_wasm_t *)calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->env = m3_NewEnvironment();
    w->rt = m3_NewRuntime(w->env, stack_bytes, NULL);
    M3Result r = m3_ParseModule(w->env, &w->mod, module, (uint32_t)len);
    if (r) FAIL(r);
    r = m3_LoadModule(w->rt, w->mod);
    if (r) FAIL(r);
    r = m3_LinkRawFunction(w->mod, "env", "opa_abort", "v(i)", &opa_abort_import);           if (r) FAIL(r);
    r = m3_LinkRawFunction(w->mod, "env", "opa_builtin0", "i(ii)", &opa_builtin_import);     if (r) FAIL(r);
    r = m3_LinkRawFunction(w->mod, "env", "opa_builtin1", "i(iii)", &opa_builtin_import);    if (r) FAIL(r);
    r = m3_LinkRawFunction(w->mod, "env", "opa_builtin2", "i(iiii)", &opa_builtin_import);   if (r) FAIL(r);
    r = m3_LinkRawFunction(w->mod, "env", "opa_builtin3", "i(iiiii)", &opa_builtin_import);  if (r) FAIL(r);
    r = m3_LinkRawFunction(w->mod, "env", "opa_builtin4", "i(iiiiii)", &opa_builtin_import); if (r) FAIL(r);
    if ((r = m3_FindFunction(&w->f_heap_get, w->rt, "opa_heap_ptr_get"))) FAIL(r);
    if ((r = m3_FindFunction(&w->f_json_parse, w->rt, "opa_json_parse"))) FAIL(r);
    if ((r = m3_FindFunction(&w->f_eval, w->rt, "opa_eval"))) FAIL(r);
    /* ABI version globals are exported; wasm3 exposes globals through m3_FindGlobal */
    IM3Global g_major = m3_FindGlobal(w->mod, "opa_wasm_abi_version");
    IM3Global g_minor = m3_FindGlobal(w->mod, "opa_wasm_abi_minor_version");
    M3TaggedValue tv1 = {0}, tv2 = {0};
    if (g_major) m3_GetGlobal(g_major, &tv1);
    if (g_minor) m3_GetGlobal(g_minor, &tv2);
    snprintf(w->abi, sizeof w->abi, "%d.%d", (int)tv1.value.i32, (int)tv2.value.i32);
    /* parse an empty data document once; it lives below every input */
    uint32_t heap = 0;
    if (call_i(w->f_heap_get, &heap, 0, NULL)) FAIL(g_err);
    size_t msize; uint8_t *m = mem(w, &msize);
    if (!m || heap + 3 > msize) FAIL("linear memory too small for data");
    memcpy(m + heap, "{}", 2);
    uint32_t args[2] = {heap, 2};
    if (call_i(w->f_json_parse, &w->data_addr, 2, args)) FAIL(g_err);
    if (call_i(w->f_heap_get, &w->heap_base, 0, NULL)) FAIL(g_err);
    return w;
}

const char *opa_wasm_eval(opa_wasm_t *w, const char *input_json, size_t input_len) {
    size_t msize; uint8_t *m = mem(w, &msize);
    if (!m || w->heap_base + input_len + 1 > msize) {
        /* let the module grow memory itself: opa_malloc grows on demand, so stage the input through it */
        IM3Function f_malloc; M3Result r = m3_FindFunction(&f_malloc, w->rt, "opa_malloc");
        if (r) FAIL(r);
        uint32_t a = (uint32_t)input_len, addr;
        if (call_i(f_malloc, &addr, 1, &a)) return NULL;
        m = mem(w, &msize);
        memcpy(m + addr, input_json, input_len);
        uint32_t heap; if (call_i(w->f_heap_get, &heap, 0, NULL)) return NULL;
        uint32_t args[7] = {0, 0, w->data_addr, addr, (uint32_t)input_len, heap, 0};
        uint32_t out;
        if (call_i(w->f_eval, &out, 7, args)) return NULL;
        m = mem(w, &msize);
        return (const char *)(m + out);
    }
    memcpy(m + w->heap_base, input_json, input_len);
    uint32_t args[7] = {0, 0, w->data_addr, w->heap_base, (uint32_t)input_len, w->heap_base + (uint32_t)input_len, 0};
    uint32_t out;
    if (call_i(w->f_eval, &out, 7, args)) return NULL;
    m = mem(w, &msize);                       /* memory may have moved on growth */
    return (const char *)(m + out);
}

void opa_wasm_close(opa_wasm_t *w) {
    if (!w) return;
    if (w->rt) m3_FreeRuntime(w->rt);
    if (w->env) m3_FreeEnvironment(w->env);
    free(w);
}
const char *opa_wasm_error(void) { return g_err; }
uint32_t opa_wasm_memory_bytes(opa_wasm_t *w) { return (uint32_t)m3_GetMemorySize(w->mod, 0); }
const char *opa_wasm_abi(opa_wasm_t *w) { return w->abi; }
