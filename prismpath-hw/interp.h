/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* interp.h — the embeddable face of the certified C target (interp.c).
 *
 * C and C++ (extern "C") API over the identical certified code paths the CLI runs:
 * the same image loader, the same evaluator. Compile interp.c into your application
 * (as C11) with -DPPT_INTERP_NO_MAIN; the certification instrument for YOUR build is
 * corpus replay — see integrations/cpp/ for a worked example that replays the
 * certified binary's own verdicts in-process and requires 100% agreement.
 *
 * Trust boundary: signature and envelope verification run upstream of this file (the
 * pack loader / policy_pack); this is the evaluator, not the verifier. A malformed or
 * truncated image exits(2) exactly as the certified CLI does.
 */
#ifndef PPT_INTERP_H
#define PPT_INTERP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Register cell: one field's typed value. Layout-identical to the interpreter's
 * internal cell (checked by a _Static_assert in interp.c). */
typedef struct { int32_t ty, val; } ppt_reg;

enum {
    PPT_TY_NONE = 0,
    PPT_TY_BOOL = 1,
    PPT_TY_INT  = 2,
    PPT_TY_STR  = 3
};

/* ppt_evaluate_node: >= 0 is the matching edge index (the priority encoder);
 * PPT_EVAL_NONE is a clean no-match; PPT_EVAL_BAD_NODE is a caller error. */
#define PPT_EVAL_NONE     (-1)
#define PPT_EVAL_BAD_NODE (-2)

typedef struct ppt_image ppt_image;

/* Load a compiled PPT v1 table image from disk. Never returns NULL: a malformed
 * image exits(2) with a diagnostic, the certified CLI contract. */
ppt_image *ppt_image_open(const char *path);
void       ppt_image_close(ppt_image *im);

uint16_t ppt_image_start(const ppt_image *im);
uint16_t ppt_image_n_fields(const ppt_image *im);
uint16_t ppt_image_n_nodes(const ppt_image *im);

/* One evaluate(node, regs): regs is an array of n_fields cells in field order.
 * Returns the matching edge index and writes the target node to out_target
 * (out_target may be NULL), or PPT_EVAL_NONE / PPT_EVAL_BAD_NODE. */
int ppt_evaluate_node(const ppt_image *im, uint16_t node, const ppt_reg *regs,
                      uint16_t *out_target);

#ifdef __cplusplus
}
#endif

#endif /* PPT_INTERP_H */
