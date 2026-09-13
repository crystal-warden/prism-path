// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_image.h: the PPT image half of the loader, without the kernel.
 *
 * Everything here is pure userspace arithmetic over the .ppt bytes: read the file, parse the header
 * and the four sections, evaluate a node against a register file on the host, build the packet a
 * kernel run needs, and pick the resident node a swap carries forward. Nothing in this unit touches
 * libbpf, so the fallback build (-DNO_LIBBPF) links it unchanged and the conformance harnesses get
 * the loader's parser without also getting its thirteen subcommands.
 *
 * The host evaluator is the reference the in-kernel program is certified against, so it must stay
 * byte for byte the same semantics as ../prismpath-hw/interp.c.
 */
#ifndef PPT_IMAGE_H
#define PPT_IMAGE_H

#include <stdint.h>

#include "ppt_common.h"

/* One parsed .ppt table. The section arrays are malloc'd by parse_image_buf and released by
 * free_image; `raw` is borrowed, so it stays valid only as long as the caller keeps the file bytes. */
typedef struct {
    uint16_t n_fields, n_interns, n_atoms, n_nodes, n_edges, prog_len,
             start, visits_idx, max_steps, max_stack, safe;
    struct ppt_atom *atoms;
    struct ppt_node *nodes;
    struct ppt_edge *edges;
    uint16_t *prog;
    const uint8_t *raw;    /* borrowed: raw table bytes, valid until the caller frees them */
    long raw_len;
    uint16_t flags;        /* header flags word low byte (PPT_FLAG_*) */
    uint32_t *name_hashes; /* per-node FNV-1a-32(name), or NULL if no PPT_FLAG_NODE_NAMES */
} Image;

uint16_t rd16(const uint8_t *bytes);
int32_t rd32(const uint8_t *bytes);

uint8_t *read_file(const char *path, long *out_len);

int build_frame(uint8_t *out, uint16_t node_idx, uint16_t n_fields, const struct ppt_reg *regs);

int parse_image_buf(const uint8_t *table_bytes, long len, Image *im);
void load_image(const char *path, Image *im);
void free_image(Image *im);

uint32_t migrate_node(const Image *old_im, const Image *new_im, uint32_t old_cur, int *out_cause);

int eval_atom_host(const struct ppt_atom *atom, const struct ppt_reg *regs, uint32_t n_fields);
int eval_prog_host(const Image *im, const struct ppt_edge *edge, const struct ppt_reg *regs);
int evaluate_host(const Image *im, uint16_t node, const struct ppt_reg *regs, int *out_target);

#endif /* PPT_IMAGE_H */
