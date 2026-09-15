// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_maps.h: the kernel facing half of the loader.
 *
 * Where ppt_image.c stops at the parsed table, this unit puts that table into the BPF maps of a
 * loaded object, stamps the policy hash the receipts are bound to, and carries the resident selector
 * posture across a policy swap. It also owns the one copy of the node names sidecar parser, which
 * used to be written out four times in the loader's argv chain.
 *
 * Needs libbpf, so the fallback build (-DNO_LIBBPF) leaves this unit out entirely; every caller of it
 * already lives behind the same guard.
 */
#ifndef PPT_MAPS_H
#define PPT_MAPS_H

#include <stdint.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ppt_common.h"
#include "ppt_image.h"

/* Resident selector state (mirrors struct ppt_sel_state in ppt_select.bpf.c); the lock field rides the
 * BPF_F_LOCK map ops. Declared here so every selector harness sees the one definition. */
struct sel_state { struct bpf_spin_lock lock; __u32 cur_node; __u32 inited; __u32 gen; };

/* The node names sidecar is one name per line in node index order. read_names caps the array at this
 * many entries, which is what the four copies in the old argv chain each did with a bare 512. */
#define PPT_MAX_NAMES 512

uint64_t policy_hash_of(const Image *im);

int populate_maps(struct bpf_object *obj, const Image *im);

long selector_hotswap(struct bpf_object *obj, const Image *old_im, const Image *new_im,
                      struct ppt_receipt *out_migr);

/* Parse a node names sidecar into an index ordered array. Returns NULL when `path` is NULL (the
 * caller's "no sidecar given" case); *out_n is always set. free_names releases the result. */
char **read_names(const char *path, int *out_n);
void free_names(char **names, int n_names);

#endif /* PPT_MAPS_H */
