// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_maps.c: fill the BPF maps from a parsed PPT image, and swap them under a live selector.
 *
 * Split out of loader.c so the selector harnesses link this instead of #including the loader. See
 * ppt_maps.h for the boundary; the behaviour here is unchanged from the code it was lifted from.
 */

#include <errno.h>              /* errno for the map write failures map_put reports */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>               /* clock_gettime for the migration receipt time axis */

#include <openssl/sha.h>        /* SHA256 for policy_hash */

#include "ppt_maps.h"

/* policy_hash = low 64 bits of sha256(image); binds selector receipts to the loaded policy, and matches
 * policy_pack.py's manifest image_sha256 so an auditor can cross-reference the signed pack. */
uint64_t policy_hash_of(const Image *im) {
    if (!im->raw) return 0;
    uint8_t dg[32]; SHA256(im->raw, (size_t)im->raw_len, dg);
    uint64_t ph; memcpy(&ph, dg, 8); return ph;
}

/* One checked map write. A dropped return code here used to leave a table half written while
 * populate_maps still reported success, so the program would route on a mix of the new rows and
 * whatever the map held before. Name the map and the index, and let the caller abort. */
static int map_put(int map_fd, uint32_t index, const void *value, const char *map_name) {
    if (bpf_map_update_elem(map_fd, &index, value, BPF_ANY) != 0) {
        fprintf(stderr, "populate_maps: %s write failed at %u: %s\n",
                map_name, index, strerror(errno));
        return -1;
    }
    return 0;
}

/* Populate the five table maps from a PPT image. Shared by the attach path and the certify path. */
int populate_maps(struct bpf_object *obj, const Image *im) {
    /* 1. config_map */
    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");
    if (config_map) {
        struct ppt_config cfg = {
            .n_fields = im->n_fields, .n_interns = im->n_interns,
            .n_atoms = im->n_atoms,   .n_nodes = im->n_nodes,
            .n_edges = im->n_edges,   .prog_len = im->prog_len,
            .start_node = im->start,  .visits_idx = im->visits_idx,
            .max_steps = im->max_steps, .max_stack = im->max_stack,
            .safe_node = im->safe,
            .policy_hash = policy_hash_of(im),   /* stamped at load so receipts are policy-bound */
        };
        if (map_put(bpf_map__fd(config_map), 0, &cfg, "config_map")) return -1;
    }

    /* 2. atoms_map */
    struct bpf_map *atoms_map = bpf_object__find_map_by_name(obj, "atoms_map");
    if (atoms_map) {
        for (uint32_t i = 0; i < im->n_atoms; i++) {
            if (map_put(bpf_map__fd(atoms_map), i, &im->atoms[i], "atoms_map")) return -1;
        }
    }

    /* 3. nodes_map */
    struct bpf_map *nodes_map = bpf_object__find_map_by_name(obj, "nodes_map");
    if (nodes_map) {
        for (uint32_t i = 0; i < im->n_nodes; i++) {
            if (map_put(bpf_map__fd(nodes_map), i, &im->nodes[i], "nodes_map")) return -1;
        }
    }

    /* 4. edges_map */
    struct bpf_map *edges_map = bpf_object__find_map_by_name(obj, "edges_map");
    if (edges_map) {
        for (uint32_t i = 0; i < im->n_edges; i++) {
            if (map_put(bpf_map__fd(edges_map), i, &im->edges[i], "edges_map")) return -1;
        }
    }

    /* 5. prog_map */
    struct bpf_map *prog_map = bpf_object__find_map_by_name(obj, "prog_map");
    if (prog_map) {
        for (uint32_t i = 0; i < im->prog_len; i++) {
            if (map_put(bpf_map__fd(prog_map), i, &im->prog[i], "prog_map")) return -1;
        }
    }

    /* 6. bank_map (net program only): a fresh load populates bank 0 above, so select bank 0. */
    struct bpf_map *bank_map = bpf_object__find_map_by_name(obj, "bank_map");
    if (bank_map) {
        uint32_t bank0 = 0;
        if (map_put(bpf_map__fd(bank_map), 0, &bank0, "bank_map")) return -1;
    }

    return 0;
}

/* Production hot-swap primitive for the resident selector: migrate the resident state per the NEW
 * policy's SIGNED strategy, then swap the table. Reads sel_state BEFORE the swap (so it resolves against
 * the OLD policy's name-hashes), computes the migrated node via migrate_node (by-name re-resolves the
 * current posture in the new policy; reset-to -> the new fail-safe), swaps the table maps
 * (populate_maps), then writes the migrated resident node back under the state lock. Returns the new
 * resident node, or -1. Single-config selector here; a live multi-CPU deployment would quiesce or bank
 * this like net_hotswap, and pin sel_state on bpffs to persist across loader invocations. */
/* out_migr (nullable) receives the migration as a first-class ppt_receipt — the SAME struct and leaf
 * format as a kernel transition receipt, so the trail-builder (receipts_selector / the forwarder) folds
 * it into the one Merkle-rooted, policy-bound audit trail. It reuses the anchored struct unchanged and
 * marks itself PPT_EVENT_MIGRATION; its cause is the migration outcome. This out-param IS the seam that
 * wires loader migration receipts into the signed trail. */
long selector_hotswap(struct bpf_object *obj, const Image *old_im, const Image *new_im,
                      struct ppt_receipt *out_migr) {
    int st_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "sel_state_map"));
    if (st_fd < 0) { fprintf(stderr, "selector_hotswap: no sel_state_map\n"); return -1; }
    struct sel_state s; __u32 k = 0;
    if (bpf_map_lookup_elem_flags(st_fd, &k, &s, BPF_F_LOCK)) { perror("sel_state read"); return -1; }
    uint32_t cur = s.inited ? s.cur_node : old_im->safe;   /* uninited old state -> its fail-safe */
    int mig_cause = PPT_CAUSE_NONE;
    uint32_t migrated = migrate_node(old_im, new_im, cur, &mig_cause);
    /* Loader migration receipt: a swap is a userspace event, so the loader attests it here (the kernel
     * ringbuf carries per-transition receipts; migrations are the loader's to record). A reset-to that
     * parks the posture on the fail-safe is a state:migration-reset, distinct from a clean by-name carry. */
    fprintf(stderr, "MIGRATION_RECEIPT prev=%u next=%u cause=%d (%s)\n", cur, migrated, mig_cause,
            mig_cause == PPT_CAUSE_MIGRATION_RESET ? "state:migration-reset" : "clean");
    if (out_migr) {                                        /* the trail seam: a ppt_receipt leaf */
        struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
        out_migr->seq         = s.gen;                     /* the generation at the swap boundary */
        out_migr->t_ns        = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
        out_migr->policy_hash = policy_hash_of(new_im);    /* bound to the policy migrated TO */
        out_migr->prev_node   = (int32_t)cur;
        out_migr->event       = PPT_EVENT_MIGRATION;       /* discriminator: a loader swap, not a packet */
        out_migr->next_node   = (int32_t)migrated;
        out_migr->cause       = mig_cause;
    }
    if (populate_maps(obj, new_im)) return -1;             /* swap the table maps to the new policy */
    s.cur_node = migrated; s.inited = 1;                   /* keep gen: monotonic across the swap */
    if (bpf_map_update_elem(st_fd, &k, &s, BPF_F_LOCK)) { perror("sel_state write"); return -1; }
    return (long)migrated;
}

char **read_names(const char *path, int *out_n) {
    *out_n = 0;
    if (!path) return NULL;
    long nlen; uint8_t *nb = read_file(path, &nlen);
    char **names = malloc(sizeof(char *) * PPT_MAX_NAMES);
    int count = 0;
    char *tok = strtok((char *)nb, "\r\n");
    while (tok && count < PPT_MAX_NAMES) {
        names[count++] = strdup(tok);
        tok = strtok(NULL, "\r\n");
    }
    /* Past the cap the sidecar and the node indices stop lining up, so every later name would be
     * read against the wrong node. Say so rather than truncating quietly. */
    if (tok) {
        fprintf(stderr, "read_names: %s lists more than %d names; the rest are ignored\n",
                path, PPT_MAX_NAMES);
    }
    free(nb);
    *out_n = count;
    return names;
}

void free_names(char **names, int n_names) {
    if (!names) return;
    for (int i = 0; i < n_names; i++) free(names[i]);
    free(names);
}
