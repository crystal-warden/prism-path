// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_common.h — PrismPath PPT v1 shared definitions for eBPF XDP & Loader */
#ifndef PPT_COMMON_H
#define PPT_COMMON_H

#include <linux/types.h>

#define PPT_MAGIC 0x4D545050u
#define PPT_VISITS_NONE 0xFFFFu

/* Value domain type tags */
#define TY_NONE 0
#define TY_BOOL 1
#define TY_INT  2
#define TY_STR  3

/* Atom comparison operators */
#define OP_EQ     0
#define OP_NE     1
#define OP_LT     2
#define OP_LE     3
#define OP_GT     4
#define OP_GE     5
#define OP_TRUTHY 6

/* Stack machine opcodes */
#define OPC_NOT   0x8000
#define OPC_AND   0x8001
#define OPC_OR    0x8002
#define OPC_TRUE  0x8003
#define OPC_FALSE 0x8004

/* Bounded capacity limits for static verifier guarantees */
#define MAX_ATOMS          1024
#define MAX_NODES          256
#define MAX_EDGES          1024
#define MAX_PROG_WORDS     4096

/* Per-iteration loop bounds. The edge loop runs via bpf_loop() (callback verified ONCE), so
 * MAX_EDGES_PER_NODE is effectively free to the verifier. eval_prog keeps EXACT RPN semantics but its
 * operand stack is a FIXED depth accessed only through constant indices (st_get/st_put's switch) — never
 * st[runtime_sp], which is what made the verifier explore every sp value and overrun the 1M-insn limit.
 * STACK_MAX is the declared max operand-stack depth of a supported predicate. Level M expressions fold
 * left-associatively, so a flat AND/OR chain (including `in`-lists) stays at depth 2; 4 covers real
 * nesting. A predicate deeper than this is outside the eBPF-target's declared subset. */
/* BIG-TEST bounds: the original large numbers that overran the verifier BEFORE the bpf_loop rewrite
 * (64x64 hit the 8192-jump limit; 16x16 processed 1,000,001 insns). With edge + prog loops now run via
 * bpf_loop (each callback verified once), MAX_EDGES_PER_NODE and MAX_PROG_PER_EDGE are O(1) to the
 * verifier, and MAX_FIELDS_PER_PKT is a once-verified field-load loop — so these should now load. */
#define MAX_FIELDS_PER_PKT 32
#define MAX_EDGES_PER_NODE 64
#define MAX_PROG_PER_EDGE  64
#define STACK_MAX          4

/* Binary table structs matching TABLE_FORMAT.md layout (little-endian) */
struct ppt_atom {
    __u16 field;
    __u8  op;
    __u8  ty;
    __s32 val;
} __attribute__((packed));

struct ppt_node {
    __u16 edge_off;
    __u16 edge_cnt;
} __attribute__((packed));

struct ppt_edge {
    __u16 target;
    __u16 prog_off;
    __u16 prog_cnt;
} __attribute__((packed));

struct ppt_reg {
    __s32 ty;
    __s32 val;
};

struct ppt_config {
    __u16 n_fields;
    __u16 n_interns;
    __u16 n_atoms;
    __u16 n_nodes;
    __u16 n_edges;
    __u16 prog_len;
    __u16 start_node;
    __u16 visits_idx;
    __u16 max_steps;
    __u16 max_stack;
    __u16 safe_node;   /* selector fail-safe: most-restrictive node index; 0 = undeclared (ppt_select) */
    /* inline enforcement (ppt_net only): bit i set => decision node i returns XDP_DROP instead of
     * XDP_PASS. 0 = observe-only (default). Covers node indices 0-63; the net program bounds the shift.
     * ppt_xdp (the conformance program) ignores this field — the 114/114 cert is unaffected. */
    __u64 drop_mask;
};

/* On-wire context header in packet payload */
struct ppt_packet_hdr {
    __u32 magic;     /* PPT_MAGIC (0x4D545050) */
    __u32 node_idx;  /* Target node index to evaluate */
    __u32 n_fields;  /* Number of registers following in packet payload */
} __attribute__((packed));

/* Result data written by XDP program */
struct ppt_result {
    __s32 matched_edge;  /* Matched edge index (-1 if none) */
    __s32 target_node;   /* Target node index (-1 if none) */
    __u32 eval_status;   /* 1 = match found, 0 = stuck (no match), 2 = parse error */
    __u64 pkt_count;     /* Counter of evaluated PPT packets */
};

#endif /* PPT_COMMON_H */
