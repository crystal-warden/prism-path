// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_image.c: read, validate and evaluate a PPT v1 table image on the host.
 *
 * Split out of loader.c so the five selector harnesses can link the parser and the host reference
 * evaluator instead of #including the whole loader. No libbpf here by design: the fallback build
 * compiles this file as is. See ppt_image.h for what the unit promises.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ppt_image.h"

uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
int32_t rd32(const uint8_t *p) {
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

uint8_t *read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "error: cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)n);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "error: cannot read %s\n", path); exit(2);
    }
    fclose(f); *out_len = n; return buf;
}

/* Build an eth+ip+udp+ppt frame for evaluating `node_idx` with `regs` (matches smoke.sh / cert_*.py
 * framing: network-order L2/L3/L4 headers, little-endian PPT payload). Returns the frame length. */
int build_frame(uint8_t *out, uint16_t node_idx, uint16_t n_fields, const struct ppt_reg *regs) {
    int ppt_len = 12 + 8 * n_fields;
    int udp_len = 8 + ppt_len;
    int ip_len = 20 + udp_len;
    uint8_t *p = out;
    memset(p, 0xff, 6); p += 6; memset(p, 0x02, 6); p += 6; *p++ = 0x08; *p++ = 0x00;   /* eth */
    *p++ = 0x45; *p++ = 0x00; *p++ = (uint8_t)(ip_len >> 8); *p++ = (uint8_t)ip_len;     /* ip  */
    *p++ = 0x12; *p++ = 0x34; *p++ = 0x00; *p++ = 0x00; *p++ = 64; *p++ = 17; *p++ = 0; *p++ = 0;
    *p++ = 192; *p++ = 168; *p++ = 1; *p++ = 1;  *p++ = 192; *p++ = 168; *p++ = 1; *p++ = 2;
    *p++ = 0x30; *p++ = 0x39; *p++ = 0x27; *p++ = 0x0f;                                  /* udp 12345->9999 */
    *p++ = (uint8_t)(udp_len >> 8); *p++ = (uint8_t)udp_len; *p++ = 0; *p++ = 0;
    uint32_t magic = PPT_MAGIC, ni = node_idx, nf = n_fields;
    memcpy(p, &magic, 4); p += 4; memcpy(p, &ni, 4); p += 4; memcpy(p, &nf, 4); p += 4;  /* ppt_hdr (LE) */
    for (int i = 0; i < n_fields; i++) {
        memcpy(p, &regs[i].ty, 4); p += 4; memcpy(p, &regs[i].val, 4); p += 4;
    }
    return (int)(p - out);
}

/* Parse a PPT image already resident in memory. Mallocs im->atoms/nodes/edges/prog (free_image frees
 * them). Returns 0 on success, -1 on a malformed image (used by the certify loop, which must not exit). */
int parse_image_buf(const uint8_t *b, long len, Image *im) {
    if (len < 28 || rd32(b) != (int32_t)PPT_MAGIC || rd16(b + 4) != 1) {
        return -1;
    }
    im->n_fields = rd16(b + 6);   im->n_interns = rd16(b + 8);
    im->n_atoms = rd16(b + 10);   im->n_nodes = rd16(b + 12);
    im->n_edges = rd16(b + 14);   im->prog_len = rd16(b + 16);
    im->start = rd16(b + 18);     im->visits_idx = rd16(b + 20);
    im->max_steps = rd16(b + 22);  im->max_stack = rd16(b + 24);
    im->safe = rd16(b + 26) >> 8;   /* high byte of the flags word = signed fail-safe node (0 = undeclared) */
    im->flags = rd16(b + 26) & 0xFF;
    im->name_hashes = NULL;
    im->raw = b; im->raw_len = len;  /* borrowed table bytes, hashed into policy_hash at populate time */
    long need = 28 + 8L * im->n_atoms + 4L * im->n_nodes + 6L * im->n_edges + 2L * im->prog_len;
    if (len < need) return -1;
    /* Capacity bounds: the kernel maps are sized to these MAX_* — an image over any of them would
     * partially populate (higher indices silently dropped) and route wrong. Reject up front. */
    if (im->n_atoms > MAX_ATOMS || im->n_nodes > MAX_NODES || im->n_edges > MAX_EDGES ||
        im->prog_len > MAX_PROG_WORDS || im->n_fields > MAX_FIELDS_PER_PKT) {
        fprintf(stderr, "parse_image: table exceeds a MAX_* capacity "
                "(atoms=%u/%d nodes=%u/%d edges=%u/%d prog=%u/%d fields=%u/%d)\n",
                im->n_atoms, MAX_ATOMS, im->n_nodes, MAX_NODES, im->n_edges, MAX_EDGES,
                im->prog_len, MAX_PROG_WORDS, im->n_fields, MAX_FIELDS_PER_PKT);
        return -1;
    }
    const uint8_t *p = b + 28;
    im->atoms = malloc(sizeof(struct ppt_atom) * (im->n_atoms ? im->n_atoms : 1));
    for (int i = 0; i < im->n_atoms; i++, p += 8) {
        im->atoms[i].field = rd16(p); im->atoms[i].op = p[2]; im->atoms[i].ty = p[3];
        im->atoms[i].val = rd32(p + 4);
    }
    im->nodes = malloc(sizeof(struct ppt_node) * (im->n_nodes ? im->n_nodes : 1));
    for (int i = 0; i < im->n_nodes; i++, p += 4) {
        im->nodes[i].edge_off = rd16(p); im->nodes[i].edge_cnt = rd16(p + 2);
    }
    im->edges = malloc(sizeof(struct ppt_edge) * (im->n_edges ? im->n_edges : 1));
    for (int i = 0; i < im->n_edges; i++, p += 6) {
        im->edges[i].target = rd16(p); im->edges[i].prog_off = rd16(p + 2);
        im->edges[i].prog_cnt = rd16(p + 4);
    }
    im->prog = malloc(sizeof(uint16_t) * (im->prog_len ? im->prog_len : 1));
    for (int i = 0; i < im->prog_len; i++, p += 2) im->prog[i] = rd16(p);
    /* Signed per-node name-hash section (for by-name hot-swap migration), appended after the optional
     * node-attribute section. Skip node-attr first so the offset is right regardless of that flag. */
    if (im->flags & PPT_FLAG_NODE_NAMES) {
        if (im->flags & PPT_FLAG_NODE_ATTR) p += 2L * im->n_nodes;
        if (b + len < p + 4L * im->n_nodes) return -1;      /* names section truncated */
        im->name_hashes = malloc(sizeof(uint32_t) * (im->n_nodes ? im->n_nodes : 1));
        for (int i = 0; i < im->n_nodes; i++, p += 4) im->name_hashes[i] = rd32(p);
    }
    return 0;
}

/* Swap-time migration: pick the resident cur_node in a NEW policy that replaces the old one, per the
 * new policy's SIGNED strategy (PPT_FLAG_MIGRATE_BY_NAME). by-name re-resolves the old node's name
 * hash in the new policy (fallback to the new fail-safe if the name is gone); reset-to (bit clear)
 * always returns the new fail-safe. Both name-hash sections ride the signed image, so the migration
 * is tamper-evident, and a raw index is never carried blindly across a reindexing swap. */
/* Called by selector_hotswap (the loader's swap primitive) and the migrate harness. */
/* out_cause (nullable) reports WHY the posture landed where it did: PPT_CAUSE_NONE when it was
 * preserved by name, PPT_CAUSE_MIGRATION_RESET when a reset-to strategy (or a vanished name) parked
 * it on the new fail-safe. This is the cause the loader attests on the swap (see selector_hotswap). */
uint32_t migrate_node(const Image *old_im, const Image *new_im, uint32_t old_cur, int *out_cause) {
    if ((new_im->flags & PPT_FLAG_MIGRATE_BY_NAME) && old_im->name_hashes && new_im->name_hashes
        && old_cur < old_im->n_nodes) {
        uint32_t want = old_im->name_hashes[old_cur];
        for (uint32_t i = 0; i < new_im->n_nodes; i++)
            if (new_im->name_hashes[i] == want) {           /* same posture, by name, in the new policy */
                if (out_cause) *out_cause = PPT_CAUSE_NONE;
                return i;
            }
    }
    if (out_cause) *out_cause = PPT_CAUSE_MIGRATION_RESET;   /* reset-to, or a vanished name -> fail-safe */
    return new_im->safe;
}

void free_image(Image *im) {
    free(im->atoms); free(im->nodes); free(im->edges); free(im->prog); free(im->name_hashes);
    im->atoms = NULL; im->nodes = NULL; im->edges = NULL; im->prog = NULL; im->name_hashes = NULL;
}

void load_image(const char *path, Image *im) {
    long len; uint8_t *b = read_file(path, &len);
    if (parse_image_buf(b, len, im) != 0) {
        fprintf(stderr, "error: bad/truncated image %s\n", path); exit(2);
    }
    free(b);
}

/* Host reference evaluator (matches interp.c) */
int eval_atom_host(const struct ppt_atom *a, const struct ppt_reg *regs, uint32_t n_fields) {
    struct ppt_reg r = (a->field < n_fields) ? regs[a->field] : (struct ppt_reg){TY_NONE, 0};
    int lnum = (r.ty == TY_BOOL || r.ty == TY_INT);
    int rnum = (a->ty == TY_BOOL || a->ty == TY_INT);
    switch (a->op) {
    case OP_EQ: case OP_NE: {
        int eq;
        if (lnum && rnum) eq = (r.val == a->val);
        else if (r.ty == TY_STR && a->ty == TY_STR) eq = (r.val == a->val);
        else if (r.ty == TY_NONE && a->ty == TY_NONE) eq = 1;
        else eq = 0;
        return a->op == OP_EQ ? eq : !eq;
    }
    case OP_LT: case OP_LE: case OP_GT: case OP_GE:
        if (!(lnum && rnum)) return 0;
        switch (a->op) {
        case OP_LT: return r.val <  a->val;
        case OP_LE: return r.val <= a->val;
        case OP_GT: return r.val >  a->val;
        default:    return r.val >= a->val;
        }
    case OP_TRUTHY:
        return r.ty == TY_NONE ? 0 : (r.val != 0);
    }
    return 0;
}

int eval_prog_host(const Image *im, const struct ppt_edge *e, const struct ppt_reg *regs) {
    uint8_t stack[STACK_MAX]; int sp = 0;
    for (int i = 0; i < e->prog_cnt; i++) {
        uint16_t w = im->prog[e->prog_off + i];
        if (w < 0x8000) stack[sp++] = (uint8_t)eval_atom_host(&im->atoms[w], regs, im->n_fields);
        else switch (w) {
        case OPC_NOT:   stack[sp - 1] = !stack[sp - 1]; break;
        case OPC_AND:   sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] && stack[sp]); break;
        case OPC_OR:    sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] || stack[sp]); break;
        case OPC_TRUE:  stack[sp++] = 1; break;
        case OPC_FALSE: stack[sp++] = 0; break;
        default: break;
        }
    }
    return sp > 0 ? stack[0] : 0;
}

int evaluate_host(const Image *im, uint16_t node, const struct ppt_reg *regs, int *out_target) {
    const struct ppt_node *n = &im->nodes[node];
    for (int i = 0; i < n->edge_cnt; i++) {
        if (eval_prog_host(im, &im->edges[n->edge_off + i], regs)) {
            if (out_target) *out_target = im->edges[n->edge_off + i].target;
            return i;
        }
    }
    return -1;
}
