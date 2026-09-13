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

uint16_t rd16(const uint8_t *bytes) { return (uint16_t)(bytes[0] | (bytes[1] << 8)); }
int32_t rd32(const uint8_t *bytes) {
    return (int32_t)((uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
                     ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24));
}

uint8_t *read_file(const char *path, long *out_len) {
    FILE *stream = fopen(path, "rb");
    if (!stream) { fprintf(stderr, "error: cannot open %s\n", path); exit(2); }
    fseek(stream, 0, SEEK_END); long file_len = ftell(stream); fseek(stream, 0, SEEK_SET);
    /* ftell returns -1 on an unseekable path (a directory, a pipe), and (size_t)(-1) is a 16 EB
     * malloc whose failure only shows up as the generic read error below. Say which it was. */
    if (file_len < 0) {
        fprintf(stderr, "error: cannot size %s (not a regular file?)\n", path);
        fclose(stream);
        exit(2);
    }
    uint8_t *buf = malloc((size_t)file_len);
    if (!buf || fread(buf, 1, (size_t)file_len, stream) != (size_t)file_len) {
        fprintf(stderr, "error: cannot read %s\n", path); exit(2);
    }
    fclose(stream); *out_len = file_len; return buf;
}

/* Build an eth+ip+udp+ppt frame for evaluating `node_idx` with `regs` (matches smoke.sh / cert_*.py
 * framing: network-order L2/L3/L4 headers, little-endian PPT payload). Returns the frame length. */
int build_frame(uint8_t *out, uint16_t node_idx, uint16_t n_fields, const struct ppt_reg *regs) {
    int ppt_len = 12 + 8 * n_fields;
    int udp_len = 8 + ppt_len;
    int ip_len = 20 + udp_len;
    uint8_t *cursor = out;
    memset(cursor, 0xff, 6); cursor += 6; memset(cursor, 0x02, 6); cursor += 6;
    *cursor++ = 0x08; *cursor++ = 0x00;                                                  /* eth */
    *cursor++ = 0x45; *cursor++ = 0x00; *cursor++ = (uint8_t)(ip_len >> 8); *cursor++ = (uint8_t)ip_len;     /* ip  */
    *cursor++ = 0x12; *cursor++ = 0x34; *cursor++ = 0x00; *cursor++ = 0x00;
    *cursor++ = 64; *cursor++ = 17; *cursor++ = 0; *cursor++ = 0;
    *cursor++ = 192; *cursor++ = 168; *cursor++ = 1; *cursor++ = 1;
    *cursor++ = 192; *cursor++ = 168; *cursor++ = 1; *cursor++ = 2;
    *cursor++ = 0x30; *cursor++ = 0x39; *cursor++ = 0x27; *cursor++ = 0x0f;              /* udp 12345->9999 */
    *cursor++ = (uint8_t)(udp_len >> 8); *cursor++ = (uint8_t)udp_len; *cursor++ = 0; *cursor++ = 0;
    uint32_t magic = PPT_MAGIC, ni = node_idx, nf = n_fields;
    /* ppt_hdr (LE) */
    memcpy(cursor, &magic, 4); cursor += 4;
    memcpy(cursor, &ni, 4); cursor += 4;
    memcpy(cursor, &nf, 4); cursor += 4;
    for (int i = 0; i < n_fields; i++) {
        memcpy(cursor, &regs[i].ty, 4); cursor += 4; memcpy(cursor, &regs[i].val, 4); cursor += 4;
    }
    return (int)(cursor - out);
}

/* Parse a PPT image already resident in memory. Mallocs im->atoms/nodes/edges/prog (free_image frees
 * them). Returns 0 on success, -1 on a malformed image (used by the certify loop, which must not exit). */
int parse_image_buf(const uint8_t *table_bytes, long len, Image *im) {
    if (len < 28 || rd32(table_bytes) != (int32_t)PPT_MAGIC || rd16(table_bytes + 4) != 1) {
        return -1;
    }
    im->n_fields = rd16(table_bytes + 6);   im->n_interns = rd16(table_bytes + 8);
    im->n_atoms = rd16(table_bytes + 10);   im->n_nodes = rd16(table_bytes + 12);
    im->n_edges = rd16(table_bytes + 14);   im->prog_len = rd16(table_bytes + 16);
    im->start = rd16(table_bytes + 18);     im->visits_idx = rd16(table_bytes + 20);
    im->max_steps = rd16(table_bytes + 22);  im->max_stack = rd16(table_bytes + 24);
    im->safe = rd16(table_bytes + 26) >> 8;   /* high byte of the flags word = signed fail-safe node (0 = undeclared) */
    im->flags = rd16(table_bytes + 26) & 0xFF;
    im->name_hashes = NULL;
    im->raw = table_bytes; im->raw_len = len;  /* borrowed table bytes, hashed into policy_hash at populate time */
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
    const uint8_t *cursor = table_bytes + 28;
    im->atoms = malloc(sizeof(struct ppt_atom) * (im->n_atoms ? im->n_atoms : 1));
    for (int slot = 0; slot < im->n_atoms; slot++, cursor += 8) {
        im->atoms[slot].field = rd16(cursor); im->atoms[slot].op = cursor[2]; im->atoms[slot].ty = cursor[3];
        im->atoms[slot].val = rd32(cursor + 4);
    }
    im->nodes = malloc(sizeof(struct ppt_node) * (im->n_nodes ? im->n_nodes : 1));
    for (int slot = 0; slot < im->n_nodes; slot++, cursor += 4) {
        im->nodes[slot].edge_off = rd16(cursor); im->nodes[slot].edge_cnt = rd16(cursor + 2);
    }
    im->edges = malloc(sizeof(struct ppt_edge) * (im->n_edges ? im->n_edges : 1));
    for (int slot = 0; slot < im->n_edges; slot++, cursor += 6) {
        im->edges[slot].target = rd16(cursor); im->edges[slot].prog_off = rd16(cursor + 2);
        im->edges[slot].prog_cnt = rd16(cursor + 4);
    }
    im->prog = malloc(sizeof(uint16_t) * (im->prog_len ? im->prog_len : 1));
    for (int slot = 0; slot < im->prog_len; slot++, cursor += 2) im->prog[slot] = rd16(cursor);
    /* Signed per-node name-hash section (for by-name hot-swap migration), appended after the optional
     * node-attribute section. Skip node-attr first so the offset is right regardless of that flag. */
    if (im->flags & PPT_FLAG_NODE_NAMES) {
        if (im->flags & PPT_FLAG_NODE_ATTR) cursor += 2L * im->n_nodes;
        if (table_bytes + len < cursor + 4L * im->n_nodes) return -1;      /* names section truncated */
        im->name_hashes = malloc(sizeof(uint32_t) * (im->n_nodes ? im->n_nodes : 1));
        for (int slot = 0; slot < im->n_nodes; slot++, cursor += 4) im->name_hashes[slot] = rd32(cursor);
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
        for (uint32_t node_index = 0; node_index < new_im->n_nodes; node_index++)
            if (new_im->name_hashes[node_index] == want) {           /* same posture, by name, in the new policy */
                if (out_cause) *out_cause = PPT_CAUSE_NONE;
                return node_index;
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
    long len; uint8_t *image_bytes = read_file(path, &len);
    if (parse_image_buf(image_bytes, len, im) != 0) {
        fprintf(stderr, "error: bad/truncated image %s\n", path); exit(2);
    }
    free(image_bytes);
}

/* Host reference evaluator (matches interp.c) */
int eval_atom_host(const struct ppt_atom *atom, const struct ppt_reg *regs, uint32_t n_fields) {
    struct ppt_reg reading = (atom->field < n_fields) ? regs[atom->field] : (struct ppt_reg){TY_NONE, 0};
    int lnum = (reading.ty == TY_BOOL || reading.ty == TY_INT);
    int rnum = (atom->ty == TY_BOOL || atom->ty == TY_INT);
    switch (atom->op) {
    case OP_EQ: case OP_NE: {
        int eq;
        if (lnum && rnum) eq = (reading.val == atom->val);
        else if (reading.ty == TY_STR && atom->ty == TY_STR) eq = (reading.val == atom->val);
        else if (reading.ty == TY_NONE && atom->ty == TY_NONE) eq = 1;
        else eq = 0;
        return atom->op == OP_EQ ? eq : !eq;
    }
    case OP_LT: case OP_LE: case OP_GT: case OP_GE:
        if (!(lnum && rnum)) return 0;
        switch (atom->op) {
        case OP_LT: return reading.val <  atom->val;
        case OP_LE: return reading.val <= atom->val;
        case OP_GT: return reading.val >  atom->val;
        default:    return reading.val >= atom->val;
        }
    case OP_TRUTHY:
        return reading.ty == TY_NONE ? 0 : (reading.val != 0);
    }
    return 0;
}

/* The depth guards are the ones prog_word_cb (ppt_eval_bpf.h) applies: a push past STACK_MAX is
 * dropped, and an operator with too few operands is a no-op. A well-formed program (the declared
 * subset, depth <= STACK_MAX) never reaches any of them, so every certified vector is unaffected.
 * Unguarded, a hand-made prog whose first word is OPC_AND indexed stack[-1] here, so the reference
 * this target is certified against read outside its own frame on an image the parser accepts. */
int eval_prog_host(const Image *im, const struct ppt_edge *edge, const struct ppt_reg *regs) {
    uint8_t stack[STACK_MAX]; int sp = 0;
    for (int word_index = 0; word_index < edge->prog_cnt; word_index++) {
        uint16_t word = im->prog[edge->prog_off + word_index];
        if (word < 0x8000) {
            if (sp < STACK_MAX)
                stack[sp++] = (uint8_t)eval_atom_host(&im->atoms[word], regs, im->n_fields);
        }
        else switch (word) {
        case OPC_NOT:   if (sp >= 1) stack[sp - 1] = !stack[sp - 1]; break;
        case OPC_AND:   if (sp >= 2) { sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] && stack[sp]); } break;
        case OPC_OR:    if (sp >= 2) { sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] || stack[sp]); } break;
        case OPC_TRUE:  if (sp < STACK_MAX) stack[sp++] = 1; break;
        case OPC_FALSE: if (sp < STACK_MAX) stack[sp++] = 0; break;
        default: break;
        }
    }
    return sp > 0 ? stack[0] : 0;
}

int evaluate_host(const Image *im, uint16_t node, const struct ppt_reg *regs, int *out_target) {
    const struct ppt_node *node_entry = &im->nodes[node];
    for (int edge_index = 0; edge_index < node_entry->edge_cnt; edge_index++) {
        if (eval_prog_host(im, &im->edges[node_entry->edge_off + edge_index], regs)) {
            if (out_target) *out_target = im->edges[node_entry->edge_off + edge_index].target;
            return edge_index;
        }
    }
    return -1;
}
