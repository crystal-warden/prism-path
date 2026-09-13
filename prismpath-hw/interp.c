// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* interp.c — PPT v1 reference interpreter: the C target.
 *
 * The behavioral twin of the Verilog interpreter: same table image, same register-file
 * semantics, certified against the same frozen conformance vectors (see TABLE_FORMAT.md
 * for the format and the engine-parity rules this file must reproduce).
 *
 *   interp eval image.ppt regs.bin    one evaluate(node): "match <edge> <target>" | "none"
 *   interp run  image.ppt script.bin  scripted run: "N <node>" per path entry, then "S <stopped>"
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "interp.h"

enum { TY_NONE = 0, TY_BOOL = 1, TY_INT = 2, TY_STR = 3 };
enum { OP_EQ = 0, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY };
enum { OPC_NOT = 0x8000, OPC_AND, OPC_OR, OPC_TRUE, OPC_FALSE };
#define MAGIC 0x4D545050u
#define VISITS_NONE 0xFFFFu
#define STACK_MAX 64

typedef struct { uint16_t field; uint8_t op, ty; int32_t val; } Atom;
typedef struct { uint16_t edge_off, edge_cnt; } Node;
typedef struct { uint16_t target, prog_off, prog_cnt; } Edge;
typedef struct { int32_t ty, val; } Reg;

typedef struct {
    uint16_t n_fields, n_interns, n_atoms, n_nodes, n_edges, prog_len,
             start, visits_idx, max_steps, max_stack;
    Atom *atoms; Node *nodes; Edge *edges; uint16_t *prog;
} Image;

static uint16_t rd16(const uint8_t *bytes) { return (uint16_t)(bytes[0] | (bytes[1] << 8)); }
static int32_t rd32(const uint8_t *bytes) {
    return (int32_t)((uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
                     ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24));
}

static uint8_t *read_file(const char *path, long *out_len) {
    FILE *stream = fopen(path, "rb");
    if (!stream) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    fseek(stream, 0, SEEK_END); long length = ftell(stream); fseek(stream, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)length);
    if (!buf || fread(buf, 1, (size_t)length, stream) != (size_t)length) {
        fprintf(stderr, "cannot read %s\n", path); exit(2);
    }
    fclose(stream); *out_len = length; return buf;
}

static void load_image(const char *path, Image *im) {
    long len; uint8_t *bytes = read_file(path, &len);
    if (len < 28 || rd32(bytes) != (int32_t)MAGIC || rd16(bytes + 4) != 1) {
        fprintf(stderr, "bad image %s\n", path); exit(2);
    }
    im->n_fields = rd16(bytes + 6);  im->n_interns = rd16(bytes + 8);
    im->n_atoms = rd16(bytes + 10);  im->n_nodes = rd16(bytes + 12);
    im->n_edges = rd16(bytes + 14);  im->prog_len = rd16(bytes + 16);
    im->start = rd16(bytes + 18);    im->visits_idx = rd16(bytes + 20);
    im->max_steps = rd16(bytes + 22); im->max_stack = rd16(bytes + 24);
    long need = 28 + 8L * im->n_atoms + 4L * im->n_nodes + 6L * im->n_edges + 2L * im->prog_len;
    if (len < need) { fprintf(stderr, "truncated image %s\n", path); exit(2); }
    const uint8_t *cursor = bytes + 28;
    im->atoms = malloc(sizeof(Atom) * im->n_atoms);
    for (int entry_index = 0; entry_index < im->n_atoms; entry_index++, cursor += 8) {
        im->atoms[entry_index].field = rd16(cursor); im->atoms[entry_index].op = cursor[2]; im->atoms[entry_index].ty = cursor[3];
        im->atoms[entry_index].val = rd32(cursor + 4);
    }
    im->nodes = malloc(sizeof(Node) * im->n_nodes);
    for (int entry_index = 0; entry_index < im->n_nodes; entry_index++, cursor += 4) {
        im->nodes[entry_index].edge_off = rd16(cursor); im->nodes[entry_index].edge_cnt = rd16(cursor + 2);
    }
    im->edges = malloc(sizeof(Edge) * im->n_edges);
    for (int entry_index = 0; entry_index < im->n_edges; entry_index++, cursor += 6) {
        im->edges[entry_index].target = rd16(cursor); im->edges[entry_index].prog_off = rd16(cursor + 2);
        im->edges[entry_index].prog_cnt = rd16(cursor + 4);
    }
    im->prog = malloc(sizeof(uint16_t) * im->prog_len);
    for (int entry_index = 0; entry_index < im->prog_len; entry_index++, cursor += 2) im->prog[entry_index] = rd16(cursor);
    free(bytes);
}

/* ------------------------------------------------------------------ the evaluator core
 * This is the function the fabric implements: atoms are parallel comparators over the
 * field register file; each edge's program folds atom results; first-true edge wins. */

static int eval_atom(const Atom *atom, const Reg *regs) {
    Reg reg = regs[atom->field];
    int lnum = (reg.ty == TY_BOOL || reg.ty == TY_INT);
    int rnum = (atom->ty == TY_BOOL || atom->ty == TY_INT);
    switch (atom->op) {
    case OP_EQ: case OP_NE: {
        int eq;
        if (lnum && rnum)                        eq = (reg.val == atom->val);
        else if (reg.ty == TY_STR && atom->ty == TY_STR) eq = (reg.val == atom->val);
        else if (reg.ty == TY_NONE && atom->ty == TY_NONE) eq = 1;
        else                                     eq = 0;
        return atom->op == OP_EQ ? eq : !eq;
    }
    case OP_LT: case OP_LE: case OP_GT: case OP_GE:
        if (!(lnum && rnum)) return 0;           /* totality: non-numeric -> unsatisfied */
        switch (atom->op) {
        case OP_LT: return reg.val <  atom->val;
        case OP_LE: return reg.val <= atom->val;
        case OP_GT: return reg.val >  atom->val;
        default:    return reg.val >= atom->val;
        }
    case OP_TRUTHY:
        return reg.ty == TY_NONE ? 0 : (reg.val != 0);   /* BOOL value; INT!=0; STR id!=0 ("" is 0) */
    }
    return 0;
}

static void overflow(void) { fprintf(stderr, "stack overflow\n"); exit(2); }   /* checked before the write, never after it */

static int eval_prog(const Image *im, const Edge *edge, const Reg *regs) {
    uint8_t stack[STACK_MAX]; int sp = 0;
    for (int word_index = 0; word_index < edge->prog_cnt; word_index++) {
        uint16_t word = im->prog[edge->prog_off + word_index];
        if (word < 0x8000) { if (sp >= STACK_MAX) overflow(); stack[sp++] = (uint8_t)eval_atom(&im->atoms[word], regs); }
        else switch (word) {
        case OPC_NOT:   stack[sp - 1] = !stack[sp - 1]; break;
        case OPC_AND:   sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] && stack[sp]); break;
        case OPC_OR:    sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] || stack[sp]); break;
        case OPC_TRUE:  if (sp >= STACK_MAX) overflow(); stack[sp++] = 1; break;
        case OPC_FALSE: if (sp >= STACK_MAX) overflow(); stack[sp++] = 0; break;
        default: fprintf(stderr, "bad opcode 0x%04x\n", word); exit(2);
        }
    }
    return stack[0];
}

/* evaluate(node, regs) -> matching edge index, or -1 (the priority encoder) */
static int evaluate(const Image *im, uint16_t node, const Reg *regs) {
    const Node *node_entry = &im->nodes[node];
    for (int edge_index = 0; edge_index < node_entry->edge_cnt; edge_index++)
        if (eval_prog(im, &im->edges[node_entry->edge_off + edge_index], regs)) return edge_index;
    return -1;
}

/* ------------------------------------------------------------------ modes */

static int mode_eval(const Image *im, const char *regs_path) {
    long len; uint8_t *bytes = read_file(regs_path, &len);
    if (len != 4 + 8L * im->n_fields) { fprintf(stderr, "bad regs size\n"); exit(2); }
    uint16_t node = (uint16_t)rd32(bytes);
    if (node >= im->n_nodes) { fprintf(stderr, "bad node\n"); exit(2); }
    Reg *regs = malloc(sizeof(Reg) * (im->n_fields ? im->n_fields : 1));
    for (int field_index = 0; field_index < im->n_fields; field_index++) {
        regs[field_index].ty = rd32(bytes + 4 + 8 * field_index); regs[field_index].val = rd32(bytes + 8 + 8 * field_index);
    }
    int matched_edge = evaluate(im, node, regs);
    if (matched_edge < 0) puts("none");
    else printf("match %d %u\n", matched_edge, im->edges[im->nodes[node].edge_off + matched_edge].target);
    return 0;
}

static int mode_run(const Image *im, const char *script_path) {
    long len; uint8_t *bytes = read_file(script_path, &len);
    if (len < 4 || rd32(bytes) != (int32_t)im->n_nodes) { fprintf(stderr, "bad script\n"); exit(2); }
    const uint8_t *cursor = bytes + 4;
    uint32_t *cnt = malloc(sizeof(uint32_t) * im->n_nodes);
    const uint8_t **rows = malloc(sizeof(uint8_t *) * im->n_nodes);
    for (int entry_index = 0; entry_index < im->n_nodes; entry_index++) {
        if (cursor + 4 > bytes + len) { fprintf(stderr, "truncated script\n"); exit(2); }
        cnt[entry_index] = (uint32_t)rd32(cursor); cursor += 4;
        rows[entry_index] = cursor; cursor += 8L * im->n_fields * cnt[entry_index];
        if (cursor > bytes + len) { fprintf(stderr, "truncated script\n"); exit(2); }
    }
    Reg *regs = malloc(sizeof(Reg) * (im->n_fields ? im->n_fields : 1));
    uint32_t *visits = calloc(im->n_nodes, sizeof(uint32_t));
    uint16_t node = im->start;
    printf("N %u\n", node);
    for (int step = 0; step < im->max_steps; step++) {
        if (im->nodes[node].edge_cnt == 0) { puts("S terminal"); return 0; }
        visits[node]++;                              /* engine: increment before the worker */
        if (cnt[node] == 0) { fprintf(stderr, "no outcome for node %u\n", node); exit(2); }
        uint32_t outcome_index = visits[node] - 1;
        if (outcome_index >= cnt[node]) outcome_index = cnt[node] - 1;       /* vectors: last outcome repeats */
        const uint8_t *row = rows[node] + 8L * im->n_fields * outcome_index;
        for (int entry_index = 0; entry_index < im->n_fields; entry_index++) {
            regs[entry_index].ty = rd32(row + 8 * entry_index); regs[entry_index].val = rd32(row + 8 * entry_index + 4);
        }
        if (im->visits_idx != VISITS_NONE) {         /* ctx = {**fields, "visits": n} */
            regs[im->visits_idx].ty = TY_INT;
            regs[im->visits_idx].val = (int32_t)visits[node];
        }
        int matched_edge = evaluate(im, node, regs);
        if (matched_edge < 0) { puts("S stuck"); return 0; }
        node = im->edges[im->nodes[node].edge_off + matched_edge].target;
        printf("N %u\n", node);
    }
    puts("S max_steps");
    return 0;
}

/* ------------------------------------------------------------------ embeddable API
 * The same certified core, callable from C or C++ (interp.h wraps these in extern "C").
 * Nothing above this line changes: the API is a thin handle over load_image/evaluate,
 * so the CLI and an embedding application run the identical certified code paths.
 * Compile with -DPPT_INTERP_NO_MAIN to omit the CLI entry point when embedding.
 * Contract notes: a malformed/truncated image exits(2) exactly as the CLI does
 * (signature and envelope verification run UPSTREAM of this file, in the pack
 * loader); ppt_reg is layout-identical to the internal register cell. */

struct ppt_image { Image im; };

_Static_assert(sizeof(ppt_reg) == sizeof(Reg), "ppt_reg must match the internal register cell");

ppt_image *ppt_image_open(const char *path) {
    ppt_image *handle = malloc(sizeof *handle);
    if (!handle) { fprintf(stderr, "out of memory\n"); exit(2); }
    load_image(path, &handle->im);
    return handle;
}

void ppt_image_close(ppt_image *handle) {
    if (!handle) return;
    free(handle->im.atoms); free(handle->im.nodes); free(handle->im.edges); free(handle->im.prog); free(handle);
}

uint16_t ppt_image_start(const ppt_image *handle)    { return handle->im.start; }
uint16_t ppt_image_n_fields(const ppt_image *handle) { return handle->im.n_fields; }
uint16_t ppt_image_n_nodes(const ppt_image *handle)  { return handle->im.n_nodes; }

int ppt_evaluate_node(const ppt_image *handle, uint16_t node, const ppt_reg *regs,
                      uint16_t *out_target) {
    if (node >= handle->im.n_nodes) return PPT_EVAL_BAD_NODE;
    int matched_edge = evaluate(&handle->im, node, (const Reg *)regs);
    if (matched_edge >= 0 && out_target)
        *out_target = handle->im.edges[handle->im.nodes[node].edge_off + matched_edge].target;
    return matched_edge;
}

#ifndef PPT_INTERP_NO_MAIN
int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "eval") && strcmp(argv[1], "run"))) {
        fprintf(stderr, "usage: interp eval|run image.ppt input.bin\n");
        return 2;
    }
    Image im;
    load_image(argv[2], &im);
    return strcmp(argv[1], "eval") == 0 ? mode_eval(&im, argv[3]) : mode_run(&im, argv[3]);
}
#endif
