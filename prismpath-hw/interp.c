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

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static int32_t rd32(const uint8_t *p) {
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static uint8_t *read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)n);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "cannot read %s\n", path); exit(2);
    }
    fclose(f); *out_len = n; return buf;
}

static void load_image(const char *path, Image *im) {
    long len; uint8_t *b = read_file(path, &len);
    if (len < 28 || rd32(b) != (int32_t)MAGIC || rd16(b + 4) != 1) {
        fprintf(stderr, "bad image %s\n", path); exit(2);
    }
    im->n_fields = rd16(b + 6);  im->n_interns = rd16(b + 8);
    im->n_atoms = rd16(b + 10);  im->n_nodes = rd16(b + 12);
    im->n_edges = rd16(b + 14);  im->prog_len = rd16(b + 16);
    im->start = rd16(b + 18);    im->visits_idx = rd16(b + 20);
    im->max_steps = rd16(b + 22); im->max_stack = rd16(b + 24);
    long need = 28 + 8L * im->n_atoms + 4L * im->n_nodes + 6L * im->n_edges + 2L * im->prog_len;
    if (len < need) { fprintf(stderr, "truncated image %s\n", path); exit(2); }
    const uint8_t *p = b + 28;
    im->atoms = malloc(sizeof(Atom) * im->n_atoms);
    for (int i = 0; i < im->n_atoms; i++, p += 8) {
        im->atoms[i].field = rd16(p); im->atoms[i].op = p[2]; im->atoms[i].ty = p[3];
        im->atoms[i].val = rd32(p + 4);
    }
    im->nodes = malloc(sizeof(Node) * im->n_nodes);
    for (int i = 0; i < im->n_nodes; i++, p += 4) {
        im->nodes[i].edge_off = rd16(p); im->nodes[i].edge_cnt = rd16(p + 2);
    }
    im->edges = malloc(sizeof(Edge) * im->n_edges);
    for (int i = 0; i < im->n_edges; i++, p += 6) {
        im->edges[i].target = rd16(p); im->edges[i].prog_off = rd16(p + 2);
        im->edges[i].prog_cnt = rd16(p + 4);
    }
    im->prog = malloc(sizeof(uint16_t) * im->prog_len);
    for (int i = 0; i < im->prog_len; i++, p += 2) im->prog[i] = rd16(p);
    free(b);
}

/* ------------------------------------------------------------------ the evaluator core
 * This is the function the fabric implements: atoms are parallel comparators over the
 * field register file; each edge's program folds atom results; first-true edge wins. */

static int eval_atom(const Atom *a, const Reg *regs) {
    Reg r = regs[a->field];
    int lnum = (r.ty == TY_BOOL || r.ty == TY_INT);
    int rnum = (a->ty == TY_BOOL || a->ty == TY_INT);
    switch (a->op) {
    case OP_EQ: case OP_NE: {
        int eq;
        if (lnum && rnum)                        eq = (r.val == a->val);
        else if (r.ty == TY_STR && a->ty == TY_STR) eq = (r.val == a->val);
        else if (r.ty == TY_NONE && a->ty == TY_NONE) eq = 1;
        else                                     eq = 0;
        return a->op == OP_EQ ? eq : !eq;
    }
    case OP_LT: case OP_LE: case OP_GT: case OP_GE:
        if (!(lnum && rnum)) return 0;           /* totality: non-numeric -> unsatisfied */
        switch (a->op) {
        case OP_LT: return r.val <  a->val;
        case OP_LE: return r.val <= a->val;
        case OP_GT: return r.val >  a->val;
        default:    return r.val >= a->val;
        }
    case OP_TRUTHY:
        return r.ty == TY_NONE ? 0 : (r.val != 0);   /* BOOL value; INT!=0; STR id!=0 ("" is 0) */
    }
    return 0;
}

static int eval_prog(const Image *im, const Edge *e, const Reg *regs) {
    uint8_t stack[STACK_MAX]; int sp = 0;
    for (int i = 0; i < e->prog_cnt; i++) {
        uint16_t w = im->prog[e->prog_off + i];
        if (w < 0x8000) stack[sp++] = (uint8_t)eval_atom(&im->atoms[w], regs);
        else switch (w) {
        case OPC_NOT:   stack[sp - 1] = !stack[sp - 1]; break;
        case OPC_AND:   sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] && stack[sp]); break;
        case OPC_OR:    sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] || stack[sp]); break;
        case OPC_TRUE:  stack[sp++] = 1; break;
        case OPC_FALSE: stack[sp++] = 0; break;
        default: fprintf(stderr, "bad opcode 0x%04x\n", w); exit(2);
        }
        if (sp > STACK_MAX) { fprintf(stderr, "stack overflow\n"); exit(2); }
    }
    return stack[0];
}

/* evaluate(node, regs) -> matching edge index, or -1 (the priority encoder) */
static int evaluate(const Image *im, uint16_t node, const Reg *regs) {
    const Node *n = &im->nodes[node];
    for (int i = 0; i < n->edge_cnt; i++)
        if (eval_prog(im, &im->edges[n->edge_off + i], regs)) return i;
    return -1;
}

/* ------------------------------------------------------------------ modes */

static int mode_eval(const Image *im, const char *regs_path) {
    long len; uint8_t *b = read_file(regs_path, &len);
    if (len != 4 + 8L * im->n_fields) { fprintf(stderr, "bad regs size\n"); exit(2); }
    uint16_t node = (uint16_t)rd32(b);
    if (node >= im->n_nodes) { fprintf(stderr, "bad node\n"); exit(2); }
    Reg *regs = malloc(sizeof(Reg) * (im->n_fields ? im->n_fields : 1));
    for (int i = 0; i < im->n_fields; i++) {
        regs[i].ty = rd32(b + 4 + 8 * i); regs[i].val = rd32(b + 8 + 8 * i);
    }
    int e = evaluate(im, node, regs);
    if (e < 0) puts("none");
    else printf("match %d %u\n", e, im->edges[im->nodes[node].edge_off + e].target);
    return 0;
}

static int mode_run(const Image *im, const char *script_path) {
    long len; uint8_t *b = read_file(script_path, &len);
    if (len < 4 || rd32(b) != (int32_t)im->n_nodes) { fprintf(stderr, "bad script\n"); exit(2); }
    const uint8_t *p = b + 4;
    uint32_t *cnt = malloc(sizeof(uint32_t) * im->n_nodes);
    const uint8_t **rows = malloc(sizeof(uint8_t *) * im->n_nodes);
    for (int i = 0; i < im->n_nodes; i++) {
        if (p + 4 > b + len) { fprintf(stderr, "truncated script\n"); exit(2); }
        cnt[i] = (uint32_t)rd32(p); p += 4;
        rows[i] = p; p += 8L * im->n_fields * cnt[i];
        if (p > b + len) { fprintf(stderr, "truncated script\n"); exit(2); }
    }
    Reg *regs = malloc(sizeof(Reg) * (im->n_fields ? im->n_fields : 1));
    uint32_t *visits = calloc(im->n_nodes, sizeof(uint32_t));
    uint16_t node = im->start;
    printf("N %u\n", node);
    for (int step = 0; step < im->max_steps; step++) {
        if (im->nodes[node].edge_cnt == 0) { puts("S terminal"); return 0; }
        visits[node]++;                              /* engine: increment before the worker */
        if (cnt[node] == 0) { fprintf(stderr, "no outcome for node %u\n", node); exit(2); }
        uint32_t k = visits[node] - 1;
        if (k >= cnt[node]) k = cnt[node] - 1;       /* vectors: last outcome repeats */
        const uint8_t *row = rows[node] + 8L * im->n_fields * k;
        for (int i = 0; i < im->n_fields; i++) {
            regs[i].ty = rd32(row + 8 * i); regs[i].val = rd32(row + 8 * i + 4);
        }
        if (im->visits_idx != VISITS_NONE) {         /* ctx = {**fields, "visits": n} */
            regs[im->visits_idx].ty = TY_INT;
            regs[im->visits_idx].val = (int32_t)visits[node];
        }
        int e = evaluate(im, node, regs);
        if (e < 0) { puts("S stuck"); return 0; }
        node = im->edges[im->nodes[node].edge_off + e].target;
        printf("N %u\n", node);
    }
    puts("S max_steps");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "eval") && strcmp(argv[1], "run"))) {
        fprintf(stderr, "usage: interp eval|run image.ppt input.bin\n");
        return 2;
    }
    Image im;
    load_image(argv[2], &im);
    return strcmp(argv[1], "eval") == 0 ? mode_eval(&im, argv[3]) : mode_run(&im, argv[3]);
}
