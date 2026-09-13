// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* interp_hdr.c: the embedded evaluator (ppt_eval.h) driven on the host with interp.c's command
 * line, so run_vectors.py certifies the header every firmware includes against the same frozen
 * corpus as the reference. Same output, same exit codes.
 *
 *   interp_hdr eval image.ppt regs.bin    "match <edge> <target>" | "none"
 *   interp_hdr run  image.ppt script.bin  "N <node>" per path entry, then "S <stopped>"        */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ppt_eval.h"

static uint8_t *read_file(const char *path, long *out_len) {
    FILE *stream = fopen(path, "rb");
    if (!stream) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    fseek(stream, 0, SEEK_END); long length = ftell(stream); fseek(stream, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)(length ? length : 1));
    if (!buf || fread(buf, 1, (size_t)length, stream) != (size_t)length) { fprintf(stderr, "cannot read %s\n", path); exit(2); }
    fclose(stream); *out_len = length; return buf;
}

static void load_image(const char *path) {
    long len; uint8_t *bytes = read_file(path, &len);
    if (len > TBL_MAX) { fprintf(stderr, "image %s exceeds TBL_MAX\n", path); exit(2); }
    memcpy(tbl, bytes, (size_t)len); free(bytes);
    uint8_t rc = parse_table((uint16_t)len);
    if (rc) { fprintf(stderr, "bad image %s rc=%u\n", path, rc); exit(2); }
}

static int mode_eval(const char *regs_path) {
    long len; uint8_t *bytes = read_file(regs_path, &len);
    if (len != 4 + 8L * n_fields) { fprintf(stderr, "bad regs size\n"); exit(2); }
    memcpy(regs, bytes, (size_t)len); free(bytes);
    uint16_t node = (uint16_t)rd32(regs);
    if (node >= n_nodes) { fprintf(stderr, "bad node\n"); exit(2); }
    uint16_t target = 0; uint8_t err = 0;
    int8_t matched_edge = evaluate(node, &target, &err);
    if (err) { fprintf(stderr, "eval error %u\n", err); exit(2); }
    if (matched_edge < 0) puts("none"); else printf("match %d %u\n", matched_edge, target);
    return 0;
}

static int mode_run(const char *script_path) {
    long len; uint8_t *bytes = read_file(script_path, &len);
    if (len < 4 || rd32(bytes) != (int32_t)n_nodes) { fprintf(stderr, "bad script\n"); exit(2); }
    const uint8_t *cursor = bytes + 4;
    uint32_t *cnt = malloc(sizeof(uint32_t) * n_nodes);
    const uint8_t **rows = malloc(sizeof(uint8_t *) * n_nodes);
    for (int entry_index = 0; entry_index < n_nodes; entry_index++) {
        if (cursor + 4 > bytes + len) { fprintf(stderr, "truncated script\n"); exit(2); }
        cnt[entry_index] = (uint32_t)rd32(cursor); cursor += 4;
        rows[entry_index] = cursor; cursor += 8L * n_fields * cnt[entry_index];
        if (cursor > bytes + len) { fprintf(stderr, "truncated script\n"); exit(2); }
    }
    uint32_t *visits = calloc(n_nodes, sizeof(uint32_t));
    uint16_t node = start_node;
    printf("N %u\n", node);
    for (int step = 0; step < max_steps; step++) {
        if (node_edge_count(node) == 0) { puts("S terminal"); return 0; }
        visits[node]++;                                  /* engine: increment before the worker */
        if (cnt[node] == 0) { fprintf(stderr, "no outcome for node %u\n", node); exit(2); }
        uint32_t outcome_index = visits[node] - 1;
        if (outcome_index >= cnt[node]) outcome_index = cnt[node] - 1;           /* vectors: last outcome repeats */
        const uint8_t *row = rows[node] + 8L * n_fields * outcome_index;
        for (int entry_index = 0; entry_index < n_fields; entry_index++)
            set_reg_typed((uint16_t)entry_index, rd32(row + 8 * entry_index), rd32(row + 8 * entry_index + 4));
        if (visits_idx != PPT_VISITS_NONE) set_reg_typed(visits_idx, TY_INT, (int32_t)visits[node]);
        uint16_t target = 0; uint8_t err = 0;
        int8_t matched_edge = evaluate(node, &target, &err);
        if (err) { fprintf(stderr, "eval error %u\n", err); exit(2); }
        if (matched_edge < 0) { puts("S stuck"); return 0; }
        node = target;
        printf("N %u\n", node);
    }
    puts("S max_steps");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: interp_hdr eval|run image.ppt payload.bin\n"); return 2; }
    load_image(argv[2]);
    if (strcmp(argv[1], "eval") == 0) return mode_eval(argv[3]);
    if (strcmp(argv[1], "run") == 0) return mode_run(argv[3]);
    fprintf(stderr, "unknown mode %s\n", argv[1]); return 2;
}
