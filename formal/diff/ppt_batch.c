// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* ppt_batch.c: the table targets' leg of the verified core's differential harness (formal/diff/core_diff.py).
 *
 * An adapter, not an evaluator: it frames many cases through the certified C evaluators, so the harness
 * does not spawn one process per reading. Built two ways from this one file:
 *
 *   cc -O2 -std=c11 -I prismpath-hw -DPPT_BATCH_HDR -o ppt_batch_hdr ppt_batch.c
 *       the embedded evaluator every firmware includes (prismpath-hw/ppt_eval.h, the FPGA's C twin)
 *   cc -O2 -std=c11 -I prismpath-hw -DPPT_INTERP_NO_MAIN -o ppt_batch_interp ppt_batch.c prismpath-hw/interp.c
 *       the reference interpreter (prismpath-hw/interp.c) through its embeddable API (interp.h)
 *
 * Input on stdin: `case <id> <n>\n`, then the compiled .ppt image and n register files (the regs.bin
 * format of TABLE_FORMAT.md: the node, then a type and a value per field), each framed as
 * `<byte length>\n<bytes>\n`. A register frame of length 0 is a reading the host refused before the table
 * (unreadable, not an object, refused at the boundary, or a value outside the table's 32 bit registers).
 * Output, one line per case: the id, then per reading `m <edge> <target>`, `n` (no edge matched), `-` (no
 * register file) or `e <why>` (the evaluator could not evaluate), separated by `;`.
 *
 * The interpreter build writes each image to the path given as the only argument, since interp.c loads
 * images from files; it exits(2) on a malformed image or a stack overflow, so this driver checks the
 * image's declared stack depth against interp.c's STACK_MAX (64) first and reports `e stack` instead. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef PPT_BATCH_HDR
#include "ppt_eval.h"
#else
#include "interp.h"
#define INTERP_STACK_MAX 64
#endif

static uint8_t *input; static size_t input_len, pos;

static int read_line(char *out, size_t cap) {
    size_t start = pos;
    while (pos < input_len && input[pos] != '\n') pos++;
    if (pos >= input_len || pos - start >= cap) return 0;
    memcpy(out, input + start, pos - start); out[pos - start] = 0; pos++;
    return 1;
}

static const uint8_t *read_frame(size_t *len) {
    char line[64];
    if (!read_line(line, sizeof line)) { fprintf(stderr, "ppt_batch: truncated frame\n"); exit(3); }
    *len = (size_t)strtoul(line, NULL, 10);
    if (pos + *len + 1 > input_len) { fprintf(stderr, "ppt_batch: truncated frame body\n"); exit(3); }
    const uint8_t *frame = input + pos; pos += *len + 1;
    return frame;
}

static int32_t le32(const uint8_t *bytes) { int32_t value; memcpy(&value, bytes, 4); return value; }

int main(int argc, char **argv) {
#ifndef PPT_BATCH_HDR
    if (argc != 2) { fprintf(stderr, "usage: ppt_batch_interp IMAGE_SCRATCH_PATH < frames\n"); return 2; }
    const char *scratch = argv[1];
#else
    (void)argc; (void)argv;
#endif
    size_t cap = 1 << 20; input = malloc(cap);
    for (size_t got; (got = fread(input + input_len, 1, cap - input_len, stdin)) > 0;) {
        input_len += got;
        if (input_len == cap) { cap *= 2; input = realloc(input, cap); }
    }
    char header[256];
    while (pos < input_len) {
        if (!read_line(header, sizeof header)) { fprintf(stderr, "ppt_batch: bad header\n"); return 3; }
        char ident[200]; unsigned count;
        if (sscanf(header, "case %199s %u", ident, &count) != 2) { fprintf(stderr, "ppt_batch: bad header %s\n", header); return 3; }
        size_t image_len; const uint8_t *image = read_frame(&image_len);
        printf("%s", ident);
#ifdef PPT_BATCH_HDR
        uint8_t rc = 0;
        if (image_len > TBL_MAX) rc = PPT_PARSE_CAPS;
        else { memcpy(tbl, image, image_len); rc = parse_table((uint16_t)image_len); }
#else
        int stack_ok = image_len >= 28 && (uint16_t)(image[24] | (image[25] << 8)) <= INTERP_STACK_MAX;
        ppt_image *handle = NULL;
        if (stack_ok) {
            FILE *stream = fopen(scratch, "wb");
            if (!stream || fwrite(image, 1, image_len, stream) != image_len) { fprintf(stderr, "ppt_batch: cannot write %s\n", scratch); return 3; }
            fclose(stream);
            handle = ppt_image_open(scratch);
        }
#endif
        for (unsigned index = 0; index < count; index++) {
            size_t regs_len; const uint8_t *frame = read_frame(&regs_len);
            printf(index ? ";" : " ");
            if (regs_len == 0) { printf("-"); continue; }
#ifdef PPT_BATCH_HDR
            if (rc) { printf("e parse%u", rc); continue; }
            if (regs_len != 4 + 8u * n_fields || regs_len > REGS_MAX) { printf("e regs"); continue; }
            memcpy(regs, frame, regs_len);
            uint16_t node = (uint16_t)le32(regs), target = 0; uint8_t err = 0;
            if (node >= n_nodes) { printf("e node"); continue; }
            int8_t edge = evaluate(node, &target, &err);
            if (err) printf("e eval%u", err);
            else if (edge < 0) printf("n");
            else printf("m %d %u", edge, target);
#else
            if (!stack_ok) { printf("e stack"); continue; }
            uint16_t n_fields = ppt_image_n_fields(handle);
            if (regs_len != 4 + 8u * n_fields) { printf("e regs"); continue; }
            ppt_reg *cells = malloc(sizeof(ppt_reg) * (n_fields ? n_fields : 1));
            for (uint16_t field = 0; field < n_fields; field++) {
                cells[field].ty = le32(frame + 4 + 8 * field); cells[field].val = le32(frame + 8 + 8 * field);
            }
            uint16_t target = 0;
            int edge = ppt_evaluate_node(handle, (uint16_t)le32(frame), cells, &target);
            free(cells);
            if (edge == PPT_EVAL_BAD_NODE) printf("e node");
            else if (edge < 0) printf("n");
            else printf("m %d %u", edge, target);
#endif
        }
#ifndef PPT_BATCH_HDR
        if (handle) ppt_image_close(handle);
#endif
        printf("\n");
    }
    return 0;
}
