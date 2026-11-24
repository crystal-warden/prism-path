/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* mesh_node.h: the logic of one ESP-NOW mesh node as a policy distribution enforcement point of kind `mesh`
 * (docs/design/spec-policy-distribution.md), with no ESP-IDF in it. ppt_mesh.c wires it to the board (NVS,
 * ESP-NOW, UART0, esp_timer), and prismpath-hw/mesh/host/mesh_sim.c runs the same file on the host with an
 * in-memory store and an in-memory radio, so what the board runs is what the host tests.
 *
 * The C core in prismpath-hw/dist/ decides everything: the frame reassembly (B6, B7, B9), the verifier (V2 to
 * V11), stage, commit and abort, revocation, rotation, the controller key and statement (K6, K7, H9, H16),
 * expiry, the action floor (section 21) and every decision (pp_pep_ask). This file keeps the durable parts in a
 * store, each under its own name, the parts IS10 names on two media, turns frames into calls of the core, and
 * sends each state record the core signs as a frame of type 3.
 *
 * Nothing here allocates. The caller gives the node its three large blocks (the machine, the assembler and the
 * packing buffer), which the board allocates once at boot and the host holds statically. */
#ifndef MESH_NODE_H
#define MESH_NODE_H

#include <stddef.h>
#include <stdint.h>

#include "pp_dist.h"

#define MESH_MEDIUM_MAIN 0 /* the NVS partition `nvs` */
#define MESH_MEDIUM_COPY 1 /* the NVS partition `nvs_copy`, the second medium of IS10 */

/* The store: a blob under a name on one medium. get answers 0 and the length, 1 for none under that name, or -1
 * when the medium does not read. set and commit answer 0, or -1 when the write did not take. */
typedef struct {
    int (*get)(void *context, int medium, const char *name, uint8_t *out, size_t *len);
    int (*set)(void *context, int medium, const char *name, const uint8_t *data, size_t len);
    int (*commit)(void *context, int medium);
    void *context;
} mesh_store;

/* What the node sends: a frame on the radio, and a line for the serial report. */
typedef struct {
    void (*radio)(void *context, const uint8_t *frame, size_t len);
    void (*record)(void *context, const uint8_t *record, size_t len);        /* each state record, oldest first */
    void (*dropped)(void *context, unsigned transfer, unsigned cause);       /* a transfer the assembler dropped */
    void *context;
} mesh_io;

/* The trust anchor baked into the build (P2, P4): the authority keys, the controller key, `fresh`, the stream, and
 * the install member when the engineer gives the node install keys (section 21). */
#define MESH_AUTHORITY_KEYS 4
typedef struct {
    size_t n_authorities;
    uint8_t authorities[MESH_AUTHORITY_KEYS][32];
    int has_controller;
    uint8_t controller[32];
    long long fresh;
    const char *stream;
    const pp_install_anchor *install; /* NULL for none */
} mesh_anchor;

/* The build: the anchor, the expiry response (X6, X10), the layout (AF10) and the domain (P4, CL4) it was built
 * with. A node has no real time clock (T2). */
typedef struct {
    const mesh_anchor *anchor;
    int expiry_hold;
    const pp_layout *layout;
    int has_domain;
    uint8_t domain_sha256[32];
} mesh_build;

typedef struct {
    pp_pep_machine *pep;    /* the caller's blocks */
    pp_assembler *assembler;
    uint8_t *packed;        /* PP_PART_PACKED_MAX bytes */
    mesh_store store;
    mesh_io io;
    const mesh_build *build;
    pp_config config;
    long long base_time, base_uptime;  /* T2: the time counts on from the latest time floor */
    int admit_refused;      /* the last drop was the verifier's refusal of the sealed part */
    int stopped;            /* the node refused to start (X10, K2) or its anchor was refused (P2) */
    uint16_t sent;          /* the transfer field of the state frames it sends */
    size_t bytes_written;   /* the bytes the durable writes took, and the writes that did not take */
    unsigned write_failures;
} mesh_node;

/* Open the node at boot: read its instance key seed from the store or take `new_seed`, the random bytes the
 * board drew, read every durable part, open the core from them, and provision from the anchor on a first boot.
 * Answers 0, or -1 when the node refuses to start (`stopped`). */
int mesh_node_open(mesh_node *node, pp_pep_machine *pep, pp_assembler *assembler, uint8_t *packed,
                   const mesh_build *build, const mesh_store *store, const mesh_io *io, const uint8_t new_seed[32],
                   int64_t uptime_us);

/* T2: the node's time in Unix seconds, its time floor plus the seconds it has run since that floor was set. */
long long mesh_node_time(mesh_node *node, int64_t uptime_us);

/* One frame from the radio or the serial line. */
void mesh_node_frame(mesh_node *node, const uint8_t *frame, size_t len, int64_t uptime_us);

/* X1 and B8 at least once a minute, and T2's saved time at least once an hour (`save`). */
void mesh_node_tick(mesh_node *node, int64_t uptime_us, int save);

/* A beat record (H1). */
void mesh_node_beat(mesh_node *node, int64_t uptime_us);

/* One decision under the core (pp_pep_ask): `regs` the register file, `ages` each register's age in seconds or
 * NULL. */
void mesh_node_ask(mesh_node *node, const uint8_t *regs, size_t regs_len, const uint32_t *ages, int64_t uptime_us,
                   pp_decision *out);

/* The node's state as the status line shows it. */
const char *mesh_node_state(const mesh_node *node);

#endif /* MESH_NODE_H */
