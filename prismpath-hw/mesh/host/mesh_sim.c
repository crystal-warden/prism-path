/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* mesh_sim.c: the mesh firmware's logic (../main/mesh_node.c) on the host, with no ESP-IDF. Up to three nodes,
 * each with two in-memory NVS media and its own uptime, share an in-memory ESP-NOW radio: a frame one node sends
 * reaches every other node that is up, and the host's radio reaches them all. The nodes are built from the same
 * sources the board builds, and prismpath/tests/test_mesh_firmware.py drives them with frames from
 * prismpath/distribution/frames.py.
 *
 *   mesh_sim < script
 *
 *   key <public hex>                       an authority key of the anchor every node is built with
 *   controller <public hex>                its controller key (K6), and
 *   fresh <seconds>                        its `fresh` (H16)
 *   stream <name>                          the stream it follows
 *   ikey | iop <public hex>                an install or an operator key of its install member, and
 *   install <threshold> <seq> <domain hex> <fingerprint hex>   that member (section 21)
 *   domain <hex>                           the domain hash the build carries (P4, CL4)
 *   layout <hex>                           the layout the build carries (AF10), and each of its fields:
 *   field <register> <role> <min> <max> <stale>
 *   node <i> <hold 0|1> <seed hex>         node i's build setting (X6) and the random seed it draws on a first boot
 *   boot <i> <ms>                          power node i on at the shared time, in milliseconds
 *   reset <i> <ms>                         its RAM is lost and it boots again (the EN line)
 *   off <i>                                power off: it hears nothing until a boot
 *   erase <i> <medium 0|1|2>               its store forgets one medium, or both (2)
 *   corrupt <i> <medium> <part>            one byte of a part's blob on a medium changed (the index of its PP_PART_*
 *                                          bit), which NVS finds by its CRC, so the blob no longer reads
 *   radio <frame hex> <ms>                 the host's radio sends a frame that every node that is up hears
 *   serial <i> <frame hex> <ms>            a frame on node i's serial line only
 *   tick <ms>                              every node that is up ticks (X1, B8)
 *   beat <i> <ms>                          a beat record
 *   ask <i> <ms> <regs hex> <ages, comma separated, - for none, or ->
 *   status <i> <ms>
 *   nvs <i>                                the bytes node i's store holds on each medium, and its largest blob
 *   bounds                                 each durable part packed at the largest the core allows
 *   sync                                   prints "sync", the end of a batch
 *   done
 *
 * prints, as each happens: "rec <i> <record hex>" for each state record node i signs, "heard <i> <n>" once per
 * step for the state frames node i heard from the others, "drop <i> <transfer> <cause>", "ask <i> <outcome>
 * <cause> <basis> <held mark>", "status <i> <state> <held> <active seq> <epoch> <instance key hex>",
 * "nvs <i> <main bytes> <copy bytes> <largest>", "bounds <part> <bytes>", "stopped <i>". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_node.h"

#define NODES 3
#define BLOBS 24
#define BLOB_MAX PP_PART_PACKED_MAX

typedef struct {
    char name[16];
    size_t len;
    int damaged; /* a byte changed since it was written, which NVS finds by the CRC32 of each entry */
    uint8_t data[BLOB_MAX];
} blob;

typedef struct {
    blob blobs[BLOBS];
    size_t n;
} medium;

typedef struct {
    int defined, up, hold;
    uint8_t seed[32];
    int64_t boot_ms;
    medium media[2];
    int heard;
    mesh_build build;
    mesh_node node;
    pp_pep_machine pep;
    pp_assembler assembler;
    uint8_t packed[PP_PART_PACKED_MAX];
} sim_node;

static sim_node nodes[NODES];
static mesh_anchor anchor;
static pp_install_anchor install;
static pp_layout layout;
static uint8_t domain[32];
static int has_domain, has_layout;
static char stream[PP_STREAM_MAX + 1] = "mesh/demo";
static int64_t now_ms;

static size_t unhex(const char *text, uint8_t *out, size_t room) {
    size_t n = strlen(text);
    if (strcmp(text, "-") == 0) return 0;
    if (n % 2 || n / 2 > room) {
        fprintf(stderr, "mesh_sim: hex of %zu digits does not fit %zu bytes\n", n, room);
        exit(2);
    }
    for (size_t k = 0; k < n / 2; k++) {
        unsigned v;
        if (sscanf(text + 2 * k, "%2x", &v) != 1) exit(2);
        out[k] = (uint8_t)v;
    }
    return n / 2;
}

static void hash32(const char *text, uint8_t out[32]) {
    if (unhex(text, out, 32) != 32) exit(2);
}

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t k = 0; k < len; k++) printf("%02x", data[k]);
}

static blob *find(medium *m, const char *name) {
    for (size_t k = 0; k < m->n; k++)
        if (strcmp(m->blobs[k].name, name) == 0) return &m->blobs[k];
    return NULL;
}

static int store_get(void *context, int which, const char *name, uint8_t *out, size_t *len) {
    sim_node *s = context;
    blob *b = find(&s->media[which], name);
    if (b == NULL) return 1;
    if (b->len > *len || b->damaged) return -1; /* nvs_get_blob fails on a CRC that does not match */
    memcpy(out, b->data, b->len);
    *len = b->len;
    return 0;
}

static int store_set(void *context, int which, const char *name, const uint8_t *data, size_t len) {
    sim_node *s = context;
    medium *m = &s->media[which];
    blob *b = find(m, name);
    if (b == NULL) {
        if (m->n == BLOBS || len > BLOB_MAX) return -1;
        b = &m->blobs[m->n++];
        snprintf(b->name, sizeof b->name, "%s", name);
    }
    memcpy(b->data, data, len);
    b->len = len;
    b->damaged = 0;
    return 0;
}

static int store_commit(void *context, int which) {
    (void)context;
    (void)which;
    return 0;
}

static int sim_index(const sim_node *s) { return (int)(s - nodes); }

static void deliver(int from, const uint8_t *frame, size_t len);

static void on_radio(void *context, const uint8_t *frame, size_t len) {
    deliver(sim_index(context), frame, len);
}

static void on_record(void *context, const uint8_t *record, size_t len) {
    printf("rec %d ", sim_index(context));
    print_hex(record, len);
    printf("\n");
}

static void on_dropped(void *context, unsigned transfer, unsigned cause) {
    printf("drop %d %u %u\n", sim_index(context), transfer, cause);
}

static int64_t uptime_us(const sim_node *s) { return (now_ms - s->boot_ms) * 1000; }

/* A frame a node sent reaches every other node that is up. A node sends only state frames, which the others
 * count and pass to their core like any frame. */
static void deliver(int from, const uint8_t *frame, size_t len) {
    for (int k = 0; k < NODES; k++) {
        if (k == from || !nodes[k].up) continue;
        nodes[k].heard += frame[0] == PP_FRAME_STATE;
        mesh_node_frame(&nodes[k].node, frame, len, uptime_us(&nodes[k]));
    }
}

static void boot(int i) {
    sim_node *s = &nodes[i];
    mesh_store store = {store_get, store_set, store_commit, s};
    mesh_io io = {on_radio, on_record, on_dropped, s};
    s->build.anchor = &anchor;
    s->build.expiry_hold = s->hold;
    s->build.layout = has_layout ? &layout : NULL;
    s->build.has_domain = has_domain;
    memcpy(s->build.domain_sha256, domain, 32);
    anchor.stream = stream;
    anchor.install = install.present ? &install : NULL;
    s->boot_ms = now_ms;
    s->up = 1;
    if (mesh_node_open(&s->node, &s->pep, &s->assembler, s->packed, &s->build, &store, &io, s->seed, 0) != 0)
        printf("stopped %d\n", i);
}

static void report_heard(void) {
    for (int k = 0; k < NODES; k++)
        if (nodes[k].heard) {
            printf("heard %d %d\n", k, nodes[k].heard);
            nodes[k].heard = 0;
        }
}

/* Each part packed with every count at the bound pp_dist.h gives it, as the most NVS must hold of it. */
static void bounds(void) {
    static pp_durable d;
    static uint8_t out[PP_PART_PACKED_MAX];
    memset(&d, 0, sizeof d);
    d.provisioned = 1;
    d.n_legacy = PP_LEGACY_STREAMS;
    d.trust.n_keys = PP_MAX_HELD_KEYS;
    d.trust.n_retired = PP_MAX_RETIRED;
    d.trust.n_revoked_keys = d.trust.n_revoked_envelopes = d.trust.n_revoked_policies = PP_MAX_LIST;
    d.trust.n_floors = PP_MAX_FLOORS;
    d.n_floor_ids = PP_MAX_FLOOR_IDS;
    pp_release *releases[3] = {&d.active, &d.previous, &d.staged};
    d.has_active = d.has_previous = d.has_staged = d.has_pending = 1;
    for (int r = 0; r < 3; r++) {
        releases[r]->n = 2;
        releases[r]->held[0].envelope.artifact = PP_ART_POLICY_PPT;
        releases[r]->held[0].sealed_len = releases[r]->held[1].sealed_len = PP_MAX_SEALED;
        releases[r]->held[0].body_len = PP_RELEASE_BODY_MAX;
        releases[r]->held[1].envelope.artifact = PP_ART_TRUST_WIDENING;
        releases[r]->held[1].body_len = PP_WIDENING_MAX;
    }
    d.has_install = 1;
    d.install.n_keys = PP_INSTALL_KEYS;
    d.install.threshold = 1;
    d.install.n_operators = PP_OPERATOR_KEYS;
    d.install.n_retired = PP_INSTALL_RETIRED;
    d.has_kept = 1;
    for (int k = 0; k < PP_SETS; k++) { /* a set held and one staged, each at the bounds of a statement */
        d.sets[k].has_held = d.sets[k].has_staged = 1;
        d.sets[k].held.sealed_len = d.sets[k].staged.sealed_len = PP_MAX_SEALED;
        d.sets[k].held.body_len = d.sets[k].staged.body_len = PP_INSTALL_BODY_MAX;
    }
    for (int part = 1; part <= PP_PARTS; part <<= 1) printf("bounds %d %zu\n", part, pp_durable_pack(&d, part, out, sizeof out));
}

int main(void) {
    static char line[2 * (PP_FRAME_LIMIT + 64) + 1024];
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        char word[32], a[2 * PP_FRAME_LIMIT + 256], b[1024];
        int skip = 0, i = 0;
        long long ms = 0;
        if (sscanf(line, "%31s %n", word, &skip) < 1) continue;
        const char *rest = line + skip;
        if (strcmp(word, "done") == 0) break;
        if (strcmp(word, "sync") == 0) { /* the end of a batch, for a driver that reads as it writes */
            printf("sync\n");
            fflush(stdout);
            continue;
        }
        if (strcmp(word, "key") == 0 && anchor.n_authorities < MESH_AUTHORITY_KEYS) {
            hash32(rest, anchor.authorities[anchor.n_authorities++]);
        } else if (strcmp(word, "controller") == 0) {
            hash32(rest, anchor.controller);
            anchor.has_controller = 1;
        } else if (strcmp(word, "fresh") == 0) {
            anchor.fresh = strtoll(rest, NULL, 10);
        } else if (strcmp(word, "stream") == 0) {
            snprintf(stream, sizeof stream, "%s", rest);
        } else if (strcmp(word, "ikey") == 0 && install.n_keys < PP_INSTALL_KEYS) {
            hash32(rest, install.keys[install.n_keys++]);
        } else if (strcmp(word, "iop") == 0 && install.n_operators < PP_OPERATOR_KEYS) {
            hash32(rest, install.operators[install.n_operators++]);
        } else if (strcmp(word, "install") == 0) {
            if (sscanf(rest, "%lld %lld %255s %255s", &install.threshold, &install.seq, a, b) != 4) return 2;
            hash32(a, install.domain);
            hash32(b, install.fingerprint);
            install.present = 1;
        } else if (strcmp(word, "domain") == 0) {
            hash32(rest, domain);
            has_domain = 1;
        } else if (strcmp(word, "layout") == 0) {
            hash32(rest, layout.sha256);
            has_layout = 1;
        } else if (strcmp(word, "field") == 0 && layout.n < PP_LAYOUT_FIELDS) {
            pp_layout_field *f = &layout.fields[layout.n++];
            unsigned reg = 0, role = 0, stale = 0;
            int lo = 0, hi = 0;
            if (sscanf(rest, "%u %u %d %d %u", &reg, &role, &lo, &hi, &stale) != 5) return 2;
            f->reg = (uint16_t)reg;
            f->role = (uint8_t)role;
            f->min = lo;
            f->max = hi;
            f->stale = stale;
        } else if (strcmp(word, "node") == 0) {
            int hold = 0;
            if (sscanf(rest, "%d %d %255s", &i, &hold, a) != 3 || i < 0 || i >= NODES) return 2;
            nodes[i].defined = 1;
            nodes[i].hold = hold;
            hash32(a, nodes[i].seed);
        } else if (strcmp(word, "boot") == 0 || strcmp(word, "reset") == 0) {
            if (sscanf(rest, "%d %lld", &i, &ms) != 2 || i < 0 || i >= NODES || !nodes[i].defined) return 2;
            now_ms = ms;
            boot(i);
        } else if (strcmp(word, "off") == 0) {
            i = atoi(rest);
            if (i < 0 || i >= NODES) return 2;
            nodes[i].up = 0;
        } else if (strcmp(word, "erase") == 0) {
            int which = 0;
            if (sscanf(rest, "%d %d", &i, &which) != 2 || i < 0 || i >= NODES) return 2;
            for (int m = 0; m < 2; m++)
                if (which == 2 || which == m) nodes[i].media[m].n = 0;
        } else if (strcmp(word, "corrupt") == 0) {
            int which = 0, part = 0;
            if (sscanf(rest, "%d %d %d", &i, &which, &part) != 3 || i < 0 || i >= NODES || which < 0 || which > 1) return 2;
            char name[8];
            snprintf(name, sizeof name, "d%d", part);
            blob *bl = find(&nodes[i].media[which], name);
            if (bl == NULL || bl->len == 0) return 2;
            bl->data[bl->len - 1] ^= 0x01;
            bl->damaged = 1;
        } else if (strcmp(word, "radio") == 0) {
            static uint8_t frame[PP_FRAME_LIMIT + 64];
            if (sscanf(rest, "%s %lld", a, &ms) != 2) return 2;
            now_ms = ms;
            size_t n = unhex(a, frame, sizeof frame);
            deliver(-1, frame, n);
        } else if (strcmp(word, "serial") == 0) {
            static uint8_t frame[PP_FRAME_LIMIT + 64];
            if (sscanf(rest, "%d %s %lld", &i, a, &ms) != 3 || i < 0 || i >= NODES || !nodes[i].up) return 2;
            now_ms = ms;
            size_t n = unhex(a, frame, sizeof frame);
            mesh_node_frame(&nodes[i].node, frame, n, uptime_us(&nodes[i]));
        } else if (strcmp(word, "tick") == 0) {
            now_ms = strtoll(rest, NULL, 10);
            for (int k = 0; k < NODES; k++)
                if (nodes[k].up) mesh_node_tick(&nodes[k].node, uptime_us(&nodes[k]), 0);
        } else if (strcmp(word, "beat") == 0) {
            if (sscanf(rest, "%d %lld", &i, &ms) != 2 || i < 0 || i >= NODES || !nodes[i].up) return 2;
            now_ms = ms;
            mesh_node_beat(&nodes[i].node, uptime_us(&nodes[i]));
        } else if (strcmp(word, "ask") == 0) {
            static uint8_t regs[4 + 8 * 64];
            static uint32_t ages[64];
            if (sscanf(rest, "%d %lld %s %1023s", &i, &ms, a, b) != 4 || i < 0 || i >= NODES || !nodes[i].up) return 2;
            now_ms = ms;
            size_t n = unhex(a, regs, sizeof regs), n_ages = 0;
            const uint32_t *given = NULL;
            if (strcmp(b, "-") != 0) {
                for (char *tok = strtok(b, ","); tok && n_ages < 64; tok = strtok(NULL, ","))
                    ages[n_ages++] = strcmp(tok, "-") == 0 ? PP_AGE_NONE : (uint32_t)strtoul(tok, NULL, 10);
                for (size_t k = n_ages; k < 64; k++) ages[k] = PP_AGE_NONE;
                given = ages;
            }
            pp_decision d;
            mesh_node_ask(&nodes[i].node, regs, n, given, uptime_us(&nodes[i]), &d);
            printf("ask %d %u %u %u %d\n", i, d.outcome, d.cause, d.basis, d.held_mark);
        } else if (strcmp(word, "status") == 0) {
            if (sscanf(rest, "%d %lld", &i, &ms) != 2 || i < 0 || i >= NODES || !nodes[i].up) return 2;
            now_ms = ms;
            sim_node *s = &nodes[i];
            printf("status %d %s %d %lld %llu ", i, mesh_node_state(&s->node), s->pep.held,
                   s->pep.d.has_active ? s->pep.d.active.seq : 0LL, (unsigned long long)s->pep.epoch);
            print_hex(s->pep.instance_public, 32);
            printf("\n");
        } else if (strcmp(word, "nvs") == 0) {
            i = atoi(rest);
            if (i < 0 || i >= NODES) return 2;
            size_t bytes[2] = {0, 0}, largest = 0;
            for (int m = 0; m < 2; m++)
                for (size_t k = 0; k < nodes[i].media[m].n; k++) {
                    bytes[m] += nodes[i].media[m].blobs[k].len;
                    if (nodes[i].media[m].blobs[k].len > largest) largest = nodes[i].media[m].blobs[k].len;
                }
            printf("nvs %d %zu %zu %zu\n", i, bytes[0], bytes[1], largest);
        } else if (strcmp(word, "bounds") == 0) {
            bounds();
        } else {
            fprintf(stderr, "mesh_sim: unknown line %s\n", word);
            return 2;
        }
        report_heard();
        fflush(stdout);
    }
    return 0;
}
