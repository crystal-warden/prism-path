/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* mesh_node.c: one mesh node over the C core of policy distribution. See mesh_node.h. */
#include "mesh_node.h"

#include <string.h>

static uint32_t mesh_ms(int64_t uptime_us) { return (uint32_t)(uptime_us / 1000); }

long long mesh_node_time(mesh_node *node, int64_t uptime_us) {
    long long uptime = uptime_us / 1000000, floor = pp_pep_trust(node->pep)->time_floor;
    long long t = node->base_time + (uptime - node->base_uptime);
    if (floor > t) { /* T1: a raised time floor moves the count on */
        node->base_time = t = floor;
        node->base_uptime = uptime;
    }
    return t;
}

/* The NVS name of a part: "d" and the index of its bit, as "d0" to "d13". */
static void mesh_name(char name[8], int part) {
    unsigned index = 0;
    while (index < PP_PART_COUNT && (1 << index) != part) index++;
    name[0] = 'd';
    name[1] = (char)(index >= 10 ? '1' : '0' + index);
    name[2] = (char)(index >= 10 ? '0' + index % 10 : 0);
    name[3] = 0;
}

/* Each part the core says changed is packed and written whole under its own name (C4), and the anchor part and the
 * parts of section 21 to both media (IS9, IS10), so a state record writes its counter and no more. Answers 0, or -1
 * when a write or a commit did not take, so the core does not act on what it saved first (AF8, OP3). */
static int mesh_persist(void *context, const pp_durable *durable, int parts) {
    mesh_node *node = context;
    int touched[2] = {0, 0}, failed = 0;
    for (int part = 1; part <= PP_PARTS; part <<= 1) {
        if (!(parts & part)) continue;
        size_t n = pp_durable_pack(durable, part, node->packed, PP_PART_PACKED_MAX);
        char name[8];
        mesh_name(name, part);
        for (int medium = 0; medium < ((part & PP_PART_COPIED) ? 2 : 1); medium++) {
            if (n == 0 || node->store.set(node->store.context, medium, name, node->packed, n) != 0) {
                node->write_failures++;
                failed = 1;
            } else {
                node->bytes_written += n;
            }
            touched[medium] = 1;
        }
    }
    for (int medium = 0; medium < 2; medium++)
        if (touched[medium] && node->store.commit(node->store.context, medium) != 0) {
            node->write_failures++;
            failed = 1;
        }
    return failed ? -1 : 0;
}

/* Every part read back into the machine's durable state, a copied part from the first medium that holds one that
 * reads (IS10). A part no medium holds is absent. One a medium holds that does not read is lost (Q5, K1). An anchor
 * part no medium holds while another part is held is lost, so the node is locked and never provisioned again from
 * the anchor baked into the build over what it holds (P1, IS9, IS10). */
static void mesh_read_parts(mesh_node *node) {
    pp_durable *d = &node->pep->d;
    int parts_held = 0;
    memset(d, 0, sizeof *d);
    for (int part = 1; part <= PP_PARTS; part <<= 1) {
        char name[8];
        mesh_name(name, part);
        int held = 0, read = 0;
        for (int medium = 0; medium < ((part & PP_PART_COPIED) ? 2 : 1) && !read; medium++) {
            size_t n = PP_PART_PACKED_MAX;
            int got = node->store.get(node->store.context, medium, name, node->packed, &n);
            if (got == 1) continue;
            held = 1;
            if (got == 0) read = pp_durable_unpack(d, part, node->packed, n) == 0;
        }
        if (!held) pp_durable_unpack(d, part, NULL, 0);
        else if (!read) pp_durable_unpack(d, part, (const uint8_t *)"", 0); /* bytes that are not the part */
        if (held) parts_held |= part;
    }
    pp_durable_held(d, parts_held);
}

/* Each record the core made in the last call, to the serial report and as a frame of type 3 on the radio (H1). */
static void mesh_flush(mesh_node *node) {
    pp_pep_machine *pep = node->pep;
    for (size_t k = 0; k < pep->n_out; k++) {
        uint8_t frame[4 + PP_RECORD_MAX];
        size_t len = pep->out_len[k];
        frame[0] = PP_FRAME_STATE;
        frame[1] = 1;
        frame[2] = (uint8_t)node->sent;
        frame[3] = (uint8_t)(node->sent >> 8);
        node->sent++;
        memcpy(frame + 4, pep->out[k], len);
        if (node->io.record) node->io.record(node->io.context, pep->out[k], len);
        if (node->io.radio) node->io.radio(node->io.context, frame, 4 + len);
    }
    pep->n_out = 0;
}

/* frames.admit_through_v8: the sealed envelope verified with no body, V9's body mismatch the one refusal that means
 * it passed V2 to V8. */
static uint8_t mesh_admit(void *context, const uint8_t *sealed, size_t len, long long *body_size, uint8_t hash[32],
                          int *trust_bounded) {
    static pp_pep view;
    static pp_verdict verdict;
    mesh_node *node = context;
    pp_pep_view(node->pep, &view);
    pp_verify(sealed, len, (const uint8_t *)"", 0, pp_pep_trust(node->pep), &view, node->pep->now, &verdict);
    if (verdict.cause == 0 || (verdict.cause == PP_CAUSE_BODY_MISMATCH && verdict.envelope.body_size > 0)) {
        *body_size = verdict.envelope.body_size;
        memcpy(hash, verdict.envelope.body_sha256, 32);
        *trust_bounded = verdict.trust_bounded;
        return 0;
    }
    node->admit_refused = 1;
    return verdict.cause;
}

int mesh_node_open(mesh_node *node, pp_pep_machine *pep, pp_assembler *assembler, uint8_t *packed,
                   const mesh_build *build, const mesh_store *store, const mesh_io *io, const uint8_t new_seed[32],
                   int64_t uptime_us) {
    memset(node, 0, sizeof *node);
    node->pep = pep;
    node->assembler = assembler;
    node->packed = packed;
    node->build = build;
    node->store = *store;
    node->io = *io;
    pp_config *config = &node->config;
    config->kind = PP_TGT_MESH;
    config->expiry_hold = build->expiry_hold;
    config->has_clock = 0; /* T2 */
    config->layout = build->layout;
    config->has_domain = build->has_domain;
    memcpy(config->domain_sha256, build->domain_sha256, 32);
    config->persist = mesh_persist;
    config->context = node;
    size_t n = 32;
    if (store->get(store->context, MESH_MEDIUM_MAIN, "seed", config->instance_seed, &n) != 0 || n != 32) {
        memcpy(config->instance_seed, new_seed, 32); /* the instance key, made on the node and never sent (K2) */
        if (store->set(store->context, MESH_MEDIUM_MAIN, "seed", new_seed, 32) != 0 ||
            store->commit(store->context, MESH_MEDIUM_MAIN) != 0)
            node->write_failures++;
    }
    mesh_read_parts(node);
    int have = pep->d.provisioned;
    node->base_time = have && pep->d.trust_reads ? pep->d.trust.time_floor : 0;
    node->base_uptime = uptime_us / 1000000;
    if (pp_pep_open(pep, config, have ? &pep->d : NULL, node->base_time) != 0) {
        node->stopped = 1; /* X10, K2: the node does not start */
        return -1;
    }
    pp_assembler_init(assembler, mesh_admit, node, 0, PP_FRAME_LIMIT, PP_MESH_TABLE_MAX);
    if (!have) { /* P2: the anchor baked into the build */
        static pp_trust trust;
        const mesh_anchor *anchor = build->anchor;
        memset(&trust, 0, sizeof trust);
        trust.readable = 1;
        for (size_t k = 0; k < anchor->n_authorities && k < MESH_AUTHORITY_KEYS; k++) {
            memcpy(trust.keys[trust.n_keys].public_key, anchor->authorities[k], 32);
            pp_sha256(anchor->authorities[k], 32, trust.keys[trust.n_keys].id);
            trust.keys[trust.n_keys++].role = PP_ROLE_AUTHORITY;
        }
        if (anchor->has_controller) {
            memcpy(trust.keys[trust.n_keys].public_key, anchor->controller, 32);
            pp_sha256(anchor->controller, 32, trust.keys[trust.n_keys].id);
            trust.keys[trust.n_keys++].role = PP_ROLE_CONTROLLER;
        }
        trust.fresh = anchor->fresh;
        if (pp_pep_provision_install(pep, &trust, anchor->install, anchor->stream, NULL, 0, node->base_time)) {
            node->stopped = 1;
            return -1;
        }
    }
    mesh_flush(node);
    return 0;
}

/* Commit and abort name the release by 16 byte prefixes (section 8.3), so the node matches them to what it has
 * staged. A prefix that names nothing staged names a release the core does not hold. */
static void mesh_control(mesh_node *node, const uint8_t *frame, size_t len, int64_t uptime_us) {
    pp_pep_machine *pep = node->pep;
    const pp_durable *d = &pep->d;
    long long now = mesh_node_time(node, uptime_us);
    if (frame[0] == PP_FRAME_EPOCH) { /* H9, H16: no record, whatever the statement says */
        (void)pp_pep_take_statement(pep, frame + 4, len - 4, now);
        return;
    }
    if (frame[0] != PP_FRAME_COMMIT && frame[0] != PP_FRAME_ABORT) return; /* a state frame of another node */
    uint8_t stream_hash[32], policy[32];
    long long seq = 0;
    for (int k = 7; k >= 0; k--) seq = seq << 8 | frame[20 + k];
    pp_sha256((const uint8_t *)d->stream, strlen(d->stream), stream_hash);
    memset(policy, 0xFF, sizeof policy);
    if (d->has_staged && memcmp(d->staged.policy_sha256, frame + 28, 16) == 0) memcpy(policy, d->staged.policy_sha256, 32);
    const char *stream = memcmp(stream_hash, frame + 4, 16) == 0 ? d->stream : "";
    if (frame[0] == PP_FRAME_COMMIT)
        pp_pep_commit(pep, stream, seq, policy, (uint16_t)(frame[44] | frame[45] << 8), mesh_ms(uptime_us), now);
    else
        pp_pep_abort(pep, stream, seq, policy, now);
    mesh_flush(node);
}

void mesh_node_frame(mesh_node *node, const uint8_t *frame, size_t len, int64_t uptime_us) {
    if (node->stopped) return;
    pp_pep_machine *pep = node->pep;
    pp_assembler *a = node->assembler;
    uint8_t cause = 0;
    pep->now = mesh_node_time(node, uptime_us); /* the admit check verifies at the node's time */
    node->admit_refused = 0;
    int event = pp_assembler_receive(a, frame, len, mesh_ms(uptime_us), &cause);
    if (event == PP_ASM_WHOLE) {
        pp_pep_stage(pep, a->t.sealed, a->t.sealed_len, a->t.body, a->t.body_len, pep->now);
        mesh_flush(node);
    } else if (event == PP_ASM_DROPPED) {
        if (node->io.dropped) node->io.dropped(node->io.context, len >= 4 ? (unsigned)(frame[2] | frame[3] << 8) : 0u, cause);
        if (node->admit_refused) {
            /* G1: a sealed envelope the verifier refused before its body was read is refused in a signed state
               record like any other, from the sealed part alone, which the verifier refuses at the same rule */
            pp_pep_stage(pep, a->t.sealed, a->t.sealed_len, (const uint8_t *)"", 0, pep->now);
            mesh_flush(node);
        }
    } else if (event == PP_ASM_CONTROL) {
        mesh_control(node, frame, len, uptime_us);
    }
}

void mesh_node_tick(mesh_node *node, int64_t uptime_us, int save) {
    if (node->stopped) return;
    long long now = mesh_node_time(node, uptime_us);
    pp_pep_tick(node->pep, mesh_ms(uptime_us), now);
    if (save) pp_pep_save_time(node->pep, now);
    mesh_flush(node);
}

void mesh_node_beat(mesh_node *node, int64_t uptime_us) {
    if (node->stopped) return;
    pp_pep_record(node->pep, PP_EV_BEAT, mesh_node_time(node, uptime_us));
    mesh_flush(node);
}

void mesh_node_ask(mesh_node *node, const uint8_t *regs, size_t regs_len, const uint32_t *ages, int64_t uptime_us,
                   pp_decision *out) {
    memset(out, 0, sizeof *out);
    if (node->stopped) return;
    pp_pep_ask(node->pep, regs, regs_len, ages, mesh_node_time(node, uptime_us), out);
    mesh_flush(node);
}

const char *mesh_node_state(const mesh_node *node) {
    if (node->stopped) return "stopped";
    if (node->pep->locked) return "locked";
    return node->pep->d.has_active ? "active" : "no-policy";
}
