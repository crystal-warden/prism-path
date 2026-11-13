// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* gn_xdp.h: the governed net decision, one text for the kernel and for its userspace test path.
 *
 * gn_xdp.bpf.c includes this inside an XDP program; gn_batch.c includes it natively over a shim of the
 * BPF facilities, so the parse, the strict reading and the decision that run over a packet corpus on a
 * host without privileges are the same text the kernel would run (what that path does NOT cover is the
 * verifier and the JIT). The protocol is integrations/governed_net/PROTOCOL.md; the Python reading of the
 * same bytes is integrations/governed_net/protocol.py, and the order of the checks below is its order, so
 * both name the same reason for the same malformed datagram.
 *
 * The includer must have defined, BEFORE this header: ppt_common.h, the table maps and ppt_eval_bpf.h
 * (the shared evaluator), gn_config_map and gn_action_map (below), and GN_EMIT(event_ptr), which reports
 * one decision and evaluates to 0 when it was recorded. A decision that could not be recorded is never let
 * through: an allowed call with no record would be an execution with no receipt.
 *
 * What is not the agent protocol is passed untouched, by construction: a frame that is not IPv4, an IPv4
 * packet that is not UDP, and a UDP datagram to any other port return GN_OTHER before a byte of payload
 * is read, so SSH, the management network and everything else on the interface never meet the policy.
 * Fragments: only a FIRST fragment carries the UDP header (an IPv4 fragment's payload is at least 8 bytes,
 * so the whole UDP header is in it), and a first fragment to the protocol's port is dropped as malformed;
 * the later fragments cannot be reassembled without it. */
#pragma once

#include "gn_common.h"

static __always_inline __u32 gn_be16(const __u8 *bytes) { return ((__u32)bytes[0] << 8) | bytes[1]; }
static __always_inline __u32 gn_be32(const __u8 *bytes)
{
    return ((__u32)bytes[0] << 24) | ((__u32)bytes[1] << 16) | ((__u32)bytes[2] << 8) | bytes[3];
}

static __always_inline int gn_name_first(__u8 c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

static __always_inline int gn_name_rest(__u8 c) { return gn_name_first(c) || c == '.' || c == '-'; }

static __always_inline int gn_uses_handle(__u32 cmd) { return cmd >= GN_LIST && cmd <= GN_RUN; }
static __always_inline int gn_uses_arg0(__u32 cmd)
{
    return cmd == GN_READ || cmd == GN_RUN || cmd == GN_GIT_LOG || cmd == GN_GIT_PUSH || cmd == GN_GIT_FETCH;
}
static __always_inline int gn_uses_data(__u32 cmd) { return cmd == GN_WRITE || cmd == GN_CREATE || cmd == GN_GIT_COMMIT; }

/* The strict reading of the payload (protocol.decode, in its order). 0 when well formed, else GN_BAD_*.
 * `payload` .. `payload + payload_len` is inside the frame (the caller checked it against data_end). */
static __always_inline __u32 gn_read(const __u8 *payload, __u32 payload_len, const void *data_end,
                                     struct gn_event *ev)
{
    if (payload_len < GN_HEADER_LEN || (const void *)(payload + GN_HEADER_LEN) > data_end)
        return GN_BAD_SHORT;
    if (gn_be32(payload) != GN_MAGIC)
        return GN_BAD_MAGIC;
    ev->version = payload[4];
    ev->cmd = payload[5];
    ev->hclass = payload[6];
    ev->name_len = payload[7];
    ev->request_id = ((__u64)gn_be32(payload + 8) << 32) | gn_be32(payload + 12);
    ev->handle = gn_be32(payload + 16);
    ev->arg0 = gn_be32(payload + 20);
    ev->arg1 = gn_be32(payload + 24);
    ev->data_len = (__u16)gn_be16(payload + 28);
    __u32 tail = gn_be16(payload + 30);
    if (ev->version != GN_VERSION)
        return GN_BAD_VERSION;
    if (ev->cmd < 1 || ev->cmd > GN_CMD_MAX)
        return GN_BAD_COMMAND;
    if (tail != 0)
        return GN_BAD_RESERVED;
    if (ev->name_len > GN_NAME_MAX)
        return GN_BAD_NAME_LENGTH;
    if (ev->data_len > GN_DATA_MAX)
        return GN_BAD_DATA_LENGTH;
    if (payload_len != GN_HEADER_LEN + ev->name_len + ev->data_len)
        return GN_BAD_LENGTH;
    if ((ev->arg0 >> 31) || (ev->arg1 >> 31))
        return GN_BAD_ARG_RANGE;
    if (ev->request_id == 0)
        return GN_BAD_REQUEST_ID;
    __u32 cmd = ev->cmd;
    if ((!gn_uses_handle(cmd) && (ev->hclass || ev->handle)) || (!gn_uses_arg0(cmd) && ev->arg0) ||
        (cmd != GN_READ && ev->arg1) || (cmd != GN_CREATE && ev->name_len) || (!gn_uses_data(cmd) && ev->data_len))
        return GN_BAD_UNUSED;
    /* the name: one component of a fixed alphabet, never '/', never a leading '.', so '.', '..' and any
     * path are not expressible; a bounded loop over at most GN_NAME_MAX bytes */
    const __u8 *name = payload + GN_HEADER_LEN;
    for (__u32 index = 0; index < GN_NAME_MAX; index++) {
        if (index >= ev->name_len)
            break;
        if ((const void *)(name + index + 1) > data_end)
            return GN_BAD_SHORT;
        __u8 c = name[index];
        if (index == 0 ? !gn_name_first(c) : !gn_name_rest(c))
            return GN_BAD_NAME_CHAR;
    }
    return 0;
}

/* The register file the policy reads, in protocol.SCHEMA order; every other slot absent. */
static __always_inline void gn_fill(struct ppt_regfile *regfile, const struct gn_event *ev)
{
    #pragma unroll
    for (__u32 field_index = 0; field_index < MAX_FIELDS_PER_PKT; field_index++) {
        regfile->reg[field_index & (MAX_FIELDS_PER_PKT - 1)].ty = TY_NONE;
        regfile->reg[field_index & (MAX_FIELDS_PER_PKT - 1)].val = 0;
    }
    __s32 values[GN_FIELDS] = {ev->version, ev->cmd, ev->hclass, (__s32)ev->arg0, (__s32)ev->arg1,
                               ev->name_len, ev->data_len};
    #pragma unroll
    for (__u32 slot = 0; slot < GN_FIELDS; slot++) {
        regfile->reg[slot].ty = TY_INT;
        regfile->reg[slot].val = values[slot];
    }
}

/* One frame, `data` .. `data_end`: GN_OTHER for what is not the agent protocol, else the outcome of the
 * decision, with `ev` filled for the logger (and already reported through GN_EMIT). */
static __always_inline __u32 gn_decide(const __u8 *data, const void *data_end, struct gn_event *ev)
{
    /* Ethernet: IPv4 only (no VLAN tag on the dedicated wire); anything else is not the protocol */
    if ((const void *)(data + 14) > data_end)
        return GN_OTHER;
    if (gn_be16(data + 12) != 0x0800)
        return GN_OTHER;
    const __u8 *ip = data + 14;
    if ((const void *)(ip + 20) > data_end)
        return GN_OTHER;
    if (ip[9] != 17)                                   /* not UDP */
        return GN_OTHER;
    __u32 ihl = (__u32)(ip[0] & 0x0F) * 4;
    if ((ip[0] >> 4) != 4 || ihl < 20)
        return GN_OTHER;                               /* not an IPv4 header the stack would accept either */
    __u32 frag = gn_be16(ip + 6);
    const __u8 *udp = ip + ihl;
    if ((frag & 0x1FFF) != 0)
        return GN_OTHER;                               /* a later fragment: no UDP header to read (see top) */
    if ((const void *)(udp + 8) > data_end)
        return GN_OTHER;
    if (gn_be16(udp + 2) != GN_PORT)
        return GN_OTHER;                               /* another port: never the policy's business */

    /* from here on the frame is addressed to the agent protocol, and it is decided or dropped */
    ev->src_ip = gn_be32(ip + 12);
    ev->src_port = (__u16)gn_be16(udp);
    struct gn_config *cfg;
    __u32 zero = 0;
    cfg = bpf_map_lookup_elem(&gn_config_map, &zero);
    ev->image_index = cfg ? cfg->image_index : 0;
    ev->edge = -1;
    __u32 reason = 0;
    if (frag & 0x2000)
        reason = GN_BAD_FRAGMENT;                      /* a first fragment: the request is not whole */
    else if (ihl > 60 || gn_be16(ip + 2) < ihl + 8)
        reason = GN_BAD_IP_HEADER;
    __u32 udp_len = gn_be16(udp + 4);
    if (!reason && (udp_len < 8 || udp_len != gn_be16(ip + 2) - ihl))
        reason = GN_BAD_UDP_LENGTH;
    const __u8 *payload = udp + 8;
    __u32 payload_len = udp_len - 8;
    if (!reason && (payload_len > GN_HEADER_LEN + GN_NAME_MAX + GN_DATA_MAX ||
                    (const void *)(payload + payload_len) > data_end))
        reason = GN_BAD_UDP_LENGTH;
    if (!reason)
        reason = gn_read(payload, payload_len, data_end, ev);
    if (reason) {
        ev->reason = (__u8)reason;
        ev->outcome = GN_DROP_BAD;
        GN_EMIT(ev);
        return GN_DROP_BAD;
    }
    if (!cfg || !cfg->loaded) {
        ev->outcome = GN_DROP_NOPOL;
        GN_EMIT(ev);
        return GN_DROP_NOPOL;
    }
    struct ppt_regfile *regfile = ppt_regs();
    if (!regfile) {
        ev->outcome = GN_DROP_NOPOL;
        GN_EMIT(ev);
        return GN_DROP_NOPOL;
    }
    gn_fill(regfile, ev);
    __s32 matched = -1, target = -1;
    evaluate(cfg->start_node, GN_FIELDS, PPT_BANK_SINGLE, &matched, &target);
    ev->edge = matched;
    __u32 outcome = GN_DROP_POLICY;
    ev->cause = 32;                                    /* route:no-matching-edge: no rule holds */
    if (matched >= 0) {
        __u32 rule = (__u32)matched;
        struct gn_action *action = bpf_map_lookup_elem(&gn_action_map, &rule);
        if (action && rule < cfg->n_rules) {
            ev->cause = action->cause;
            if (action->pass)
                outcome = GN_ALLOW;
        } else {
            ev->cause = 0;                             /* a rule with no action: dropped, reported */
        }
    }
    ev->outcome = (__u8)outcome;
    if (GN_EMIT(ev) != 0 && outcome == GN_ALLOW) {
        ev->outcome = GN_DROP_NOLOG;
        return GN_DROP_NOLOG;
    }
    return outcome;
}
