// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* gn_common.h: the governed net protocol's constants and the structs the XDP program, its loader, its
 * userspace test path and the receipt logger share (integrations/governed_net/PROTOCOL.md). */
#pragma once

#include <linux/types.h>

/* Map pinning marker. Empty by default, so the ordinary object (gn_xdp.bpf.o) is byte-identical to a build
 * without it and the libbpf C loader is unaffected. The no-install deployment builds gn_xdp.pin.bpf.c,
 * which defines GN_PIN to `__uint(pinning, LIBBPF_PIN_BY_NAME);` so iproute2 pins every map under
 * /sys/fs/bpf/<if>/ where the pure-Python loader (gn_loader.py) can reach it. The userspace shim leaves it
 * empty. A map that uses it writes `GN_PIN` as its last member. */
#ifndef GN_PIN
#define GN_PIN
#endif

#define GN_PORT        47011u
#define GN_MAGIC       0x474E4554u   /* "GNET" */
#define GN_VERSION     1u
#define GN_HEADER_LEN  32u
#define GN_NAME_MAX    64u
#define GN_DATA_MAX    1024u
#define GN_CMD_MAX     11u
#define GN_FIELDS      7u            /* version cmd hclass arg0 arg1 name_len data_len (protocol.SCHEMA) */
#define GN_MAX_RULES   64u

/* Per-verdict counters, so the owner can see the program coexist on a shared LAN port: how much traffic
 * passed untouched against how much was the agent protocol and what became of it. The loader prints them
 * (gn_loader stats / on exit). PERCPU in the kernel, summed by the loader; one slot in the userspace shim. */
#define GN_CNT_OTHER     0u          /* not the agent protocol (another host, port, ethertype, fragment): passed */
#define GN_CNT_ALLOW     1u          /* an agent request the policy allowed: passed to the tool server */
#define GN_CNT_DROP      2u          /* an agent request refused, escalated, with no policy, or unloggable: dropped */
#define GN_CNT_MALFORMED 3u          /* an agent request the strict reader refused: dropped */
#define GN_CNT_N         4u

/* commands (protocol.py) */
#define GN_LIST 1u
#define GN_READ 2u
#define GN_WRITE 3u
#define GN_CREATE 4u
#define GN_DELETE 5u
#define GN_RUN 6u
#define GN_GIT_LOG 8u
#define GN_GIT_COMMIT 9u
#define GN_GIT_PUSH 10u
#define GN_GIT_FETCH 11u

/* the outcome of one frame */
#define GN_OTHER        0u   /* not the agent protocol: XDP_PASS, nothing recorded */
#define GN_ALLOW        1u   /* decided, allowed: XDP_PASS to the tool server */
#define GN_DROP_POLICY  2u   /* decided, refused or escalated: XDP_DROP */
#define GN_DROP_BAD     3u   /* the agent port, but not a well formed request: XDP_DROP */
#define GN_DROP_NOPOL   4u   /* no policy loaded: XDP_DROP (empty tables fail closed) */
#define GN_DROP_NOLOG   5u   /* allowed, but the record could not be written: XDP_DROP */

/* malformed reasons (protocol.REASONS), and the frame level ones above them */
#define GN_BAD_SHORT 1u
#define GN_BAD_MAGIC 2u
#define GN_BAD_VERSION 3u
#define GN_BAD_COMMAND 4u
#define GN_BAD_RESERVED 5u
#define GN_BAD_LENGTH 6u
#define GN_BAD_NAME_LENGTH 7u
#define GN_BAD_DATA_LENGTH 8u
#define GN_BAD_ARG_RANGE 9u
#define GN_BAD_NAME_CHAR 10u
#define GN_BAD_UNUSED 11u
#define GN_BAD_REQUEST_ID 12u
#define GN_BAD_FRAGMENT 20u
#define GN_BAD_UDP_LENGTH 21u
#define GN_BAD_IP_HEADER 22u

struct gn_config {
    __u32 loaded;        /* 0 until the loader has written the whole table: every MATCHED request is then dropped */
    __u32 start_node;
    __u32 image_index;   /* which signed image the tables hold (the logger maps it to its sha256) */
    __u32 n_rules;
    /* The deployment target, set by the loader (gn_loader run --server-ip --port). A frame is the agent
     * protocol only when its IPv4 DESTINATION is match_dst_ip and its UDP destination port is match_port;
     * every other frame on this shared LAN port passes untouched. With the empty maps of a bare `ip link
     * ... obj` attach these are 0, which no real frame matches, so a bare attach is a pass-through no-op
     * and does not disturb the household LAN until the loader has set a target and loaded the policy. */
    __u32 match_dst_ip;  /* host order; the tool server's IPv4 address on the LAN */
    __u32 match_port;    /* the agent UDP destination port (0..65535) */
};

struct gn_action {
    __u8  pass;          /* 1: the rule's target is allow, the packet goes to the tool server */
    __u8  kind;          /* 0 allow, 1 refuse, 2 escalate */
    __u16 cause;         /* the registered cause code of a refusal or an escalation, else 0 */
};

/* One decision as the ring buffer carries it to the receipt logger: 64 bytes, every member explicit. */
struct gn_event {
    __u64 request_id;
    __u64 t_ns;          /* bpf_ktime_get_ns(): monotonic since boot, not a time anchor */
    __u32 image_index;
    __s32 edge;          /* the matched rule (-1: none) */
    __u16 cause;         /* 32 (route:no-matching-edge) when no rule matched */
    __u8  outcome;       /* GN_ALLOW .. GN_DROP_NOLOG */
    __u8  reason;        /* GN_BAD_* of a malformed request, else 0 */
    __u8  version;
    __u8  cmd;
    __u8  hclass;
    __u8  name_len;
    __u16 data_len;
    __u16 src_port;
    __u32 handle;
    __u32 arg0;
    __u32 arg1;
    __u32 src_ip;        /* host order */
    __u32 pad;
};
_Static_assert(sizeof(struct gn_event) == 56, "the event layout is fixed (receipt_logger.py reads it)");
