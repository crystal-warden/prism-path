// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* gn_common.h: the governed net protocol's constants and the structs the XDP program, its loader, its
 * userspace test path and the receipt logger share (integrations/governed_net/PROTOCOL.md). */
#pragma once

#include <linux/types.h>

#define GN_PORT        47011u
#define GN_MAGIC       0x474E4554u   /* "GNET" */
#define GN_VERSION     1u
#define GN_HEADER_LEN  32u
#define GN_NAME_MAX    64u
#define GN_DATA_MAX    1024u
#define GN_CMD_MAX     11u
#define GN_FIELDS      7u            /* version cmd hclass arg0 arg1 name_len data_len (protocol.SCHEMA) */
#define GN_MAX_RULES   64u

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
    __u32 loaded;        /* 0 until the loader has written the whole table: every request is then dropped */
    __u32 start_node;
    __u32 image_index;   /* which signed image the tables hold (the logger maps it to its sha256) */
    __u32 n_rules;
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
