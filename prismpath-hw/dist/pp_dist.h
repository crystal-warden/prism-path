/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* pp_dist.h: the C core of policy distribution (docs/design/spec-policy-distribution.md, section 19) for the
 * `mesh` and `cfs` targets: the sealed container (S2), the strict envelope scanner (E9), the trust store
 * (section 5) and the one verifier, rules V2 to V11 in order (section 9.1). It is the twin of
 * prismpath/distribution/{envelope,trust,verify}.py and is held to it by the shared corpus
 * (prismpath/tests/test_distribution_c.py, through host_check.c).
 *
 * The same files, unchanged, are what the mesh firmware and the cFS app compile. Nothing allocates, every
 * bound is a constant here, and the only dependency is Monocypher's Ed25519 (monocypher-ed25519.h). */
#ifndef PP_DIST_H
#define PP_DIST_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ cause codes (prismpath/kernel/causes.py) */
/* test_distribution_c.py holds each to the registry, so a renumbering cannot pass unseen. */
#define PP_CAUSE_NONE 0
#define PP_CAUSE_NO_MATCHING_EDGE 32      /* route:no-matching-edge */
#define PP_CAUSE_SIG_INVALID 2            /* sig:invalid */
#define PP_CAUSE_SIG_REVOKED_KEY 3        /* sig:revoked-key */
#define PP_CAUSE_IMAGE_SHA256_MISMATCH 6  /* image:sha256-mismatch */
#define PP_CAUSE_IMAGE_CAPS_EXCEEDED 16   /* image:caps-exceeded */
#define PP_CAUSE_IMAGE_TRUNCATED_HEADER 69 /* image:truncated-header */
#define PP_CAUSE_IMAGE_BAD_MAGIC 70       /* image:bad-magic */
#define PP_CAUSE_IMAGE_BAD_VERSION 71     /* image:bad-version */
#define PP_CAUSE_IMAGE_SAFE_NODE_OOB 72   /* image:safe-node-oob */
#define PP_CAUSE_IMAGE_LENGTH_MISMATCH 73 /* image:length-mismatch */
#define PP_CAUSE_IMAGE_UNKNOWN_OP 74      /* image:unknown-op */
#define PP_CAUSE_IMAGE_UNKNOWN_TYPE 75    /* image:unknown-type */
#define PP_CAUSE_IMAGE_FIELD_INDEX_OOB 76 /* image:field-index-oob */
#define PP_CAUSE_IMAGE_EDGE_TARGET_OOB 77 /* image:edge-target-oob */
#define PP_CAUSE_IMAGE_EDGE_PROG_OOB 78   /* image:edge-prog-oob */
#define PP_CAUSE_IMAGE_UNKNOWN_OPCODE 79  /* image:unknown-opcode */
#define PP_CAUSE_IMAGE_ATOM_INDEX_OOB 80  /* image:atom-index-oob */
#define PP_CAUSE_IMAGE_NODE_ATTR_OOB 81   /* image:node-attr-oob */
#define PP_CAUSE_NOT_CANONICAL 103        /* document:not-canonical */
#define PP_CAUSE_BAD_FORMAT 135           /* dist:bad-format */
#define PP_CAUSE_UNKNOWN_KEY 136          /* dist:unknown-key */
#define PP_CAUSE_TARGET_MISMATCH 137      /* dist:target-mismatch */
#define PP_CAUSE_BODY_MISMATCH 138        /* dist:body-mismatch */
#define PP_CAUSE_SEQ_REPLAY 139           /* dist:seq-replay */
#define PP_CAUSE_NOT_YET_VALID 140        /* dist:not-yet-valid */
#define PP_CAUSE_EXPIRED 141              /* dist:expired */
#define PP_CAUSE_REVOKED 142              /* dist:revoked */
#define PP_CAUSE_TRUST_REPLAY 144         /* dist:trust-replay */
#define PP_CAUSE_ROTATION_INVALID 145     /* dist:rotation-invalid */
#define PP_CAUSE_TOO_LARGE 148            /* dist:too-large */
#define PP_CAUSE_FRAME_INVALID 150        /* dist:frame-invalid */
#define PP_CAUSE_WIDENING_UNSIGNED 143    /* dist:widening-unsigned */
#define PP_CAUSE_NOT_STAGED 151           /* dist:not-staged */
#define PP_CAUSE_INCOMPLETE 152           /* dist:incomplete */
#define PP_CAUSE_POLICY_LAPSED 153        /* dist:policy-lapsed */
#define PP_CAUSE_FLOOR_LOST 154           /* dist:floor-lost */
#define PP_CAUSE_HELD 159                 /* dist:held */
#define PP_CAUSE_LEGACY_REFUSED 146       /* dist:legacy-refused */
#define PP_CAUSE_FALLBACK 161             /* dist:fallback */
#define PP_CAUSE_FLOOR_ALLOWED 162        /* dist:floor-allowed */
#define PP_CAUSE_INSTALL_LOST 163         /* dist:install-lost */
#define PP_CAUSE_INSTALL_WIDENED 164      /* dist:install-widened */
#define PP_CAUSE_ABOVE_CEILING 165        /* dist:above-ceiling */
#define PP_CAUSE_FLOOR_RATE 166           /* dist:floor-rate */
#define PP_CAUSE_FLOOR_BROAD 167          /* dist:floor-broad */
#define PP_CAUSE_ANSWER_UNBOUND 168       /* dist:answer-unbound */

/* ------------------------------------------------------------------ bounds */
#define PP_MAX_ENVELOPE 2048  /* E6 */
#define PP_MAX_ENTRIES 4      /* S2 */
#define PP_ENTRY_SIZE 96      /* a 32 byte key id and a 64 byte signature */
#define PP_MAX_SEALED (6 + PP_ENTRY_SIZE * PP_MAX_ENTRIES + 2 + PP_MAX_ENVELOPE) /* 2,440 bytes (B9) */
#define PP_MAX_BODY 16777215LL /* E1 body_size */
#define PP_MAX_SEQ 9007199254740991LL
#define PP_SKEW 300           /* section 7 */
#define PP_STREAM_MAX 64
#define PP_MAX_KEYS 8         /* K5: keys a trust store holds that are not retired */
#define PP_MAX_RETIRED 16     /* K5: retired key ids a trust store remembers, each with its key */
#define PP_MAX_HELD_KEYS (PP_MAX_KEYS + PP_MAX_RETIRED) /* the keys a store keeps, the retired ones among them */
#define PP_MAX_LIST 64        /* R6, R7: a PEP holds the latest revocation list, at most 64 entries a list */
#define PP_MAX_FLOORS 1       /* R6: a PEP keeps the floor a revocation raised for its own stream only */
#define PP_REVOCATION_ENTRIES 64 /* R7: the entries of one revocation list */
#define PP_REVOCATION_FLOORS 16  /* R7: the streams of one revocation list */
#define PP_TRUST_BOUND 16384  /* E6: every kind's bound on a trust body, which holds the largest list R7 allows */
#define PP_MAX_FLOOR_IDS 4    /* envelope ids committed at one floor */
#define PP_MESH_TABLE_MAX 640 /* E6: TBL_MAX in prismpath-hw/mesh/main/ppt_mesh.c */
#define PP_CFS_TABLE_MAX 4692 /* E6: the PP_PolicyTable_t bytes before ImageSig (integrations/cfs, section 3) */
/* The largest table this build holds, which sizes every release and install slot. A mesh node's by default, so the
 * firmware keeps its RAM; the cFS app and the host check of the cfs kind build with PP_CFS_TABLE_MAX, and a build
 * whose bound is below a kind's has no row for that kind (a PEP of it does not open). */
#ifndef PP_TABLE_MAX
#define PP_TABLE_MAX PP_MESH_TABLE_MAX
#endif
/* OP3: the open escalations a PEP holds, the oldest dropped first. Only a cfs PEP escalates, so a build without the cfs
 * row keeps one slot that is never used, and a mesh node keeps its RAM. */
#if PP_TABLE_MAX >= PP_CFS_TABLE_MAX
#define PP_OPEN_ESCALATIONS 8
#else
#define PP_OPEN_ESCALATIONS 1
#endif
/* The members of a cfs.table body (PP_PolicyTable_t in integrations/cfs/prismpath_app/fsw/inc/prismpath_app_kernel.h,
 * which holds itself to these offsets at compile time). Little endian, no padding. */
#define PP_CFS_OFF_LAYOUT 0
#define PP_CFS_OFF_IMAGE_LEN 4
#define PP_CFS_OFF_RULE_COUNT 6
#define PP_CFS_OFF_CONTRACT 8
#define PP_CFS_OFF_NOMATCH 10
#define PP_CFS_OFF_VERSION 12
#define PP_CFS_OFF_CORE_LEN 16
#define PP_CFS_OFF_FLOW_LEN 18
#define PP_CFS_OFF_RULES 20
#define PP_CFS_RULES_MAX 16
#define PP_CFS_IMAGE_MAX 1024
#define PP_CFS_CORE_MAX 2048
#define PP_CFS_FLOW_MAX 1536
#define PP_CFS_OFF_IMAGE (PP_CFS_OFF_RULES + 4 * PP_CFS_RULES_MAX)
#define PP_CFS_OFF_CORE (PP_CFS_OFF_IMAGE + PP_CFS_IMAGE_MAX)
#define PP_CFS_OFF_FLOW (PP_CFS_OFF_CORE + PP_CFS_CORE_MAX)
#define PP_META_MAX_DEPTH 3   /* E9: the scanner's bound on meta's nesting */
#define PP_INSTALL_KEYS 4     /* IS2, IS11: install keys */
#define PP_OPERATOR_KEYS 4    /* OP1: operator keys */
#define PP_INSTALL_RETIRED 8  /* IS10, IS11: retired install and operator key ids remembered */
#define PP_CEILING_BODIES 64  /* CL1: the hashes a policy list holds */
#define PP_FLOOR_RULES 8      /* AF9: the rules of an action floor */
#define PP_LAYOUT_FIELDS 32   /* AF10: the fields a layout labels */
#define PP_LEGACY_STREAMS 4   /* L2: the streams the older forms are refused on, past which every stream is */
#define PP_ANSWER_LIFE 600    /* OP2, OP3: an answer's lifetime and an escalation's, in seconds */
#define PP_REQUEST_MAX 32     /* OP3: the bytes of the one request an escalation keeps for its answer */
#define PP_COMMAND_MAX 8      /* OP3: the bytes of the caller's command an escalation keeps beside its request */

/* ------------------------------------------------------------------ the kinds (section 3) */
typedef enum {
    PP_ART_POLICY_CORE, PP_ART_POLICY_PPT, PP_ART_POLICY_SPIRAL, PP_ART_SANDBOX_PROFILE, PP_ART_EGRESS_HOSTS,
    PP_ART_AGENT_ZONES, PP_ART_GATEWAY_ROUTES, PP_ART_NET_DESTS, PP_ART_NET_EDGE, PP_ART_CFS_TABLE, PP_ART_GRANT,
    PP_ART_TRUST_WIDENING, PP_ART_TRUST_REVOCATION, PP_ART_TRUST_ROTATION,
    PP_ART_INSTALL_FLOOR, PP_ART_INSTALL_FALLBACK, PP_ART_INSTALL_CEILING, PP_ART_INSTALL_TRUST, /* section 21 */
    PP_ART_OPERATOR_ANSWER,                                                                    /* OP2 */
    PP_ART_TRUST_CONTROLLER,                                                                   /* K7 */
    PP_ART_TRUST_CHANGE,                                                                       /* W10 */
    PP_ART_INSTALL_CHANGE,                                                                     /* IS14 */
    PP_ART_COUNT
} pp_artifact;

/* The three install sets, in the order of the install id (H10), and what `as` names (IS1, CL1). */
enum { PP_SET_FLOOR, PP_SET_FALLBACK, PP_SET_CEILING, PP_SETS };
enum { PP_AS_ABSENT, PP_AS_NONE, PP_AS_POLICY_PPT, PP_AS_POLICY_LIST, PP_AS_OTHER, PP_AS_CFS_TABLE };

typedef enum { PP_TGT_AGENT, PP_TGT_CFS, PP_TGT_GATEWAY, PP_TGT_HOST, PP_TGT_MESH, PP_TGT_XDP, PP_TGT_COUNT } pp_target;

/* The name of a kind, or NULL. */
const char *pp_artifact_name(pp_artifact artifact);
const char *pp_target_name(pp_target target);

/* ------------------------------------------------------------------ the parts */
typedef struct {
    uint8_t key_id[32];
    uint8_t signature[64];
} pp_entry;

/* An envelope the scanner read (E1). Strings are copied into the struct, so it holds nothing of the input. */
typedef struct {
    pp_artifact artifact;
    uint8_t body_sha256[32];
    long long body_size;
    long long expires;
    long long not_before;
    uint8_t policy_sha256[32];
    uint8_t release[32];
    uint8_t replaces[32];
    int has_replaces;
    long long seq;
    char stream[PP_STREAM_MAX + 1]; /* a stream name, or "@trust" */
    uint32_t targets;               /* a bit per pp_target */
    int widens;
    uint8_t envelope_id[32];        /* E3, the SHA-256 of the envelope bytes */
    /* IS1: the members of an install kind's `meta` every reader reads, the E9 scanner too. The rest it skips. */
    uint8_t as;                     /* PP_AS_* */
    int has_layout, has_command, has_rate, has_answer_rate;
    uint8_t layout[32];             /* AF10: the hash of the layout document of a table floor */
    int command;                    /* AF9: the register of the command field */
    long long rate_allows, rate_window, answer_allows, answer_window; /* AF8, OP4 */
} pp_envelope;

#define PP_ROLE_AUTHORITY 0 /* K4: the role of every key of the trust store that counts */
#define PP_ROLE_OTHER 1     /* a key in a role this version does not know is kept and never counts */
#define PP_ROLE_CONTROLLER 2 /* K6: the controller key, which signs controller statements (H9) and never counts */

typedef struct {
    uint8_t id[32];
    uint8_t public_key[32];
    uint8_t role;
} pp_key;

typedef struct {
    char stream[PP_STREAM_MAX + 1];
    long long seq;
} pp_raised_floor;

/* The trust store (K1). `readable` 0 is a store whose durable form could not be read: it counts nothing. */
typedef struct {
    int readable;
    pp_key keys[PP_MAX_HELD_KEYS]; /* at most PP_MAX_KEYS of them not retired (K5) */
    size_t n_keys;
    uint8_t retired[PP_MAX_RETIRED][32];
    size_t n_retired;
    uint8_t revoked_keys[PP_MAX_LIST][32];
    size_t n_revoked_keys;
    uint8_t revoked_envelopes[PP_MAX_LIST][32];
    size_t n_revoked_envelopes;
    uint8_t revoked_policies[PP_MAX_LIST][32];
    size_t n_revoked_policies;
    pp_raised_floor floors[PP_MAX_FLOORS];
    size_t n_floors;
    long long trust_seq;
    uint8_t trust_id[32];
    int has_trust_id;
    long long time_floor;
    long long key_seq;              /* K6, K7: the key sequence of the controller key, 0 when the anchor named it */
    long long fresh;                /* H16, P4: the anchor's `fresh`, the longest lifetime in seconds of a fresh
                                       statement, 0 for freshness off. Provisioning copies it from the anchor, and no
                                       message changes it */
} pp_trust;

/* What a staged release shares (E7). */
typedef struct {
    char stream[PP_STREAM_MAX + 1];
    long long seq;
    uint8_t policy_sha256[32];
    uint8_t release[32];
    uint8_t replaces[32];
    int has_replaces;
    int widens;
} pp_staged;

/* ------------------------------------------------------------------ the install record (section 21, IS10) */

typedef struct {
    uint8_t id[32];
    uint8_t public_key[32];
} pp_ikey;

/* One install kind as the record names it: the install sequence it stands at, which nothing lowers (IS6), and
 * the set held at it, by set id (IS1) and the envelope id of its one statement (a `mesh` set is one statement,
 * IS3). The empty set withdraws the kind: the PEP then holds none at that `seq`, and keeps its envelope id only so
 * the same statement again changes nothing. */
typedef struct {
    long long seq;
    int held;                      /* a set is held of this kind */
    uint8_t set_id[32];
    uint8_t envelope_id[32];       /* of the held set, or of the empty set that withdrew it */
    uint8_t policy_sha256[32];     /* of the held set, the `replaces` the next one names (IS12) */
    uint8_t body_sha256[32];       /* of the held set's one statement, so a resend of a lost set is known (IS10,
                                    * IS12); packed in place of the set id, which the envelope id gives */
} pp_install_slot;

/* IS10: the install keys and their threshold, the operator keys (OP1), the retired install and operator key ids
 * oldest first, the install trust sequence and id, and the three install kinds. Under 1,024 bytes packed. */
typedef struct {
    pp_ikey keys[PP_INSTALL_KEYS];
    size_t n_keys;
    long long threshold;
    pp_ikey operators[PP_OPERATOR_KEYS];
    size_t n_operators;
    uint8_t retired[PP_INSTALL_RETIRED][32];
    size_t n_retired;
    long long trust_seq;
    uint8_t trust_id[32];          /* the latest install.trust applied, or the anchor's fingerprint (IS10) */
    uint8_t domain[32];            /* P4, CL4: the hash of the reading domain the anchor named */
    pp_install_slot sets[PP_SETS];
} pp_install;

/* AF10: one field of the layout a table kind is built with. */
enum { PP_ROLE_COMMAND, PP_ROLE_PARAMETER, PP_ROLE_INDEPENDENT, PP_ROLE_PROPOSER };
typedef struct {
    uint16_t reg;
    uint8_t role;                  /* PP_ROLE_COMMAND ... */
    int32_t min, max;
    uint32_t stale;                /* seconds, never 0 for an independent field and 0 for every other */
} pp_layout_field;

typedef struct {
    uint8_t sha256[32];            /* the hash of the layout document (AF10), `layout` in a table floor's meta */
    size_t n;
    pp_layout_field fields[PP_LAYOUT_FIELDS];
} pp_layout;

/* IS14, IS15: an install change statement staged before the set it carries, by what V10 and IS15 hold it to: its seq,
 * policy hash, release id and `from`, which V11 held to its `replaces`, and its envelope id. */
typedef struct {
    long long seq;
    uint8_t policy_sha256[32], release[32], from[32], envelope_id[32];
} pp_change;

/* What the verifier needs of a PEP's install part. NULL `record` for a PEP that holds none, which takes no
 * install statement (`dist:unknown-key`). */
typedef struct {
    const pp_install *record;
    const pp_envelope *staged[PP_SETS]; /* the statement staged of each kind, NULL for none (IS4, G2, V10) */
    const pp_change *change[PP_SETS];   /* the install change statement staged of each kind, NULL for none (IS15) */
    int message;                    /* 1 in a message, where a threshold of 1 takes no install statement (IS4) */
    int has_ceiling;                /* a policy list is held (CL1) */
    const uint8_t (*ceiling)[32];
    size_t n_ceiling;
    const pp_layout *layout;        /* the layout the PEP was built with, NULL for none (AF10) */
    const pp_trust *trust;          /* the trust store an install.trust's keys are held apart from (IS11, K4) */
} pp_install_view;

/* What the verifier needs of an enforcement point (verify.PepView). */
typedef struct {
    pp_target kind;                 /* PP_TGT_MESH or PP_TGT_CFS */
    char stream[PP_STREAM_MAX + 1];
    long long floor_seq;
    uint8_t floor_ids[PP_MAX_FLOOR_IDS][32];
    size_t n_floor_ids;
    int has_staged;
    pp_staged staged;
    long long body_bound;           /* the PEP's own bound on the body of an artifact, within its kind's, never on a
                                       trust body (E6) */
    int has_clock;                  /* 0 for a PEP with no real time clock (T2), which never applies T3 */
    int has_instance_key_id;        /* the PEP's own instance key id, which a rotation may never add (O4) */
    uint8_t instance_key_id[32];
    const pp_install_view *install; /* NULL for a PEP that holds no install record */
    /* V11: the PEP's own check of a table of its kind beyond the core's, run after it on a release's table and on a
     * table an install set names (section 3: on cfs, the app's kernel check). NULL for none. 0, or its cause. */
    uint8_t (*table_check)(void *context, const uint8_t *body, size_t len);
    void *table_context;
} pp_pep;

/* A verifier's answer: `cause` 0 when it passed. `has_envelope` once the envelope read, with its id.
 * `unchanged` for an envelope at its floor that changes nothing (Q3, R1), and `time_floor` once V6 passed (V13). */
typedef struct {
    uint8_t cause;
    int has_envelope;
    pp_envelope envelope;
    int unchanged;
    int has_time_floor;
    long long time_floor;
    int trust_bounded;              /* the body is held to the trust bound: a trust body, a policy list or an
                                       install.trust (E6, IS5) */
    int install_widens;             /* IS11: an install.trust that adds a key or lowers the threshold */
    int change_set;                 /* IS14: the set kind an install change statement carries, once V11 read it */
    uint8_t change_from[32];
} pp_verdict;

/* ------------------------------------------------------------------ the functions */

/* S2: the envelope bytes and the entries of a sealed envelope, or PP_CAUSE_BAD_FORMAT. Reads nothing past
 * PP_MAX_SEALED bytes (B9). */
uint8_t pp_unseal(const uint8_t *sealed, size_t len, const uint8_t **envelope, size_t *envelope_len,
                  pp_entry entries[PP_MAX_ENTRIES], size_t *n_entries);

/* S1: the DSSE pre-authentication encoding of the envelope bytes, written into `out` (at least
 * PP_MAX_ENVELOPE + 64 bytes). Returns its length. */
size_t pp_signed_message(const uint8_t *envelope, size_t len, uint8_t *out);

/* E1, E2, E5, E8, E9: the envelope in `bytes`. PP_CAUSE_NOT_CANONICAL for canon/2 in another spelling,
 * PP_CAUSE_BAD_FORMAT for anything else that is not the format. `meta` is read only to be an object nesting
 * at most three levels that ends inside the envelope. */
uint8_t pp_read_envelope(const uint8_t *bytes, size_t len, pp_envelope *out);

/* S3 to S5: whether the entries sign `message` under the store, and the one cause when they do not. */
uint8_t pp_counting(const pp_trust *trust, const pp_entry *entries, size_t n_entries, const uint8_t *message,
                    size_t message_len);

/* V1: the sealed envelope and its body checked in the order V2 to V11 for `pep` at the PEP's time `now`. */
void pp_verify(const uint8_t *sealed, size_t sealed_len, const uint8_t *body, size_t body_len,
               const pp_trust *trust, const pp_pep *pep, long long now, pp_verdict *out);

/* The image check of a `policy.ppt` body on a mesh node (policy_pack.validate_image with no caps): 0, or the
 * cause of the first problem in the reference's order. */
uint8_t pp_validate_image(const uint8_t *image, size_t len);

/* SHA-256, which the envelope id, the body hash and a key id use. */
void pp_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* ------------------------------------------------------------------ the frame binding (section 8.3) */

#define PP_FRAME_OFFER 1
#define PP_FRAME_CHUNK 2
#define PP_FRAME_STATE 3
#define PP_FRAME_COMMIT 4
#define PP_FRAME_ABORT 5
#define PP_FRAME_EPOCH 6
#define PP_FRAME_LIMIT 250        /* ESP_NOW_MAX_DATA_LEN */
#define PP_TRANSFER_TIMEOUT_MS 5000 /* B7 */
#ifndef PP_ASSEMBLER_BODY_MAX
#define PP_ASSEMBLER_BODY_MAX PP_TRUST_BOUND /* the largest body this build assembles: a trust body (E6) */
#endif

/* The enforcement point's check of a whole sealed envelope through V8 (B9): 0 and the signed body_size and
 * body_sha256, or the verifier's cause. */
typedef uint8_t (*pp_admit_fn)(void *context, const uint8_t *sealed, size_t len, long long *body_size,
                               uint8_t body_sha256[32], int *trust_bounded);

/* One transfer being assembled (B6, B7, B11). Its buffers are its own, so nothing allocates. */
typedef struct {
    int active;
    uint16_t transfer;
    uint8_t envelope_prefix[16];
    size_t sealed_len, sealed_missing, sealed_next;
    size_t body_len, body_missing, body_next;
    int body_open; /* B9: no body is read before admit passed the envelope */
    uint8_t body_sha256[32];
    uint32_t started_ms;
    uint8_t sealed[PP_MAX_SEALED];
    uint8_t sealed_have[(PP_MAX_SEALED + 7) / 8];         /* a bit per byte that has arrived */
    uint8_t body[PP_ASSEMBLER_BODY_MAX];
    uint8_t body_have[(PP_ASSEMBLER_BODY_MAX + 7) / 8];
} pp_transfer;

typedef struct {
    pp_transfer t;
    int ordered; /* B11: the link is declared ordered */
    size_t limit; /* the link's frame limit */
    long long artifact_bound; /* the PEP's bound on the body of an artifact */
    long long trust_bound;    /* its bound on a trust body, never below PP_TRUST_BOUND (E6) */
    pp_admit_fn admit;
    void *context;
} pp_assembler;

#define PP_ASM_NONE 0    /* nothing to act on yet */
#define PP_ASM_WHOLE 1   /* the transfer is whole: sealed and body in the assembler, to verify and stage */
#define PP_ASM_DROPPED 2 /* a transfer dropped with `cause` */
#define PP_ASM_CONTROL 3 /* a state, commit, abort or epoch frame, for the caller */

void pp_assembler_init(pp_assembler *a, pp_admit_fn admit, void *context, int ordered, size_t limit,
                       long long artifact_bound);

/* Whether a commit or abort frame names the release at `seq` of `policy_sha256` on `stream` (frames.Abort.names). */
int pp_frame_names(const uint8_t *frame, size_t len, const char *stream, long long seq, const uint8_t policy_sha256[32]);
/* The delay in milliseconds a commit frame carries (B8), 0 for an abort. */
uint16_t pp_frame_delay(const uint8_t *frame, size_t len);

/* One frame's bytes at the PEP's monotonic time `now_ms`. Answers PP_ASM_* with the cause of a drop. */
int pp_assembler_receive(pp_assembler *a, const uint8_t *frame, size_t len, uint32_t now_ms, uint8_t *cause);

/* ------------------------------------------------------------------ the enforcement point machine (section 9) */

#define PP_RELEASE_BODY_MAX PP_TABLE_MAX /* every body of a release is within its kind's table bound */
#define PP_WIDENING_HASHES 64                 /* W4: the hashes a widening statement's `from` holds at most */
/* W4: the canonical bytes of a widening statement whose `from` holds 64 hashes, the most a release slot keeps */
#define PP_WIDENING_MAX (sizeof("{\"encoding\":\"canon/2\",\"format\":\"prismpath.dist-widening/1\",\"from\":[]}") - 1 + \
                         PP_WIDENING_HASHES * 67 - 1)
#define PP_RECORD_PLAIN (148 + 64)            /* a state record with no Facet body and no extension (H1, H5) */
#define PP_INSTALL_ENTRY 27                   /* H10: the type 3 entry of a PEP that holds an install record */
#define PP_RECORD_MAX (PP_RECORD_PLAIN + 3 + PP_INSTALL_ENTRY) /* 242 bytes, a frame of 246 (B10) */

/* H1 event and state codes, in the order of state_record.EVENTS and STATES. */
enum { PP_EV_BEAT, PP_EV_STAGED, PP_EV_REFUSED, PP_EV_COMMITTED, PP_EV_ABORTED, PP_EV_TRUST_APPLIED, PP_EV_LAPSED,
       PP_EV_ROLLED_BACK, PP_EV_PROVISIONED, PP_EV_HELD, PP_EV_FALLBACK, PP_EV_INSTALL_APPLIED,
       PP_EV_INSTALL_WIDENED, PP_EV_ANSWERED };
/* H10: what an event of staged, refused, answered, install-applied or install-widened is about. */
enum { PP_SUBJECT_NONE, PP_SUBJECT_FLOOR, PP_SUBJECT_FALLBACK, PP_SUBJECT_CEILING, PP_SUBJECT_TRUST,
       PP_SUBJECT_ANSWER };
enum { PP_ST_NO_POLICY, PP_ST_ACTIVE, PP_ST_LOCKED };

typedef struct {
    pp_envelope envelope;
    size_t sealed_len;
    uint8_t sealed[PP_MAX_SEALED]; /* kept so a revocation can test whether a held key still signs it (R5) */
    size_t body_len;               /* the body is in the release's buffer for its kind (pp_held_body) */
} pp_artifact_held;

/* A release as the PEP holds it (E7): its shared members and the artifacts it holds, in staging order. */
typedef struct {
    char stream[PP_STREAM_MAX + 1];
    long long seq;
    uint8_t policy_sha256[32];
    uint8_t release[32];
    uint8_t replaces[32];
    int has_replaces;
    int widens;
    size_t n;
    pp_artifact_held held[2]; /* a mesh release holds a policy.ppt and one statement, a trust.widening or a trust.change */
    uint8_t artifact_body[PP_RELEASE_BODY_MAX]; /* the body of the artifact, within the kind's bound */
    uint8_t trust_body[PP_WIDENING_MAX];        /* the statement it holds, a widening one of at most 64 hashes (W4) */
} pp_release;

/* The body of the release's k-th artifact, in the buffer for its kind. */
uint8_t *pp_held_body(pp_release *release, size_t k);

/* Everything the PEP keeps durably, in parts, each with whether it reads. The caller's `persist` is told which
 * parts changed and writes each of them whole, the old one or the new one (C4), so a state record writes the
 * counter alone. A restart opens the PEP from the parts it can read. A commit and a rollback write the intent
 * (pending), a commit the floor, then one call each in this order: previous, active, staged, then the intent
 * cleared. Each call names one part, so a power loss between two calls leaves a known state (pp_flip). */
#define PP_PART_ANCHOR 1     /* provisioned, the stream and the expiry response (P2, X10) */
#define PP_PART_COUNTER 2    /* the state record counter (H3) */
#define PP_PART_TRUST 4      /* the trust store (K1) */
#define PP_PART_FLOOR 8      /* the floor (Q1) */
#define PP_PART_ACTIVE 16    /* the active release */
#define PP_PART_PREVIOUS 32  /* the release the active one replaced (RB1) */
#define PP_PART_STAGED 64    /* the staged release */
#define PP_PART_PENDING 128  /* a commit or rollback under way, by release id and seq (C4) */
/* Section 21. The install record and what it names are kept apart from the store Q5 can lose, each in two copies
 * on two media where the PEP has them (IS10): a second NVS partition on a mesh node, a Critical Data Store area on
 * cfs. The caller's `persist` writes each of these parts to both, and a restart unpacks the first copy that reads.
 * An install set is applied by writing the record that names it first and its set part after, so a power loss
 * between the two finds the set in the set part's staged slot, which a start takes as held (IS4, IS12). */
#define PP_PART_INSTALL 256  /* the install record (IS10) */
#define PP_PART_RATES 512    /* the rate counts of AF8, beside the record */
#define PP_PART_SET_FLOOR 1024    /* the action floor held and the one staged (IS4) */
#define PP_PART_SET_FALLBACK 2048 /* the fallback policy held and the one staged */
#define PP_PART_SET_CEILING 4096  /* the ceiling held and the one staged */
#define PP_PART_COPIED (PP_PART_INSTALL | PP_PART_RATES | PP_PART_SET_FLOOR | PP_PART_SET_FALLBACK | PP_PART_SET_CEILING)
#define PP_PART_FRESH 8192   /* H16: the latest fresh controller statement, where freshness is on */
#define PP_PART_COUNT 14
#define PP_PARTS 16383

/* H9, H16: the controller statement, 102 bytes, or 126 with the freshness fields, signed by the controller key over
 * the DSSE encoding of the bytes before the signature with the payload type application/vnd.prismpath.dist-epoch.
 * It is the twin of prismpath/distribution/statement.py. */
#define PP_STATEMENT_SIZE 102
#define PP_FRESH_STATEMENT_SIZE 126
typedef struct {
    uint64_t key_seq;
    uint8_t stream[16];            /* the first 16 bytes of SHA-256 of the stream name */
    uint64_t epoch;
    int fresh;
    uint64_t trust_seq, stream_seq, expires; /* 0 when `fresh` is 0 */
} pp_controller_statement;

/* 0 and the statement when `data` reads and its signature verifies under `public_key` (32 raw bytes), else
 * PP_CAUSE_BAD_FORMAT for bytes that are not a statement and PP_CAUSE_SIG_INVALID for a signature that does not
 * verify. NULL `public_key` is a PEP with no controller key, which takes nothing (K6). */
uint8_t pp_statement_verify(const uint8_t *data, size_t len, const uint8_t *public_key, pp_controller_statement *out);

/* A statement of an install set as the PEP holds it: the sealed envelope and the body, a table, or for a policy
 * list its hashes, 32 bytes each, from which the canonical body is written again to check its hash (CL1). */
#define PP_INSTALL_BODY_MAX (PP_CEILING_BODIES * 32 > PP_TABLE_MAX ? PP_CEILING_BODIES * 32 : PP_TABLE_MAX)
typedef struct {
    pp_envelope envelope;
    size_t sealed_len;
    uint8_t sealed[PP_MAX_SEALED];
    size_t body_len;
    uint8_t body[PP_INSTALL_BODY_MAX];
} pp_statement;

typedef struct {
    int has_held, has_staged;
    pp_statement held, staged;
    int has_change;                 /* IS15: a change statement is staged for this kind */
    pp_change change;
} pp_install_set;

/* RC4: a held statement's body as its bytes, a policy list written again from its hashes (CL1), so a run can hold the
 * statement it decided under. The pointer is to the statement, or to a buffer the next call writes again. */
const uint8_t *pp_statement_bytes(const pp_statement *st, size_t *len);

/* OP3: an escalation the action floor made, by the hash of its receipt, under the floor of `policy_sha256`, at the
 * PEP's time `at`, with the cause it escalated with and the request it holds for an answer `allow` (the caller's
 * bytes, at most PP_REQUEST_MAX). The cause is the refusal an answer `refuse` receipts (OP3). `command` is the
 * caller's bytes that say how the request was asked, which the core never reads, so an answer `allow` carries out
 * that command and no other (a cFS command's message id and function code). An escalation kept by a build before
 * the command was kept reads with none (command_len 0), which the caller does not carry out. */
typedef struct {
    uint8_t receipt[32];
    uint8_t policy_sha256[32];
    long long at;
    uint8_t answered;
    uint8_t request_len;
    uint8_t request[PP_REQUEST_MAX];
    uint8_t cause;
    uint8_t command_len; /* the first member after the older layout's, so that layout is a prefix of this one */
    uint8_t command[PP_COMMAND_MAX];
} pp_escalation;

/* OP2, OP3: an answer the last call applied: `allow` or not, the answer's envelope id, the receipt hash it answered,
 * the floor's policy hash, the cause and the request of that escalation, for the caller's receipt with basis
 * operator. */
typedef struct {
    int applied;
    int allow;
    uint8_t cause;
    uint8_t envelope_id[32];
    uint8_t receipt[32];
    uint8_t policy_sha256[32];
    size_t request_len;
    uint8_t request[PP_REQUEST_MAX];
    size_t command_len;         /* the command its escalation kept, 0 for none */
    uint8_t command[PP_COMMAND_MAX];
} pp_answer;
typedef struct {
    int provisioned;            /* the anchor is confirmed (P2) */
    int setting_reads, expiry_hold; /* X10: the expiry response the PEP was provisioned with */
    int trust_reads;
    pp_trust trust;
    int floor_reads;
    char stream[PP_STREAM_MAX + 1];
    long long floor_seq;
    uint8_t floor_ids[PP_MAX_FLOOR_IDS][32];
    size_t n_floor_ids;
    int counter_reads;
    uint64_t counter;
    int has_active, has_previous, has_staged;
    pp_release active, previous, staged;
    int has_pending, pending_rollback;  /* a commit or rollback under way (C4), named by its release and seq */
    uint8_t pending_release[32];
    long long pending_seq;
    /* the anchor part's marks, which no provisioning clears */
    int install_mark;           /* IS9: the PEP held an install statement or install keys */
    int ceiling_mark;           /* IS10: the PEP holds a ceiling, so a lost one does not fail open */
    int legacy_all;             /* L2: the older forms are refused on every stream */
    size_t n_legacy;
    uint8_t legacy[PP_LEGACY_STREAMS][16]; /* L2: the stream prefixes a release was committed on */
    uint32_t floor_answers, floor_overrides; /* H10: saved with the counter, so no count goes down */
    int install_reads;          /* the install record part read */
    int has_install;            /* the PEP holds an install record */
    pp_install install;
    int rates_reads;
    long long rate_start[PP_FLOOR_RULES]; /* AF8: the window of each floor rule and the overrides counted in it */
    uint32_t rate_count[PP_FLOOR_RULES];
    int has_kept;               /* H16: a fresh statement is kept, its bytes, its expires and the time it was kept */
    uint8_t kept[PP_FRESH_STATEMENT_SIZE];
    uint64_t kept_expires;
    long long kept_at;
    long long answer_start;     /* OP4: the window of the operator answers `allow` and the count in it */
    uint32_t answer_count;
    size_t n_open;              /* OP3: the open escalations, oldest first, kept with the rate counts */
    pp_escalation open[PP_OPEN_ESCALATIONS];
    int set_reads[PP_SETS];
    pp_install_set sets[PP_SETS]; /* last, so a provisioning clears all before it and keeps these (IS6) */
} pp_durable;

/* Write the `parts` (PP_PART_* bits) of `durable` that changed, each whole. */
typedef void (*pp_persist_fn)(void *context, const pp_durable *durable, int parts);
/* What the runtime runs: the active release, or with `fallback` set the fallback policy's table when no release
 * decides (FB1), or nothing (NULL), when the runtime refuses (X3). */
typedef void (*pp_runtime_fn)(void *context, const pp_release *active, const pp_statement *fallback);

/* The PEP's configuration, fixed for its life (X10). */
typedef struct {
    pp_target kind;
    int expiry_hold;          /* HOLD at expiry (X6), allowed on mesh and cfs */
    int has_clock;            /* 0 for a PEP with no real time clock (T2) */
    uint8_t instance_seed[32]; /* the instance key (K2), which signs every state record (H2) */
    const pp_layout *layout;  /* AF10: the layout the PEP was built with, NULL for none: it takes no table floor */
    int has_domain;           /* P4, CL4: the hash of the reading domain it was built with */
    uint8_t domain_sha256[32];
    pp_persist_fn persist;
    pp_runtime_fn runtime;
    void *context;
    uint8_t (*table_check)(void *context, const uint8_t *body, size_t len); /* V11, as in pp_pep, given `context` */
    /* RC4: an install statement the PEP applied, a set or an install.trust, once it is durable and before its event,
     * so a run can hold every statement it decided under in the order applied. NULL for none. */
    void (*applied)(void *context, const uint8_t *sealed, size_t sealed_len, const uint8_t *body, size_t body_len);
} pp_config;

#define PP_OUTBOX 6

typedef struct {
    pp_config config;
    pp_durable d;
    uint8_t instance_secret[64], instance_public[32];
    int locked, held;
    uint64_t epoch;           /* H9, H15: in memory only, 0 at every start, at provisioning and at a new key sequence */
    int time_taken;           /* H16: a PEP with no clock took its time floor from a statement in this start */
    long long now; /* the clock reading of the call being made, Unix seconds */
    int commit_due; /* B8: a commit waiting for its delay */
    uint32_t commit_due_ms;
    char due_stream[PP_STREAM_MAX + 1];
    long long due_seq;
    uint8_t due_policy[32];
    pp_install_view install_view; /* what pp_pep_view points the verifier at */
    int message;              /* the statement being staged came in a message (IS4), not by provisioning */
    int stood_out;            /* an install set applied by the last call stood out (IS12) */
    int record_lost;          /* IS10: no copy of the install record reads */
    int set_lost[PP_SETS];    /* IS10: a set the record names that no copy holds */
    pp_answer answer;         /* OP3: the answer the last call applied, `applied` 0 for none */
    int escalating;           /* OP3: the last ask was a floor escalation, which pp_pep_escalated may open */
    uint8_t escalating_policy[32];
    uint8_t escalating_cause;
    size_t n_out;
    size_t out_len[PP_OUTBOX];
    uint8_t out[PP_OUTBOX][PP_RECORD_MAX]; /* the records made by the last call, oldest first (H4) */
} pp_pep_machine;

/* One part of the durable state as bytes, for a store that keeps each part under its own name, such as NVS: only
 * what is used is written. pp_durable_pack answers the length of `part`, 0 when `room` is too small.
 * pp_durable_unpack reads one part into `out`, given NULL when the store holds none of it: answered 0, or -1 for
 * bytes that are not the part, which leaves that part as one that does not read (an anchor or a floor that does
 * not read locks the PEP, a trust store that does not read counts nothing, Q5, K1). Clear `out` before the first. */
#define PP_PART_PACKED_MAX (2 * (PP_MAX_SEALED + PP_INSTALL_BODY_MAX + 512) + 1024) /* the largest part, a set */
size_t pp_durable_pack(const pp_durable *d, int part, uint8_t *out, size_t room);
int pp_durable_unpack(pp_durable *out, int part, const uint8_t *bytes, size_t len);

/* Open the PEP from what it holds durably (NULL for a PEP never provisioned), finishing or reporting an
 * interrupted commit (C4). 0, or -1 when the PEP refuses to start: HOLD on a kind without it, an expiry
 * response other than the one provisioned (X10), or an instance key that is a trusted key (K2). */
int pp_pep_open(pp_pep_machine *pep, const pp_config *config, const pp_durable *durable, long long now);

/* P2 step 4, P3: start again from a confirmed anchor's trust store and stream, a locked PEP included. */
void pp_pep_provision(pp_pep_machine *pep, const pp_trust *anchor, const char *stream, long long now);

/* P4: the `install` member of a `/2` anchor, which the owner's tool reads on the host. `fingerprint` is the anchor's,
 * the install trust id it starts (IS10). */
typedef struct pp_install_anchor_s {
    int present;
    uint8_t keys[PP_INSTALL_KEYS][32];
    size_t n_keys;
    long long threshold;
    uint8_t operators[PP_OPERATOR_KEYS][32];
    size_t n_operators;
    long long seq;
    uint8_t domain[32];
    uint8_t fingerprint[32];
} pp_install_anchor;

/* P2, P4: a trust anchor, `prismpath.dist-trust/1` or `/2`, read into the store it starts, the install member of a /2
 * anchor (`install->present` 0 for none), its stream and its target kind, and its fingerprint, the SHA-256 of its
 * bytes. 0, or PP_CAUSE_NOT_CANONICAL or PP_CAUSE_BAD_FORMAT (a key in a role other than authority, a threshold other
 * than 1, more keys than K5 holds). A /2 anchor's controller key is checked apart from every other key and not held,
 * since this core takes no controller statement (K6, H9), and one with `fresh` other than 0 is refused with
 * PP_CAUSE_BAD_FORMAT, since this core cannot honour freshness (H16). */
uint8_t pp_read_anchor(const uint8_t *bytes, size_t len, pp_trust *trust, struct pp_install_anchor_s *install,
                       char stream[PP_STREAM_MAX + 1], pp_target *target, uint8_t fingerprint[32]);

/* One install statement brought by provisioning (P2 step 3, IS13). */
typedef struct {
    const uint8_t *sealed;
    size_t sealed_len;
    const uint8_t *body;
    size_t body_len;
} pp_brought;

/* P2 step 3 and 4, P3, P4, IS6: provision from an anchor's trust store, its install member (`install` NULL or not
 * present for none) and the install statements the engineer brings. 0, or a cause and the PEP left as it was: an
 * anchor whose keys are not apart (K4, dist:rotation-invalid), whose install trust sequence is below the PEP's or at
 * it with another key set (dist:trust-replay), whose domain is not the PEP's (dist:target-mismatch), or a brought
 * statement that does not verify under the record the provisioning leaves. */
uint8_t pp_pep_provision_install(pp_pep_machine *pep, const pp_trust *anchor, const pp_install_anchor *install,
                                 const char *stream, const pp_brought *brought, size_t n_brought, long long now);

/* IS13: an install provisioning, statements and no anchor, each held to IS5 and IS6 with no message rule. 0, or
 * dist:unknown-key for a PEP that holds no install record. */
uint8_t pp_pep_install_provision(pp_pep_machine *pep, const pp_brought *brought, size_t n_brought, long long now);

/* L2, IS9: 0 when an older signed form may still be read on `stream`, else dist:legacy-refused. */
uint8_t pp_pep_legacy(const pp_pep_machine *pep, const char *stream);

/* H10: the install id of the PEP's install record as it is now (zeros for none). */
void pp_pep_install_id(const pp_pep_machine *pep, uint8_t out[16]);

/* What the verifier needs of this PEP now (verify.PepView), for a caller that verifies ahead of staging, as the
 * frame assembler's admit check does (B9). */
void pp_pep_view(const pp_pep_machine *pep, pp_pep *out);

/* The trust store the PEP holds now. */
static inline const pp_trust *pp_pep_trust(const pp_pep_machine *pep) { return &pep->d.trust; }

/* G1, G2: verify one sealed envelope and its body and hold it. */
void pp_pep_stage(pp_pep_machine *pep, const uint8_t *sealed, size_t sealed_len, const uint8_t *body, size_t body_len,
                  long long now);

/* C1 to C5 and B8: make the staged release named by stream, seq and policy hash active, at `now_ms` plus
 * `delay_ms` of the PEP's monotonic time. A delayed commit flips in pp_pep_tick. */
void pp_pep_commit(pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy_sha256[32],
                   uint16_t delay_ms, uint32_t now_ms, long long now);

/* What pp_pep_commit with no delay would answer at `now` for the release it names: 0 when it would commit, else the
 * cause of its refusal. Nothing changes and no record is made. A runtime whose switch can fail, the cFS table
 * service (section 9.5), switches first under this answer and commits after: at one `now` the two answer alike,
 * since the PEP does nothing in between, so its active record is never ahead of what the runtime holds. */
uint8_t pp_pep_commit_check(pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy_sha256[32],
                            long long now);

/* The same for pp_pep_rollback: 0 when it would roll back, PP_CAUSE_NOT_STAGED when no release is kept. */
uint8_t pp_pep_rollback_check(pp_pep_machine *pep, long long now);

/* A1: drop the staged release the abort names, and change nothing otherwise. */
void pp_pep_abort(pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy_sha256[32], long long now);

/* X1, B8: check expiry, and flip a commit whose delay has passed. */
void pp_pep_tick(pp_pep_machine *pep, uint32_t now_ms, long long now);

/* RB1 to RB3, X9: return to the release the active one replaced. 0, or PP_CAUSE_NOT_STAGED when no release
 * is kept, which writes no record. */
uint8_t pp_pep_rollback(pp_pep_machine *pep, long long now);

/* A step the PEP's runtime refused before the core changed anything, such as a cFS table whose image attestation does
 * not verify: a state record with event refused and `cause`, and nothing else changes. */
void pp_pep_refuse(pp_pep_machine *pep, uint8_t cause, long long now);

/* A state record of the PEP as it is now, after the expiry check (X1). */
void pp_pep_record(pp_pep_machine *pep, uint8_t event, long long now);

/* T2: a PEP with no clock saves the time it has counted from its time floor, at least once an hour, so a restart
 * after a power loss runs slow by the time without power and never fast. */
void pp_pep_save_time(pp_pep_machine *pep, long long now);

/* H9, H16: one controller statement (a frame of type 6 carries one). The epoch id is taken from a statement that
 * reads, names this PEP's stream, verifies under the controller key the trust store holds (not retired, not revoked,
 * K6) and carries the key sequence the store holds for it, when the id is above the one held. Where freshness is on,
 * such a statement may also give freshness, and on a PEP with no clock the first of a start that passes every other
 * check raises the time floor to its `expires` less `fresh`. Anything else changes nothing. No call sends a record.
 * Answers 1 when the epoch id was taken. */
int pp_pep_take_statement(pp_pep_machine *pep, const uint8_t *data, size_t len, long long now);

/* K6: the controller key a statement is verified under, or NULL. */
const uint8_t *pp_pep_controller_key(const pp_pep_machine *pep);

/* X3, X7: the cause every decision is refused with (0 while a release decides), and the hold mark. */
uint8_t pp_pep_decide(pp_pep_machine *pep, int *held_mark, long long now);

/* One decision on a table kind (AF1, AF2, AF7, AF8, FB1, RC1). */
enum { PP_OUT_NONE, PP_OUT_ALLOW, PP_OUT_REFUSE, PP_OUT_ESCALATE };
enum { PP_BASIS_NONE, PP_BASIS_RELEASE, PP_BASIS_FLOOR, PP_BASIS_FALLBACK, PP_BASIS_OPERATOR };
#define PP_AGE_NONE 0xFFFFFFFFu /* AF10: no value of an independent field was ever received */
typedef struct {
    uint8_t outcome;            /* PP_OUT_* */
    uint8_t cause;              /* the cause of a refusal or an escalation, dist:floor-allowed on a floor allow (RC3) */
    uint8_t basis;              /* PP_BASIS_*, none for a refusal made with no set */
    int held_mark;              /* X7, RC2 */
    int has_policy;
    uint8_t policy_sha256[32];  /* the policy hash of the set that decided (RC1) */
    uint8_t would, would_cause; /* AF7: what the release, or the fallback policy, would have answered, none for none */
    int has_would_policy;
    uint8_t would_policy[32];
    int override;               /* AF7: a floor answer whose would is not an allow */
    int counted, rule;          /* AF8: a counted override, its rule (edge), the window start and the count after */
    long long window;
    uint32_t count;
    int rate_escalated;         /* AF8: escalated past the rate, with `rule`, `window` and `count` the spent window */
    int decided_rule;           /* the rule (edge) of the set that decided, -1 for none (a receipt's route target) */
    int would_rule;             /* AF7: the rule of the set `would` names, -1 for none */
} pp_decision;

/* The decision of one request on a `mesh` PEP: `regs` the register file the table reads (a 4 byte prefix, then 8
 * bytes per field, type and value), `ages` the age in seconds of each register's value, PP_AGE_NONE for none, or
 * NULL when no age is known. The action floor is asked first in every state (AF1). It answers only by an edge of
 * its start node, an allow (AF2), and is silent otherwise, when an independent field it tests is stale (AF10) and,
 * past a signed rate, on an override (AF8). Then the active release decides, or the fallback policy when none does
 * (FB1), or the refusal of X3. */
void pp_pep_ask(pp_pep_machine *pep, const uint8_t *regs, size_t regs_len, const uint32_t *ages, long long now,
                pp_decision *out);

/* OP3: open the escalation the last pp_pep_ask made by the action floor, under the hash of the receipt the caller wrote
 * for it and with the request an answer `allow` lets through (at most PP_REQUEST_MAX bytes) and the command it was
 * asked as (at most PP_COMMAND_MAX bytes, or none), durably, the oldest of nine dropped. 0, or dist:not-staged when
 * the last ask was no floor escalation or a bound is passed. */
uint8_t pp_pep_escalated(pp_pep_machine *pep, const uint8_t receipt_sha256[32], const uint8_t *request, size_t len,
                         const uint8_t *command, size_t command_len);

/* H1: the PEP id, the first 16 bytes of the SHA-256 of the instance public key. */
void pp_pep_id(const pp_pep_machine *pep, uint8_t out[16]);

/* AF9, AF10: whether the table `image` is a narrow action floor for `layout` with command register `command`: 0, or
 * dist:floor-broad. One pass over each edge's postfix program with a bounded stack (PP_FLOOR_WALK). */
#define PP_FLOOR_WALK 64
uint8_t pp_floor_narrow(const uint8_t *image, size_t len, const pp_layout *layout, int command);

#endif /* PP_DIST_H */
