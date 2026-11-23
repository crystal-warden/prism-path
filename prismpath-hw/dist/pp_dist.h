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
#define PP_CAUSE_SIG_INVALID 2            /* sig:invalid */
#define PP_CAUSE_SIG_REVOKED_KEY 3        /* sig:revoked-key */
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
#define PP_CAUSE_TOO_LARGE 148            /* dist:too-large */
#define PP_CAUSE_FRAME_INVALID 150        /* dist:frame-invalid */
#define PP_CAUSE_WIDENING_UNSIGNED 143    /* dist:widening-unsigned */
#define PP_CAUSE_NOT_STAGED 151           /* dist:not-staged */
#define PP_CAUSE_INCOMPLETE 152           /* dist:incomplete */
#define PP_CAUSE_POLICY_LAPSED 153        /* dist:policy-lapsed */
#define PP_CAUSE_FLOOR_LOST 154           /* dist:floor-lost */
#define PP_CAUSE_HELD 159                 /* dist:held */

/* ------------------------------------------------------------------ bounds */
#define PP_MAX_ENVELOPE 2048  /* E6 */
#define PP_MAX_ENTRIES 4      /* S2 */
#define PP_ENTRY_SIZE 96      /* a 32 byte key id and a 64 byte signature */
#define PP_MAX_SEALED (6 + PP_ENTRY_SIZE * PP_MAX_ENTRIES + 2 + PP_MAX_ENVELOPE) /* 2,440 bytes (B9) */
#define PP_MAX_BODY 16777215LL /* E1 body_size */
#define PP_MAX_SEQ 9007199254740991LL
#define PP_SKEW 300           /* section 7 */
#define PP_STREAM_MAX 64
#define PP_MAX_KEYS 8         /* keys a trust store holds */
#define PP_MAX_LIST 64        /* entries of one revocation list (R7) */
#define PP_MAX_FLOORS 8       /* streams whose floor a revocation raised */
#define PP_MAX_FLOOR_IDS 4    /* envelope ids committed at one floor */
#define PP_MESH_TABLE_MAX 640 /* E6: TBL_MAX in prismpath-hw/mesh/main/ppt_mesh.c */
#define PP_META_MAX_DEPTH 3   /* E9: the scanner's bound on meta's nesting */

/* ------------------------------------------------------------------ the kinds (section 3) */
typedef enum {
    PP_ART_POLICY_CORE, PP_ART_POLICY_PPT, PP_ART_POLICY_SPIRAL, PP_ART_SANDBOX_PROFILE, PP_ART_EGRESS_HOSTS,
    PP_ART_GATEWAY_ROUTES, PP_ART_NET_DESTS, PP_ART_NET_EDGE, PP_ART_CFS_TABLE, PP_ART_GRANT,
    PP_ART_TRUST_WIDENING, PP_ART_TRUST_REVOCATION, PP_ART_TRUST_ROTATION, PP_ART_COUNT
} pp_artifact;

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
} pp_envelope;

#define PP_ROLE_AUTHORITY 0 /* K4: the one role this version knows */
#define PP_ROLE_OTHER 1     /* a key in a role this version does not know is kept and never counts */

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
    pp_key keys[PP_MAX_KEYS];
    size_t n_keys;
    uint8_t retired[PP_MAX_LIST][32];
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

/* What the verifier needs of an enforcement point (verify.PepView). */
typedef struct {
    pp_target kind;                 /* PP_TGT_MESH or PP_TGT_CFS */
    char stream[PP_STREAM_MAX + 1];
    long long floor_seq;
    uint8_t floor_ids[PP_MAX_FLOOR_IDS][32];
    size_t n_floor_ids;
    int has_staged;
    pp_staged staged;
    long long body_bound;           /* the PEP's own bound on a body, within its kind's (E6) */
    int has_clock;                  /* 0 for a PEP with no real time clock (T2), which never applies T3 */
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
#define PP_ASSEMBLER_BODY_MAX PP_MESH_TABLE_MAX /* the largest body this build assembles */
#endif

/* The enforcement point's check of a whole sealed envelope through V8 (B9): 0 and the signed body_size and
 * body_sha256, or the verifier's cause. */
typedef uint8_t (*pp_admit_fn)(void *context, const uint8_t *sealed, size_t len, long long *body_size,
                               uint8_t body_sha256[32]);

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
    uint8_t sealed_have[PP_MAX_SEALED];
    uint8_t body[PP_ASSEMBLER_BODY_MAX];
    uint8_t body_have[PP_ASSEMBLER_BODY_MAX];
} pp_transfer;

typedef struct {
    pp_transfer t;
    int ordered; /* B11: the link is declared ordered */
    size_t limit; /* the link's frame limit */
    long long body_bound;
    pp_admit_fn admit;
    void *context;
} pp_assembler;

#define PP_ASM_NONE 0    /* nothing to act on yet */
#define PP_ASM_WHOLE 1   /* the transfer is whole: sealed and body in the assembler, to verify and stage */
#define PP_ASM_DROPPED 2 /* a transfer dropped with `cause` */
#define PP_ASM_CONTROL 3 /* a state, commit, abort or epoch frame, for the caller */

void pp_assembler_init(pp_assembler *a, pp_admit_fn admit, void *context, int ordered, size_t limit,
                       long long body_bound);

/* One frame's bytes at the PEP's monotonic time `now_ms`. Answers PP_ASM_* with the cause of a drop. */
int pp_assembler_receive(pp_assembler *a, const uint8_t *frame, size_t len, uint32_t now_ms, uint8_t *cause);

/* ------------------------------------------------------------------ the enforcement point machine (section 9) */

#define PP_RELEASE_BODY_MAX PP_MESH_TABLE_MAX /* every body of a mesh release is within the kind's bound */
#define PP_RECORD_MAX (148 + 64)              /* a state record with no Facet body and no extension (H1, H5) */

/* H1 event and state codes, in the order of state_record.EVENTS and STATES. */
enum { PP_EV_BEAT, PP_EV_STAGED, PP_EV_REFUSED, PP_EV_COMMITTED, PP_EV_ABORTED, PP_EV_TRUST_APPLIED, PP_EV_LAPSED,
       PP_EV_ROLLED_BACK, PP_EV_PROVISIONED, PP_EV_HELD };
enum { PP_ST_NO_POLICY, PP_ST_ACTIVE, PP_ST_LOCKED };

typedef struct {
    pp_envelope envelope;
    size_t body_len;
    uint8_t body[PP_RELEASE_BODY_MAX];
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
    pp_artifact_held held[2]; /* a mesh release holds a policy.ppt and may hold a trust.widening */
} pp_release;

/* Everything the PEP keeps durably, each part with whether it reads. The caller's `persist` writes it, the
 * whole of it or nothing (C4), and a restart opens the PEP from it. */
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
    int has_active, has_previous, has_staged, has_pending, pending_rollback;
    pp_release active, previous, staged, pending;
} pp_durable;

typedef void (*pp_persist_fn)(void *context, const pp_durable *durable);
typedef void (*pp_runtime_fn)(void *context, const pp_release *active); /* NULL: the runtime refuses (X3) */

/* The PEP's configuration, fixed for its life (X10). */
typedef struct {
    pp_target kind;
    int expiry_hold;          /* HOLD at expiry (X6), allowed on mesh and cfs */
    int has_clock;            /* 0 for a PEP with no real time clock (T2) */
    uint8_t instance_seed[32]; /* the instance key (K2), which signs every state record (H2) */
    pp_persist_fn persist;
    pp_runtime_fn runtime;
    void *context;
} pp_config;

#define PP_OUTBOX 4

typedef struct {
    pp_config config;
    pp_durable d;
    uint8_t instance_secret[64], instance_public[32];
    int locked, held;
    uint64_t epoch;
    long long now; /* the clock reading of the call being made, Unix seconds */
    int commit_due; /* B8: a commit waiting for its delay */
    uint32_t commit_due_ms;
    char due_stream[PP_STREAM_MAX + 1];
    long long due_seq;
    uint8_t due_policy[32];
    size_t n_out;
    size_t out_len[PP_OUTBOX];
    uint8_t out[PP_OUTBOX][PP_RECORD_MAX]; /* the records made by the last call, oldest first (H4) */
} pp_pep_machine;

/* Open the PEP from what it holds durably (NULL for a PEP never provisioned), finishing or reporting an
 * interrupted commit (C4). 0, or -1 when the PEP refuses to start: HOLD on a kind without it, an expiry
 * response other than the one provisioned (X10), or an instance key that is a trusted key (K2). */
int pp_pep_open(pp_pep_machine *pep, const pp_config *config, const pp_durable *durable, long long now);

/* P2 step 4, P3: start again from a confirmed anchor's trust store and stream, a locked PEP included. */
void pp_pep_provision(pp_pep_machine *pep, const pp_trust *anchor, const char *stream, long long now);

/* G1, G2: verify one sealed envelope and its body and hold it. */
void pp_pep_stage(pp_pep_machine *pep, const uint8_t *sealed, size_t sealed_len, const uint8_t *body, size_t body_len,
                  long long now);

/* C1 to C5 and B8: make the staged release named by stream, seq and policy hash active, at `now_ms` plus
 * `delay_ms` of the PEP's monotonic time. A delayed commit flips in pp_pep_tick. */
void pp_pep_commit(pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy_sha256[32],
                   uint16_t delay_ms, uint32_t now_ms, long long now);

/* A1: drop the staged release the abort names, and change nothing otherwise. */
void pp_pep_abort(pp_pep_machine *pep, const char *stream, long long seq, const uint8_t policy_sha256[32], long long now);

/* X1, B8: check expiry, and flip a commit whose delay has passed. */
void pp_pep_tick(pp_pep_machine *pep, uint32_t now_ms, long long now);

/* RB1 to RB3, X9: return to the release the active one replaced. 0, or PP_CAUSE_NOT_STAGED when no release
 * is kept, which writes no record. */
uint8_t pp_pep_rollback(pp_pep_machine *pep, long long now);

/* A state record of the PEP as it is now, after the expiry check (X1). */
void pp_pep_record(pp_pep_machine *pep, uint8_t event, long long now);

/* H9: keep the highest epoch id the controller sent. */
void pp_pep_see_epoch(pp_pep_machine *pep, uint64_t epoch);

/* X3, X7: the cause every decision is refused with (0 while a release decides), and the hold mark. */
uint8_t pp_pep_decide(pp_pep_machine *pep, int *held_mark, long long now);

#endif /* PP_DIST_H */
