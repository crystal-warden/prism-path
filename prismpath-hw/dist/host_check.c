/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* host_check.c: a stdio harness for the C core of policy distribution on the host, as
 * integrations/cfs/tests/run_check.c is for the cFS app. prismpath/tests/test_distribution_c.py builds it
 * with the host cc and Monocypher and feeds it the corpus, one case at a time.
 *
 *   host_check < cases      each case is lines of "<word> <values>" ending with "end"
 *
 *   case <name>
 *   key <key id hex> <public hex> <role 0 authority | 1 another>
 *   retired | revoked_key | revoked_envelope | revoked_policy <hex>
 *   raised <stream> <seq>
 *   trust <readable 0|1> <trust_seq> <trust_id hex or -> <time_floor>
 *   pep <kind> <stream> <floor seq> <body bound> <has clock 0|1>
 *   floor_id <hex>
 *   staged <stream> <seq> <policy hex> <release hex> <replaces hex or -> <widens 0|1>
 *   now <seconds>
 *   sealed <hex or ->
 *   body <hex or ->
 *   end
 *
 * prints for each case one line: <name> <cause code> <unchanged 0|1> <time floor or -> <envelope id or ->
 *
 * A machine script drives one enforcement point instead, after the key lines of its anchor:
 *
 *   machine <hold 0|1> <has clock 0|1> <instance seed hex>
 *   provision <stream> <now>
 *   stage <sealed hex> <body hex or -> <now>
 *   commit <stream> <seq> <policy hex> <delay ms> <now ms> <now>
 *   abort <stream> <seq> <policy hex> <now>
 *   tick <now ms> <now>
 *   rollback <now>
 *   record <event code> <now>
 *   epoch <epoch id>
 *   decide <now>
 *   restart <now>
 *   lose anchor | setting | counter | trust | floor | active | previous | staged | pending   (that part's bytes do not read)
 *   written   the bytes the durable writes took since the last "written": total, writes, the largest
 *   sizes     sizeof the durable state, a release and the machine
 *   done
 *
 * and prints one line per step: "records" and the hex of each state record the step made, oldest first,
 * "decide <cause> <held mark>", "none" for a rollback with nothing kept, or "refused-start".
 *
 * An assembler script feeds frames to the reassembly, after the trust and pep lines its admit check uses:
 *
 *   assembler <ordered 0|1> <frame limit> <body bound>
 *   frame <hex> <now ms>
 *   done
 *
 * and prints one line per frame: "none", "whole <sealed hex> <body hex>", "dropped <cause>" or
 * "control <frame type>". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pp_dist.h"

#define PP_MAX_BODY_TEST 65536 /* the largest body the corpus carries is far below this */

static uint8_t sealed[PP_MAX_SEALED + 64], body[PP_MAX_BODY_TEST];

static size_t unhex(const char *text, uint8_t *out, size_t room) {
    size_t n = strlen(text);
    if (strcmp(text, "-") == 0) return 0;
    if (n % 2 || n / 2 > room) {
        fprintf(stderr, "host_check: hex of %zu digits does not fit %zu bytes\n", n, room);
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

/* The durable state as a store that keeps each part under its own name keeps it: each part the PEP says changed
 * is packed and kept, a restart reads every part back, and `written` counts the bytes each write took. */
#define N_PARTS 8
static uint8_t parts[N_PARTS][PP_PART_PACKED_MAX];
static size_t part_len[N_PARTS];
static int part_kept[N_PARTS];
static size_t written, writes, largest_write;
static pp_durable saved;

static void persist(void *context, const pp_durable *durable, int changed) {
    (void)context;
    size_t bytes = 0;
    for (int k = 0; k < N_PARTS; k++) {
        if (!(changed & (1 << k))) continue;
        size_t n = pp_durable_pack(durable, 1 << k, parts[k], sizeof parts[k]);
        if (n == 0) {
            fprintf(stderr, "host_check: part %d of the durable state does not pack\n", 1 << k);
            exit(3);
        }
        part_len[k] = n;
        part_kept[k] = 1;
        bytes += n;
    }
    written += bytes;
    writes++;
    if (bytes > largest_write) largest_write = bytes;
}

/* Read every part back into `saved`, as a restart does. */
static const pp_durable *reread(void) {
    memset(&saved, 0, sizeof saved);
    for (int k = 0; k < N_PARTS; k++)
        if (pp_durable_unpack(&saved, 1 << k, part_kept[k] ? parts[k] : NULL, part_len[k]) != 0) {
            fprintf(stderr, "host_check: part %d does not read back\n", 1 << k);
        }
    return saved.provisioned ? &saved : NULL;
}

static int part_index(const char *name) {
    static const char *const names[N_PARTS] = {"anchor", "counter", "trust", "floor", "active", "previous", "staged",
                                               "pending"};
    for (int k = 0; k < N_PARTS; k++)
        if (strcmp(names[k], name) == 0) return k;
    return -1;
}

static void print_records(const pp_pep_machine *pep) {
    printf("records");
    for (size_t k = 0; k < pep->n_out; k++) {
        printf(" ");
        for (size_t j = 0; j < pep->out_len[k]; j++) printf("%02x", pep->out[k][j]);
    }
    printf("\n");
}

/* One machine script, read from stdin up to its "done". */
static int machine(const char *args, pp_trust *anchor) {
    static pp_pep_machine pep;
    static pp_config config;
    static uint8_t sealed_bytes[PP_MAX_SEALED + 64], body_bytes[PP_MAX_BODY_TEST];
    static char line[2 * (PP_MAX_SEALED + PP_MAX_BODY_TEST) + 256], a[sizeof line], b[sizeof line];
    char seed[80], c[80];
    memset(&config, 0, sizeof config);
    if (sscanf(args, "%d %d %79s", &config.expiry_hold, &config.has_clock, seed) != 3) return 2;
    hash32(seed, config.instance_seed);
    config.kind = PP_TGT_MESH;
    config.persist = persist;
    memset(part_kept, 0, sizeof part_kept);
    written = writes = largest_write = 0;
    int started = pp_pep_open(&pep, &config, NULL, 0) == 0;
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        char word[32];
        int skip = 0;
        if (sscanf(line, "%31s %n", word, &skip) < 1) continue;
        const char *rest = line + skip;
        long long now = 0, seq = 0;
        unsigned delay = 0, now_ms = 0;
        uint8_t policy[32];
        if (strcmp(word, "done") == 0) return 0;
        if (!started && strcmp(word, "restart") != 0 && strcmp(word, "lose") != 0) { printf("refused-start\n"); continue; }
        if (strcmp(word, "provision") == 0) {
            if (sscanf(rest, "%64s %lld", a, &now) != 2) return 2;
            pp_pep_provision(&pep, anchor, a, now);
            print_records(&pep);
        } else if (strcmp(word, "stage") == 0) {
            if (sscanf(rest, "%s %s %lld", a, b, &now) != 3) return 2;
            size_t ns = unhex(a, sealed_bytes, sizeof sealed_bytes), nb = unhex(b, body_bytes, sizeof body_bytes);
            pp_pep_stage(&pep, sealed_bytes, ns, body_bytes, nb, now);
            print_records(&pep);
        } else if (strcmp(word, "commit") == 0) {
            if (sscanf(rest, "%64s %lld %79s %u %u %lld", a, &seq, c, &delay, &now_ms, &now) != 6) return 2;
            hash32(c, policy);
            pp_pep_commit(&pep, a, seq, policy, (uint16_t)delay, now_ms, now);
            print_records(&pep);
        } else if (strcmp(word, "abort") == 0) {
            if (sscanf(rest, "%64s %lld %79s %lld", a, &seq, c, &now) != 4) return 2;
            hash32(c, policy);
            pp_pep_abort(&pep, a, seq, policy, now);
            print_records(&pep);
        } else if (strcmp(word, "tick") == 0) {
            if (sscanf(rest, "%u %lld", &now_ms, &now) != 2) return 2;
            pp_pep_tick(&pep, now_ms, now);
            print_records(&pep);
        } else if (strcmp(word, "rollback") == 0) {
            now = strtoll(rest, NULL, 10);
            if (pp_pep_rollback(&pep, now)) printf("none\n");
            else print_records(&pep);
        } else if (strcmp(word, "record") == 0) {
            unsigned event = 0;
            if (sscanf(rest, "%u %lld", &event, &now) != 2) return 2;
            pp_pep_record(&pep, (uint8_t)event, now);
            print_records(&pep);
        } else if (strcmp(word, "epoch") == 0) {
            pp_pep_see_epoch(&pep, strtoull(rest, NULL, 10));
            printf("records\n");
        } else if (strcmp(word, "decide") == 0) {
            int mark = 0;
            uint8_t cause = pp_pep_decide(&pep, &mark, strtoll(rest, NULL, 10));
            printf("decide %u %d\n", cause, mark);
        } else if (strcmp(word, "restart") == 0) {
            started = pp_pep_open(&pep, &config, reread(), strtoll(rest, NULL, 10)) == 0;
            if (started) print_records(&pep);
            else printf("refused-start\n");
        } else if (strcmp(word, "lose") == 0) {
            int k = part_index(strcmp(rest, "setting") == 0 ? "anchor" : rest);
            if (k < 0) return 2;
            memcpy(parts[k], "PPD", 3); /* bytes that are not the part */
            part_len[k] = 3;
        } else if (strcmp(word, "written") == 0) {
            printf("written %zu %zu %zu\n", written, writes, largest_write); /* since the last "written" */
            written = writes = largest_write = 0;
        } else if (strcmp(word, "sizes") == 0) {
            printf("sizes %zu %zu %zu\n", sizeof(pp_durable), sizeof(pp_release), sizeof(pp_pep_machine));
        } else if (strcmp(word, "setting") == 0) {
            config.expiry_hold = atoi(rest); /* the next restart asks for this expiry response */
        } else {
            fprintf(stderr, "host_check: unknown machine line %s\n", word);
            return 2;
        }
        fflush(stdout);
    }
    return 0;
}

typedef struct {
    const pp_trust *trust;
    const pp_pep *pep;
    long long now;
} admit_context;

/* frames.admit_through_v8: the sealed envelope verified with no body, V9's body mismatch the only refusal
 * that means it passed V2 to V8. */
static uint8_t admit(void *context, const uint8_t *sealed_part, size_t len, long long *body_size, uint8_t hash[32],
                     pp_artifact *artifact) {
    static pp_verdict verdict;
    admit_context *ctx = context;
    pp_verify(sealed_part, len, (const uint8_t *)"", 0, ctx->trust, ctx->pep, ctx->now, &verdict);
    if (verdict.cause == 0 || (verdict.cause == PP_CAUSE_BODY_MISMATCH && verdict.envelope.body_size > 0)) {
        *body_size = verdict.envelope.body_size;
        memcpy(hash, verdict.envelope.body_sha256, 32);
        *artifact = verdict.envelope.artifact;
        return 0;
    }
    return verdict.cause;
}

static void print_hex(const uint8_t *data, size_t len) {
    if (len == 0) printf("-");
    for (size_t k = 0; k < len; k++) printf("%02x", data[k]);
}

static int assembler(const char *args, const pp_trust *trust, const pp_pep *pep, long long now) {
    static pp_assembler a;
    static uint8_t frame[PP_FRAME_LIMIT + 64];
    static char line[2 * (PP_FRAME_LIMIT + 64) + 64];
    int ordered = 0;
    size_t limit = 0;
    long long bound = 0;
    admit_context ctx = {trust, pep, now};
    if (sscanf(args, "%d %zu %lld", &ordered, &limit, &bound) != 3) return 2;
    pp_assembler_init(&a, admit, &ctx, ordered, limit, bound);
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        char word[16], hex[2 * (PP_FRAME_LIMIT + 64) + 8];
        unsigned now_ms = 0;
        if (sscanf(line, "%15s", word) != 1) continue;
        if (strcmp(word, "done") == 0) return 0;
        if (sscanf(line, "%15s %s %u", word, hex, &now_ms) != 3) return 2;
        size_t n = unhex(hex, frame, sizeof frame);
        uint8_t cause = 0;
        int event = pp_assembler_receive(&a, frame, n, now_ms, &cause);
        if (event == PP_ASM_WHOLE) {
            printf("whole ");
            print_hex(a.t.sealed, a.t.sealed_len);
            printf(" ");
            print_hex(a.t.body, a.t.body_len);
            printf("\n");
        } else if (event == PP_ASM_DROPPED) {
            printf("dropped %u\n", cause);
        } else if (event == PP_ASM_CONTROL) {
            printf("control %u\n", frame[0]);
        } else {
            printf("none\n");
        }
    }
    return 0;
}

int main(void) {
    static char line[2 * (PP_MAX_BODY_TEST + 64) + 64];
    static pp_trust trust;
    static pp_pep pep;
    static pp_verdict verdict;
    char name[256] = "", a[256], b[256], c[256], d[256], e[256];
    size_t sealed_len = 0, body_len = 0;
    long long now = 0;
    memset(&trust, 0, sizeof trust);
    memset(&pep, 0, sizeof pep);
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        char word[32];
        int skip = 0;
        if (sscanf(line, "%31s %n", word, &skip) < 1) continue;
        const char *rest = line + skip;
        if (strcmp(word, "case") == 0) {
            memset(&trust, 0, sizeof trust);
            memset(&pep, 0, sizeof pep);
            sealed_len = body_len = 0;
            snprintf(name, sizeof name, "%s", rest);
        } else if (strcmp(word, "key") == 0 && trust.n_keys < PP_MAX_KEYS) {
            int role = 0;
            if (sscanf(rest, "%255s %255s %d", a, b, &role) != 3) return 2;
            hash32(a, trust.keys[trust.n_keys].id);
            hash32(b, trust.keys[trust.n_keys].public_key);
            trust.keys[trust.n_keys++].role = (uint8_t)role;
        } else if (strcmp(word, "retired") == 0 && trust.n_retired < PP_MAX_RETIRED) {
            hash32(rest, trust.retired[trust.n_retired++]);
        } else if (strcmp(word, "revoked_key") == 0 && trust.n_revoked_keys < PP_MAX_LIST) {
            hash32(rest, trust.revoked_keys[trust.n_revoked_keys++]);
        } else if (strcmp(word, "revoked_envelope") == 0 && trust.n_revoked_envelopes < PP_MAX_LIST) {
            hash32(rest, trust.revoked_envelopes[trust.n_revoked_envelopes++]);
        } else if (strcmp(word, "revoked_policy") == 0 && trust.n_revoked_policies < PP_MAX_LIST) {
            hash32(rest, trust.revoked_policies[trust.n_revoked_policies++]);
        } else if (strcmp(word, "raised") == 0 && trust.n_floors < PP_MAX_FLOORS) {
            pp_raised_floor *floor = &trust.floors[trust.n_floors++];
            if (sscanf(rest, "%64s %lld", floor->stream, &floor->seq) != 2) return 2;
        } else if (strcmp(word, "trust") == 0) {
            if (sscanf(rest, "%d %lld %255s %lld", &trust.readable, &trust.trust_seq, a, &trust.time_floor) != 4) return 2;
            trust.has_trust_id = strcmp(a, "-") != 0;
            if (trust.has_trust_id) hash32(a, trust.trust_id);
        } else if (strcmp(word, "pep") == 0) {
            if (sscanf(rest, "%255s %64s %lld %lld %d", a, pep.stream, &pep.floor_seq, &pep.body_bound, &pep.has_clock) != 5)
                return 2;
            pep.kind = PP_TGT_COUNT;
            for (int k = 0; k < PP_TGT_COUNT; k++)
                if (strcmp(a, pp_target_name((pp_target)k)) == 0) pep.kind = (pp_target)k;
        } else if (strcmp(word, "floor_id") == 0 && pep.n_floor_ids < PP_MAX_FLOOR_IDS) {
            hash32(rest, pep.floor_ids[pep.n_floor_ids++]);
        } else if (strcmp(word, "staged") == 0) {
            pp_staged *st = &pep.staged;
            if (sscanf(rest, "%64s %lld %255s %255s %255s %d", st->stream, &st->seq, c, d, e, &st->widens) != 6) return 2;
            hash32(c, st->policy_sha256);
            hash32(d, st->release);
            st->has_replaces = strcmp(e, "-") != 0;
            if (st->has_replaces) hash32(e, st->replaces);
            pep.has_staged = 1;
        } else if (strcmp(word, "now") == 0) {
            now = strtoll(rest, NULL, 10);
        } else if (strcmp(word, "sealed") == 0) {
            sealed_len = unhex(rest, sealed, sizeof sealed);
        } else if (strcmp(word, "body") == 0) {
            body_len = unhex(rest, body, sizeof body);
        } else if (strcmp(word, "assembler") == 0) {
            int r = assembler(rest, &trust, &pep, now);
            if (r) return r;
        } else if (strcmp(word, "machine") == 0) {
            int r = machine(rest, &trust);
            if (r) return r;
            memset(&trust, 0, sizeof trust);
        } else if (strcmp(word, "end") == 0) {
            pp_verify(sealed, sealed_len, body, body_len, &trust, &pep, now, &verdict);
            char floor_text[32] = "-", id[65] = "-";
            if (verdict.has_time_floor) snprintf(floor_text, sizeof floor_text, "%lld", verdict.time_floor);
            if (verdict.has_envelope)
                for (int k = 0; k < 32; k++) snprintf(id + 2 * k, 3, "%02x", verdict.envelope.envelope_id[k]);
            printf("%s %u %d %s %s\n", name, verdict.cause, verdict.unchanged, floor_text, id);
        } else {
            fprintf(stderr, "host_check: unknown line %s\n", word);
            return 2;
        }
    }
    return 0;
}
