/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* host_check_min.c: a stdio harness for the constrained profile (B12), pp_dist.c built with PP_DIST_PROFILE_MIN.
 * prismpath/tests/test_distribution_c_min.py builds it with the host cc and drives it with the lines host_check.c
 * reads, so the same corpus cases and machine scripts run on both builds.
 *
 * A corpus case (case, key, retired, revoked_key, raised, trust, pep, floor_id, staged, now, sealed, body, end) prints
 * <name> <cause code> <unchanged 0|1> <time floor or -> <envelope id or ->. Every byte it is handed goes to the PEP in
 * pieces of `piece` bytes (7 unless a "piece <n>" line says otherwise) from one small buffer that is written over after
 * each call, so the PEP never reads a byte twice and never holds the envelope whole.
 *
 * A machine script (key, then machine <hold 0> <has clock 0|1> <instance seed hex>, provision, stage, commit, abort,
 * tick, record, restart, lose, sizes, done) prints the records each step sent, as host_check.c does. There a line
 * "frame <hex> <now ms> <now>" hands one frame of the ordered link to pp_min_frame and prints its event, as the frame
 * script below does, then the records it sent.
 *
 * A frame script (the trust and pep lines of a case, then assembler <ordered 1> <frame limit> <body bound>, frame
 * <hex> <now ms>, done) prints for each frame "none", "whole", "dropped <cause>" or "control <type>", and "records"
 * with the hex of each record the frame made after a frame that sent any. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pp_dist.h"

#define BODY_ROOM 65536

static uint8_t sealed[PP_MAX_SEALED + 64], body[BODY_ROOM], table[PP_MESH_TABLE_MAX], active_table[PP_MESH_TABLE_MAX];
static size_t piece = 7;

static size_t unhex(const char *text, uint8_t *out, size_t room) {
    size_t n = strlen(text);
    if (strcmp(text, "-") == 0) return 0;
    if (n % 2 || n / 2 > room) {
        fprintf(stderr, "host_check_min: hex of %zu digits does not fit %zu bytes\n", n, room);
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

/* The store: the durable state as the last write left it, and the active table beside it. */
static pp_min_durable saved;
static int has_saved, saved_reads = 1;

static int persist(void *context, const pp_min_durable *d, int what) {
    (void)context;
    saved = *d;
    has_saved = 1;
    saved_reads = 1;
    if (what & PP_MIN_TABLE) memcpy(active_table, table, sizeof table);
    return 0;
}

/* The records one step sent, oldest first. */
static uint8_t out[16][PP_RECORD_PLAIN];
static size_t n_out;

static void send(void *context, const uint8_t *record, size_t len) {
    (void)context;
    if (n_out < 16 && len == PP_RECORD_PLAIN) memcpy(out[n_out++], record, len);
}

static void print_records(void) {
    printf("records");
    for (size_t k = 0; k < n_out; k++) {
        printf(" ");
        for (size_t j = 0; j < PP_RECORD_PLAIN; j++) printf("%02x", out[k][j]);
    }
    printf("\n");
    n_out = 0;
}

/* Hand `n` bytes to `feed` in pieces, each copied into one small buffer that is written over after the call. */
static int feed(pp_min *pep, const uint8_t *bytes, size_t n, int sealed_part) {
    static uint8_t window[64];
    int read = 0;
    for (size_t at = 0; at < n;) {
        size_t take = n - at < piece ? n - at : piece;
        memcpy(window, bytes + at, take);
        if (sealed_part) read = pp_min_sealed(pep, window, take);
        else pp_min_body(pep, window, take);
        memset(window, 0xA5, sizeof window);
        at += take;
        if (sealed_part && read != 0) break;
    }
    return read;
}

static void config_for(pp_min_config *config, const char *seed, int has_clock, size_t room) {
    memset(config, 0, sizeof *config);
    if (seed) hash32(seed, config->instance_seed);
    config->has_clock = has_clock;
    config->table = table;
    config->table_room = room < sizeof table ? room : sizeof table;
    config->persist = persist;
    config->send = send;
}

static int staged_names(const pp_min *pep, const char *stream) { return strcmp(stream, pep->d.stream) == 0; }

static int machine(const char *args, const uint8_t key[32], int has_key) {
    static pp_min pep;
    static pp_min_config config;
    static char line[2 * (PP_MAX_SEALED + BODY_ROOM) + 256], a[sizeof line], b[sizeof line];
    char seed[80];
    int hold = 0, clock = 1;
    if (sscanf(args, "%d %d %79s", &hold, &clock, seed) != 3 || hold) return 2; /* B12: REFUSE only */
    config_for(&config, seed, clock, sizeof table);
    has_saved = 0;
    saved_reads = 1;
    n_out = 0;
    int started = pp_min_open(&pep, &config, NULL, 1, 0) == 0;
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        char word[32], stream[PP_STREAM_MAX + 2];
        int skip = 0;
        if (sscanf(line, "%31s %n", word, &skip) < 1) continue;
        const char *rest = line + skip;
        long long now = 0, seq = 0;
        unsigned delay = 0, now_ms = 0;
        int event = 0;
        uint8_t policy[32];
        if (strcmp(word, "done") == 0) return 0;
        if (!started && strcmp(word, "restart") != 0 && strcmp(word, "lose") != 0) {
            printf("refused-start\n");
            continue;
        }
        if (strcmp(word, "provision") == 0) {
            if (sscanf(rest, "%65s %lld", stream, &now) != 2 || !has_key) return 2;
            uint8_t cause = pp_min_provision(&pep, key, stream, now);
            if (cause) printf("provision-refused %u\n", cause);
            else print_records();
        } else if (strcmp(word, "stage") == 0) {
            if (sscanf(rest, "%s %s %lld", a, b, &now) != 3) return 2;
            size_t sealed_len = unhex(a, sealed, sizeof sealed), body_len = unhex(b, body, sizeof body);
            pp_min_begin(&pep, sealed_len, body_len, now);
            if (feed(&pep, sealed, sealed_len, 1) == 1) feed(&pep, body, body_len, 0);
            pp_min_stage(&pep);
            print_records();
        } else if (strcmp(word, "commit") == 0) {
            if (sscanf(rest, "%65s %lld %64s %u %u %lld", stream, &seq, a, &delay, &now_ms, &now) != 6) return 2;
            hash32(a, policy);
            if (!staged_names(&pep, stream)) memset(policy, 0, 32);
            pp_min_commit(&pep, seq, policy, (uint16_t)delay, now_ms, now);
            print_records();
        } else if (strcmp(word, "abort") == 0) {
            if (sscanf(rest, "%65s %lld %64s %lld", stream, &seq, a, &now) != 4) return 2;
            hash32(a, policy);
            if (!staged_names(&pep, stream)) memset(policy, 0, 32);
            pp_min_abort(&pep, seq, policy, now);
            print_records();
        } else if (strcmp(word, "tick") == 0) {
            if (sscanf(rest, "%u %lld", &now_ms, &now) != 2) return 2;
            pp_min_tick(&pep, now_ms, now);
            print_records();
        } else if (strcmp(word, "record") == 0) {
            if (sscanf(rest, "%d %lld", &event, &now) != 2) return 2;
            pp_min_record(&pep, (uint8_t)event, now);
            print_records();
        } else if (strcmp(word, "frame") == 0) { /* one frame from the ordered link: its event line, then its records */
            static uint8_t frame[PP_FRAME_LIMIT + 64];
            if (sscanf(rest, "%s %u %lld", a, &now_ms, &now) != 3) return 2;
            size_t n = unhex(a, frame, sizeof frame);
            uint8_t type = frame[0], cause = 0;
            int got = pp_min_frame(&pep, frame, n, now_ms, now, &cause);
            memset(frame, 0xA5, sizeof frame);
            if (got == PP_ASM_WHOLE) printf("whole\n");
            else if (got == PP_ASM_DROPPED) printf("dropped %u\n", cause);
            else if (got == PP_ASM_CONTROL) printf("control %u\n", type);
            else printf("none\n");
            print_records();
        } else if (strcmp(word, "save_time") == 0) {
            pp_min_save_time(&pep, strtoll(rest, NULL, 10));
        } else if (strcmp(word, "restart") == 0) {
            started = pp_min_open(&pep, &config, has_saved ? &saved : NULL, saved_reads, strtoll(rest, NULL, 10)) == 0;
            if (started) print_records();
            else printf("refused-start\n");
        } else if (strcmp(word, "lose") == 0) { /* the one part does not read */
            saved_reads = 0;
        } else if (strcmp(word, "sizes") == 0) {
            printf("sizes %zu %zu %zu %zu\n", sizeof(pp_min), sizeof(pp_min_durable), sizeof(pp_min_verify),
                   sizeof(pp_min_reader));
        } else {
            fprintf(stderr, "host_check_min: unknown machine line %s\n", word);
            return 2;
        }
    }
    return 0;
}

/* The PEP a corpus case describes, held as the profile holds it. */
typedef struct {
    int has_key, readable, has_clock, revoked, retired;
    uint8_t key[32], key_id[32];
    char stream[PP_STREAM_MAX + 2], raised_stream[PP_STREAM_MAX + 2];
    long long trust_seq, time_floor, floor_seq, raised, body_bound;
    int has_trust_id, n_floor_ids, has_staged;
    uint8_t trust_id[32], floor_ids[PP_MIN_FLOOR_IDS][32];
    pp_min_release staged;
} case_state;

static void open_case(pp_min *pep, pp_min_config *config, const case_state *c, long long now) {
    config_for(config, NULL, c->has_clock, (size_t)(c->body_bound < 0 ? 0 : c->body_bound));
    pp_min_open(pep, config, NULL, 1, now);
    pp_min_durable *d = &pep->d;
    d->provisioned = 1;
    if (c->has_key && c->readable) {
        d->key_state = c->revoked ? PP_MIN_KEY_REVOKED : c->retired ? PP_MIN_KEY_RETIRED : PP_MIN_KEY_COUNTS;
        memcpy(d->key, c->key, 32);
        memcpy(d->key_id, c->key_id, 32);
    }
    memcpy(d->stream, c->stream, strlen(c->stream) + 1);
    d->trust_seq = c->trust_seq;
    d->time_floor = c->time_floor;
    d->has_trust_id = (uint8_t)c->has_trust_id;
    memcpy(d->trust_id, c->trust_id, 32);
    d->floor_seq = c->floor_seq;
    d->raised = strcmp(c->raised_stream, c->stream) == 0 ? c->raised : 0;
    d->n_floor_ids = (uint8_t)c->n_floor_ids;
    memcpy(d->floor_ids, c->floor_ids, sizeof d->floor_ids);
    d->has_staged = (uint8_t)c->has_staged;
    d->staged = c->staged;
    pep->now = now;
}

static int frames(const char *args, const case_state *c, long long now) {
    static pp_min pep;
    static pp_min_config config;
    static uint8_t frame[PP_FRAME_LIMIT + 64];
    static char line[2 * (PP_FRAME_LIMIT + 64) + 64];
    int ordered = 0;
    size_t limit = 0;
    long long bound = 0;
    if (sscanf(args, "%d %zu %lld", &ordered, &limit, &bound) != 3 || !ordered) return 2; /* B11: ordered only */
    open_case(&pep, &config, c, now);
    n_out = 0;
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        char word[16], hex[2 * (PP_FRAME_LIMIT + 64) + 8];
        unsigned now_ms = 0;
        if (sscanf(line, "%15s", word) != 1) continue;
        if (strcmp(word, "done") == 0) return 0;
        if (sscanf(line, "%15s %s %u", word, hex, &now_ms) != 3) return 2;
        size_t n = unhex(hex, frame, sizeof frame);
        uint8_t cause = 0;
        uint8_t type = frame[0];
        int event = pp_min_frame(&pep, frame, n, now_ms, now, &cause);
        memset(frame, 0xA5, sizeof frame); /* nothing of a frame is read after its call */
        if (event == PP_ASM_WHOLE) printf("whole\n");
        else if (event == PP_ASM_DROPPED) printf("dropped %u\n", cause);
        else if (event == PP_ASM_CONTROL) printf("control %u\n", type);
        else printf("none\n");
        if (n_out) print_records();
    }
    return 0;
}

int main(void) {
    static char line[2 * (BODY_ROOM + 64) + 64];
    static case_state c;
    static pp_min pep;
    static pp_min_config config;
    char name[256] = "", a[256], b[256], d[256], e[256];
    size_t sealed_len = 0, body_len = 0;
    long long now = 0;
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        char word[32];
        int skip = 0, role = 0;
        if (sscanf(line, "%31s %n", word, &skip) < 1) continue;
        const char *rest = line + skip;
        if (strcmp(word, "case") == 0) {
            memset(&c, 0, sizeof c);
            sealed_len = body_len = 0;
            snprintf(name, sizeof name, "%s", rest);
        } else if (strcmp(word, "piece") == 0) {
            piece = (size_t)strtoul(rest, NULL, 10);
            if (piece < 1 || piece > 64) return 2;
        } else if (strcmp(word, "key") == 0) { /* B12: one authority key and no other */
            if (sscanf(rest, "%255s %255s %d", a, b, &role) != 3 || role != 0 || c.has_key) {
                fprintf(stderr, "host_check_min: the profile holds one authority key\n");
                return 2;
            }
            hash32(a, c.key_id);
            hash32(b, c.key);
            c.has_key = 1;
        } else if (strcmp(word, "retired") == 0 || strcmp(word, "revoked_key") == 0) {
            uint8_t id[32];
            hash32(rest, id);
            if (!c.has_key || memcmp(id, c.key_id, 32) != 0) return 2; /* it keeps no other key's id */
            if (strcmp(word, "retired") == 0) c.retired = 1;
            else c.revoked = 1;
        } else if (strcmp(word, "raised") == 0) {
            if (sscanf(rest, "%65s %lld", c.raised_stream, &c.raised) != 2) return 2;
        } else if (strcmp(word, "trust") == 0) {
            if (sscanf(rest, "%d %lld %255s %lld", &c.readable, &c.trust_seq, a, &c.time_floor) != 4) return 2;
            c.has_trust_id = strcmp(a, "-") != 0;
            if (c.has_trust_id) hash32(a, c.trust_id);
        } else if (strcmp(word, "pep") == 0) {
            if (sscanf(rest, "%255s %65s %lld %lld %d", a, c.stream, &c.floor_seq, &c.body_bound, &c.has_clock) != 5 ||
                strcmp(a, "mesh") != 0)
                return 2;
        } else if (strcmp(word, "floor_id") == 0) {
            if (c.n_floor_ids >= PP_MIN_FLOOR_IDS) return 2;
            hash32(rest, c.floor_ids[c.n_floor_ids++]);
        } else if (strcmp(word, "staged") == 0) {
            char stream[PP_STREAM_MAX + 2];
            int widens = 0;
            if (sscanf(rest, "%65s %lld %255s %255s %255s %d", stream, &c.staged.seq, b, d, e, &widens) != 6) return 2;
            hash32(b, c.staged.policy_sha256);
            hash32(d, c.staged.release);
            c.staged.has_replaces = strcmp(e, "-") != 0;
            if (c.staged.has_replaces) hash32(e, c.staged.replaces);
            c.staged.widens = (uint8_t)widens;
            c.has_staged = 1;
        } else if (strcmp(word, "now") == 0) {
            now = strtoll(rest, NULL, 10);
        } else if (strcmp(word, "sealed") == 0) {
            sealed_len = unhex(rest, sealed, sizeof sealed);
        } else if (strcmp(word, "body") == 0) {
            body_len = unhex(rest, body, sizeof body);
        } else if (strcmp(word, "assembler") == 0) {
            int r = frames(rest, &c, now);
            if (r) return r;
        } else if (strcmp(word, "machine") == 0) {
            int r = machine(rest, c.key, c.has_key);
            if (r) return r;
            memset(&c, 0, sizeof c);
        } else if (strcmp(word, "end") == 0) {
            open_case(&pep, &config, &c, now);
            pp_min_begin(&pep, sealed_len, body_len, now);
            if (feed(&pep, sealed, sealed_len, 1) == 1) feed(&pep, body, body_len, 0);
            uint8_t cause = pp_min_verdict(&pep);
            char floor_text[32] = "-", id[65] = "-";
            if (pep.v.has_time_floor) snprintf(floor_text, sizeof floor_text, "%lld", pep.v.time_floor);
            if (pep.v.has_envelope)
                for (int k = 0; k < 32; k++) snprintf(id + 2 * k, 3, "%02x", pep.v.envelope_id[k]);
            printf("%s %u %d %s %s\n", name, cause, pep.v.unchanged, floor_text, id);
        } else {
            fprintf(stderr, "host_check_min: unknown line %s\n", word);
            return 2;
        }
    }
    return 0;
}
