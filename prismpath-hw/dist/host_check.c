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
 *   ikey <public hex>   an install key of the PEP's install record, and then
 *   install <threshold> the PEP holds that record (section 21)
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
 *   stop <n>  after n more part writes nothing reaches the store, as a power loss; a restart restores the power
 *   state     the durable state as read back: active, previous and staged, each its seq or "-"
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
#define PP_CEILING_BODY_MAX_TEST 16384

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
 * is packed and kept, a restart reads every part back, and `written` counts the bytes each write took. The parts
 * of section 21 are kept in two copies, as on two media (IS10), and a restart takes the first that reads. */
#define N_PARTS PP_PART_COUNT
static uint8_t parts[N_PARTS][2][PP_PART_PACKED_MAX];
static size_t part_len[N_PARTS][2];
static int part_kept[N_PARTS][2];
static size_t written, writes, largest_write;
static pp_durable saved;
static long stop_after = -1; /* the writes that still reach the store before a power loss, or -1 for no loss */

static void persist(void *context, const pp_durable *durable, int changed) {
    (void)context;
    size_t bytes = 0;
    for (int k = 0; k < N_PARTS; k++) { /* a store writes the parts it is given one after another */
        if (!(changed & (1 << k))) continue;
        if (stop_after == 0) break;      /* the power is gone: nothing more is written */
        if (stop_after > 0) stop_after--;
        size_t n = pp_durable_pack(durable, 1 << k, parts[k][0], sizeof parts[k][0]);
        if (n == 0) {
            fprintf(stderr, "host_check: part %d of the durable state does not pack\n", 1 << k);
            exit(3);
        }
        part_len[k][0] = n;
        part_kept[k][0] = 1;
        if ((1 << k) & PP_PART_COPIED) { /* the second medium */
            memcpy(parts[k][1], parts[k][0], n);
            part_len[k][1] = n;
            part_kept[k][1] = 1;
        }
        bytes += n;
    }
    written += bytes;
    writes++;
    if (bytes > largest_write) largest_write = bytes;
}

/* Read every part back into `saved`, as a restart does, a copied part from its first copy that reads. */
static const pp_durable *reread(void) {
    memset(&saved, 0, sizeof saved);
    for (int k = 0; k < N_PARTS; k++) {
        int copies = ((1 << k) & PP_PART_COPIED) ? 2 : 1, read = 0;
        for (int c = 0; c < copies && !read; c++)
            if (part_kept[k][c]) read = pp_durable_unpack(&saved, 1 << k, parts[k][c], part_len[k][c]) == 0;
        if (!read && !part_kept[k][0] && !(copies == 2 && part_kept[k][1])) pp_durable_unpack(&saved, 1 << k, NULL, 0);
    }
    return saved.provisioned ? &saved : NULL;
}

static int part_index(const char *name) {
    static const char *const names[N_PARTS] = {"anchor", "counter", "trust", "floor", "active", "previous", "staged",
                                               "pending", "install", "rates", "set_floor", "set_fallback",
                                               "set_ceiling"};
    for (int k = 0; k < N_PARTS; k++)
        if (strcmp(names[k], name) == 0) return k;
    return -1;
}

static void print_hex16(const uint8_t *hash) {
    if (hash == NULL) printf("-");
    else
        for (int k = 0; k < 16; k++) printf("%02x", hash[k]);
}

static void print_records(const pp_pep_machine *pep) {
    printf("records");
    for (size_t k = 0; k < pep->n_out; k++) {
        printf(" ");
        for (size_t j = 0; j < pep->out_len[k]; j++) printf("%02x", pep->out[k][j]);
    }
    printf("\n");
}

#define MAX_BROUGHT 8

static void print_decision(const pp_decision *d) {
    printf("ask %u %u %u %d ", d->outcome, d->cause, d->basis, d->held_mark);
    print_hex16(d->has_policy ? d->policy_sha256 : NULL);
    printf(" %u %u ", d->would, d->would_cause);
    print_hex16(d->has_would_policy ? d->would_policy : NULL);
    printf(" %d %d %d %lld %u\n", d->override, d->counted, d->rule, d->window, d->count);
}

/* One machine script, read from stdin up to its "done". Beyond the steps above:
 *
 *   akey <key id hex> <public hex>      a key of the next anchor (anchor_clear empties it, the install part and the
 *   anchor_clear                        statements brought)
 *   ikey | iop <public hex>             an install or operator key of the next anchor's install member
 *   install <threshold> <seq> <domain hex> <fingerprint hex>   the next anchor has an install member
 *   bring <sealed hex> <body hex>       a statement the next provisioning or install provisioning brings
 *   install_provision <now>             IS13
 *   domain <hex>                        the domain hash the PEP was built with
 *   layout <hex> | field <register> <role> <min> <max> <stale>  the layout it was built with (AF10)
 *   ask <now> <regs hex> <ages, comma separated, - for none, or ->
 *   legacy <stream>                     L2, IS9
 *   lose2 <part> | corrupt <part>       the second copy does not read | one byte of the first copy changed
 *   installid
 *
 * print "provision-refused <cause>", "ask ...", "legacy <cause>", "installid <hex>". */
static int machine(const char *args, pp_trust *anchor) {
    static pp_pep_machine pep;
    static pp_config config;
    static pp_layout layout;
    static pp_install_anchor install;
    static uint8_t sealed_bytes[PP_MAX_SEALED + 64], body_bytes[PP_MAX_BODY_TEST];
    static uint8_t brought_sealed[MAX_BROUGHT][PP_MAX_SEALED], brought_body[MAX_BROUGHT][PP_CEILING_BODY_MAX_TEST];
    static pp_brought brought[MAX_BROUGHT];
    static size_t n_brought;
    static char line[2 * (PP_MAX_SEALED + PP_MAX_BODY_TEST) + 256], a[sizeof line], b[sizeof line];
    char seed[80], c[80];
    memset(&config, 0, sizeof config);
    memset(&layout, 0, sizeof layout);
    memset(&install, 0, sizeof install);
    n_brought = 0;
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
        if (!started && strcmp(word, "restart") != 0 && strncmp(word, "lose", 4) != 0 && strcmp(word, "corrupt") != 0 &&
            strcmp(word, "field") != 0 && strcmp(word, "layout") != 0 && strcmp(word, "domain") != 0) {
            printf("refused-start\n");
            continue;
        }
        if (strcmp(word, "provision") == 0) {
            if (sscanf(rest, "%64s %lld", a, &now) != 2) return 2;
            uint8_t cause = pp_pep_provision_install(&pep, anchor, &install, a, brought, n_brought, now);
            if (cause) printf("provision-refused %u\n", cause);
            else print_records(&pep);
            n_brought = 0;
        } else if (strcmp(word, "akey") == 0 && anchor->n_keys < PP_MAX_HELD_KEYS) {
            if (sscanf(rest, "%s %s", a, b) != 2) return 2;
            hash32(a, anchor->keys[anchor->n_keys].id);
            hash32(b, anchor->keys[anchor->n_keys].public_key);
            anchor->keys[anchor->n_keys++].role = PP_ROLE_AUTHORITY;
            anchor->readable = 1;
            continue;
        } else if (strcmp(word, "anchor_clear") == 0) {
            memset(anchor, 0, sizeof *anchor);
            memset(&install, 0, sizeof install);
            n_brought = 0;
            continue;
        } else if (strcmp(word, "ikey") == 0 && install.n_keys < PP_INSTALL_KEYS) {
            hash32(rest, install.keys[install.n_keys++]);
            continue;
        } else if (strcmp(word, "iop") == 0 && install.n_operators < PP_OPERATOR_KEYS) {
            hash32(rest, install.operators[install.n_operators++]);
            continue;
        } else if (strcmp(word, "install") == 0) {
            if (sscanf(rest, "%lld %lld %s %s", &install.threshold, &install.seq, a, b) != 4) return 2;
            hash32(a, install.domain);
            hash32(b, install.fingerprint);
            install.present = 1;
            continue;
        } else if (strcmp(word, "bring") == 0 && n_brought < MAX_BROUGHT) {
            if (sscanf(rest, "%s %s", a, b) != 2) return 2;
            brought[n_brought].sealed = brought_sealed[n_brought];
            brought[n_brought].sealed_len = unhex(a, brought_sealed[n_brought], PP_MAX_SEALED);
            brought[n_brought].body = brought_body[n_brought];
            brought[n_brought].body_len = unhex(b, brought_body[n_brought], PP_CEILING_BODY_MAX_TEST);
            n_brought++;
            continue;
        } else if (strcmp(word, "install_provision") == 0) {
            uint8_t cause = pp_pep_install_provision(&pep, brought, n_brought, strtoll(rest, NULL, 10));
            n_brought = 0;
            if (cause) printf("refused %u\n", cause);
            else print_records(&pep);
        } else if (strcmp(word, "domain") == 0) {
            hash32(rest, config.domain_sha256);
            config.has_domain = 1;
            pep.config.has_domain = 1;
            memcpy(pep.config.domain_sha256, config.domain_sha256, 32);
            continue;
        } else if (strcmp(word, "layout") == 0) {
            hash32(rest, layout.sha256);
            config.layout = pep.config.layout = &layout;
            continue;
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
            continue;
        } else if (strcmp(word, "ask") == 0) {
            static uint32_t ages[64];
            static uint8_t regs[4 + 8 * 64];
            if (sscanf(rest, "%lld %s %s", &now, a, b) != 3) return 2;
            size_t n = unhex(a, regs, sizeof regs), n_ages = 0;
            const uint32_t *given = NULL;
            if (strcmp(b, "-") != 0) {
                for (char *tok = strtok(b, ","); tok && n_ages < 64; tok = strtok(NULL, ","))
                    ages[n_ages++] = strcmp(tok, "-") == 0 ? PP_AGE_NONE : (uint32_t)strtoul(tok, NULL, 10);
                for (size_t k = n_ages; k < 64; k++) ages[k] = PP_AGE_NONE;
                given = ages;
            }
            pp_decision d;
            pp_pep_ask(&pep, regs, n, given, now, &d);
            print_decision(&d);
        } else if (strcmp(word, "legacy") == 0) {
            printf("legacy %u\n", pp_pep_legacy(&pep, rest));
        } else if (strcmp(word, "installid") == 0) {
            uint8_t id[16];
            pp_pep_install_id(&pep, id);
            printf("installid ");
            for (int k = 0; k < 16; k++) printf("%02x", id[k]);
            printf("\n");
        } else if (strcmp(word, "lose2") == 0 || strcmp(word, "corrupt") == 0) {
            int k = part_index(rest);
            if (k < 0) return 2;
            if (word[0] == 'l') {
                memcpy(parts[k][1], "PPD", 3);
                part_len[k][1] = 3;
            } else {
                parts[k][0][part_len[k][0] - 1] ^= 0x01; /* the last byte, in the body of a set part */
            }
            continue;
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
        } else if (strcmp(word, "stop") == 0) {
            stop_after = strtol(rest, NULL, 10);
            printf("records\n");
        } else if (strcmp(word, "state") == 0) {
            const pp_durable *d = reread();
            if (d == NULL) printf("state - - -\n");
            else {
                printf("state ");
                if (d->has_active) printf("%lld ", d->active.seq); else printf("- ");
                if (d->has_previous) printf("%lld ", d->previous.seq); else printf("- ");
                if (d->has_staged) printf("%lld\n", d->staged.seq); else printf("-\n");
            }
        } else if (strcmp(word, "restart") == 0) {
            stop_after = -1;
            started = pp_pep_open(&pep, &config, reread(), strtoll(rest, NULL, 10)) == 0;
            if (started) print_records(&pep);
            else printf("refused-start\n");
        } else if (strcmp(word, "lose") == 0) {
            int k = part_index(strcmp(rest, "setting") == 0 ? "anchor" : rest);
            if (k < 0) return 2;
            memcpy(parts[k][0], "PPD", 3); /* bytes that are not the part */
            part_len[k][0] = 3;
        } else if (strcmp(word, "written") == 0) {
            printf("written %zu %zu %zu\n", written, writes, largest_write); /* since the last "written" */
            written = writes = largest_write = 0;
        } else if (strcmp(word, "sizes") == 0) {
            printf("sizes %zu %zu %zu %zu %zu\n", sizeof(pp_durable), sizeof(pp_release), sizeof(pp_pep_machine),
                   pp_durable_pack(&pep.d, PP_PART_INSTALL, parts[0][1], sizeof parts[0][1]), sizeof(pp_statement));
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
                     int *trust_bounded) {
    static pp_verdict verdict;
    admit_context *ctx = context;
    pp_verify(sealed_part, len, (const uint8_t *)"", 0, ctx->trust, ctx->pep, ctx->now, &verdict);
    if (verdict.cause == 0 || (verdict.cause == PP_CAUSE_BODY_MISMATCH && verdict.envelope.body_size > 0)) {
        *body_size = verdict.envelope.body_size;
        memcpy(hash, verdict.envelope.body_sha256, 32);
        *trust_bounded = verdict.trust_bounded;
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
    static pp_install install;
    static pp_install_view install_view;
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
            memset(&install, 0, sizeof install);
            sealed_len = body_len = 0;
            snprintf(name, sizeof name, "%s", rest);
        } else if (strcmp(word, "key") == 0 && trust.n_keys < PP_MAX_HELD_KEYS) {
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
        } else if (strcmp(word, "ikey") == 0 && install.n_keys < PP_INSTALL_KEYS) {
            pp_ikey *key = &install.keys[install.n_keys++];
            hash32(rest, key->public_key);
            pp_sha256(key->public_key, 32, key->id);
        } else if (strcmp(word, "install") == 0) { /* the PEP holds an install record of these keys (section 21) */
            install.threshold = strtoll(rest, NULL, 10);
            memset(&install_view, 0, sizeof install_view);
            install_view.record = &install;
            install_view.message = 1;
            install_view.trust = &trust;
            pep.install = &install_view;
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
