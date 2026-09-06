// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* Hot-swap migration enforcement for the stateful selector — the loader adjusts resident state on a
 * policy swap per the NEW policy's signed strategy, so a raw node index is never carried blindly across
 * a reindexing swap.
 *
 * The demo advances the resident posture to `lockdown` IN-KERNEL under policy A (posture_selector:
 * normal=0 elevated=1 lockdown=2), then swaps to a REINDEXED policy B (posture_selector_v2:
 * normal=0 lockdown=1 elevated=2 — same names, different indices) and migrates:
 *   - by-name: the loader re-resolves the current node's NAME hash in B -> B's lockdown (idx 1), so the
 *     posture is preserved; a raw carry of idx 2 would land on B's 'elevated' (wrong);
 *   - reset-to: the loader resets to B's fail-safe (lockdown) on swap.
 * Both policies' per-node name hashes ride the signed image, so the migration is tamper-evident.
 *
 *   python3 gen_migrate_fixtures.py     # writes migrate_A.ppt / migrate_Bname.ppt / migrate_Breset.ppt
 *   gcc -O2 -Wno-unused-function -I. migrate_selector.c -o migrate_selector -lcrypto $(pkg-config --libs libbpf)
 *   sudo ./migrate_selector ppt_select.bpf.o
 */
#define main loader_orig_main
#include "loader.c"
#undef main
#include "merkle.h"   /* the one canonical receipt-trail Merkle root, shared with receipts_selector.c */

/* struct sel_state is defined in loader.c (included above) */

static uint32_t fnv32(const char *s) {
    uint32_t h = 0x811c9dc5u;
    for (; *s; s++) h = (h ^ (uint8_t)*s) * 0x01000193u;
    return h;
}

static int g_prog, g_st, g_res;

/* The unified audit trail: kernel DATA receipts drained from the selector ringbuf during the
 * scenarios, PLUS the loader MIGRATION receipts, Merkle-rooted with the one canonical helper. This
 * harness proves migration receipts join the SAME signed, policy-bound trail as kernel transitions. */
#define MAX_RCPT 512
static struct ppt_receipt g_batch[MAX_RCPT];
static int g_nk = 0;                                   /* kernel receipts drained so far */
static struct ring_buffer *g_rb = NULL;

static int rb_cb(void *ctx, void *data, size_t sz) {
    (void)ctx;
    if (sz >= sizeof(struct ppt_receipt) && g_nk < MAX_RCPT)
        memcpy(&g_batch[g_nk++], data, sizeof(struct ppt_receipt));
    return 0;
}

static int run_ev(int32_t ev) {                        /* one event through the selector -> new posture */
    struct ppt_reg regs[1] = {{ TY_INT, ev }};
    uint8_t frame[256]; int flen = build_frame(frame, 0, 1, regs);
    uint8_t out[256];
    struct bpf_test_run_opts o; memset(&o, 0, sizeof(o)); o.sz = sizeof(o);
    o.data_in = frame; o.data_size_in = flen; o.data_out = out; o.data_size_out = sizeof(out);
    bpf_prog_test_run_opts(g_prog, &o);
    if (g_rb) ring_buffer__poll(g_rb, 100);            /* drain this event's kernel receipt into g_batch */
    __u32 k = 0; struct ppt_result r; bpf_map_lookup_elem(g_res, &k, &r);
    return r.target_node;
}

static uint32_t read_cur(void) {
    __u32 k = 0; struct sel_state s;
    bpf_map_lookup_elem_flags(g_st, &k, &s, BPF_F_LOCK);
    return s.cur_node;
}

static void set_cur(uint32_t cur) {
    __u32 k = 0; struct sel_state s = { .cur_node = cur, .inited = 1, .gen = 0 };
    bpf_map_update_elem(g_st, &k, &s, BPF_F_LOCK);
}

int main(int argc, char **argv) {
    const char *objp = argc > 1 ? argv[1] : "ppt_select.bpf.o";
    long la, lbn, lbr;
    uint8_t *ba = read_file("migrate_A.ppt", &la);
    uint8_t *bbn = read_file("migrate_Bname.ppt", &lbn);
    uint8_t *bbr = read_file("migrate_Breset.ppt", &lbr);
    if (!ba || !bbn || !bbr) { fprintf(stderr, "read fixtures failed (run gen_migrate_fixtures.py)\n"); return 1; }
    Image A, Bname, Breset;
    if (parse_image_buf(ba, la, &A) || parse_image_buf(bbn, lbn, &Bname) ||
        parse_image_buf(bbr, lbr, &Breset)) { fprintf(stderr, "parse fixture failed\n"); return 1; }

    struct bpf_object *obj = bpf_object__open_file(objp, NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "load/verify failed\n"); return 1; }
    g_prog = bpf_program__fd(bpf_object__find_program_by_name(obj, "ppt_select_prog"));
    g_st   = bpf_map__fd(bpf_object__find_map_by_name(obj, "sel_state_map"));
    g_res  = bpf_map__fd(bpf_object__find_map_by_name(obj, "result_map"));
    if (g_prog < 0 || g_st < 0 || g_res < 0) { fprintf(stderr, "prog/map missing\n"); return 1; }
    int rb_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "receipt_map"));
    g_rb = (rb_fd >= 0) ? ring_buffer__new(rb_fd, rb_cb, NULL, NULL) : NULL;   /* drain kernel receipts */

    uint32_t H_LOCK = fnv32("lockdown"), H_ELEV = fnv32("elevated");

    /* --- Scenario 1: by-name preserves the posture across a reindexing swap --- */
    populate_maps(obj, &A);
    set_cur(A.start);
    run_ev(1); run_ev(1);                              /* normal -> elevated -> lockdown, in-kernel */
    uint32_t old = read_cur();                         /* A's lockdown index (2) */
    struct ppt_receipt migr_bn;                        /* by-name migration receipt (trail leaf) */
    long byname = selector_hotswap(obj, &A, &Bname, &migr_bn);   /* LOADER: migrate by-name, swap table */
    int s1_ok = (byname >= 0) && ((uint32_t)byname < Bname.n_nodes) && (Bname.name_hashes[byname] == H_LOCK);
    int naive_wrong = (old < Bname.n_nodes) && (Bname.name_hashes[old] == H_ELEV);
    int live = (run_ev(2) == 2);                        /* from B-lockdown, de-escalate -> B-elevated (2) */

    /* --- Scenario 2: reset-to sends the posture to the new fail-safe on swap --- */
    populate_maps(obj, &A);
    set_cur(A.start);
    run_ev(1);                                          /* normal -> elevated */
    uint32_t old2 = read_cur();                         /* A's elevated index (1) */
    struct ppt_receipt migr_rs;                         /* reset-to migration receipt (trail leaf) */
    long reset = selector_hotswap(obj, &A, &Breset, &migr_rs);   /* LOADER: reset-to -> the new fail-safe */
    int s2_ok = (reset >= 0) && ((uint32_t)reset < Breset.n_nodes) && (Breset.name_hashes[reset] == H_LOCK);
    uint32_t byname2 = migrate_node(&A, &Bname, old2, NULL);  /* contrast: by-name would keep elevated */
    int s2_contrast = (byname2 < Bname.n_nodes) && (Bname.name_hashes[byname2] == H_ELEV);

    /* migration cause attest: a by-name carry is clean (PPT_CAUSE_NONE); a reset-to that parks the
     * posture on the new fail-safe is state:migration-reset (66), the same cause selector_hotswap
     * records on its loader migration receipt. */
    int c_byname = -1, c_reset = -1;
    (void)migrate_node(&A, &Bname,  old,  &c_byname);
    (void)migrate_node(&A, &Breset, old2, &c_reset);
    int cause_ok = (c_byname == PPT_CAUSE_NONE) && (c_reset == PPT_CAUSE_MIGRATION_RESET);

    /* ---- Unified signed audit trail: migration receipts join the kernel receipt trail ---------------
     * Fold the two loader migration receipts into the same batch as the kernel DATA receipts drained
     * during the scenarios, then Merkle-root the whole thing with the one canonical merkle.h helper. */
    if (g_rb) ring_buffer__poll(g_rb, 100);            /* final drain */
    int nk = g_nk;                                     /* kernel data receipts captured */
    int room = (g_nk + 2 <= MAX_RCPT);
    if (room) { g_batch[g_nk++] = migr_bn; g_batch[g_nk++] = migr_rs; }
    uint8_t root[32]; merkle_root(g_batch, g_nk, root);
    char rhex[65]; for (int i = 0; i < 32; i++) sprintf(rhex + 2 * i, "%02x", root[i]);

    /* The migration receipts are well-formed leaves: the migration discriminator, the right cause, the
     * pre/post posture, and a non-zero policy hash bound to the policy each migrated TO (distinct, since
     * by-name and reset-to are different signed images). */
    int migr_ok = (migr_bn.event == PPT_EVENT_MIGRATION && migr_bn.cause == PPT_CAUSE_NONE &&
                   migr_bn.prev_node == (int32_t)old && migr_bn.next_node == (int32_t)byname &&
                   migr_bn.policy_hash != 0) &&
                  (migr_rs.event == PPT_EVENT_MIGRATION && migr_rs.cause == PPT_CAUSE_MIGRATION_RESET &&
                   migr_rs.prev_node == (int32_t)old2 && migr_rs.next_node == (int32_t)reset &&
                   migr_rs.policy_hash != 0 && migr_rs.policy_hash != migr_bn.policy_hash);

    /* Tamper-evidence: the migration receipts are genuinely COVERED by the root — flip the reset-to
     * receipt's cause and the root must move. */
    uint8_t root2[32]; struct ppt_receipt saved = g_batch[g_nk - 1];
    g_batch[g_nk - 1].cause = PPT_CAUSE_NONE; merkle_root(g_batch, g_nk, root2);
    g_batch[g_nk - 1] = saved;
    int covered = (memcmp(root, root2, 32) != 0);
    int trail_ok = room && (nk >= 1) && migr_ok && covered;

    int ok = s1_ok && naive_wrong && live && s2_ok && s2_contrast && cause_ok && trail_ok;
    printf("SELECTOR HOT-SWAP MIGRATION (loader-enforced, signed name-hashes):\n");
    printf("  by-name: A lockdown idx %u -> B idx %u (%s); a raw carry of idx %u -> B '%s'\n",
           old, (unsigned)byname, s1_ok ? "lockdown preserved" : "WRONG",
           old, naive_wrong ? "elevated = would misread" : "?");
    printf("  migrated state is live in-kernel: from B-lockdown a de-escalate routes to idx 2: %s\n",
           live ? "yes" : "NO");
    printf("  reset-to: A elevated idx %u -> B idx %u (%s); by-name would keep idx %u (%s)\n",
           old2, (unsigned)reset, s2_ok ? "lockdown = fail-safe" : "WRONG",
           byname2, s2_contrast ? "elevated" : "?");
    printf("  migration cause: by-name=%d (%s), reset-to=%d (%s)\n",
           c_byname, c_byname == PPT_CAUSE_NONE ? "clean" : "?",
           c_reset, c_reset == PPT_CAUSE_MIGRATION_RESET ? "state:migration-reset" : "?");
    printf("  SIGNED TRAIL: %d kernel receipt(s) + 2 migration receipt(s) -> %d leaves, one Merkle root\n",
           nk, g_nk);
    printf("    migration receipts well-formed + policy-bound: %s; covered by the root (tamper-evident): %s\n",
           migr_ok ? "yes" : "NO", covered ? "yes" : "NO");
    printf("    Merkle root (kernel + migration receipts, one canonical helper): %s\n", rhex);
    printf("%s\n", ok ? "PASS - by-name preserves the posture across reindexing; reset-to fails safe;"
                        " migration receipts join the one signed trail"
                      : "FAIL");
    if (g_rb) ring_buffer__free(g_rb);
    bpf_object__close(obj); free_image(&A); free_image(&Bname); free_image(&Breset);
    return ok ? 0 : 1;
}
