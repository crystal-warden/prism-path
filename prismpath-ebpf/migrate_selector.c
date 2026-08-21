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

struct sel_state { struct bpf_spin_lock lock; __u32 cur_node; __u32 inited; __u32 gen; };

static uint32_t fnv32(const char *s) {
    uint32_t h = 0x811c9dc5u;
    for (; *s; s++) h = (h ^ (uint8_t)*s) * 0x01000193u;
    return h;
}

static int g_prog, g_st, g_res;

static int run_ev(int32_t ev) {                        /* one event through the selector -> new posture */
    struct ppt_reg regs[1] = {{ TY_INT, ev }};
    uint8_t frame[256]; int flen = build_frame(frame, 0, 1, regs);
    uint8_t out[256];
    struct bpf_test_run_opts o; memset(&o, 0, sizeof(o)); o.sz = sizeof(o);
    o.data_in = frame; o.data_size_in = flen; o.data_out = out; o.data_size_out = sizeof(out);
    bpf_prog_test_run_opts(g_prog, &o);
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

    uint32_t H_LOCK = fnv32("lockdown"), H_ELEV = fnv32("elevated");

    /* --- Scenario 1: by-name preserves the posture across a reindexing swap --- */
    populate_maps(obj, &A);
    set_cur(A.start);
    run_ev(1); run_ev(1);                              /* normal -> elevated -> lockdown, in-kernel */
    uint32_t old = read_cur();                         /* A's lockdown index (2) */
    uint32_t byname = migrate_node(&A, &Bname, old);   /* the loader's by-name migration */
    populate_maps(obj, &Bname);                        /* the swap: the new policy into the maps */
    set_cur(byname);                                   /* apply the migrated resident node */
    int s1_ok = (byname < Bname.n_nodes) && (Bname.name_hashes[byname] == H_LOCK);
    int naive_wrong = (old < Bname.n_nodes) && (Bname.name_hashes[old] == H_ELEV);
    int live = (run_ev(2) == 2);                        /* from B-lockdown, de-escalate -> B-elevated (2) */

    /* --- Scenario 2: reset-to sends the posture to the new fail-safe on swap --- */
    populate_maps(obj, &A);
    set_cur(A.start);
    run_ev(1);                                          /* normal -> elevated */
    uint32_t old2 = read_cur();                         /* A's elevated index (1) */
    uint32_t reset = migrate_node(&A, &Breset, old2);   /* reset-to (no by-name bit) -> Breset.safe */
    int s2_ok = (reset < Breset.n_nodes) && (Breset.name_hashes[reset] == H_LOCK);
    uint32_t byname2 = migrate_node(&A, &Bname, old2);  /* contrast: by-name would keep elevated */
    int s2_contrast = (byname2 < Bname.n_nodes) && (Bname.name_hashes[byname2] == H_ELEV);

    int ok = s1_ok && naive_wrong && live && s2_ok && s2_contrast;
    printf("SELECTOR HOT-SWAP MIGRATION (loader-enforced, signed name-hashes):\n");
    printf("  by-name: A lockdown idx %u -> B idx %u (%s); a raw carry of idx %u -> B '%s'\n",
           old, byname, s1_ok ? "lockdown preserved" : "WRONG",
           old, naive_wrong ? "elevated = would misread" : "?");
    printf("  migrated state is live in-kernel: from B-lockdown a de-escalate routes to idx 2: %s\n",
           live ? "yes" : "NO");
    printf("  reset-to: A elevated idx %u -> B idx %u (%s); by-name would keep idx %u (%s)\n",
           old2, reset, s2_ok ? "lockdown = fail-safe" : "WRONG",
           byname2, s2_contrast ? "elevated" : "?");
    printf("%s\n", ok ? "PASS - by-name preserves the posture across reindexing; reset-to fails safe"
                      : "FAIL");
    bpf_object__close(obj); free_image(&A); free_image(&Bname); free_image(&Breset);
    return ok ? 0 : 1;
}
