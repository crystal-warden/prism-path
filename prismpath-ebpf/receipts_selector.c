/* Receipts + Merkle anchor for the stateful selector — the audit trail the flat result_map drops.
 *
 * Each COMMITTED resident transition emits a ppt_receipt {seq, policy_hash, prev, event, next} to a
 * ringbuf. This harness drains the ringbuf while replaying the frozen corpus and proves the receipt
 * stream reproduces the certified posture trail EXACTLY — a complete, policy-bound audit log that
 * carries the PRE-state, so the whole stateful history is reconstructable from the log alone. It then
 * Merkle-roots the batch: that root is what an OTS stamp anchors (the stamp is the held-for-publish
 * step, exactly like the corpus manifest). This is the review's "receipts carrying pre-state" — it
 * restores the statefulness a current-state-only map would flatten, and makes it tamper-evident.
 *
 *   clang -O2 -target bpf -I. -c ppt_select.bpf.c -o ppt_select.bpf.o
 *   gcc -O2 -Wno-unused-function -I. receipts_selector.c -o receipts_selector -lcrypto $(pkg-config --libs libbpf)
 *   sudo ./receipts_selector selector_corpus.bin ppt_select.bpf.o
 */
#define main loader_orig_main
#include "loader.c"
#undef main
#include <openssl/sha.h>

/* mirrors struct ppt_sel_state in ppt_select.bpf.c; the lock field rides the BPF_F_LOCK map ops */
struct sel_state { struct bpf_spin_lock lock; __u32 cur_node; __u32 inited; __u32 gen; };

#define MAX_EV 4096
static struct ppt_receipt g_rcpts[MAX_EV];
static int g_nr = 0;

static int rb_cb(void *ctx, void *data, size_t sz) {
    (void)ctx;
    if (sz >= sizeof(struct ppt_receipt) && g_nr < MAX_EV)
        memcpy(&g_rcpts[g_nr++], data, sizeof(struct ppt_receipt));
    return 0;
}

/* Merkle root over the receipt leaves: leaf = sha256(receipt bytes), pairwise sha256 to the root,
 * duplicating the last node on an odd layer. The root anchors the whole batch with one OTS stamp. */
static void merkle_root(const struct ppt_receipt *r, int n, uint8_t root[32]) {
    if (n <= 0) { memset(root, 0, 32); return; }
    uint8_t (*cur)[32] = malloc((size_t)n * 32);
    for (int i = 0; i < n; i++) SHA256((const unsigned char *)&r[i], sizeof(r[i]), cur[i]);
    int cnt = n;
    while (cnt > 1) {
        int half = (cnt + 1) / 2;
        uint8_t (*nx)[32] = malloc((size_t)half * 32);
        for (int i = 0; i < half; i++) {
            uint8_t buf[64];
            memcpy(buf, cur[2 * i], 32);
            memcpy(buf + 32, cur[(2 * i + 1 < cnt) ? 2 * i + 1 : 2 * i], 32);   /* dup last if odd */
            SHA256(buf, 64, nx[i]);
        }
        free(cur); cur = nx; cnt = half;
    }
    memcpy(root, cur[0], 32); free(cur);
}

int main(int argc, char **argv) {
    const char *corpus = argc > 1 ? argv[1] : "selector_corpus.bin";
    const char *objp   = argc > 2 ? argv[2] : "ppt_select.bpf.o";
    long clen; uint8_t *cb = read_file(corpus, &clen);
    if (!cb) { fprintf(stderr, "read %s failed\n", corpus); return 1; }
    const uint8_t *p = cb;
    uint32_t tbl_len; memcpy(&tbl_len, p, 4); p += 4;
    const uint8_t *tbl = p; p += tbl_len;
    Image im;
    if (parse_image_buf(tbl, tbl_len, &im)) { fprintf(stderr, "malformed table\n"); return 1; }
    uint32_t n_streams; memcpy(&n_streams, p, 4); p += 4;

    /* policy_hash = low 64 bits of sha256(table) — the same image bytes the signed manifest hashes */
    uint8_t dg[32]; SHA256(tbl, tbl_len, dg);
    uint64_t policy_hash; memcpy(&policy_hash, dg, 8);

    struct bpf_object *obj = bpf_object__open_file(objp, NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "load/verify failed\n"); return 1; }
    if (populate_maps(obj, &im)) return 1;
    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "ppt_select_prog"));
    int st_fd   = bpf_map__fd(bpf_object__find_map_by_name(obj, "sel_state_map"));
    int cfg_fd  = bpf_map__fd(bpf_object__find_map_by_name(obj, "config_map"));
    int rb_fd   = bpf_map__fd(bpf_object__find_map_by_name(obj, "receipt_map"));
    if (prog_fd < 0 || st_fd < 0 || cfg_fd < 0 || rb_fd < 0) { fprintf(stderr, "prog/map missing\n"); return 1; }

    /* stamp policy_hash into the config the program reads, so every receipt is bound to this image */
    __u32 k0 = 0; struct ppt_config cfg;
    if (bpf_map_lookup_elem(cfg_fd, &k0, &cfg)) { perror("config read"); return 1; }
    cfg.policy_hash = policy_hash;
    if (bpf_map_update_elem(cfg_fd, &k0, &cfg, BPF_ANY)) { perror("config write"); return 1; }

    struct ring_buffer *rb = ring_buffer__new(rb_fd, rb_cb, NULL, NULL);
    if (!rb) { fprintf(stderr, "ringbuf open failed\n"); return 1; }

    static int32_t exp_prev[MAX_EV], exp_ev[MAX_EV], exp_next[MAX_EV];
    int ne = 0;
    for (uint32_t s = 0; s < n_streams; s++) {
        uint32_t n_ev; memcpy(&n_ev, p, 4); p += 4;
        struct sel_state clean = { .cur_node = (uint32_t)im.start, .inited = 1, .gen = 0 };
        bpf_map_update_elem(st_fd, &k0, &clean, BPF_F_LOCK);
        int32_t prev = (int32_t)im.start;
        for (uint32_t e = 0; e < n_ev; e++) {
            int32_t ev, ref; memcpy(&ev, p, 4); p += 4; memcpy(&ref, p, 4); p += 4;
            struct ppt_reg regs[1] = {{ TY_INT, ev }};
            uint8_t frame[256]; int flen = build_frame(frame, 0, 1, regs);
            uint8_t out[256];
            struct bpf_test_run_opts o; memset(&o, 0, sizeof(o)); o.sz = sizeof(o);
            o.data_in = frame; o.data_size_in = flen; o.data_out = out; o.data_size_out = sizeof(out);
            if (bpf_prog_test_run_opts(prog_fd, &o)) { perror("test_run"); return 1; }
            ring_buffer__poll(rb, 100);                     /* drain this event's receipt */
            if (ne < MAX_EV) { exp_prev[ne] = prev; exp_ev[ne] = ev; exp_next[ne] = ref; ne++; }
            prev = ref;
        }
    }
    ring_buffer__poll(rb, 100);                             /* final drain */

    int mism = 0;
    for (int k = 0; k < g_nr && k < ne; k++) {
        if (g_rcpts[k].prev_node != exp_prev[k] || g_rcpts[k].event != exp_ev[k] ||
            g_rcpts[k].next_node != exp_next[k] || g_rcpts[k].policy_hash != policy_hash)
            mism++;
    }
    int ok = (g_nr == ne) && (mism == 0);

    uint8_t root[32]; merkle_root(g_rcpts, g_nr, root);
    char hex[65]; for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", root[i]);

    ring_buffer__free(rb); free_image(&im);
    printf("SELECTOR RECEIPTS (in-kernel ringbuf, replaying the frozen corpus):\n");
    printf("  %d receipts for %d committed transitions (one per event) -> %s\n",
           g_nr, ne, g_nr == ne ? "complete log" : "MISSING RECEIPTS");
    printf("  faithful trail + recorded pre-state + event + policy binding: %d mismatch(es)\n", mism);
    printf("  policy_hash (low64 of sha256 image): %016llx\n", (unsigned long long)policy_hash);
    printf("  Merkle root over the receipt batch:  %s\n", hex);
    printf("  (OTS anchor of that root is the held-for-publish step, via the ledger_ots machinery)\n");
    printf("%s\n", ok ? "PASS - receipts reproduce the certified trail, carry pre-state, and bind to the signed policy"
                      : "FAIL");
    return ok ? 0 : 1;
}
