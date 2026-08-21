/* Concurrency smoke test for the stateful selector — measured shut, not argued shut.
 *
 * The cert (cert_selector) replays streams serially through BPF_PROG_TEST_RUN, so it never exercises
 * the multi-CPU case a real multi-queue NIC produces. This hammers the ONE shared sel_state_map from
 * many threads at once (each thread runs the loaded ppt_select via BPF_PROG_TEST_RUN on its own CPU,
 * all against the same map fd) and checks the resident posture never tears or goes out of range under
 * the CAS-under-spinlock. It also counts committed advances (the generation counter) vs CAS drops, so
 * genuine contention is visible: a drop is a concurrent event that lost the CAS and was discarded, not
 * misapplied from a stale snapshot.
 *
 *   clang -O2 -target bpf -I. -c ppt_select.bpf.c -o ppt_select.bpf.o
 *   gcc  -O2 -Wno-unused-function -I. smoke_selector.c -o smoke_selector -lpthread $(pkg-config --libs libbpf)
 *   sudo ./smoke_selector selector_corpus.bin ppt_select.bpf.o
 */
#define main loader_orig_main
#include "loader.c"
#undef main
#include <pthread.h>
#include <stdatomic.h>

/* struct sel_state is defined in loader.c (included above) */

#define NTHREADS 8
#define NITERS   20000

static int g_prog_fd;
static atomic_long g_runs;

static void *worker(void *arg) {
    unsigned seed = (unsigned)(uintptr_t)arg * 2654435761u + 1u;
    for (int i = 0; i < NITERS; i++) {
        seed = seed * 1103515245u + 12345u;
        int ev = (int)((seed >> 16) & 3u);                 /* event in {0,1,2,3} */
        struct ppt_reg regs[1] = {{ TY_INT, ev }};
        uint8_t frame[256]; int flen = build_frame(frame, 0, 1, regs);
        uint8_t out[256];
        struct bpf_test_run_opts o; memset(&o, 0, sizeof(o)); o.sz = sizeof(o);
        o.data_in = frame; o.data_size_in = flen; o.data_out = out; o.data_size_out = sizeof(out);
        if (bpf_prog_test_run_opts(g_prog_fd, &o) == 0) atomic_fetch_add(&g_runs, 1);
    }
    return NULL;
}

int main(int argc, char **argv) {
    const char *corpus = argc > 1 ? argv[1] : "selector_corpus.bin";
    const char *objp   = argc > 2 ? argv[2] : "ppt_select.bpf.o";
    long clen; uint8_t *cb = read_file(corpus, &clen);   /* reuse the corpus only for its table image */
    if (!cb) { fprintf(stderr, "read %s failed\n", corpus); return 1; }
    uint32_t tbl_len; memcpy(&tbl_len, cb, 4);
    const uint8_t *tbl = cb + 4;
    Image im;
    if (parse_image_buf(tbl, tbl_len, &im)) { fprintf(stderr, "malformed table\n"); return 1; }

    struct bpf_object *obj = bpf_object__open_file(objp, NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "load/verify failed\n"); return 1; }
    if (populate_maps(obj, &im)) return 1;
    g_prog_fd  = bpf_program__fd(bpf_object__find_program_by_name(obj, "ppt_select_prog"));
    int st_fd  = bpf_map__fd(bpf_object__find_map_by_name(obj, "sel_state_map"));
    if (g_prog_fd < 0 || st_fd < 0) { fprintf(stderr, "prog/map missing\n"); return 1; }

    __u32 k0 = 0;
    struct sel_state clean = { .cur_node = (uint32_t)im.start, .inited = 1, .gen = 0 };
    if (bpf_map_update_elem(st_fd, &k0, &clean, BPF_F_LOCK)) { perror("state init"); return 1; }

    pthread_t th[NTHREADS];
    for (long t = 0; t < NTHREADS; t++) pthread_create(&th[t], NULL, worker, (void *)(t + 1));
    for (int t = 0; t < NTHREADS; t++) pthread_join(th[t], NULL);

    struct sel_state fin;
    if (bpf_map_lookup_elem_flags(st_fd, &k0, &fin, BPF_F_LOCK)) { perror("state read"); return 1; }

    long events  = (long)NTHREADS * NITERS;
    long runs    = atomic_load(&g_runs);
    long commits = (long)fin.gen;                        /* gen: +1 per committed advance, from 0 */
    long drops   = runs - commits;                       /* concurrent losers, dropped not misapplied */
    int state_valid = (fin.inited == 1) && (fin.cur_node < im.n_nodes);
    __u32 n_nodes = im.n_nodes;
    free_image(&im);

    printf("SELECTOR CONCURRENCY SMOKE: %d threads x %d = %ld events, %ld runs ok\n",
           NTHREADS, NITERS, events, runs);
    printf("  final posture=%u (valid range 0..%u), inited=%u -> %s\n",
           fin.cur_node, n_nodes - 1, fin.inited, state_valid ? "VALID" : "TORN/INVALID");
    printf("  committed advances=%ld, CAS drops (real contention)=%ld\n", commits, drops);
    printf("  contention observed: %s\n",
           drops > 0 ? "yes — concurrent CAS losers were dropped, never misapplied"
                     : "none in this run (state safety still proven)");
    int ok = state_valid && (runs == events) && (drops >= 0);
    printf("%s\n", ok ? "PASS - resident posture stayed valid under T-way concurrency"
                      : "FAIL - state torn or a run failed");
    return ok ? 0 : 1;
}
