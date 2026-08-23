/* sel_forward_receipts.c - the delivery node, with a SIGNED delta trail.
 *
 * Upgrade of sel_forward.c. Control EVENTS arrive from the dev station over UDP; each is run through
 * the SIGNED posture_selector (the certified eBPF resident FSM) via BPF_PROG_TEST_RUN. Where the
 * original forwarder logged its own clock, this one DRAINS THE PROGRAM'S AUDIT RINGBUF after each
 * event and logs the receipt the kernel emitted: {seq, t_ns=bpf_ktime_get_ns() at commit,
 * policy_hash, prev_node, event, next_node}. So the delta trail's TIME axis is tamper-evident and
 * policy-bound, not a side note. The posture is forwarded to the FPGA SEND-ON-DELTA (only when it
 * changes); holds transmit nothing. At the end it Merkle-roots the session's receipts - the same
 * per-session anchor object certified in ledger row #119, now driving physical LEDs live.
 *
 *   clang -O2 -target bpf -I.. -c ../ppt_select.bpf.c -o ppt_select.bpf.o
 *   gcc -O2 -Wno-unused-function -I.. sel_forward_receipts.c -o sel_forward_receipts \
 *       -lcrypto $(pkg-config --libs libbpf)
 *   sudo ./sel_forward_receipts <corpus.bin> ppt_select.bpf.o <fpga_ip> 9410 9500 90 receipt_trail.log
 */
#define main loader_orig_main
#include "loader.c"
#undef main
#include <arpa/inet.h>
#include <time.h>
#include <openssl/sha.h>

static double now(void) { struct timespec t; clock_gettime(CLOCK_REALTIME, &t); return t.tv_sec + t.tv_nsec / 1e9; }

#define MAX_EV 4096
static struct ppt_receipt g_rcpts[MAX_EV];
static int g_nr = 0;
static struct ppt_receipt g_last;
static int g_got = 0;

static int rb_cb(void *ctx, void *data, size_t sz) {
    (void)ctx;
    if (sz >= sizeof(struct ppt_receipt)) {
        memcpy(&g_last, data, sizeof(struct ppt_receipt));
        g_got = 1;
        if (g_nr < MAX_EV) memcpy(&g_rcpts[g_nr++], data, sizeof(struct ppt_receipt));
    }
    return 0;
}

/* Merkle root over receipt leaves (copied from receipts_selector.c): the per-session anchor. */
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
            memcpy(buf + 32, cur[(2 * i + 1 < cnt) ? 2 * i + 1 : 2 * i], 32);
            SHA256(buf, 64, nx[i]);
        }
        free(cur); cur = nx; cnt = half;
    }
    memcpy(root, cur[0], 32); free(cur);
}

int main(int argc, char **argv) {
    const char *corpus  = argc > 1 ? argv[1] : "selector_corpus.bin";
    const char *objp    = argc > 2 ? argv[2] : "ppt_select.bpf.o";
    const char *fpga    = argc > 3 ? argv[3] : "10.10.10.2";
    int fpga_port       = argc > 4 ? atoi(argv[4]) : 9410;
    int listen_port     = argc > 5 ? atoi(argv[5]) : 9500;
    int duration        = argc > 6 ? atoi(argv[6]) : 90;
    const char *trailp  = argc > 7 ? argv[7] : "receipt_trail.log";

    long clen; uint8_t *cb = read_file(corpus, &clen);
    if (!cb) { fprintf(stderr, "read %s failed\n", corpus); return 1; }
    uint32_t tbl_len; memcpy(&tbl_len, cb, 4); const uint8_t *tbl = cb + 4;
    Image im; if (parse_image_buf(tbl, tbl_len, &im)) { fprintf(stderr, "bad table\n"); return 1; }

    struct bpf_object *obj = bpf_object__open_file(objp, NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "load/verify failed\n"); return 1; }
    if (populate_maps(obj, &im)) return 1;
    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "ppt_select_prog"));
    int st_fd   = bpf_map__fd(bpf_object__find_map_by_name(obj, "sel_state_map"));
    int rb_fd   = bpf_map__fd(bpf_object__find_map_by_name(obj, "receipt_map"));
    int cfg_fd  = bpf_map__fd(bpf_object__find_map_by_name(obj, "config_map"));
    if (prog_fd < 0 || st_fd < 0 || rb_fd < 0 || cfg_fd < 0) { fprintf(stderr, "prog/map missing\n"); return 1; }

    __u32 k0 = 0;
    struct sel_state s = { .cur_node = (uint32_t)im.start, .inited = 1, .gen = 0 };
    bpf_map_update_elem(st_fd, &k0, &s, BPF_F_LOCK);
    struct ppt_config cfg; memset(&cfg, 0, sizeof(cfg));
    bpf_map_lookup_elem(cfg_fd, &k0, &cfg);        /* loader-stamped policy_hash */

    struct ring_buffer *rb = ring_buffer__new(rb_fd, rb_cb, NULL, NULL);
    if (!rb) { fprintf(stderr, "ringbuf open failed\n"); return 1; }

    int rx = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in la = { .sin_family = AF_INET, .sin_port = htons(listen_port) };
    la.sin_addr.s_addr = INADDR_ANY;
    if (bind(rx, (struct sockaddr *)&la, sizeof(la))) { perror("bind"); return 1; }
    struct timeval tv = { .tv_sec = 0, .tv_usec = 400000 }; setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in fa = { .sin_family = AF_INET, .sin_port = htons(fpga_port) };
    inet_pton(AF_INET, fpga, &fa.sin_addr);

    FILE *tf = fopen(trailp, "a");
    if (tf) { fprintf(tf, "# recv_wall_s\tseq\tt_ns\tprev\tevent\tnext\taction\n"); fflush(tf); }

    const char *NM[] = { "normal", "elevated", "lockdown" };
    printf("FORWARD(receipts): signed posture_selector deciding; events udp/%d -> send-on-delta -> %s:%d (%ds)\n",
           listen_port, fpga, fpga_port, duration);
    printf("  policy_hash (loader-stamped, low64 of sha256 image): %016llx\n",
           (unsigned long long)cfg.policy_hash); fflush(stdout);

    int last = (int)im.start, sent = 0, held = 0, events = 0, stuck = 0;
    double t0 = now();
    while (now() - t0 < duration) {
        char buf[64]; int n = recvfrom(rx, buf, sizeof(buf) - 1, 0, NULL, NULL);
        if (n <= 0) continue;
        buf[n] = 0; int ev = atoi(buf);
        events++;

        struct ppt_reg regs[1] = {{ TY_INT, ev }};
        uint8_t frame[256]; int flen = build_frame(frame, 0, 1, regs);
        uint8_t out[256]; struct bpf_test_run_opts o; memset(&o, 0, sizeof(o)); o.sz = sizeof(o);
        o.data_in = frame; o.data_size_in = flen; o.data_out = out; o.data_size_out = sizeof(out);
        g_got = 0;
        if (bpf_prog_test_run_opts(prog_fd, &o)) { perror("test_run"); continue; }
        ring_buffer__poll(rb, 100);                 /* drain THIS event's signed receipt */

        if (!g_got) {                               /* no matched edge: nothing committed, nothing to send */
            stuck++;
            printf("  ev=%d -> stuck (no receipt, no send)\n", ev); fflush(stdout);
            if (tf) { fprintf(tf, "%.6f\t-\t-\t%d\t%d\t-\tstuck\n", now(), last, ev); fflush(tf); }
            continue;
        }

        int next = g_last.next_node, prev = g_last.prev_node;
        int delta = (next != last);
        const char *action = delta ? "SENT" : "held";
        printf("  ev=%d -> %s%s->%s  seq=%llu t_ns=%llu  %s\n", ev,
               delta ? "DELTA " : "hold  ",
               (prev >= 0 && prev < 3) ? NM[prev] : "?",
               (next >= 0 && next < 3) ? NM[next] : "?",
               (unsigned long long)g_last.seq, (unsigned long long)g_last.t_ns,
               delta ? "sent" : "send-on-delta: suppressed"); fflush(stdout);
        if (tf) { fprintf(tf, "%.6f\t%llu\t%llu\t%d\t%d\t%d\t%s\n", now(),
                          (unsigned long long)g_last.seq, (unsigned long long)g_last.t_ns,
                          prev, ev, next, action); fflush(tf); }

        if (delta) {                                /* SEND-ON-DELTA: carry posture + signed seq/t_ns */
            char msg[64];
            int mlen = snprintf(msg, sizeof(msg), "%d %llu %llu",
                                next, (unsigned long long)g_last.seq, (unsigned long long)g_last.t_ns);
            sendto(tx, msg, mlen, 0, (struct sockaddr *)&fa, sizeof(fa));
            last = next; sent++;
        } else held++;
    }

    uint8_t root[32]; merkle_root(g_rcpts, g_nr, root);
    char hex[65]; for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", root[i]);
    ring_buffer__free(rb); free_image(&im);
    if (tf) { fprintf(tf, "# merkle_root=%s policy_hash=%016llx events=%d deltas=%d holds=%d receipts=%d\n",
                      hex, (unsigned long long)cfg.policy_hash, events, sent, held, g_nr); fclose(tf); }

    printf("\nDECISION-DELTA SESSION (signed trail):\n");
    printf("  events=%d  deltas_sent=%d  holds_suppressed=%d  stuck=%d  receipts=%d\n",
           events, sent, held, stuck, g_nr);
    printf("  policy_hash: %016llx\n", (unsigned long long)cfg.policy_hash);
    printf("  Merkle root (decisions + signed t_ns -> per-session anchor): %s\n", hex);
    printf("  (OTS anchor of that root is the held-for-publish step, owner-gated)\n");
    return 0;
}
