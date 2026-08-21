/* In-kernel conformance for the stateful selector: replay every frozen event stream through
 * ppt_select via BPF_PROG_TEST_RUN (resident state reset per stream) and diff the kernel's posture
 * trail against the C/Python reference frozen in the corpus. Reuses the loader's image parse + frame
 * build + map fill. Corpus: <u32 tbl_len><tbl><u32 n_streams>{<u32 n_ev>{<s32 ev><s32 posture>}}.
 *
 *   clang -O2 -target bpf -I. -c ppt_select.bpf.c -o ppt_select.bpf.o
 *   gcc  -O2 -Wno-unused-function -I. cert_selector.c -o cert_selector $(pkg-config --libs libbpf)
 *   sudo ./cert_selector selector_corpus.bin ppt_select.bpf.o
 */
#define main loader_orig_main
#include "loader.c"
#undef main

struct sel_state { __u32 cur_node; __u32 inited; };

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

    struct bpf_object *obj = bpf_object__open_file(objp, NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "load/verify failed\n"); return 1; }
    if (populate_maps(obj, &im)) return 1;
    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "ppt_select_prog"));
    int res_fd  = bpf_map__fd(bpf_object__find_map_by_name(obj, "result_map"));
    int st_fd   = bpf_map__fd(bpf_object__find_map_by_name(obj, "sel_state_map"));
    if (prog_fd < 0 || res_fd < 0 || st_fd < 0) { fprintf(stderr, "prog/map missing\n"); return 1; }

    __u32 k0 = 0;
    long ev_total = 0, ev_bad = 0; uint32_t streams_bad = 0;
    for (uint32_t s = 0; s < n_streams; s++) {
        uint32_t n_ev; memcpy(&n_ev, p, 4); p += 4;
        struct sel_state reset = {0, 0};
        bpf_map_update_elem(st_fd, &k0, &reset, BPF_ANY);      /* fresh resident state per stream */
        int stream_ok = 1;
        for (uint32_t e = 0; e < n_ev; e++) {
            int32_t ev, ref; memcpy(&ev, p, 4); p += 4; memcpy(&ref, p, 4); p += 4;
            struct ppt_reg regs[1] = {{ TY_INT, ev }};
            uint8_t frame[256]; int flen = build_frame(frame, 0, 1, regs);
            uint8_t out[256];
            struct bpf_test_run_opts o; memset(&o, 0, sizeof(o)); o.sz = sizeof(o);
            o.data_in = frame; o.data_size_in = flen; o.data_out = out; o.data_size_out = sizeof(out);
            if (bpf_prog_test_run_opts(prog_fd, &o)) { perror("test_run"); return 1; }
            struct ppt_result r; bpf_map_lookup_elem(res_fd, &k0, &r);
            ev_total++;
            if (r.target_node != ref) { ev_bad++; stream_ok = 0; }
        }
        if (!stream_ok) streams_bad++;
    }
    free_image(&im);
    printf("SELECTOR CERT (in-kernel, BPF_PROG_TEST_RUN): %ld/%ld events match, %u/%u streams clean\n",
           ev_total - ev_bad, ev_total, n_streams - streams_bad, n_streams);
    printf("%s\n", ev_bad == 0 ? "PASS - the kernel reproduces the frozen posture trail exactly" : "FAIL");
    return ev_bad == 0 ? 0 : 1;
}
