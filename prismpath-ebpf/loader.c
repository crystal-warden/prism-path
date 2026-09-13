// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* loader.c — PrismPath PPT v1 eBPF/XDP Userspace Loader
 *
 * Reads a PPT table image (.ppt binary format), populates BPF maps,
 * attaches the XDP program to a network interface (e.g. veth),
 * feeds input register files, and reads back classification verdicts.
 *
 * The reusable halves live next door: ppt_image.c reads, validates and evaluates a table on the
 * host, ppt_maps.c fills the kernel maps and carries the resident selector posture across a policy
 * swap. What is left here is the command line over those two, one row per verb in LOADER_COMMANDS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>       /* ETH_P_ALL */
#include <arpa/inet.h>          /* htons */
#include <pthread.h>

#ifndef NO_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>   /* XDP_FLAGS_SKB_MODE */
#endif

#include "ppt_common.h"
#include "ppt_image.h"       /* the image half: parse, free, the host reference evaluator, build_frame */
#ifndef NO_LIBBPF
#include "ppt_maps.h"        /* the kernel half: populate_maps, selector_hotswap, read_names */
#endif

#define PIN_PATH "/sys/fs/bpf/ppt_result"   /* result_map pin: read back the in-kernel verdict */
#define NET_VERDICT_PIN "/sys/fs/bpf/ppt_net_verdict"  /* real-packet per-target histogram */
#define NET_RESULT_PIN  "/sys/fs/bpf/ppt_net_result"   /* real-packet last-verdict + pkt_count */
#define SEL_STATE_PIN   "/sys/fs/bpf/ppt_sel_state"     /* resident selector posture, persists across loads */
#define SEL_RESULT_PIN  "/sys/fs/bpf/ppt_sel_result"    /* selector last-decision + pkt_count */
#define SEL_RECEIPT_PIN "/sys/fs/bpf/ppt_sel_receipts"  /* selector audit-receipt ringbuf (drainable) */

#ifndef NO_LIBBPF
/* SHA256 here is only the migration receipt leaf that swapselector prints; the policy hash itself
 * is computed in ppt_maps.c. */
#include <openssl/sha.h>

/* ---- resident selector deployment ------------------------------------------------------------
 * sel_state is pinned on bpffs, so it survives across loader invocations and across a policy reload:
 * every selector load sets the pin path, and libbpf REUSES the pinned map when it already exists. That
 * is what makes the resident posture persist while the policy is hot-swapped. */

/* Open + load ppt_select.bpf.o with sel_state (and result/receipt) pinned. A later load reuses the same
 * resident-state map, persisting the posture. Populates the table maps with `im`. Returns obj or NULL. */
static struct bpf_object *sel_open(const Image *im) {
    struct bpf_object *obj = bpf_object__open_file("ppt_select.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "sel_open: cannot open ppt_select.bpf.o (run make)\n"); return NULL; }
    struct bpf_map *pinned_map;
    if ((pinned_map = bpf_object__find_map_by_name(obj, "sel_state_map")))
        bpf_map__set_pin_path(pinned_map, SEL_STATE_PIN);
    if ((pinned_map = bpf_object__find_map_by_name(obj, "result_map")))
        bpf_map__set_pin_path(pinned_map, SEL_RESULT_PIN);
    if ((pinned_map = bpf_object__find_map_by_name(obj, "receipt_map")))
        bpf_map__set_pin_path(pinned_map, SEL_RECEIPT_PIN);
    if (bpf_object__load(obj)) {
        fprintf(stderr, "sel_open: load/verify failed\n"); bpf_object__close(obj); return NULL;
    }
    if (populate_maps(obj, im)) { bpf_object__close(obj); return NULL; }
    return obj;
}

/* loader <policy.ppt> selattach <iface> — deploy the resident selector: load with pinned state, seed a
 * clean start, attach in XDP SKB mode. The program + pinned state outlive this process. */
static int sel_attach_cmd(const char *policy_ppt, const char *iface, __u32 xdp_flags) {
    long image_len; uint8_t *image_bytes = read_file(policy_ppt, &image_len);
    Image im;
    if (!image_bytes || parse_image_buf(image_bytes, image_len, &im)) {
        fprintf(stderr, "selattach: parse %s failed\n", policy_ppt); return 1;
    }
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "selattach: unknown interface %s\n", iface); return 1; }
    struct bpf_object *obj = sel_open(&im);
    if (!obj) return 1;
    int st_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "sel_state_map"));
    struct sel_state seed_posture = { .cur_node = im.start, .inited = 1, .gen = 0 };   /* deliberate clean start */
    __u32 state_key = 0;
    if (st_fd < 0 || bpf_map_update_elem(st_fd, &state_key, &seed_posture, BPF_F_LOCK)) {
        fprintf(stderr, "selattach: seed failed\n"); return 1;
    }
    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "ppt_select_prog"));
    const char *mode = (xdp_flags & XDP_FLAGS_DRV_MODE) ? "native/DRV" : "SKB";
    if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL)) {
        fprintf(stderr, "selattach: XDP %s attach on %s failed (need root / driver XDP support)\n", mode, iface);
        return 1;
    }
    printf("OK: ppt_select attached to %s (%s); sel_state pinned at %s; clean start = node %u.\n",
           iface, mode, SEL_STATE_PIN, im.start);
    bpf_object__close(obj);   /* the XDP attach + the bpffs pins keep the program and state alive */
    free_image(&im);
    return 0;
}

/* loader x selstate — read the pinned resident posture (works in a fresh process). */
static int sel_state_cmd(void) {
    int fd = bpf_obj_get(SEL_STATE_PIN);
    if (fd < 0) { fprintf(stderr, "selstate: no pinned state at %s (selattach first)\n", SEL_STATE_PIN); return 1; }
    struct sel_state posture; __u32 state_key = 0;
    if (bpf_map_lookup_elem_flags(fd, &state_key, &posture, BPF_F_LOCK)) {
        perror("selstate read"); close(fd); return 1;
    }
    printf("SEL STATE: resident node=%u inited=%u gen=%u (pinned at %s)\n",
           posture.cur_node, posture.inited, posture.gen, SEL_STATE_PIN);
    close(fd);
    return 0;
}

/* loader x seldetach <iface> — detach the selector and remove its pins. */
static int sel_detach_cmd(const char *iface) {
    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex) bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    unlink(SEL_STATE_PIN); unlink(SEL_RESULT_PIN); unlink(SEL_RECEIPT_PIN);
    printf("OK: ppt_select detached from %s; pins removed.\n", iface);
    return 0;
}

/* loader x selsend <iface> <ev> — inject a raw control-event frame on <iface> (AF_PACKET). Sent out
 * <iface>; on a veth pair it arrives at the peer where the selector XDP is attached, so the attached
 * program advances the (pinned) resident posture from a real packet. */
static int sel_send_cmd(const char *iface, int ev) {
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "selsend: unknown interface %s\n", iface); return 1; }
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("selsend socket"); return 1; }
    struct ppt_reg regs[1] = {{ TY_INT, ev }};
    uint8_t frame[256]; int flen = build_frame(frame, 0, 1, regs);
    struct sockaddr_ll sll; memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET; sll.sll_ifindex = ifindex; sll.sll_halen = 6;
    memcpy(sll.sll_addr, frame, 6);                  /* dest mac = the frame's eth dst (broadcast) */
    int rc = (int)sendto(fd, frame, flen, 0, (struct sockaddr *)&sll, sizeof(sll));
    close(fd);
    if (rc < 0) { perror("selsend sendto"); return 1; }
    printf("selsend: injected control event %d (%d bytes) on %s\n", ev, flen, iface);
    return 0;
}

/* Append a receipt to the append-only receipt journal (raw ppt_receipt records). The journal is a
 * persistent, sealable trail: seal_receipts Merkle-roots it with the shared merkle.h, so an OUT-OF-BAND
 * admin swap becomes a first-class anchorable leaf in the SAME leaf format as every other trail, not
 * just a console line. */
static int append_receipt_journal(const char *path, const struct ppt_receipt *receipt) {
    FILE *journal = fopen(path, "ab");
    if (!journal) { fprintf(stderr, "receipt journal %s: %s\n", path, strerror(errno)); return -1; }
    int ok = (fwrite(receipt, sizeof(*receipt), 1, journal) == 1);
    fclose(journal);
    return ok ? 0 : -1;
}

/* loader <new.ppt> swapselector <old.ppt> [iface] — hot-swap the LIVE selector policy while MIGRATING
 * the persistent resident posture. Loads the new policy REUSING the pinned sel_state (so the old posture
 * carries into this process), migrates it via selector_hotswap per the new policy's signed strategy, and
 * (if iface given) attaches the new program, replacing the old. If PPT_RECEIPT_JOURNAL is set, the
 * migration receipt is appended there, so this out-of-band admin swap joins the sealable signed trail. */
static int selector_swap_cmd(const char *new_ppt, const char *old_ppt, const char *iface) {
    long lo, ln;
    uint8_t *bo = read_file(old_ppt, &lo), *bn = read_file(new_ppt, &ln);
    Image old_image, new_image;
    if (!bo || !bn || parse_image_buf(bo, lo, &old_image) || parse_image_buf(bn, ln, &new_image)) {
        fprintf(stderr, "swapselector: read/parse failed\n"); return 1;
    }
    struct bpf_object *obj = sel_open(&new_image);   /* reuse the pinned sel_state (holds the OLD posture) */
    if (!obj) return 1;
    /* Capture the migration receipt only when a journal is configured; otherwise NULL keeps the seam
     * cost-free. The receipt is the SAME leaf the forwarder folds into its live trail. */
    const char *jpath = getenv("PPT_RECEIPT_JOURNAL");
    struct ppt_receipt migr;
    /* migrate, swap table, write */
    long migrated = selector_hotswap(obj, &old_image, &new_image, jpath ? &migr : NULL);
    if (migrated < 0) { bpf_object__close(obj); return 1; }
    if (jpath && append_receipt_journal(jpath, &migr) == 0) {
        uint8_t leaf[32]; SHA256((const unsigned char *)&migr, sizeof(migr), leaf);
        char lx[65]; for (int i = 0; i < 32; i++) sprintf(lx + 2 * i, "%02x", leaf[i]);
        printf("  migration receipt appended to journal %s (cause=%d, leaf=%s)\n", jpath, migr.cause, lx);
    }
    int by_name = (new_image.flags & PPT_FLAG_MIGRATE_BY_NAME) != 0;
    if (iface) {
        unsigned int ifindex = if_nametoindex(iface);
        int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "ppt_select_prog"));
        if (!ifindex || bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL))
            fprintf(stderr, "swapselector: re-attach on %s failed\n", iface);
    }
    printf("SELECTOR SWAP: resident posture migrated to node %ld via %s%s.\n",
           migrated, by_name ? "by-name" : "reset-to", iface ? " (new policy re-attached)" : "");
    printf("  sel_state persisted across the reload via the bpffs pin at %s.\n", SEL_STATE_PIN);
    bpf_object__close(obj); free_image(&old_image); free_image(&new_image);
    return 0;
}

static int populate_and_attach_bpf(const Image *im, const char *ifname) {
    struct bpf_object *obj = bpf_object__open_file("ppt_xdp.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "error: failed to open ppt_xdp.bpf.o. Ensure 'make' compiled the BPF object.\n");
        return -1;
    }

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "error: failed to load bpf object (err=%d). Root / CAP_BPF required for kernel load.\n", err);
        bpf_object__close(obj);
        return -1;
    }

    populate_maps(obj, im);

    /* Pin result_map so it outlives this process: the smoke test injects a packet (the attached XDP
     * program writes its verdict here) and then reads it back to compare against the host reference. */
    struct bpf_map *result_map = bpf_object__find_map_by_name(obj, "result_map");
    if (result_map) {
        unlink(PIN_PATH);                         /* clear any stale pin from a prior run */
        if (bpf_map__pin(result_map, PIN_PATH) == 0)
            printf("[loader] pinned result_map at %s\n", PIN_PATH);
        else
            fprintf(stderr, "warning: failed to pin result_map at %s\n", PIN_PATH);
    }

    if (ifname) {
        unsigned int ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            fprintf(stderr, "error: invalid network interface %s\n", ifname);
            bpf_object__close(obj);
            return -1;
        }
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_xdp_prog");
        if (!prog) {
            fprintf(stderr, "error: program ppt_xdp_prog not found\n");
            bpf_object__close(obj);
            return -1;
        }
        int prog_fd = bpf_program__fd(prog);
        err = bpf_xdp_attach((int)ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (err) {
            fprintf(stderr, "error: bpf_xdp_attach failed on %s (err=%d). Requires root.\n", ifname, err);
            bpf_object__close(obj);
            return -1;
        }
        printf("[loader] Attached XDP program to interface %s (SKB/generic mode).\n", ifname);
    }

    bpf_object__close(obj);
    return 0;
}

/* Read the pinned result_map back (populated by the in-kernel XDP run) so the smoke test can compare
 * the kernel's verdict to the host reference for the same packet. */
static int read_pinned_result(void)
{
    int fd = bpf_obj_get(PIN_PATH);
    if (fd < 0) {
        fprintf(stderr, "error: cannot open pinned result map at %s\n", PIN_PATH);
        return 2;
    }
    __u32 key = 0;
    struct ppt_result result = {0};
    if (bpf_map_lookup_elem(fd, &key, &result) != 0) {
        fprintf(stderr, "error: result map lookup failed\n");
        return 2;
    }
    printf("KERNEL RESULT: matched_edge=%d target_node=%d eval_status=%u pkt_count=%llu\n",
           result.matched_edge, result.target_node, result.eval_status, (unsigned long long)result.pkt_count);
    return 0;
}

/* Certify the eBPF target against a frozen conformance vector set, IN-KERNEL, without a NIC: load the
 * PPT image into the maps, then run each crafted packet through the actual XDP program via
 * BPF_PROG_TEST_RUN and compare the in-kernel target_node to the recorded reference. Requires CAP_BPF.
 * Packet file format (little-endian, repeated): <s32 expected_target><u32 pkt_len><pkt_len bytes>. */
/* Drive a whole flow through the XDP program IN-KERNEL, hop by hop: start at the flow's start node,
 * evaluate it via BPF_PROG_TEST_RUN, follow the matched target, repeat to a terminal. Compares the
 * in-kernel routing path against the host reference (evaluate_host, == interp.c). `names[]` (optional,
 * one node name per line) makes the path human-readable. regs_path is encode_regs format. Root/CAP_BPF. */
static int run_flow(const char *ppt_path, const char *regs_path, char **names, int n_names) {
    Image im; load_image(ppt_path, &im);
    long len; uint8_t *regs_bytes = read_file(regs_path, &len);
    int nf = im.n_fields;
    struct ppt_reg *regs = calloc(nf ? nf : 1, sizeof(struct ppt_reg));
    for (int i = 0; i < nf; i++) {
        regs[i].ty = rd32(regs_bytes + 4 + 8 * i);
        regs[i].val = rd32(regs_bytes + 8 + 8 * i);
    }
    free(regs_bytes);
    int cap = im.max_steps ? im.max_steps : 64;

    #define NAME(ix) ((names && (ix) >= 0 && (ix) < n_names) ? names[ix] : NULL)
    #define PRINTPATH(arr, cnt) do { for (int hop = 0; hop < (cnt); hop++) { \
            if (NAME(arr[hop])) printf("%s%s", NAME(arr[hop]), hop + 1 < (cnt) ? " -> " : "\n"); \
            else printf("%d%s", arr[hop], hop + 1 < (cnt) ? " -> " : "\n"); } } while (0)

    /* host reference path */
    int hp[256], hn = 0, cur = im.start; hp[hn++] = cur;
    for (int step = 0; step < cap && im.nodes[cur].edge_cnt; step++) {
        int tgt = -1;
        if (evaluate_host(&im, cur, regs, &tgt) < 0) { printf("  [host stuck]\n"); break; }
        cur = tgt; if (hn < 256) hp[hn++] = cur;
    }

    struct bpf_object *obj = bpf_object__open_file("ppt_xdp.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "error: bpf open/load failed (verifier / CAP_BPF).\n");
        if (obj) bpf_object__close(obj);
        return -1;
    }
    populate_maps(obj, &im);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_xdp_prog");
    struct bpf_map *result_map = bpf_object__find_map_by_name(obj, "result_map");
    int prog_fd = bpf_program__fd(prog), res_fd = bpf_map__fd(result_map);

    /* in-kernel path */
    int kp[256], kn = 0; cur = im.start; kp[kn++] = cur;
    uint8_t frame[2048], out_buf[2048];
    for (int step = 0; step < cap && im.nodes[cur].edge_cnt; step++) {
        int flen = build_frame(frame, (uint16_t)cur, im.n_fields, regs);
        struct bpf_test_run_opts opts; memset(&opts, 0, sizeof(opts));
        opts.sz = sizeof(opts); opts.data_in = frame; opts.data_size_in = flen;
        opts.data_out = out_buf; opts.data_size_out = sizeof(out_buf); opts.repeat = 1;
        struct ppt_result result = {0}; __u32 key = 0;
        if (bpf_prog_test_run_opts(prog_fd, &opts) != 0 ||
            bpf_map_lookup_elem(res_fd, &key, &result) != 0 || result.eval_status != 1) {
            printf("  [in-kernel stuck]\n"); break;
        }
        cur = result.target_node; if (kn < 256) kp[kn++] = cur;
    }

    printf("\n[Host reference path (evaluate_host == interp.c)]\n  "); PRINTPATH(hp, hn);
    printf("[In-kernel path (XDP program, hop-by-hop BPF_PROG_TEST_RUN)]\n  "); PRINTPATH(kp, kn);
    int same = (hn == kn); for (int hop = 0; hop < hn && same; hop++) same = (hp[hop] == kp[hop]);
    printf("\n%s: the flow routed IN-KERNEL along the same path as the reference.\n",
           same ? "PASS" : "FAIL");
    free(regs); bpf_object__close(obj);
    return same ? 0 : 1;
}

/* Trace a flow to a terminal using the host reference evaluator (== interp.c). Fills out[] with the
 * node-index path, returns its length. */
static int host_trace(const Image *im, const struct ppt_reg *regs, int *out, int cap) {
    int path_len = 0, cur = im->start; out[path_len++] = cur;
    int lim = im->max_steps ? im->max_steps : 64;
    for (int step = 0; step < lim && im->nodes[cur].edge_cnt; step++) {
        int tgt = -1;
        if (evaluate_host(im, cur, regs, &tgt) < 0) break;
        cur = tgt; if (path_len < cap) out[path_len++] = cur;
    }
    return path_len;
}

/* Trace a flow to a terminal IN-KERNEL: evaluate each node via BPF_PROG_TEST_RUN, follow the target. */
static int kernel_trace(const Image *im, const struct ppt_reg *regs, int prog_fd, int res_fd,
                        int *out, int cap) {
    int path_len = 0, cur = im->start; out[path_len++] = cur;
    int lim = im->max_steps ? im->max_steps : 64;
    uint8_t frame[2048], ob[2048];
    for (int step = 0; step < lim && im->nodes[cur].edge_cnt; step++) {
        int flen = build_frame(frame, (uint16_t)cur, im->n_fields, regs);
        struct bpf_test_run_opts opts; memset(&opts, 0, sizeof(opts)); opts.sz = sizeof(opts);
        opts.data_in = frame; opts.data_size_in = flen; opts.data_out = ob; opts.data_size_out = sizeof(ob);
        opts.repeat = 1;
        struct ppt_result result = {0}; __u32 result_key = 0;
        if (bpf_prog_test_run_opts(prog_fd, &opts) != 0 ||
            bpf_map_lookup_elem(res_fd, &result_key, &result) != 0 || result.eval_status != 1) break;
        cur = result.target_node; if (path_len < cap) out[path_len++] = cur;
    }
    return path_len;
}

/* Batch: route MANY register files (one per REAL alert) through the SAME flow table in-kernel, each
 * hop-by-hop, and confirm each path matches the host reference. One BPF load for the whole batch.
 * Record format (LE): <u32 reg_len><reg_len bytes of ppt_reg[]>  (reg_len = n_fields * 8). */
static int runbatch_flow(const char *ppt_path, const char *records_path, char **names, int n_names) {
    Image im; load_image(ppt_path, &im);
    struct bpf_object *obj = bpf_object__open_file("ppt_xdp.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "error: bpf open/load failed (verifier / CAP_BPF).\n");
        if (obj) bpf_object__close(obj);
        return -1;
    }
    populate_maps(obj, &im);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_xdp_prog");
    struct bpf_map *rm = bpf_object__find_map_by_name(obj, "result_map");
    int prog_fd = bpf_program__fd(prog), res_fd = bpf_map__fd(rm);

    long flen; uint8_t *buf = read_file(records_path, &flen);
    int nf = im.n_fields;
    struct ppt_reg *regs = calloc(nf ? nf : 1, sizeof(struct ppt_reg));
    long off = 0; int total = 0, passed = 0;

    printf("\n[Real alerts -> eBPF router IN-KERNEL, hop-by-hop, vs host reference]\n");
    while (off + 4 <= flen) {
        uint32_t rlen = rd32(buf + off); off += 4;
        if (off + (long)rlen > flen) break;
        int cnt = (int)(rlen / 8);
        for (int i = 0; i < nf; i++) {
            if (i < cnt) { regs[i].ty = rd32(buf + off + 8 * i); regs[i].val = rd32(buf + off + 8 * i + 4); }
            else { regs[i].ty = 0; regs[i].val = 0; }
        }
        off += rlen;
        total++;
        int hp[256], kp[256];
        int hn = host_trace(&im, regs, hp, 256);
        int kn = kernel_trace(&im, regs, prog_fd, res_fd, kp, 256);
        int same = (hn == kn); for (int hop = 0; hop < hn && same; hop++) same = (hp[hop] == kp[hop]);
        passed += same;
        printf("  alert %3d [%s]  ", total, same ? "PASS" : "FAIL");
        for (int hop = 0; hop < kn; hop++) {
            const char *nm = (names && kp[hop] >= 0 && kp[hop] < n_names) ? names[kp[hop]] : NULL;
            if (nm) printf("%s%s", nm, hop + 1 < kn ? " -> " : "\n");
            else printf("%d%s", kp[hop], hop + 1 < kn ? " -> " : "\n");
        }
    }
    free(regs); free(buf); bpf_object__close(obj);
    printf("\neBPF vs reference: %d/%d REAL alerts routed identically in-kernel.\n", passed, total);
    return (total > 0 && passed == total) ? 0 : 1;
}

static int certify_bpf(const char *packets_path) {
    struct bpf_object *obj = bpf_object__open_file("ppt_xdp.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "error: failed to open ppt_xdp.bpf.o (run 'make').\n"); return -1; }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "error: bpf load failed (verifier / CAP_BPF).\n");
        bpf_object__close(obj); return -1;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_xdp_prog");
    struct bpf_map *result_map = bpf_object__find_map_by_name(obj, "result_map");
    if (!prog || !result_map) {
        fprintf(stderr, "error: ppt_xdp_prog / result_map not found in object.\n");
        bpf_object__close(obj); return -1;
    }
    int prog_fd = bpf_program__fd(prog);
    int res_fd = bpf_map__fd(result_map);

    long flen = 0; uint8_t *buf = read_file(packets_path, &flen);

    /* Each vector carries its OWN compiled table (predicates each compile to a distinct PPT), so the
     * maps are repopulated per vector before the in-kernel run. The BPF program bounds every access by
     * config_map's counts, so stale higher-index map entries from a larger prior table are never read.
     * Record format (LE): <s32 expected_target><u32 tbl_len><tbl><u32 pkt_len><pkt>. */
    printf("\n[eBPF in-kernel conformance — BPF_PROG_TEST_RUN, table-per-vector]\n");
    long off = 0; int total = 0, passed = 0, first_fail = -1;
    uint8_t out_buf[2048];
    while (off + 4 <= flen) {
        int32_t expected = (int32_t)rd32(buf + off); off += 4;
        if (off + 4 > flen) break;
        uint32_t tbl_len = rd32(buf + off); off += 4;
        if (off + (long)tbl_len > flen) break;
        const uint8_t *tbl = buf + off; off += tbl_len;
        if (off + 4 > flen) break;
        uint32_t pkt_len = rd32(buf + off); off += 4;
        if (off + (long)pkt_len > flen) break;
        uint8_t *pkt = buf + off; off += pkt_len;
        total++;

        Image im; memset(&im, 0, sizeof(im));
        if (parse_image_buf(tbl, tbl_len, &im) != 0) {
            printf("  vector %3d: BAD TABLE (%u B)\n", total, tbl_len);
            if (first_fail < 0) first_fail = total;
            continue;
        }
        populate_maps(obj, &im);

        struct bpf_test_run_opts opts;
        memset(&opts, 0, sizeof(opts));
        opts.sz = sizeof(opts);
        opts.data_in = pkt; opts.data_size_in = pkt_len;
        opts.data_out = out_buf; opts.data_size_out = sizeof(out_buf);
        opts.repeat = 1;
        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        struct ppt_result result = {0}; __u32 key = 0;
        if (err == 0) bpf_map_lookup_elem(res_fd, &key, &result);
        int got = (err == 0) ? result.target_node : -2;
        int ok = (got == expected);
        passed += ok;
        if (!ok) {
            printf("  vector %3d: FAIL  expected target=%d  in-kernel=%d (edge=%d status=%u ret=%u err=%d)\n",
                   total, expected, got, result.matched_edge, result.eval_status, opts.retval, err);
            if (first_fail < 0) first_fail = total;
        }
        free_image(&im);
    }
    free(buf);
    bpf_object__close(obj);
    if (total == 0) { fprintf(stderr, "error: no vectors read from %s\n", packets_path); return 2; }
    printf("\neBPF in-kernel conformance: %d/%d vectors match the reference.\n", passed, total);
    if (first_fail >= 0) printf("  (first mismatch at vector %d)\n", first_fail);
    else printf("  ALL PASS — every in-fragment vector routed identically in-kernel and by the reference.\n");
    return (passed == total) ? 0 : 1;
}

/* Attach the REAL-packet program (ppt_net.bpf.o) to a live interface, observe-only (it only ever
 * returns XDP_PASS). Populates the PPT table from <ppt>, pins the verdict + result maps so `netstats`
 * can read them after this process exits, and attaches in SKB/generic mode (works on veth/gretap). */
/* Derive the drop-node bitmask from the node-name sidecar (a node named "drop" or "block" => XDP_DROP)
 * and write it into config_map[0].drop_mask. names_path may be NULL => observe-only (mask stays 0).
 * Covers node indices 0-63 (the net program bounds the shift). */
/* The sidecar arrives already parsed (read_names, ppt_maps.c), so this function no longer re-reads the
 * file that its caller just read; names_path is still taken because the two observe-only cases read
 * differently to an operator, no sidecar asked for versus one that would not parse. */
static void config_set_drop_mask(struct bpf_object *obj, const char *names_path,
                                 char **names, int n_names) {
    if (!names_path) { printf("[loader] observe-only (no names sidecar given)\n"); return; }
    if (!names) { printf("[loader] observe-only (names sidecar unreadable)\n"); return; }
    __u64 mask = 0;
    for (int idx = 0; idx < n_names && idx < 64; idx++) {
        if (strcmp(names[idx], "drop") == 0 || strcmp(names[idx], "block") == 0) mask |= (1ULL << idx);
    }
    struct bpf_map *cm = bpf_object__find_map_by_name(obj, "config_map");
    __u32 key = 0; struct ppt_config cfg;
    if (cm && bpf_map_lookup_elem(bpf_map__fd(cm), &key, &cfg) == 0) {
        cfg.drop_mask = mask;
        bpf_map_update_elem(bpf_map__fd(cm), &key, &cfg, BPF_ANY);
    }
    if (mask) printf("[loader] INLINE ENFORCEMENT on: drop_mask=0x%llx (drop/block decision nodes)\n",
                     (unsigned long long)mask);
    else printf("[loader] observe-only (no drop/block node in this flow)\n");
}

static int net_attach(const char *ppt_path, const char *ifname, const char *names_path) {
    Image im; load_image(ppt_path, &im);
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { fprintf(stderr, "error: no such interface %s\n", ifname); return 2; }

    struct bpf_object *obj = bpf_object__open_file("ppt_net.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "error: open/load ppt_net.bpf.o failed (verifier / CAP_BPF).\n");
        if (obj) bpf_object__close(obj);
        return -1;
    }
    populate_maps(obj, &im);
    int n_names = 0;
    char **names = read_names(names_path, &n_names);
    config_set_drop_mask(obj, names_path, names, n_names);
    free_names(names, n_names);

    struct bpf_map *vmap = bpf_object__find_map_by_name(obj, "verdict_map");
    struct bpf_map *rmap = bpf_object__find_map_by_name(obj, "result_map");
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_net_prog");
    if (!vmap || !rmap || !prog) {
        fprintf(stderr, "error: ppt_net program/maps not found.\n");
        bpf_object__close(obj); return -1;
    }
    unlink(NET_VERDICT_PIN); unlink(NET_RESULT_PIN);
    if (bpf_map__pin(vmap, NET_VERDICT_PIN) || bpf_map__pin(rmap, NET_RESULT_PIN)) {
        fprintf(stderr, "warning: could not pin net maps (netstats may not find them)\n");
    }
    /* zero the histogram so counts reflect this attach only */
    int vfd = bpf_map__fd(vmap);
    for (__u32 node_index = 0; node_index < MAX_NODES; node_index++) {
        __u64 zero_count = 0;
        bpf_map_update_elem(vfd, &node_index, &zero_count, BPF_ANY);
    }

    int err = bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "error: bpf_xdp_attach on %s failed (err=%d)\n", ifname, err);
        bpf_object__close(obj); return -1;
    }
    /* The attach holds a ref on the iface; the pinned maps keep the histogram readable after we exit. */
    bpf_object__close(obj);
    printf("OK: ppt_net attached to %s (SKB mode). Read counts with:\n", ifname);
    printf("     sudo ./loader netstats %s <names>\n", ifname);
    return 0;
}

/* Read the pinned per-target histogram + total. Observe-only output over whatever real traffic the
 * attached program has classified so far. */
static int net_stats(char **names, int n_names) {
    int vfd = bpf_obj_get(NET_VERDICT_PIN);
    int rfd = bpf_obj_get(NET_RESULT_PIN);
    if (vfd < 0 || rfd < 0) {
        fprintf(stderr, "error: net maps not pinned — attach first (loader netattach <ppt> <iface>)\n");
        return 2;
    }
    __u32 zero = 0; struct ppt_result res = {0};
    bpf_map_lookup_elem(rfd, &zero, &res);
    printf("\n[ppt_net — real-traffic classification histogram]\n");
    __u64 total = 0;
    for (__u32 node_index = 0; node_index < MAX_NODES; node_index++) {
        __u64 count = 0;
        if (bpf_map_lookup_elem(vfd, &node_index, &count) != 0 || count == 0) continue;
        const char *nm = (names && node_index < (unsigned)n_names) ? names[node_index]
                        : (node_index == MAX_NODES - 1 ? "(no-match)" : NULL);
        if (nm) printf("  %-14s %llu\n", nm, (unsigned long long)count);
        else    printf("  node[%u]        %llu\n", node_index, (unsigned long long)count);
        total += count;
    }
    printf("  ----\n  total classified: %llu packets  (result_map pkt_count=%llu)\n",
           (unsigned long long)total, (unsigned long long)res.pkt_count);
    return 0;
}

/* Build a real (non-PPT) Ethernet+IPv4+L4 frame for benchmarking the parser+eval path. */
static int build_ip_frame(uint8_t *out, uint8_t proto, uint16_t dport, int app_bytes) {
    int l4 = (proto == 6) ? 20 : (proto == 17) ? 8 : 8;   /* tcp / udp / icmp header */
    int tot = 20 + l4 + app_bytes;
    uint8_t *cursor = out;
    memset(cursor, 0xff, 6); cursor += 6; memset(cursor, 0x02, 6); cursor += 6;
    *cursor++ = 0x08; *cursor++ = 0x00;                                                  /* eth ipv4 */
    *cursor++ = 0x45; *cursor++ = 0; *cursor++ = (uint8_t)(tot >> 8); *cursor++ = (uint8_t)tot;              /* ip */
    *cursor++ = 0x00; *cursor++ = 0x01; *cursor++ = 0x00; *cursor++ = 0x00;
    *cursor++ = 64; *cursor++ = proto; *cursor++ = 0; *cursor++ = 0;
    *cursor++ = 192; *cursor++ = 168; *cursor++ = 1; *cursor++ = 50;
    *cursor++ = 192; *cursor++ = 168; *cursor++ = 1; *cursor++ = 60;
    if (proto == 6) {                                    /* tcp */
        *cursor++ = 0x30; *cursor++ = 0x39; *cursor++ = (uint8_t)(dport >> 8); *cursor++ = (uint8_t)dport;
        memset(cursor, 0, 8); cursor += 8;                          /* seq + ack */
        *cursor++ = 0x50; *cursor++ = 0x18;                         /* data offset 5, flags PSH|ACK */
        *cursor++ = 0xff; *cursor++ = 0xff; *cursor++ = 0; *cursor++ = 0; *cursor++ = 0; *cursor++ = 0;
    } else if (proto == 17) {                            /* udp */
        int ul = 8 + app_bytes;
        *cursor++ = 0x30; *cursor++ = 0x39; *cursor++ = (uint8_t)(dport >> 8); *cursor++ = (uint8_t)dport;
        *cursor++ = (uint8_t)(ul >> 8); *cursor++ = (uint8_t)ul; *cursor++ = 0; *cursor++ = 0;
    } else {                                             /* icmp echo */
        *cursor++ = 8; *cursor++ = 0; *cursor++ = 0; *cursor++ = 0;
        *cursor++ = 0; *cursor++ = 0; *cursor++ = 0; *cursor++ = 0;
    }
    for (int i = 0; i < app_bytes; i++) *cursor++ = 0x41;
    return (int)(cursor - out);
}

/* Benchmark the real-packet path: for representative classes, BPF_PROG_TEST_RUN with a large repeat and
 * report the kernel-measured average ns/packet (parse + Level M eval) and the implied packet rate. */
static int net_bench(const char *ppt_path) {
    Image im; load_image(ppt_path, &im);
    struct bpf_object *obj = bpf_object__open_file("ppt_net.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "error: open/load ppt_net.bpf.o failed (verifier / CAP_BPF).\n");
        if (obj) bpf_object__close(obj);
        return -1;
    }
    populate_maps(obj, &im);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_net_prog");
    if (!prog) { fprintf(stderr, "error: ppt_net_prog not found\n"); bpf_object__close(obj); return -1; }
    int prog_fd = bpf_program__fd(prog);

    struct { const char *name; uint8_t proto; uint16_t dport; int app; } cases[] = {
        {"https (tcp/443)", 6, 443, 100},
        {"dns   (udp/53)",  17, 53, 60},
        {"icmp  (proto 1)", 1, 0, 56},
        {"jumbo (tcp/443)", 6, 443, 1400},
        {"other (tcp/9999)",6, 9999, 100},
    };
    const int REPEAT = 1000000;
    uint8_t frame[2048], out_buf[2048];
    printf("\n[ppt_net per-packet latency — BPF_PROG_TEST_RUN x %d, kernel-measured]\n", REPEAT);
    for (unsigned case_index = 0; case_index < sizeof(cases) / sizeof(cases[0]); case_index++) {
        int flen = build_ip_frame(frame, cases[case_index].proto, cases[case_index].dport, cases[case_index].app);
        struct bpf_test_run_opts opts; memset(&opts, 0, sizeof(opts));
        opts.sz = sizeof(opts);
        opts.data_in = frame; opts.data_size_in = flen;
        opts.data_out = out_buf; opts.data_size_out = sizeof(out_buf);
        opts.repeat = REPEAT;
        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err) { printf("  %-16s ERROR err=%d\n", cases[case_index].name, err); continue; }
        double ns = (double)opts.duration;                /* kernel returns avg ns per run */
        double mpps = ns > 0 ? 1000.0 / ns : 0;           /* million packets/sec on one core */
        printf("  %-16s %7.1f ns/pkt   ~%.2f Mpps/core   (xdp_ret=%u, %d B)\n",
               cases[case_index].name, ns, mpps, opts.retval, flen);
    }
    bpf_object__close(obj);
    return 0;
}

/* ---- double-buffered live hot-swap ------------------------------------------------------------
 * The old element-wise repopulate rewrote the ACTIVE table in place, so a packet mid-swap could
 * read a torn mix of old and new rows. Now the swap writes the INACTIVE bank in full and commits
 * with a single atomic store to bank_map — a packet sees the old table whole or the new table
 * whole. `nfd` collects the map fds of the live program by name so we can address each by bank. */
struct net_maps { int atoms, nodes, edges, prog, config, bank, verdict; };

#define BANK_UPD(fd, base, slot, val_ptr, mapname)                                          \
    do { __u32 _k = (base) + (slot);                                                        \
         if (bpf_map_update_elem((fd), &_k, (val_ptr), BPF_ANY) != 0) {                     \
             fprintf(stderr, "netupdate: %s bank write failed at %u: %s\n",                 \
                     (mapname), _k, strerror(errno)); return -1; }                          \
    } while (0)

/* Write the whole image into `bank` of the live maps. Returns 0 on success, -1 on any write error
 * (a partial inactive-bank write is safe — it is never committed — but we still abort loudly). */
static int write_bank(const struct net_maps *maps, __u32 bank, const Image *im) {
    __u32 ba = bank * MAX_ATOMS, bn = bank * MAX_NODES,
          be = bank * MAX_EDGES, bp = bank * MAX_PROG_WORDS;
    for (__u32 i = 0; i < im->n_atoms; i++) BANK_UPD(maps->atoms, ba, i, &im->atoms[i], "atoms_map");
    for (__u32 i = 0; i < im->n_nodes; i++) BANK_UPD(maps->nodes, bn, i, &im->nodes[i], "nodes_map");
    for (__u32 i = 0; i < im->n_edges; i++) BANK_UPD(maps->edges, be, i, &im->edges[i], "edges_map");
    for (__u32 i = 0; i < im->prog_len; i++) BANK_UPD(maps->prog, bp, i, &im->prog[i], "prog_map");

    /* per-bank config: full struct into config_map[bank], carrying drop_mask from the active bank */
    struct ppt_config cfg = {
        .n_fields = im->n_fields, .n_interns = im->n_interns, .n_atoms = im->n_atoms,
        .n_nodes = im->n_nodes, .n_edges = im->n_edges, .prog_len = im->prog_len,
        .start_node = im->start, .visits_idx = im->visits_idx,
        .max_steps = im->max_steps, .max_stack = im->max_stack,
        .safe_node = im->safe, .policy_hash = policy_hash_of(im) };
    __u32 active = bank ^ 1u;
    struct ppt_config old;
    if (bpf_map_lookup_elem(maps->config, &active, &old) == 0) cfg.drop_mask = old.drop_mask;
    if (bpf_map_update_elem(maps->config, &bank, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "netupdate: config_map[%u] write failed: %s\n", bank, strerror(errno));
        return -1;
    }
    return 0;
}

/* Hot-swap the policy of the LIVE program attached to <iface> with a fresh compiled table
 * (<new.ppt>) — NO detach, NO reload. Writes the inactive bank in full, then flips bank_map in a
 * single atomic store: the packet after the flip routes by the new policy, and no packet ever
 * observes a torn table. */
static int net_update(const char *new_ppt, const char *ifname) {
    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) { fprintf(stderr, "error: no such interface %s\n", ifname); return 2; }
    __u32 prog_id = 0;
    if (bpf_xdp_query_id(ifindex, XDP_FLAGS_SKB_MODE, &prog_id) || !prog_id) {
        fprintf(stderr, "error: no XDP program attached to %s — netattach first.\n", ifname);
        return 2;
    }
    int prog_fd = bpf_prog_get_fd_by_id(prog_id);
    if (prog_fd < 0) { fprintf(stderr, "error: cannot open prog id %u\n", prog_id); return -1; }

    __u32 map_ids[32] = {0};
    struct bpf_prog_info pinfo; memset(&pinfo, 0, sizeof(pinfo));
    pinfo.nr_map_ids = 32; pinfo.map_ids = (__u64)(unsigned long)map_ids;
    __u32 len = sizeof(pinfo);
    if (bpf_obj_get_info_by_fd(prog_fd, &pinfo, &len)) {
        fprintf(stderr, "error: cannot read prog info\n"); close(prog_fd); return -1;
    }

    /* collect the live map fds by name */
    struct net_maps maps = { -1, -1, -1, -1, -1, -1, -1 };
    for (__u32 map_slot = 0; map_slot < pinfo.nr_map_ids; map_slot++) {
        int mfd = bpf_map_get_fd_by_id(map_ids[map_slot]);
        if (mfd < 0) continue;
        struct bpf_map_info mi; memset(&mi, 0, sizeof(mi)); __u32 ml = sizeof(mi);
        if (bpf_obj_get_info_by_fd(mfd, &mi, &ml)) { close(mfd); continue; }
        if      (!strcmp(mi.name, "atoms_map"))   maps.atoms = mfd;
        else if (!strcmp(mi.name, "nodes_map"))   maps.nodes = mfd;
        else if (!strcmp(mi.name, "edges_map"))   maps.edges = mfd;
        else if (!strcmp(mi.name, "prog_map"))    maps.prog = mfd;
        else if (!strcmp(mi.name, "config_map"))  maps.config = mfd;
        else if (!strcmp(mi.name, "bank_map"))    maps.bank = mfd;
        else if (!strcmp(mi.name, "verdict_map")) maps.verdict = mfd;
        else close(mfd);
    }
    close(prog_fd);
    if (maps.atoms < 0 || maps.nodes < 0 || maps.edges < 0 || maps.prog < 0 || maps.config < 0 || maps.bank < 0) {
        fprintf(stderr, "error: attached program is missing a double-buffer map — rebuild + reattach\n");
        return -1;
    }

    Image im; load_image(new_ppt, &im);

    /* which bank is live now? default 0 if unreadable. Write the OTHER one. */
    __u32 zero = 0, active = 0;
    bpf_map_lookup_elem(maps.bank, &zero, &active);
    active &= 1;
    __u32 target = active ^ 1u;

    if (write_bank(&maps, target, &im) != 0) {
        /* the inactive bank is never read; abort without touching bank_map — active policy intact */
        fprintf(stderr, "netupdate: aborting — active bank %u still live, no flip performed\n", active);
        free_image(&im);
        return 1;
    }

    /* THE COMMIT: one aligned store flips the active bank atomically. */
    if (bpf_map_update_elem(maps.bank, &zero, &target, BPF_ANY) != 0) {
        fprintf(stderr, "netupdate: bank flip failed: %s (active bank %u still live)\n",
                strerror(errno), active);
        free_image(&im);
        return 1;
    }

    /* histogram reset happens AFTER the flip (post-swap counts start clean; a couple of in-flight
     * packets may land in the old bank's buckets, which is honest, not torn). */
    if (maps.verdict >= 0)
        for (__u32 i = 0; i < MAX_NODES; i++) {
            __u64 zero_count = 0;
            bpf_map_update_elem(maps.verdict, &i, &zero_count, BPF_ANY);
        }

    printf("OK: hot-swapped the LIVE %s policy from %s — bank %u -> %u, NO detach.\n",
           ifname, new_ppt, active, target);
    printf("     table now: %u nodes, %u edges, %u atoms, %u prog-words (atomic double-buffer flip)\n",
           im.n_nodes, im.n_edges, im.n_atoms, im.prog_len);
    free_image(&im);
    return 0;
}

/* ---- swap-storm concurrency proof ------------------------------------------------------------
 * The atomicity claim, tested under adversarial concurrency: preload bank 0 = policy A and
 * bank 1 = policy B (both fully written), spin a thread flipping bank_map 0<->1 as fast as it can,
 * and on the main thread hammer BPF_PROG_TEST_RUN with one probe packet whose verdict differs
 * between A and B. Every observed verdict must be EXACTLY policy A's tuple or policy B's tuple —
 * a torn read (an edge from one bank with a target from the other, or an out-of-range node) would
 * show up as a third value. Zero torn over the storm is the proof the flip is atomic. */
struct storm_flip_arg { int bank_fd; volatile int *stop; unsigned long flips; };

static void *storm_flipper(void *raw_arg) {
    struct storm_flip_arg *flip_arg = raw_arg;
    __u32 zero = 0, bank_index = 0;
    while (!*flip_arg->stop) {
        bank_index ^= 1u;
        bpf_map_update_elem(flip_arg->bank_fd, &zero, &bank_index, BPF_ANY);
        flip_arg->flips++;
    }
    return NULL;
}

static int net_storm(const char *ppt_a, const char *ppt_b) {
    struct bpf_object *obj = bpf_object__open_file("ppt_net.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "error: open/load ppt_net.bpf.o failed (verifier / CAP_BPF).\n");
        if (obj) bpf_object__close(obj);
        return -1;
    }
    /* bank 0 = A (via populate_maps), bank 1 = B (manual) */
    Image image_a, image_b; load_image(ppt_a, &image_a); load_image(ppt_b, &image_b);
    populate_maps(obj, &image_a);                 /* writes bank 0 + bank_map=0 */
    struct net_maps maps = {
        bpf_map__fd(bpf_object__find_map_by_name(obj, "atoms_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "nodes_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "edges_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "prog_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "config_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "bank_map")),
        bpf_map__fd(bpf_object__find_map_by_name(obj, "verdict_map")),
    };
    if (write_bank(&maps, 1, &image_b) != 0) { bpf_object__close(obj); return -1; }

    /* the probe packet + the two expected verdicts. Run once in each bank (flipper idle) to learn
     * A's and B's ground-truth tuples, so the test is self-calibrating for any A/B pair. */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ppt_net_prog");
    int prog_fd = bpf_program__fd(prog);
    __u32 zero = 0;
    uint8_t frame[2048], out[2048];
    int flen = build_ip_frame(frame, 6, 443, 64);      /* tcp/443 */
    struct ppt_result rA, rB;
    __u32 zerob = 0, oneb = 1;
    struct bpf_test_run_opts opts;
    #define RUN() do { memset(&opts,0,sizeof(opts)); opts.sz=sizeof(opts); opts.data_in=frame; opts.data_size_in=flen; \
                       opts.data_out=out; opts.data_size_out=sizeof(out); opts.repeat=1; \
                       bpf_prog_test_run_opts(prog_fd,&opts); } while(0)
    int result_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "result_map"));
    __u32 rk = 0;
    bpf_map_update_elem(maps.bank, &zero, &zerob, BPF_ANY); RUN();
    bpf_map_lookup_elem(result_fd, &rk, &rA);
    bpf_map_update_elem(maps.bank, &zero, &oneb, BPF_ANY); RUN();
    bpf_map_lookup_elem(result_fd, &rk, &rB);
    printf("[swap-storm] probe tcp/443 -> A(edge=%d,node=%d)  B(edge=%d,node=%d)\n",
           rA.matched_edge, rA.target_node, rB.matched_edge, rB.target_node);
    if (rA.matched_edge == rB.matched_edge && rA.target_node == rB.target_node) {
        fprintf(stderr, "storm: A and B give the same verdict — pick policies that differ on the probe\n");
        bpf_object__close(obj); return 2;
    }

    /* storm */
    volatile int stop = 0;
    struct storm_flip_arg fa = { maps.bank, &stop, 0 };
    pthread_t th; pthread_create(&th, NULL, storm_flipper, &fa);

    const int EVALUATIONS = 200000;
    long nA = 0, nB = 0, torn = 0;
    for (int evaluation_index = 0; evaluation_index < EVALUATIONS; evaluation_index++) {
        RUN();
        struct ppt_result result; __u32 rk = 0;
        bpf_map_lookup_elem(result_fd, &rk, &result);
        if (result.matched_edge == rA.matched_edge && result.target_node == rA.target_node) nA++;
        else if (result.matched_edge == rB.matched_edge && result.target_node == rB.target_node) nB++;
        else {
            torn++;
            if (torn <= 5) fprintf(stderr, "  TORN: edge=%d node=%d\n", result.matched_edge, result.target_node);
        }
    }
    stop = 1; pthread_join(th, NULL);
    #undef RUN

    printf("[swap-storm] %d evaluations under %lu concurrent bank flips: A=%ld B=%ld TORN=%ld\n",
           EVALUATIONS, fa.flips, nA, nB, torn);
    printf("%s\n", torn == 0
        ? "\xE2\x9C\x85 ATOMIC: every verdict was a consistent policy; zero torn reads under the storm"
        : "\xE2\x9C\x97 TORN READS OBSERVED — the swap is NOT atomic");
    bpf_object__close(obj); free_image(&image_a); free_image(&image_b);
    return torn == 0 ? 0 : 1;
}

static int net_detach(const char *ifname) {
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { fprintf(stderr, "error: no such interface %s\n", ifname); return 2; }
    int err = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    unlink(NET_VERDICT_PIN); unlink(NET_RESULT_PIN);
    if (err) fprintf(stderr, "warning: detach returned %d\n", err);
    else printf("OK: ppt_net detached from %s, pins removed.\n", ifname);
    return err ? 1 : 0;
}
#endif

/* ---- the verb table ---------------------------------------------------------------------------
 * One row per subcommand: the word an operator types as argv[2], the argc that word needs, the
 * refusal it prints when it needs privilege and does not have it, the handler, and the help line.
 * `loader help` walks the rows, so the usage text cannot drift away from what main dispatches; the
 * strcmp chain this replaces documented six of the fifteen verbs and hid the rest in README.md.
 *
 * argv[1] is the image path, so a handler reads its own arguments from argv[1] and argv[3] onward.
 * A verb whose argc is short falls through to the plain image summary at the end of main, which is
 * what the chain did too. */
static void print_usage(const char *prog);

#ifndef NO_LIBBPF
struct loader_command {
    const char *verb;
    int min_argc;               /* argc this verb needs, argv[0] and the image path counted */
    const char *root_refusal;   /* printed on stderr when not root; NULL = no privilege needed */
    int (*handler)(int argc, char **argv);
    const char *help;           /* the usage line, everything after the program name */
};

static int cmd_readresult(int argc, char **argv) {
    (void)argc; (void)argv;
    return read_pinned_result();
}

static int cmd_certify(int argc, char **argv) {
    (void)argc;
    /* Each vector in the corpus file carries its own compiled table; argv[1] (ppt) is unused here. */
    return certify_bpf(argv[3]);
}

static int cmd_selattach(int argc, char **argv) {
    __u32 xdp_flags = (argc >= 5 && strcmp(argv[4], "native") == 0) ? XDP_FLAGS_DRV_MODE
                                                                   : XDP_FLAGS_SKB_MODE;
    return sel_attach_cmd(argv[1], argv[3], xdp_flags);
}

static int cmd_selstate(int argc, char **argv) {
    (void)argc; (void)argv;
    return sel_state_cmd();
}

static int cmd_seldetach(int argc, char **argv) {
    (void)argc;
    return sel_detach_cmd(argv[3]);
}

static int cmd_selsend(int argc, char **argv) {
    (void)argc;
    return sel_send_cmd(argv[3], atoi(argv[4]));
}

static int cmd_swapselector(int argc, char **argv) {
    return selector_swap_cmd(argv[1], argv[3], argc >= 5 ? argv[4] : NULL);
}

static int cmd_run(int argc, char **argv) {
    int n_names = 0;
    char **names = read_names(argc >= 5 ? argv[4] : NULL, &n_names);
    int rc = run_flow(argv[1], argv[3], names, n_names);
    free_names(names, n_names);
    return rc;
}

static int cmd_runbatch(int argc, char **argv) {
    int n_names = 0;
    char **names = read_names(argc >= 5 ? argv[4] : NULL, &n_names);
    int rc = runbatch_flow(argv[1], argv[3], names, n_names);
    free_names(names, n_names);
    return rc;
}

static int cmd_netattach(int argc, char **argv) {
    return net_attach(argv[1], argv[3], argc >= 5 ? argv[4] : NULL);
}

static int cmd_netstats(int argc, char **argv) {
    int n_names = 0;
    char **names = read_names(argc >= 4 ? argv[3] : NULL, &n_names);
    int rc = net_stats(names, n_names);
    free_names(names, n_names);
    return rc;
}

static int cmd_netdetach(int argc, char **argv) {
    (void)argc;
    return net_detach(argv[3]);
}

static int cmd_netbench(int argc, char **argv) {
    (void)argc;
    return net_bench(argv[1]);
}

static int cmd_netupdate(int argc, char **argv) {
    (void)argc;
    return net_update(argv[1], argv[3]);
}

static int cmd_netstorm(int argc, char **argv) {
    (void)argc;
    return net_storm(argv[1], argv[3]);
}

static int cmd_help(int argc, char **argv) {
    (void)argc;
    print_usage(argv[0]);
    return 0;
}

static const struct loader_command LOADER_COMMANDS[] = {
    { "readresult", 3, NULL,
      cmd_readresult, "<image.ppt> readresult" },
    { "certify", 4, "error: 'certify' loads the program into the kernel — run as root / CAP_BPF.\n",
      cmd_certify, "<image.ppt> certify <packets.bin>   (in-kernel conformance; root)" },
    { "selattach", 4, "error: 'selattach' needs root.\n",
      cmd_selattach, "<policy.ppt> selattach <iface> [native]  (deploy resident selector, pin state; root)" },
    { "selstate", 3, NULL,
      cmd_selstate, "x selstate                           (read the pinned resident posture)" },
    { "seldetach", 4, NULL,
      cmd_seldetach, "x seldetach <iface>                  (detach + remove pins; root)" },
    { "selsend", 5, NULL,
      cmd_selsend, "x selsend <iface> <ev>               (inject one control event frame)" },
    { "swapselector", 4, "error: 'swapselector' loads the program into the kernel — run as root.\n",
      cmd_swapselector, "<new.ppt> swapselector <old.ppt> [iface]  (hot-swap + migrate posture; root)" },
    { "run", 4, "error: 'run' loads the program into the kernel — run as root / CAP_BPF.\n",
      cmd_run, "<image.ppt> run <regs.bin> [names]   (drive one flow hop by hop in kernel; root)" },
    { "runbatch", 4, "error: 'runbatch' loads the program into the kernel — run as root / CAP_BPF.\n",
      cmd_runbatch, "<image.ppt> runbatch <records.bin> [names]  (the same, many register files; root)" },
    { "netattach", 4, "error: 'netattach' needs root / CAP_BPF.\n",
      cmd_netattach, "<image.ppt> netattach <iface> [names]  (attach the real packet program; root)" },
    { "netstats", 3, "error: 'netstats' needs root / CAP_BPF.\n",
      cmd_netstats, "x netstats [names]                   (read the pinned real traffic histogram; root)" },
    { "netdetach", 4, "error: 'netdetach' needs root / CAP_BPF.\n",
      cmd_netdetach, "x netdetach <iface>                  (detach the real packet program; root)" },
    { "netbench", 3, "error: 'netbench' needs root / CAP_BPF.\n",
      cmd_netbench, "<image.ppt> netbench                 (per packet latency of the real packet path; root)" },
    { "netupdate", 4, "error: 'netupdate' needs root / CAP_BPF.\n",
      cmd_netupdate, "<new.ppt> netupdate <iface>          (hot swap the live policy, atomic bank flip; root)" },
    { "netstorm", 4, "error: 'netstorm' needs root / CAP_BPF.\n",
      cmd_netstorm, "<a.ppt> netstorm <b.ppt>             (bank flip atomicity under a swap storm; root)" },
    { "help", 3, NULL,
      cmd_help, "help                                 (print this list of verbs)" },
};

static const struct loader_command *find_command(const char *verb) {
    if (!verb) return NULL;
    for (unsigned row = 0; row < sizeof(LOADER_COMMANDS) / sizeof(LOADER_COMMANDS[0]); row++)
        if (strcmp(LOADER_COMMANDS[row].verb, verb) == 0) return &LOADER_COMMANDS[row];
    return NULL;
}
#endif

static void print_usage(const char *prog) {
    printf("usage: %s <image.ppt> [ifname] [input_regs.bin]\n", prog);
#ifndef NO_LIBBPF
    for (unsigned row = 0; row < sizeof(LOADER_COMMANDS) / sizeof(LOADER_COMMANDS[0]); row++)
        printf("       %s %s\n", prog, LOADER_COMMANDS[row].help);
#endif
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 2;
    }
    /* `loader help` carries no image path for the dispatch below to key on, so answer it here. */
    if (argc == 2 && (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "-h") == 0 ||
                      strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    const char *ppt_path = argv[1];
    const char *ifname = (argc >= 3 && strlen(argv[2]) > 0) ? argv[2] : NULL;
    const char *regs_path = (argc >= 4) ? argv[3] : NULL;

#ifndef NO_LIBBPF
    const struct loader_command *cmd = find_command(argc >= 3 ? argv[2] : NULL);
    if (cmd && argc >= cmd->min_argc) {
        if (cmd->root_refusal && getuid() != 0) {
            fputs(cmd->root_refusal, stderr);
            return 2;
        }
        return cmd->handler(argc, argv);
    }
#endif

    Image im;
    load_image(ppt_path, &im);

    printf("=====================================================\n");
    printf("  PrismPath PPT v1 Table Loader & Semantics Checker  \n");
    printf("=====================================================\n");
    printf("Image File : %s\n", ppt_path);
    printf("Atoms      : %u\n", im.n_atoms);
    printf("Nodes      : %u\n", im.n_nodes);
    printf("Edges      : %u\n", im.n_edges);
    printf("Prog Length: %u words\n", im.prog_len);
    printf("Fields     : %u\n", im.n_fields);
    printf("Start Node : %u\n", im.start);

    if (regs_path) {
        long len; uint8_t *regs_bytes = read_file(regs_path, &len);
        if (len == 4 + 8L * im.n_fields) {
            uint16_t node = (uint16_t)rd32(regs_bytes);
            struct ppt_reg *regs = malloc(sizeof(struct ppt_reg) * (im.n_fields ? im.n_fields : 1));
            for (int field_index = 0; field_index < im.n_fields; field_index++) {
                regs[field_index].ty = rd32(regs_bytes + 4 + 8 * field_index);
                regs[field_index].val = rd32(regs_bytes + 8 + 8 * field_index);
            }
            int target = -1;
            int matched_edge = evaluate_host(&im, node, regs, &target);
            printf("\n[Host Semantics Reference Match]\n");
            if (matched_edge >= 0) {
                printf("  Matched Edge Index : %d\n", matched_edge);
                printf("  Target Node Index  : %d\n", target);
            } else {
                printf("  Matched Edge Index : none (stuck)\n");
            }
            free(regs);
        }
        free(regs_bytes);
    }

    int load_rc = 0;
#ifndef NO_LIBBPF
    printf("\n[BPF Kernel Load Path]\n");
    if (getuid() != 0) {
        printf("NOTICE: Running as non-root user (uid=%d).\n", getuid());
        printf("        Loading eBPF maps/programs into kernel requires root / CAP_BPF.\n");
        printf("        Host-side validation completed successfully.\n");
    } else {
        /* Propagate the real load/attach result as the process exit code so callers (smoke.sh, CI)
         * get an honest pass/fail without parsing the verifier log. */
        load_rc = populate_and_attach_bpf(&im, ifname);
        if (load_rc == 0 && ifname && ifname[0])
            printf("OK: XDP program loaded (verifier passed) and attached to %s.\n", ifname);
    }
#else
    (void)ifname;
    printf("\n[BPF Kernel Load Path]\n");
    printf("NOTICE: Compiled without libbpf (-DNO_LIBBPF).\n");
    printf("        Host-side validation completed successfully.\n");
    printf("        When libbpf-dev is installed, re-run 'make' to enable kernel map loading & XDP attachment.\n");
#endif

    printf("=====================================================\n");
    return load_rc ? 1 : 0;
}
