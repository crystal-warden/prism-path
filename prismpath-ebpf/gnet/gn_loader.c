// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* gn_loader.c: load, fill, attach and read the governed net XDP program (needs CAP_BPF and CAP_NET_ADMIN;
 * integrations/governed_net/SETUP.md says when and how the owner runs it).
 *
 *   gn_loader test-run OBJ TABLE.ppt ACTIONS [--image-index N]  < frames  > decisions
 *       Loads the program (the kernel verifier runs here), fills its maps, and runs every frame through
 *       BPF_PROG_TEST_RUN, printing gn_batch's line format so the two outputs diff directly. Attaches to
 *       nothing.
 *   gn_loader run IFNAME OBJ TABLE.ppt ACTIONS [--generic] [--image-index N]
 *       Loads, fills (gn_config_map.loaded written last), attaches in native (driver) mode, or generic with
 *       --generic, then prints every ring buffer event as one hex line (struct gn_event) on standard output
 *       for receipt_logger.py, until SIGINT or SIGTERM, when it DETACHES and exits. If the logger goes away
 *       (a broken pipe), it clears `loaded`, so every request is dropped, leaves the program attached and
 *       exits 6: a decision that cannot be receipted is never an allow. If the loader itself is killed, the
 *       program stays attached and its ring buffer fills, and an allowed request whose event cannot be
 *       written is dropped (GN_DROP_NOLOG); until it is full, the events it holds are never receipted.
 *   gn_loader detach IFNAME
 *       Removes any XDP program from the interface (the same as `ip link set dev IFNAME xdp off`).
 *
 *   cc -O2 -I prismpath-ebpf -o gn_loader prismpath-ebpf/gnet/gn_loader.c prismpath-ebpf/ppt_image.c \
 *      $(pkg-config --cflags --libs libbpf) -lelf -lz */
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

#include "ppt_common.h"
#include "ppt_image.h"
#include "gnet/gn_common.h"

static volatile sig_atomic_t stopping, logger_gone;
static void on_signal(int sig) { (void)sig; stopping = 1; }
static void on_pipe(int sig) { (void)sig; logger_gone = 1; }

static int map_fd(struct bpf_object *obj, const char *name)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    if (!map) { fprintf(stderr, "gn_loader: no map %s\n", name); exit(3); }
    return bpf_map__fd(map);
}

static void put(int fd, uint32_t key, const void *value, const char *what)
{
    if (bpf_map_update_elem(fd, &key, value, BPF_ANY) != 0) {
        fprintf(stderr, "gn_loader: cannot write %s[%u]: %s\n", what, key, strerror(errno));
        exit(3);
    }
}

/* The table and the actions into the maps; `loaded` last, so a packet never sees half a table. */
static void fill(struct bpf_object *obj, const char *table_path, const char *actions_path, uint32_t image_index)
{
    long table_len, actions_len;
    uint8_t *table = read_file(table_path, &table_len);
    uint8_t *actions = read_file(actions_path, &actions_len);
    Image im; memset(&im, 0, sizeof im);
    if (parse_image_buf(table, table_len, &im) != 0) { fprintf(stderr, "gn_loader: the table is refused\n"); exit(3); }
    if (actions_len < 40 || (uint32_t)rd32(actions) != 0x474E4143u) { fprintf(stderr, "gn_loader: bad action file\n"); exit(3); }
    uint32_t rules = (uint32_t)rd32(actions + 4);
    if (rules > GN_MAX_RULES || actions_len != 40 + 4 * (long)rules) { fprintf(stderr, "gn_loader: bad action file\n"); exit(3); }
    int atoms = map_fd(obj, "atoms_map"), nodes = map_fd(obj, "nodes_map"), edges = map_fd(obj, "edges_map"),
        prog = map_fd(obj, "prog_map"), acts = map_fd(obj, "gn_action_map"), cfg = map_fd(obj, "gn_config_map");
    for (uint32_t i = 0; i < im.n_atoms; i++) put(atoms, i, &im.atoms[i], "atoms_map");
    for (uint32_t i = 0; i < im.n_nodes; i++) put(nodes, i, &im.nodes[i], "nodes_map");
    for (uint32_t i = 0; i < im.n_edges; i++) put(edges, i, &im.edges[i], "edges_map");
    for (uint32_t i = 0; i < im.prog_len; i++) put(prog, i, &im.prog[i], "prog_map");
    for (uint32_t rule = 0; rule < rules; rule++) {
        struct gn_action action = {actions[40 + 4 * rule], actions[41 + 4 * rule], rd16(actions + 42 + 4 * rule)};
        put(acts, rule, &action, "gn_action_map");
    }
    struct gn_config config = {1, im.start, image_index, rules};
    put(cfg, 0, &config, "gn_config_map");
    free_image(&im);
    free(table); free(actions);
}

static struct bpf_object *open_load(const char *path, struct bpf_program **prog)
{
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    if (!obj) { fprintf(stderr, "gn_loader: cannot open %s\n", path); exit(3); }
    if (bpf_object__load(obj) != 0) { fprintf(stderr, "gn_loader: the kernel refuses %s (verifier log above)\n", path); exit(4); }
    *prog = bpf_object__find_program_by_name(obj, "gn_xdp_prog");
    if (!*prog) { fprintf(stderr, "gn_loader: no program gn_xdp_prog\n"); exit(3); }
    return obj;
}

/* ------------------------------------------------------------------ test-run */
static struct gn_event last_event;
static int have_event;
static int keep_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len == sizeof last_event) { memcpy(&last_event, data, len); have_event = 1; }
    return 0;
}

static int test_run(const char *obj_path, const char *table, const char *actions, uint32_t image_index)
{
    struct bpf_program *prog;
    struct bpf_object *obj = open_load(obj_path, &prog);
    fill(obj, table, actions, image_index);
    struct ring_buffer *ring = ring_buffer__new(map_fd(obj, "gn_events"), keep_event, NULL, NULL);
    if (!ring) { fprintf(stderr, "gn_loader: no ring buffer\n"); return 3; }
    static uint8_t frame[65536];
    int mismatches = 0;
    for (;;) {
        uint8_t prefix[4];
        if (fread(prefix, 1, 4, stdin) != 4) break;
        uint32_t len = (uint32_t)rd32(prefix);
        if (len > sizeof frame || fread(frame, 1, len, stdin) != len) { fprintf(stderr, "gn_loader: truncated frame\n"); return 3; }
        LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = frame, .data_size_in = len, .repeat = 1);
        have_event = 0;
        if (bpf_prog_test_run_opts(bpf_program__fd(prog), &opts) != 0) {
            fprintf(stderr, "gn_loader: test run failed: %s\n", strerror(errno));
            return 3;
        }
        ring_buffer__consume(ring);
        struct gn_event ev; memset(&ev, 0, sizeof ev);
        if (have_event) ev = last_event;
        unsigned outcome = have_event ? ev.outcome : GN_OTHER;
        /* the program's return value must be what its event says: pass exactly for other traffic and allows */
        int passed = opts.retval == XDP_PASS;
        if (passed != (outcome == GN_OTHER || outcome == GN_ALLOW)) mismatches++;
        printf("%u %u %d %u %d %llu %u %u %u %u %u %u %u %u %u %u\n", outcome, ev.reason, have_event ? ev.edge : -1,
               ev.cause, have_event, (unsigned long long)ev.request_id, ev.cmd, ev.hclass, ev.arg0, ev.arg1,
               ev.name_len, ev.data_len, ev.handle, ev.image_index, ev.src_port, ev.src_ip);
    }
    ring_buffer__free(ring);
    bpf_object__close(obj);
    if (mismatches) fprintf(stderr, "gn_loader: %d frames whose return value disagrees with their event\n", mismatches);
    return mismatches ? 5 : 0;
}

/* ------------------------------------------------------------------ run */
static int print_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    const uint8_t *bytes = data;
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
    printf("\n");
    if (fflush(stdout) != 0 || ferror(stdout)) logger_gone = 1;
    return logger_gone ? -1 : 0;
}

static int run(const char *ifname, const char *obj_path, const char *table, const char *actions, int generic,
               uint32_t image_index)
{
    unsigned ifindex = if_nametoindex(ifname);
    if (!ifindex) { fprintf(stderr, "gn_loader: no interface %s\n", ifname); return 3; }
    struct bpf_program *prog;
    struct bpf_object *obj = open_load(obj_path, &prog);
    fill(obj, table, actions, image_index);
    struct ring_buffer *ring = ring_buffer__new(map_fd(obj, "gn_events"), print_event, NULL, NULL);
    if (!ring) { fprintf(stderr, "gn_loader: no ring buffer\n"); return 3; }
    uint32_t flags = generic ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
    if (bpf_xdp_attach((int)ifindex, bpf_program__fd(prog), flags | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) != 0) {
        fprintf(stderr, "gn_loader: cannot attach to %s: %s (is another XDP program attached?)\n", ifname, strerror(errno));
        return 3;
    }
    fprintf(stderr, "gn_loader: attached to %s (%s mode); Ctrl-C detaches\n", ifname, generic ? "generic" : "native");
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, on_pipe);
    while (!stopping && !logger_gone) {
        int got = ring_buffer__poll(ring, 200);
        if (got < 0 && got != -EINTR && !logger_gone) { fprintf(stderr, "gn_loader: ring buffer poll failed: %d\n", got); break; }
    }
    if (logger_gone) {
        /* the receipt logger is gone: a decision now could not be receipted, so stop allowing any. Clear
         * `loaded` (every request to the port is then dropped), leave the program attached so the port does
         * not fall open to the tool server, and say how to detach. */
        struct gn_config closed = {0, 0, image_index, 0};
        put(map_fd(obj, "gn_config_map"), 0, &closed, "gn_config_map");
        fprintf(stderr, "gn_loader: the receipt logger is gone; every request to the port is now dropped and the "
                        "program is left attached. Detach with: ip link set dev %s xdp off\n", ifname);
        return 6;
    }
    bpf_xdp_detach((int)ifindex, flags, NULL);
    fprintf(stderr, "gn_loader: detached from %s\n", ifname);
    ring_buffer__free(ring);
    bpf_object__close(obj);
    return 0;
}

int main(int argc, char **argv)
{
    uint32_t image_index = 1;
    int generic = 0, positional = 0;
    const char *args[6] = {0};
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--image-index") && i + 1 < argc) image_index = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--generic")) generic = 1;
        else if (positional < 6) args[positional++] = argv[i];
    }
    if (positional == 4 && !strcmp(args[0], "test-run")) return test_run(args[1], args[2], args[3], image_index);
    if (positional == 5 && !strcmp(args[0], "run")) return run(args[1], args[2], args[3], args[4], generic, image_index);
    if (positional == 2 && !strcmp(args[0], "detach")) {
        unsigned ifindex = if_nametoindex(args[1]);
        if (!ifindex) { fprintf(stderr, "gn_loader: no interface %s\n", args[1]); return 3; }
        int rc = bpf_xdp_detach((int)ifindex, 0, NULL);
        if (rc) fprintf(stderr, "gn_loader: detach: %s\n", strerror(-rc));
        return rc ? 3 : 0;
    }
    fprintf(stderr, "usage: gn_loader test-run OBJ TABLE.ppt ACTIONS < frames\n"
                    "       gn_loader run IFNAME OBJ TABLE.ppt ACTIONS [--generic] [--image-index N]\n"
                    "       gn_loader detach IFNAME\n");
    return 2;
}
