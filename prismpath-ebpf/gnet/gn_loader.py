#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""gn_loader.py: a no-install loader for the governed net XDP program (integrations/governed_net).

The enforcement host (the Proxmox host, x86_64) has clang, python3 and iproute2, but no bpftool and no
libbpf, so the C loader (gn_loader.c) cannot be built or run there. This does the parts that are plain
bpf(2) syscalls, through ctypes, with only the standard library, and leaves the program load, the verifier
and the attach to the host's own iproute2:

  * `ip link set dev <IF> xdpdrv obj gn_xdp.pin.bpf.o sec xdp` loads the program (the kernel verifier runs
    inside iproute2's libbpf) and, because that object declares every map `pinning = LIBBPF_PIN_BY_NAME`,
    pins the maps under /sys/fs/bpf/tc/globals where this tool can reach them;
  * `gn_loader.py fill  --maps-dir /sys/fs/bpf/tc/globals --table T.ppt --actions A --server-ip IP --port N`
    writes the table, the actions and the match target into the pinned maps, setting `loaded` last;
  * `gn_loader.py events --maps-dir ...` consumes the pinned ring buffer and prints one hex line per
    decision (struct gn_event), exactly the stdout the C loader's `run` prints, for receipt_logger.py;
  * `gn_loader.py stats  --maps-dir ...` prints the per-verdict counters `counters <other> <allow> <drop>
    <malformed>`; `gn_loader.py clear --maps-dir ...` sets `loaded` to 0 (fail closed);
  * `gn_loader.py attach <IF> <OBJ> [--generic]` and `detach <IF>` wrap the `ip link` commands.

It cannot BPF_PROG_TEST_RUN (that needs the loaded program's fd and the full ELF relocation libbpf does);
the in-kernel differential of SETUP.md section "the kernel test run" uses the C loader where libbpf exists,
and on the no-install host the verifier acceptance is shown by the `ip link ... obj` load succeeding.

`gn_loader.py --self-test` runs every part that needs no privilege (the bpf_attr packing, the ring buffer
record decoder, the .ppt and .actions parsers, and the per-CPU counter summation) and is what the tests
and a host without a kernel can check. The privileged syscalls are exercised only by the owner on the host
(SETUP.md), and are not proven here.
"""
import argparse
import ctypes
import os
import struct
import subprocess
import sys
import time

# bpf(2) command numbers (uapi/linux/bpf.h), stable across architectures
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_OBJ_GET = 7
# the bpf(2) syscall number is per-architecture; only used when actually talking to the kernel
BPF_SYSCALL_NR = {"x86_64": 321, "aarch64": 280, "armv7l": 386, "i686": 357, "ppc64le": 361, "s390x": 351}

# map value layouts, matching the C structs (gn_common.h, ppt_common.h)
CONFIG = struct.Struct("<IIIIII")        # loaded, start_node, image_index, n_rules, match_dst_ip, match_port
ACTION = struct.Struct("<BBH")           # pass, kind, cause
ATOM = struct.Struct("<HBBi")            # field, op, ty, val   (packed, 8 bytes)
NODE = struct.Struct("<HH")              # edge_off, edge_cnt
EDGE = struct.Struct("<HHH")             # target, prog_off, prog_cnt
WORD = struct.Struct("<H")
GN_EVENT_SIZE = 56
GN_CNT_N = 4
ACTIONS_MAGIC = 0x474E4143
PPT_MAGIC = 0x4D545050


# ----------------------------------------------------------------- pure parsing (no privilege)
def ip_to_u32(text):
    parts = [int(part) for part in text.split(".")]
    if len(parts) != 4 or any(not 0 <= part <= 255 for part in parts):
        raise ValueError("not an IPv4 address: " + text)
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def parse_actions(data):
    """(rules, [(pass, kind, cause), ...]) from a .actions file, or raise."""
    if len(data) < 40 or struct.unpack_from("<I", data, 0)[0] != ACTIONS_MAGIC:
        raise ValueError("not a gn actions file")
    rules = struct.unpack_from("<I", data, 4)[0]
    if len(data) != 40 + 4 * rules:
        raise ValueError("actions file length does not match the rule count")
    return rules, [ACTION.unpack_from(data, 40 + 4 * index) for index in range(rules)]


def parse_ppt(data):
    """The .ppt header fields and the four section byte-lists, enough to fill the maps. Raises on a bad
    header. Mirrors prismpath/kernel/ppt_compile.serialize and prismpath-ebpf/ppt_image.c."""
    if len(data) < 28 or struct.unpack_from("<I", data, 0)[0] != PPT_MAGIC:
        raise ValueError("not a PPT image")
    (_magic, _ver, n_fields, n_interns, n_atoms, n_nodes, n_edges, prog_len, start, _visits,
     _steps, _stack, _flags) = struct.unpack_from("<IHHHHHHHHHHHH", data, 0)
    pos = 28
    atoms = [ATOM.unpack_from(data, pos + 8 * i) for i in range(n_atoms)]
    pos += 8 * n_atoms
    nodes = [NODE.unpack_from(data, pos + 4 * i) for i in range(n_nodes)]
    pos += 4 * n_nodes
    edges = [EDGE.unpack_from(data, pos + 6 * i) for i in range(n_edges)]
    pos += 6 * n_edges
    prog = [WORD.unpack_from(data, pos + 2 * i)[0] for i in range(prog_len)]
    return {"start": start, "n_fields": n_fields, "atoms": atoms, "nodes": nodes, "edges": edges, "prog": prog}


def ringbuf_records(data, consumer_pos, producer_pos, size=None):
    """Yield each completed record's payload bytes between the consumer and producer positions of a BPF
    ring buffer data area `data` (a bytes-like of the mmap'd data pages). `size` is the power-of-two data
    length positions are taken modulo (defaults to len(data)); `data` may be longer than `size` so a record
    near the wrap reads into the kernel's second mapping. Each record has an 8-byte header: a u32 length
    with the top bits BUSY (1<<31) and DISCARD (1<<30), then the data, rounded up to 8 bytes. Returns
    (records, new_consumer_pos). A BUSY record stops the walk (not yet committed). Pure, so a synthetic
    buffer exercises it without a kernel."""
    BUSY, DISCARD = 1 << 31, 1 << 30
    if size is None:
        size = len(data)
    pos = consumer_pos
    out = []
    while pos < producer_pos:
        off = pos & (size - 1)
        (header,) = struct.unpack_from("<I", data, off)
        if header & BUSY:
            break
        length = header & (DISCARD - 1)
        record_off = off + 8
        if not (header & DISCARD):
            out.append(bytes(data[record_off:record_off + length]))
        pos += 8 + ((length + 7) & ~7)
    return out, pos


def sum_percpu(buffer, value_size, ncpus):
    """Sum a per-CPU map value (ncpus copies of value_size bytes, each rounded up to 8) as u64s."""
    stride = (value_size + 7) & ~7
    total = 0
    for cpu in range(ncpus):
        total += struct.unpack_from("<Q", buffer, cpu * stride)[0]
    return total


def num_possible_cpus():
    try:
        with open("/sys/devices/system/cpu/possible") as handle:
            text = handle.read().strip()
        return int(text.split("-")[-1]) + 1
    except OSError:
        return os.cpu_count() or 1


# ----------------------------------------------------------------- bpf(2) through ctypes (privileged)
class Bpf:
    def __init__(self):
        machine = os.uname().machine
        if machine not in BPF_SYSCALL_NR:
            raise RuntimeError("no bpf(2) syscall number known for %s" % machine)
        self.nr = BPF_SYSCALL_NR[machine]
        self.libc = ctypes.CDLL("libc.so.6", use_errno=True)

    def _call(self, cmd, attr):
        res = self.libc.syscall(self.nr, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
        if res < 0:
            raise OSError(ctypes.get_errno(), "bpf(cmd=%d): %s" % (cmd, os.strerror(ctypes.get_errno())))
        return res

    def obj_get(self, path):
        class Attr(ctypes.Structure):
            _fields_ = [("pathname", ctypes.c_uint64), ("bpf_fd", ctypes.c_uint32), ("file_flags", ctypes.c_uint32)]
        buf = ctypes.create_string_buffer(path.encode() + b"\0")
        attr = Attr(pathname=ctypes.cast(buf, ctypes.c_void_p).value, bpf_fd=0, file_flags=0)
        return self._call(BPF_OBJ_GET, attr)

    def _elem_attr(self, fd, key_bytes, value_bytes):
        class Attr(ctypes.Structure):
            _fields_ = [("map_fd", ctypes.c_uint32), ("pad", ctypes.c_uint32), ("key", ctypes.c_uint64),
                        ("value", ctypes.c_uint64), ("flags", ctypes.c_uint64)]
        self._key = ctypes.create_string_buffer(key_bytes)
        self._val = ctypes.create_string_buffer(value_bytes, len(value_bytes))
        return Attr(map_fd=fd, pad=0, key=ctypes.cast(self._key, ctypes.c_void_p).value,
                    value=ctypes.cast(self._val, ctypes.c_void_p).value, flags=0)

    def map_update(self, fd, key, value):
        attr = self._elem_attr(fd, key, value)
        self._call(BPF_MAP_UPDATE_ELEM, attr)

    def map_lookup(self, fd, key, value_size):
        attr = self._elem_attr(fd, key, b"\0" * value_size)
        self._call(BPF_MAP_LOOKUP_ELEM, attr)
        return self._val.raw[:value_size]


def _u32(value):
    return struct.pack("<I", value)


def fill(maps_dir, table_path, actions_path, server_ip, port, image_index):
    """Write the table, the actions and the match target into the pinned maps; set `loaded` last."""
    bpf = Bpf()
    with open(table_path, "rb") as handle:
        image = parse_ppt(handle.read())
    with open(actions_path, "rb") as handle:
        rules, actions = parse_actions(handle.read())
    opened = {name: bpf.obj_get(os.path.join(maps_dir, name)) for name in
              ("atoms_map", "nodes_map", "edges_map", "prog_map", "gn_action_map", "gn_config_map")}
    for index, atom in enumerate(image["atoms"]):
        bpf.map_update(opened["atoms_map"], _u32(index), ATOM.pack(*atom))
    for index, node in enumerate(image["nodes"]):
        bpf.map_update(opened["nodes_map"], _u32(index), NODE.pack(*node))
    for index, edge in enumerate(image["edges"]):
        bpf.map_update(opened["edges_map"], _u32(index), EDGE.pack(*edge))
    for index, word in enumerate(image["prog"]):
        bpf.map_update(opened["prog_map"], _u32(index), WORD.pack(word))
    for index, action in enumerate(actions):
        bpf.map_update(opened["gn_action_map"], _u32(index), ACTION.pack(*action))
    config = CONFIG.pack(1, image["start"], image_index, rules, ip_to_u32(server_ip), port)   # loaded = 1, last
    bpf.map_update(opened["gn_config_map"], _u32(0), config)
    sys.stderr.write("gn_loader.py: filled %d atoms, %d nodes, %d edges, %d rules; target %s:%d, image %d\n"
                     % (len(image["atoms"]), len(image["nodes"]), len(image["edges"]), rules, server_ip, port, image_index))


def read_counters(maps_dir):
    bpf = Bpf()
    fd = bpf.obj_get(os.path.join(maps_dir, "gn_counts_map"))
    ncpus = num_possible_cpus()
    counts = [sum_percpu(bpf.map_lookup(fd, _u32(index), 8 * ncpus), 8, ncpus) for index in range(GN_CNT_N)]
    return counts


def clear(maps_dir):
    """Set loaded = 0, keeping the match target, so every matched request is dropped (fail closed)."""
    bpf = Bpf()
    fd = bpf.obj_get(os.path.join(maps_dir, "gn_config_map"))
    current = bytearray(bpf.map_lookup(fd, _u32(0), CONFIG.size))
    struct.pack_into("<I", current, 0, 0)
    bpf.map_update(fd, _u32(0), bytes(current))
    sys.stderr.write("gn_loader.py: cleared loaded; every matched request is now dropped\n")


RINGBUF_DATA_SIZE = 1 << 20              # must equal gn_events max_entries in gn_xdp.bpf.c

def consume_events(maps_dir):
    """mmap the pinned ring buffer and print each committed record as a hex line, for receipt_logger.py.

    The kernel's BPF ring buffer mmap layout (as libbpf uses it): the consumer position is one read/write
    page at offset 0; the producer position is a read-only page at offset page_size, immediately followed
    by the data area (mapped twice so a record never wraps). `ringbuf_records` above decodes the data area
    and is unit-tested; this is the one wiring that needs a real kernel, so it is exercised only on the host
    (SETUP.md), not here."""
    import mmap
    bpf = Bpf()
    fd = bpf.obj_get(os.path.join(maps_dir, "gn_events"))
    page = os.sysconf("SC_PAGE_SIZE")
    consumer_mm = mmap.mmap(fd, page, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
    producer_mm = mmap.mmap(fd, page + 2 * RINGBUF_DATA_SIZE, mmap.MAP_SHARED, mmap.PROT_READ, offset=page)
    data = memoryview(producer_mm)[page:page + RINGBUF_DATA_SIZE + page]   # the double map covers a wrap
    try:
        while True:
            consumer_pos = struct.unpack_from("<Q", consumer_mm, 0)[0]
            producer_pos = struct.unpack_from("<Q", producer_mm, 0)[0]
            if producer_pos == consumer_pos:
                time.sleep(0.05)
                continue
            records, new_pos = ringbuf_records(data, consumer_pos, producer_pos, size=RINGBUF_DATA_SIZE)
            for record in records:
                sys.stdout.write(record[:GN_EVENT_SIZE].hex() + "\n")
            sys.stdout.flush()
            struct.pack_into("<Q", consumer_mm, 0, new_pos)
    except KeyboardInterrupt:
        pass
    finally:
        consumer_mm.close()
        producer_mm.close()


# ----------------------------------------------------------------- iproute2 (load / attach / detach)
# iproute2 pins maps marked LIBBPF_PIN_BY_NAME in its shared globals directory, whatever the interface
# (seen on the first attach, 2026-11-14), so map names must not collide with another program's there.
PIN_DIR = "/sys/fs/bpf/tc/globals"

def attach(ifname, obj, generic):
    mode = "xdpgeneric" if generic else "xdpdrv"
    subprocess.run(["ip", "link", "set", "dev", ifname, mode, "obj", obj, "sec", "xdp"], check=True)
    sys.stderr.write("gn_loader.py: attached %s to %s (%s); iproute2 pins the maps under %s/\n"
                     % (obj, ifname, mode, PIN_DIR))


# Every map the pinned object declares. iproute2 leaves pins behind on detach, and a later attach would
# reuse them with the old target and policy loaded, so detach removes them.
PINNED_MAPS = ("gn_config_map", "gn_action_map", "gn_counts_map", "gn_events",
               "atoms_map", "nodes_map", "edges_map", "prog_map", "regs_map")


def detach(ifname):
    subprocess.run(["ip", "link", "set", "dev", ifname, "xdp", "off"], check=True)
    removed = 0
    for name in PINNED_MAPS:
        try:
            os.unlink(os.path.join(PIN_DIR, name))
            removed += 1
        except FileNotFoundError:
            pass
    sys.stderr.write("gn_loader.py: detached from %s; removed %d pinned maps from %s/\n" % (ifname, removed, PIN_DIR))


# ----------------------------------------------------------------- the self test (no privilege)
def self_test():
    checks = []

    def ok(name, cond):
        checks.append((name, bool(cond)))

    ok("ipv4", ip_to_u32("192.0.2.20") == ((192 << 24) | (0 << 16) | (2 << 8) | 20))
    ok("config-size", CONFIG.size == 24)
    ok("action-size", ACTION.size == 4 and ATOM.size == 8 and NODE.size == 4 and EDGE.size == 6)
    # a synthetic actions file
    blob = struct.pack("<II", ACTIONS_MAGIC, 2) + b"\0" * 32 + ACTION.pack(1, 0, 0) + ACTION.pack(0, 1, 107)
    rules, acts = parse_actions(blob)
    ok("actions", rules == 2 and acts == [(1, 0, 0), (0, 1, 107)])
    try:
        parse_actions(b"nope")
        ok("actions-reject", False)
    except ValueError:
        ok("actions-reject", True)
    # a synthetic PPT with one atom, two nodes, one edge, one prog word
    ppt = struct.pack("<IHHHHHHHHHHHH", PPT_MAGIC, 1, 7, 1, 1, 2, 1, 1, 0, 0xFFFF, 25, 1, 0)
    ppt += ATOM.pack(1, 0, 2, 3) + NODE.pack(0, 1) + NODE.pack(0, 0) + EDGE.pack(1, 0, 1) + WORD.pack(5)
    image = parse_ppt(ppt)
    ok("ppt", image["start"] == 0 and len(image["atoms"]) == 1 and len(image["nodes"]) == 2
       and len(image["edges"]) == 1 and image["prog"] == [5])
    # the ring buffer record decoder over a synthetic buffer: two 8-byte records and a trailing BUSY one
    size = 4096
    buf = bytearray(size)
    struct.pack_into("<I", buf, 0, 8)
    buf[8:16] = b"AAAAAAAA"
    struct.pack_into("<I", buf, 16, 8)
    buf[24:32] = b"BBBBBBBB"
    struct.pack_into("<I", buf, 32, (1 << 31) | 8)             # BUSY: not yet committed
    records, new_pos = ringbuf_records(buf, 0, 48)
    ok("ringbuf", records == [b"AAAAAAAA", b"BBBBBBBB"] and new_pos == 32)
    # a discarded record is skipped
    buf2 = bytearray(64)
    struct.pack_into("<I", buf2, 0, (1 << 30) | 8)             # DISCARD
    struct.pack_into("<I", buf2, 16, 8)
    buf2[24:32] = b"CCCCCCCC"
    records2, _ = ringbuf_records(buf2, 0, 32)
    ok("ringbuf-discard", records2 == [b"CCCCCCCC"])
    # per-CPU summation
    ncpus = 3
    percpu = struct.pack("<QQQ", 10, 20, 12)
    ok("percpu", sum_percpu(percpu, 8, ncpus) == 42)
    passed = all(result for _name, result in checks)
    for name, result in checks:
        print("%s %s" % ("ok " if result else "FAIL", name))
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--self-test", action="store_true", help="run the non-privileged checks and exit")
    sub = parser.add_subparsers(dest="cmd")
    f = sub.add_parser("fill")
    f.add_argument("--maps-dir", required=True)
    f.add_argument("--table", required=True)
    f.add_argument("--actions", required=True)
    f.add_argument("--server-ip", required=True)
    f.add_argument("--port", type=int, required=True)
    f.add_argument("--image-index", type=int, default=1)
    for name in ("events", "stats", "clear"):
        s = sub.add_parser(name)
        s.add_argument("--maps-dir", required=True)
    a = sub.add_parser("attach")
    a.add_argument("ifname")
    a.add_argument("obj")
    a.add_argument("--generic", action="store_true")
    d = sub.add_parser("detach")
    d.add_argument("ifname")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.cmd == "fill":
        if args.port <= 0 or args.port > 65535:
            parser.error("--port must be 1..65535")
        try:
            ip_to_u32(args.server_ip)
        except ValueError as bad:
            parser.error(str(bad))
        fill(args.maps_dir, args.table, args.actions, args.server_ip, args.port, args.image_index)
        return 0
    if args.cmd == "stats":
        print("counters %d %d %d %d" % tuple(read_counters(args.maps_dir)))
        return 0
    if args.cmd == "clear":
        clear(args.maps_dir)
        return 0
    if args.cmd == "events":
        consume_events(args.maps_dir)
        return 0
    if args.cmd == "attach":
        attach(args.ifname, args.obj, args.generic)
        return 0
    if args.cmd == "detach":
        detach(args.ifname)
        return 0
    parser.error("a subcommand or --self-test is required")


if __name__ == "__main__":
    raise SystemExit(main())
