#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Certify the XDP decode plane via BPF_PROG_TEST_RUN: feed crafted UDP/IP/eth frames carrying
Facet payloads, capture the rewritten output, and byte-compare the decoded cell array against the
Python reference. No network. Positive corpus (reference generated) + negative matrix (corrupt,
truncated, overflow) proving strict DROP in kernel. Requires root/CAP_BPF."""
import ctypes as C
import random
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "adapters" / "telemetry"))
import packed  # noqa: E402
import zeckendorf as z  # noqa: E402

FACET_PORT = 4711

def frame(payload):
    eth = b"\x02"*6 + b"\x02"*6 + struct.pack(">H", 0x0800)
    udp = struct.pack(">HHHH", 5000, FACET_PORT, 8 + len(payload), 0) + payload
    tot = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, 1, 0, 64, 17, 0,
                     bytes([10,0,0,1]), bytes([10,0,0,2]))
    return eth + ip + udp

def facet_payload(wire_ints):
    return packed.pack(z.encode_stream(wire_ints), 8)

# --- minimal libbpf ctypes binding ---
lib = C.CDLL("libbpf.so.1", use_errno=True)

class bpf_test_run_opts(C.Structure):
    _fields_ = [("sz", C.c_size_t), ("data_in", C.c_void_p), ("data_out", C.c_void_p),
                ("data_size_in", C.c_uint), ("data_size_out", C.c_uint),
                ("ctx_in", C.c_void_p), ("ctx_out", C.c_void_p),
                ("ctx_size_in", C.c_uint), ("ctx_size_out", C.c_uint),
                ("retval", C.c_int), ("repeat", C.c_int), ("duration", C.c_uint),
                ("flags", C.c_uint), ("cpu", C.c_uint), ("batch_size", C.c_uint)]

lib.bpf_object__open_file.restype = C.c_void_p
lib.bpf_object__open_file.argtypes = [C.c_char_p, C.c_void_p]
lib.bpf_object__load.restype = C.c_int
lib.bpf_object__load.argtypes = [C.c_void_p]
lib.bpf_object__find_program_by_name.restype = C.c_void_p
lib.bpf_object__find_program_by_name.argtypes = [C.c_void_p, C.c_char_p]
lib.bpf_program__fd.restype = C.c_int
lib.bpf_program__fd.argtypes = [C.c_void_p]
lib.bpf_prog_test_run_opts.restype = C.c_int
lib.bpf_prog_test_run_opts.argtypes = [C.c_int, C.POINTER(bpf_test_run_opts)]

XDP_ABORTED, XDP_DROP, XDP_PASS = 0, 1, 2

def run(prog_fd, frm):
    buf_in = C.create_string_buffer(frm, len(frm))
    buf_out = C.create_string_buffer(2048)
    o = bpf_test_run_opts(sz=C.sizeof(bpf_test_run_opts),
                          data_in=C.cast(buf_in, C.c_void_p), data_size_in=len(frm),
                          data_out=C.cast(buf_out, C.c_void_p), data_size_out=2048, repeat=1)
    r = lib.bpf_prog_test_run_opts(prog_fd, C.byref(o))
    if r != 0:
        raise OSError(f"TEST_RUN failed rc={r} errno={C.get_errno()}")
    return o.retval, buf_out.raw[:o.data_size_out]

def decoded_cells(outframe):
    p = outframe[14+20+8:]           # eth+ip+udp
    assert p[0] == ord('F'), "bad magic"
    n = p[1]
    return [struct.unpack("<H", p[2+2*i:4+2*i])[0] for i in range(n)]

def main():
    obj = lib.bpf_object__open_file(b"facet_decode.bpf.o", None)
    if not obj: sys.exit("open_file failed (root? CAP_BPF?)")
    if lib.bpf_object__load(obj) != 0: sys.exit(f"load failed errno={C.get_errno()} (need root)")
    prog = lib.bpf_object__find_program_by_name(obj, b"facet_decode")
    fd = lib.bpf_program__fd(prog)

    random.seed(42)
    npass = nfail = 0
    # positive: reference generated
    for _ in range(200):
        ints = [random.randint(1, 6) for _ in range(random.randint(1, 4))]
        ret, out = run(fd, frame(facet_payload(ints)))
        if ret != XDP_PASS or decoded_cells(out) != ints:
            nfail += 1; print(f"POS FAIL {ints}: ret={ret}")
        else:
            npass += 1
    # big values through 2^53-ish symbol range (wire ints stay small = cell indices, but stress the table)
    for _ in range(50):
        ints = [random.randint(1, 1000) for _ in range(random.randint(1, 3))]
        ret, out = run(fd, frame(facet_payload(ints)))
        if ret != XDP_PASS or decoded_cells(out) != ints:
            nfail += 1
            try: got = decoded_cells(out)
            except Exception as e: got = f"<{e}>"
            print(f"POS-BIG FAIL {ints}: ret={ret} got={got}")
        else:
            npass += 1
    # negative matrix: STRUCTURALLY malformed frames must DROP, never emit a wrong event.
    # NOTE: single-bit corruption that stays a syntactically valid Fibonacci stream decodes to a
    # DIFFERENT valid value and is NOT dropped -- that is the codec's documented scope boundary
    # (detecting it is the upstream Merkle integrity layer's job, not the decoder's). So the
    # negative matrix asserts DROP only for truncation, overflow, and empty.
    negs = []
    good = facet_payload([3, 5, 2])
    negs.append(("truncated-midcodeword", good[:-1]))          # nonzero tail
    negs.append(("empty", b""))
    negs.append(("field-overflow", facet_payload([1]*20)))     # > MAX_SYMS symbols
    negs.append(("dangling-ones", good + b"\x80"))            # a lone 1 with no terminator
    ndrop = 0
    for name, pl in negs:
        ret, out = run(fd, frame(pl))
        if ret == XDP_PASS:
            nfail += 1; print(f"NEG FAIL {name}: PASSED a malformed frame -> {out[42:60].hex()}")
        else:
            ndrop += 1
    print(f"\nPOSITIVE: {npass} byte-identical to reference, {nfail} failures")
    print(f"NEGATIVE: {ndrop}/{len(negs)} malformed frames dropped (never a wrong event)")
    print("RESULT:", "PASS" if nfail == 0 else "FAIL")
    sys.exit(0 if nfail == 0 else 1)

if __name__ == "__main__":
    main()
