// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* gn_xdp.pin.bpf.c: the governed net XDP program with every map pinned by name.
 *
 * This is gn_xdp.bpf.c unchanged except that GN_PIN becomes `__uint(pinning, LIBBPF_PIN_BY_NAME)`, so when
 * the host's iproute2 loads this object (`ip link set dev <if> xdpdrv obj gn_xdp.pin.bpf.o sec xdp`) it
 * pins every map under /sys/fs/bpf/tc/globals. The pure-Python loader (gn_loader.py) then reaches those maps by
 * path with plain bpf(2) syscalls, so the enforcement host needs no bpftool and no libbpf, only python3
 * and iproute2. The program text, the evaluator and the decision are identical to gn_xdp.bpf.c; only the
 * map pinning attribute differs, so its behaviour and the verifier budget are the same.
 *
 * GN_PIN expands only at the map declarations inside gn_xdp.bpf.c, after it has included
 * <bpf/bpf_helpers.h> (which brings in LIBBPF_PIN_BY_NAME), so nothing needs to be included here. */
#define GN_PIN __uint(pinning, LIBBPF_PIN_BY_NAME);

#include "gn_xdp.bpf.c"
