# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Zeckendorf / Fibonacci codec — the self-framing wire for the decision-preserving telemetry stream.

Every positive integer has a unique Zeckendorf representation (a sum of non-consecutive Fibonacci
numbers), so its bit pattern never contains ``11``. The Fibonacci code appends a terminal ``1``, making a
trailing ``11`` that appears nowhere else — a permanent, data-agnostic frame boundary. Variable-length,
prefix-free, ``O(log n)``, and densest on small integers (``1 -> 11``, ``2 -> 011``, ``3 -> 0011``,
``4 -> 1011``), which is exactly where delta-differenced telemetry lives.

Fibonacci coding is defined for POSITIVE integers (n >= 1). Callers that need to send 0 or signed deltas
offset/zig-zag at the symbol layer, not here — this module stays the pure, doc-faithful wire.

Reference (bit-string) implementation for Phase A: correctness + measurement first. The u64-accumulate
CPU path and the FPGA shift-register codec are Phase C.
"""
from __future__ import annotations

from typing import Iterable, List


def _fibs_upto(n: int) -> List[int]:
    """Ascending Fibonacci basis ``[1, 2, 3, 5, 8, ...]`` (F2, F3, F4, ...) with the largest term <= n."""
    fibs = [1, 2]
    while fibs[-1] <= n:
        fibs.append(fibs[-1] + fibs[-2])
    if fibs[-1] > n:
        fibs.pop()
    return fibs


def encode(n: int) -> str:
    """Fibonacci code of a positive integer ``n`` (>= 1) as a bit-string ending in ``11``."""
    if n < 1:
        raise ValueError(f"Fibonacci coding is for positive integers; got {n}")
    fibs = _fibs_upto(n)
    bits = ["0"] * len(fibs)                 # bits[i] <-> fibs[i] (= F_{i+2}), low -> high order
    rem = n
    for i in range(len(fibs) - 1, -1, -1):   # greedy: subtract the largest Fibonacci that fits
        if fibs[i] <= rem:
            bits[i] = "1"
            rem -= fibs[i]
    assert rem == 0, f"Zeckendorf decomposition failed for {n}"
    return "".join(bits) + "1"               # append terminator -> unique trailing '11'


def decode(code: str) -> int:
    """Inverse of :func:`encode`: one Fibonacci code (bit-string ending in ``11``) -> the integer."""
    if len(code) < 2 or code[-2:] != "11":
        raise ValueError(f"not a Fibonacci code (must end in '11'): {code!r}")
    zeck = code[:-1]                          # strip the terminator '1'; the rest is d2 d3 ... d_max
    fibs = [1, 2]
    while len(fibs) < len(zeck):
        fibs.append(fibs[-1] + fibs[-2])
    return sum(fibs[i] for i, b in enumerate(zeck) if b == "1")


def encode_stream(values: Iterable[int]) -> str:
    """Concatenate the codes; each code's trailing ``11`` frames the next — zero header, self-delimiting."""
    return "".join(encode(v) for v in values)


def decode_stream(bits: str) -> List[int]:
    """Split a concatenated stream at each self-framing ``11`` and decode each code.

    Within a single code the only ``11`` is its terminator (Zeckendorf forbids consecutive 1s), so the
    first ``11`` at/after a code's start is its boundary. A trailing run of bits with no terminator is an
    incomplete final frame and is dropped (the receiver requests it via the MMR self-heal, out of scope
    here).
    """
    out: List[int] = []
    start = 0
    i = 0
    n = len(bits)
    while i < n:
        if bits[i] == "1" and i + 1 < n and bits[i + 1] == "1":
            out.append(decode(bits[start:i + 2]))
            i += 2
            start = i
        else:
            i += 1
    return out
