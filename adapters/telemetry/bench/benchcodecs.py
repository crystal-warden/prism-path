# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Codecs under comparison, each measured in BITS on a channel of integers. All the variable-length ones
have a decode inverse (round-trip tested) so the sizes are trustworthy — a benchmark of a broken codec is
worse than none.

  fixed32                  — 32 bits/sample, the naive baseline
  uvarint                  — LEB128 (unsigned)
  delta+zigzag+uvarint     — the standard streaming baseline
  fib                      — Fibonacci/Zeckendorf on the raw values
  delta+zigzag+fib         — our codec (lossless, on raw values)
  zstd / zlib / lzma       — general-purpose baselines on the int32 byte array
"""
from __future__ import annotations

import lzma
import struct
import sys
import zlib
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import zeckendorf as z  # noqa: E402

try:
    import zstandard as _zstd
except Exception:                       # pragma: no cover
    _zstd = None


# --------------------------------------------------------------- transforms
def delta(xs: List[int]) -> List[int]:
    return [xs[0]] + [xs[i] - xs[i - 1] for i in range(1, len(xs))] if xs else []


def undelta(ds: List[int]) -> List[int]:
    out: List[int] = []
    for d in ds:
        out.append(d if not out else out[-1] + d)
    return out


def zigzag(n: int) -> int:
    return 2 * n if n >= 0 else -2 * n - 1


def unzigzag(u: int) -> int:
    return (u >> 1) if (u & 1) == 0 else -((u + 1) >> 1)


def _unsigned_deltas(xs: List[int]) -> List[int]:
    return [zigzag(d) for d in delta(xs)]


# --------------------------------------------------------------- LEB128 uvarint
def uvarint_encode(u: int) -> bytes:
    if u < 0:
        raise ValueError("uvarint is unsigned")
    out = bytearray()
    while True:
        b = u & 0x7F
        u >>= 7
        out.append(b | (0x80 if u else 0))
        if not u:
            return bytes(out)


def uvarint_decode_all(data: bytes) -> List[int]:
    out, u, shift = [], 0, 0
    for byte in data:
        u |= (byte & 0x7F) << shift
        if byte & 0x80:
            shift += 7
        else:
            out.append(u); u, shift = 0, 0
    return out


def _int32_bytes(xs: List[int]) -> bytes:
    return struct.pack("<%di" % len(xs), *xs)


# --------------------------------------------------------------- size in bits
def bits_fixed32(xs: List[int]) -> int:
    return 32 * len(xs)


def bits_uvarint(xs: List[int]) -> int:                    # requires xs >= 0
    return 8 * sum(len(uvarint_encode(x)) for x in xs)


def bits_fib(xs: List[int]) -> int:                        # xs >= 0; +1 offset for the positive codec
    return sum(len(z.encode(x + 1)) for x in xs)


def bits_delta_zigzag_uvarint(xs: List[int]) -> int:
    return 8 * sum(len(uvarint_encode(u)) for u in _unsigned_deltas(xs))


def bits_delta_zigzag_fib(xs: List[int]) -> int:
    return sum(len(z.encode(u + 1)) for u in _unsigned_deltas(xs))


def bits_zstd(xs: List[int], level: int = 19) -> Optional[int]:
    if _zstd is None:
        return None
    return 8 * len(_zstd.ZstdCompressor(level=level).compress(_int32_bytes(xs)))


def bits_zlib(xs: List[int]) -> int:
    return 8 * len(zlib.compress(_int32_bytes(xs), 9))


def bits_lzma(xs: List[int]) -> int:
    return 8 * len(lzma.compress(_int32_bytes(xs), preset=9))


CODECS = {
    "fixed32": bits_fixed32,
    "uvarint": bits_uvarint,
    "delta+zz+uvarint": bits_delta_zigzag_uvarint,
    "fib(raw)": bits_fib,
    "delta+zz+fib": bits_delta_zigzag_fib,
    "zstd-19": bits_zstd,
    "zlib-9": bits_zlib,
    "lzma-9": bits_lzma,
}


# --------------------------------------------------------------- round-trip (for the correctness test)
def roundtrip_uvarint(xs: List[int]) -> List[int]:
    return uvarint_decode_all(b"".join(uvarint_encode(x) for x in xs))


def roundtrip_fib(xs: List[int]) -> List[int]:
    return [w - 1 for w in z.decode_stream(z.encode_stream([x + 1 for x in xs]))]


def roundtrip_delta_zigzag_fib(xs: List[int]) -> List[int]:
    us = _unsigned_deltas(xs)
    back = [w - 1 for w in z.decode_stream(z.encode_stream([u + 1 for u in us]))]
    return undelta([unzigzag(u) for u in back])


def roundtrip_delta_zigzag_uvarint(xs: List[int]) -> List[int]:
    us = _unsigned_deltas(xs)
    back = uvarint_decode_all(b"".join(uvarint_encode(u) for u in us))
    return undelta([unzigzag(u) for u in back])
