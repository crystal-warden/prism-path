"""Word-packed wire — the real byte format (Phase A's codec is a bit-string reference; this is what goes
on the link).

The Fibonacci bits are accumulated MSB-first into a 64-bit word register and flushed per word; the final
partial word is zero-padded on the right. Because a code ends in a unique ``11`` and the pad is a run of
0s, the padding is a partial frame with no terminator — ``decode_stream`` drops it — so the round-trip is
exact without carrying a bit count. (This is the doc's CPU/MCU path: accumulate-into-a-word for ~10-20x
throughput on C/hardware; the Python reference here nails the *format* + correctness + padding cost, not
the raw speed — that win lives in the C/FPGA codec, Phase C2.)
"""
from __future__ import annotations

from typing import Dict, List

import zeckendorf as z

WORD_BITS = 64


def pack(bits: str, word_bits: int = WORD_BITS) -> bytes:
    """Bit-string -> bytes, MSB-first, flushing per `word_bits`-bit word; final word zero-padded right."""
    out = bytearray()
    acc = 0
    n = 0
    for ch in bits:
        acc = (acc << 1) | (1 if ch == "1" else 0)
        n += 1
        if n == word_bits:
            out += acc.to_bytes(word_bits // 8, "big")
            acc, n = 0, 0
    if n:
        acc <<= (word_bits - n)                      # left-align the partial word; low bits = zero pad
        out += acc.to_bytes(word_bits // 8, "big")
    return bytes(out)


def unpack(data: bytes) -> str:
    """Bytes -> bit-string, MSB-first (includes any trailing zero pad — harmless, dropped on decode)."""
    return "".join(format(b, "08b") for b in data)


def encode(ints: List[int], word_bits: int = WORD_BITS) -> bytes:
    """Positive ints -> Fibonacci-coded, word-packed bytes."""
    return pack(z.encode_stream(ints), word_bits)


def decode(data: bytes) -> List[int]:
    """Word-packed bytes -> ints (trailing zero pad is a partial frame and is dropped)."""
    return z.decode_stream(unpack(data))


def padding_overhead(ints: List[int], word_bits: int = WORD_BITS) -> Dict:
    """Measure the word-padding cost: only the final word is padded, so it amortizes away as N grows."""
    actual_bits = len(z.encode_stream(ints))
    wire = encode(ints, word_bits)
    padded_bits = len(wire) * 8
    pad_bits = padded_bits - actual_bits
    return {"n": len(ints), "actual_bits": actual_bits, "wire_bytes": len(wire),
            "pad_bits": pad_bits, "pad_pct": (100.0 * pad_bits / actual_bits) if actual_bits else 0.0}


if __name__ == "__main__":                           # human-readable padding-overhead table
    print(f"{'N':>8} {'wire_bytes':>11} {'pad_bits':>9} {'pad_%':>7}")
    for n in (10, 100, 1_000, 10_000, 100_000):
        o = padding_overhead(list(range(1, n + 1)))
        print(f"{o['n']:>8} {o['wire_bytes']:>11} {o['pad_bits']:>9} {o['pad_pct']:>6.3f}%")
