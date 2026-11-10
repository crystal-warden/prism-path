# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze cross-language CANONICAL JSON vectors for canon/1: the exact bytes `prismpath.canon` wrote,
before the canon/2 migration, for every pack signature, envelope signature, audit leaf, attestation
manifest and connector content hash. canon/1 is now verify only: it is the reader of documents that do
not name canon/2, and nothing writes it. What is written now is canon/2, whose vectors are
`conformance/canon2.json` (`gen_canon2_fixtures.py`). Every expected string here is produced by RUNNING
`canon.canonical_compact` and `canon.canonical_spaced`, so a port that verifies an old document is
measured against what Python wrote.

    python prismpath/portable/gen_canonical_fixtures.py   ->  conformance/canonical.json

Each input is kept as JSON TEXT, not as a value, because the interesting cases (`1e16`, `-0.0`,
integers wider than 64 bits, `NaN`) do not survive being loaded into a language's number type and
written back; the port must parse the same text and reach the same bytes.

  * `cases`    both encodings must match exactly.
  * `refused`  inputs canonical JSON has no form for: `NaN`, `Infinity`, `-Infinity`, a number beyond the
               double range (`1e400`), a lone surrogate. Both languages refuse them when they read the
               document (`prismpath.canon.loads`, `prismpath_rs::value::parse_strict`) and neither
               ever writes bytes for them; nothing is converted to infinity or zero. The list of
               inputs Python writes bytes for and Rust refuses is empty.
  * `floats`   `repr(float)` for IEEE doubles given by bit pattern, the base of every float spelling.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from prismpath import canon  # noqa: E402

OUT = HERE / "conformance" / "canonical.json"

_CASES = [
    # exponents and the fixed/exponent boundary of repr(float)
    ("float_exp_pos_boundary", "1e16"), ("float_below_boundary", "9999999999999998.0"),
    ("float_exp_neg_boundary", "1e-5"), ("float_above_neg_boundary", "0.0001"),
    ("float_exp_two_digits", "1.5e-7"), ("float_exp_three_digits", "1e-100"), ("float_exp_big", "1.5e20"),
    ("float_exp_22", "1e22"), ("float_exp_308", "1e308"), ("float_max", "1.7976931348623157e308"),
    ("float_min_subnormal", "5e-324"), ("float_small", "2.5e-7"),
    ("float_upper_case_exponent", "1E5"), ("float_signed_exponent", "1e+2"),
    # integral floats stay floats
    ("float_integral", "2.0"), ("float_integral_big", "123456789012345678.0"),
    ("float_integral_1e15", "1e15"), ("float_integral_hundred", "100.0"), ("float_zero", "0.0"),
    ("float_exponent_integral", "3e2"),
    # below the double range is not a refusal: both languages read a finite value, here zero
    ("float_underflow_zero", "1e-400"), ("int_400_digits", "1" + "0" * 400),
    # negative zero
    ("float_negative_zero", "-0.0"), ("int_negative_zero", "-0"), ("float_negative_zero_exp", "-0e5"),
    # ordinary and shortest-digit floats
    ("float_tenth", "0.1"), ("float_sum", "0.30000000000000004"), ("float_negative", "-2.675"),
    ("float_timestamp", "1730800001.2345679"), ("float_pi", "3.141592653589793"),
    ("float_17_digits_input", "0.12345678901234567890"),
    # the float-digit tie: the 17-digit text below is one ulp from the shortest round trip digits, which
    # the port only reproduces when it parses the text correctly rounded
    ("float_digit_tie", "123456789012345680000.0"), ("float_digit_tie_plain", "123456789012345680000"),
    ("float_digit_tie_exp", "1.2345678901234568e20"),
    # integers at and beyond the 64-bit edges
    ("int_i64_max", "9223372036854775807"), ("int_i64_min", "-9223372036854775808"),
    ("int_u64_max", "18446744073709551615"), ("int_u64_max_plus_one", "18446744073709551616"),
    ("int_below_i64_min", "-9223372036854775809"), ("int_huge", "123456789012345678901234567890"),
    ("int_negative_huge", "-123456789012345678901234567890"), ("int_two_pow_64", "18446744073709551616"),
    ("int_zero", "0"), ("int_negative", "-5"),
    ("int_in_structures", '{"ids": [18446744073709551617, 1], "n": {"big": -18446744073709551617}}'),
    ("float_huge_not_int", "1e30"), ("float_with_fraction_huge", "123456789012345678901234567890.5"),
    # unicode and escapes (ensure_ascii)
    ("unicode_bmp", '"café — ☕"'), ("unicode_astral", '"𝄞 😀"'), ("unicode_escape_input", '"\\u00e9\\ud83d\\ude00"'),
    ("escapes_short", '"quote \\" backslash \\\\ nl \\n cr \\r tab \\t bs \\b ff \\f"'),
    ("escapes_control", '"\\u0000\\u0001\\u001f\\u007f\\u0080"'), ("escape_slash", '"a\\/b"'),
    ("unicode_key", '{"é": 1, "e": 2, "𝄞": 3}'), ("empty_string", '""'),
    # key ordering: code point order, including an astral key against a high BMP key
    ("keys_sorted", '{"b": 1, "a": 2, "B": 3, "_": 4, "1": 5, "": 6}'),
    ("keys_astral_vs_bmp", '{"\\uffff": 1, "\\ud83d\\ude00": 2, "\\ue000": 3, "z": 4}'),
    ("keys_duplicate_last_wins", '{"a": 1, "a": 2, "b": 0, "a": 3}'),
    ("keys_numeric_strings", '{"10": 1, "9": 2, "2": 3}'),
    # nesting, empties, scalars
    ("nested", '{"z": [1, {"y": [2.0, {"x": null}], "a": true}], "a": {"b": {"c": [[], {}]}}}'),
    ("deep_arrays", "[[[[[[[[1]]]]]]]]"), ("empty_containers", '{"l": [], "o": {}, "s": ""}'),
    ("null", "null"), ("true", "true"), ("false", "false"), ("bare_string", '"x"'), ("bare_float", "1.5"),
    ("array_mixed", '[1, 1.0, "1", true, null, -1e-7, {"k": 0.5}]'),
    ("manifest_like", '{"counts": {"atoms": 1, "nodes": 2}, "created": "2026-08-12T00:00:00+00:00", '
                      '"version": 3, "wcet_cycles": 12, "ratio": 0.75, "tiny": 1e-9}'),
]

# Inputs with no canonical form: refused when read, by both languages, with no bytes written.
_REFUSED = [
    ("nan", "NaN"), ("infinity", "Infinity"), ("negative_infinity", "-Infinity"),
    ("nan_in_array", "[1, NaN, 2]"), ("infinity_in_object", '{"a": {"b": Infinity}}'),
    ("overflow_float", "1e400"), ("negative_overflow_float", "-1e400"),
    ("overflow_just_past_max", "1.7976931348623159e308"), ("overflow_exponent_999", "1E+999"),
    ("overflow_in_object", '{"a": [1, 1e999]}'),
    ("lone_high_surrogate", '"\\ud800"'), ("lone_low_surrogate_key", '{"\\udc00": 1}'),
    ("lone_high_surrogate_in_array", '["ok", "\\udbff"]'), ("high_surrogate_then_letter", '"\\ud83dx"'),
]

_FLOAT_BITS = [0x0000000000000000, 0x8000000000000000, 0x3FF0000000000000, 0x0000000000000001,
               0x000FFFFFFFFFFFFF, 0x0010000000000000, 0x7FEFFFFFFFFFFFFF, 0x7FF0000000000000,
               0xFFF0000000000000, 0x7FF8000000000000, 0x3F1A36E2EB1C432D, 0x4415AF1D78B58C40,
               0x44B52D02C7E14AF6, 0x3EE4F8B588E368F1, 0x7B1F6E1A2C3D4E5F, 0x4341C37937E08000,
               0x4341C37937E08001, 0x3FB999999999999A, 0x40091EB851EB851F, 0x3FD5555555555555]


def encode(text: str) -> dict:
    value = canon.loads(text)      # the strict reader every hashed document is read with; big ints stay exact
    return {"compact": canon.canonical_compact(value).decode("ascii"),
            "spaced": canon.canonical_spaced(value).decode("ascii")}


def main() -> int:
    cases = [{"name": name, "json": text, **encode(text)} for name, text in _CASES]
    refused = []
    for name, text in _REFUSED:
        try:
            canon.loads(text)
        except canon.CanonicalReadError as error:
            refused.append({"name": name, "json": text, "error": str(error)})
        else:
            raise SystemExit(f"{name}: canon.loads accepted {text!r}, which must be refused")
    floats = [{"bits": f"{bits:016x}", "repr": json.dumps(struct.unpack(">d", struct.pack(">Q", bits))[0])}
              for bits in _FLOAT_BITS]
    doc = {
        "version": 1,
        "note": "Canonical JSON bytes. Every expected string was produced by prismpath.canon "
                "(canonical_compact, canonical_spaced). `cases`: the port parses `json` and must write "
                "both strings exactly. `refused`: canonical JSON has no form for the input (NaN, "
                "Infinity, -Infinity, a number beyond the double range, a lone surrogate), so the "
                "port must refuse it when it reads the document, as canon.loads does, and never "
                "write bytes for it; `error` is Python's message, not compared. `floats`: repr of the double with this big endian bit "
                "pattern, spelled as json.dumps spells it.",
        "cases": cases, "refused": refused, "floats": floats,
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n")
    print(f"wrote {OUT}  ({len(cases)} cases, {len(refused)} refused, {len(floats)} floats)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
