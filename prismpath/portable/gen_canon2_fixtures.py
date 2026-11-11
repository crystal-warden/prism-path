# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze the canon/2 vectors (docs/design/spec-verified-core.md, section 3) as language neutral data.

    python -m prismpath.portable.gen_canon2_fixtures           writes conformance/canon2.json
    python -m prismpath.portable.gen_canon2_fixtures --check   exits 1 when the file is stale

Each case is a byte string (as hex, so invalid UTF-8 and every escape survive exactly) and what the
reference makes of it on both of its paths:

* `refuse`, when present, is the rule the strict reader `prismpath.kernel.canon2.loads` refuses it with:
  a reader rule, or `not-canonical` for a document that reads but is not its canonical spelling. When it
  is absent the strict reader accepts the bytes, and they are their own canonical spelling;
* `canonical_hex`, when present, is what `canonicalize` (the path for text a person wrote) makes of it,
  the canonical bytes of the value it reads; when it is absent `canonicalize` refuses it with `refuse`.

So a canonical document has no `refuse` and `canonical_hex` equal to `hex`, a document spelled otherwise
has `refuse: not-canonical` and its `canonical_hex`, and a text canon/2 does not read has only `refuse`.
The Rust, JavaScript and Go twins replay the file (`prismpath-rs/tests/test_canon2.rs`,
`prismpath/portable/run_vectors.mjs`, `prismpath-go/conformance_test.go`), and
`prismpath/tests/test_canon2.py` replays it through the Lean oracle as well, so every reader is held to
one table. Regenerating it is a spec change.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from prismpath.kernel import canon2

OUT = Path(__file__).parent / "conformance" / "canon2.json"
VERSION = 2

CASES = [
    # readable documents: canonical ones, which the strict reader accepts, and other spellings, which it
    # refuses as not canonical and canonicalize writes canonically
    ("empty object", b"{}"), ("empty array", b"[]"), ("literals", b"[null,true,false]"),
    ("whitespace", b" \t\r\n{ \"a\" : [ 1 , 2 ] }\n"), ("zero", b"0"), ("negative", b"-5"),
    ("exact limit", b"9007199254740991"), ("negative exact limit", b"-9007199254740991"),
    ("sorted keys", b'{"b":1,"a":2,"aa":3,"":4,"B":5}'),
    ("utf16 order", '{"":1,"\U0001f600":2,"￿":3}'.encode()),
    ("raw non ascii", '"é\U0001f600 \x7f"'.encode()),
    ("escapes", b'"\\"\\\\\\/\\b\\f\\n\\r\\t\\u0001\\u001f\\u0020\\u00e9\\ud83d\\ude00"'),
    ("control escape lowercase", b'"\\u001F"'), ("nested", b'{"a":{"b":[{"c":[]}]}}'),
    ("depth 128", b"[" * 128 + b"]" * 128), ("string with nul escape", b'"\\u0000"'),
    ("key escapes", b'{"\\u0061":1,"b\\n":2}'),
    ("canonical escapes", b'"\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f/\xc3\xa9"'),
    ("canonical object", b'{"":4,"B":5,"a":[1,-2,{"b":null}],"aa":"x"}'),
    # readable, and refused by the strict reader as not canonical: one spelling difference each
    ("trailing line feed", b"{}\n"), ("leading space", b" 0"), ("space after colon", b'{"a": 1}'),
    ("space after comma", b"[1, 2]"), ("members out of order", b'{"b":1,"a":2}'),
    ("escaped solidus", b'"\\/"'), ("uppercase escape", b'"\\u001F"'), ("escaped letter", b'"\\u0041"'),
    ("escaped non ascii", b'"\\u00e9"'), ("surrogate pair escape", b'"\\ud83d\\ude00"'),
    ("escaped tab as u", b'"\\u0009"'), ("nested out of order", b'[{"z":1,"y":2}]'),
    # refusals, the first rule broken reading left to right
    ("not utf8", b"\xff"), ("overlong", b'"\xc0\xaf"'), ("encoded surrogate", b'"\xed\xa0\x80"'),
    ("past U+10FFFF", b'"\xf4\x90\x80\x80"'), ("truncated utf8", b'"\xe2\x82'),
    ("utf8 before syntax", b"{\xff"), ("bom", "﻿{}".encode()), ("empty", b""), ("trailing", b"{}x"),
    ("NaN", b"NaN"), ("Infinity", b"[Infinity]"), ("plus sign", b"+1"), ("leading zero", b"01"),
    ("leading zero in array", b"[01]"), ("bare minus", b"-"), ("fraction", b"1.5"), ("zero fraction", b"1.0"),
    ("exponent", b"1e3"), ("huge exponent", b"1e400"), ("fraction without digits", b"1."),
    ("exponent without digits", b"1e"), ("float before range", b"99999999999999999999.5"),
    ("range", b"9007199254740992"), ("negative range", b"-9007199254740992"),
    ("long integer", b"1" + b"0" * 5000), ("negative zero", b"-0"), ("negative zero padded", b"-00"),
    ("negative zero fraction", b"-0.0"), ("duplicate key", b'{"a":1,"a":2}'),
    ("duplicate before value", b'{"a":1,"a":1.5}'), ("duplicate by escape", b'{"a":1,"\\u0061":2}'),
    ("nested duplicate", b'[{"x":{"k":1,"k":1}}]'), ("lone high", b'"\\ud800"'), ("lone low", b'"\\udc00"'),
    ("high then text", b'"\\ud800x"'), ("high then high", b'"\\ud800\\ud800"'),
    ("high then bad hex", b'"\\ud800\\u00zz"'), ("bad hex", b'"\\u00zz"'), ("short u escape", b'"\\u00"'),
    ("bad escape", b'"\\x41"'), ("raw control", b'"a\x01"'), ("raw newline", b'"a\nb"'),
    ("unterminated", b'"abc'), ("depth 129", b"[" * 129 + b"]" * 129),
    ("depth object", b'{"a":' * 129 + b"1" + b"}" * 129), ("depth before syntax", b"[" * 129),
    ("trailing comma", b"[1,]"), ("trailing member comma", b'{"a":1,}'), ("missing colon", b'{"a" 1}'),
    ("single quote", b"{'a':1}"), ("nul literal", b"nul"), ("true prefix", b"truex"),
    ("float in object", b'{"x":0.5}'), ("range in object", b'{"y":9007199254740993}'),
    ("negative zero in object", b'{"x":-0}'), ("non ascii whitespace", '{ }'.encode()),
]


def build() -> dict:
    cases = []
    for name, data in CASES:
        case = {"name": name, "hex": data.hex()}
        try:
            canon2.loads(data)
        except canon2.Canon2Error as error:
            case["refuse"] = error.rule
        try:
            case["canonical_hex"] = canon2.canonicalize(data).hex()
        except canon2.Canon2Error as error:
            assert case.get("refuse") == error.rule, (name, error.rule, case.get("refuse"))
        cases.append(case)
    return {"version": VERSION, "spec": "docs/design/spec-verified-core.md section 3", "cases": cases}


def text() -> str:
    return json.dumps(build(), indent=1, ensure_ascii=True) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        if not OUT.exists() or OUT.read_text() != text():
            print(f"{OUT} is not what the reference produces now; regenerate it", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text())
    print(f"wrote {OUT} ({len(CASES)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
