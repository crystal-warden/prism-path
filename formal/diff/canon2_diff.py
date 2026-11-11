# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The canon/2 differential: the Lean oracle against the Python, Rust, JavaScript and Go readers and writers.

Every leg reads a framed document (`<byte length>\\n<bytes>\\n`) and prints one line, `<strict> ; <canonicalize>`:

- `<strict>` is its strict reader's answer, the reader every hashed or signed document and every reading
  goes through (specification section 3.2): `ok <hex>` with its writer's bytes of the value read, which
  must be the input itself, or `refuse <rule>` with the first reader rule broken or `not-canonical`;
- `<canonicalize>` is its canonicalize path's answer, the writer's step for text a person wrote:
  `canon <hex>` with the canonical bytes of the value read in any spelling, or `refuse <rule>`;

or `panic`. The legs are

- `lean`: `lake exe canon2-oracle --batch` (formal/Core/Canon2Main.lean), whose strict reader, writer and
  canonicalize are the functions formal/Core/Canon2Proofs.lean is about; the spec says the Lean reader
  defines canon/2, so on a disagreement the Lean line is the spec's answer;
- `python`: `prismpath.kernel.canon2` in process;
- `rust`: `prismpath-rs/examples/canon2_diff.rs` (`--rust`, built with `cargo build --release --example
  canon2_diff`);
- `js`: `formal/diff/canon2_diff_js.mjs` over `prismpath/portable/prismpath.mjs`;
- `go`: `prismpath-go/cmd/canon2_diff` (`--go`, built with `go build`).

Three sets, all seeded:

1. `vectors`: the frozen cases of `prismpath/portable/conformance/canon2.json`, each against its expected
   strict answer and canonical bytes as well as across the legs;
2. `values`: generated values (`--values`, default 100000) in the writer's domain, each sent twice, as its
   canonical bytes (every leg must print `ok` and those bytes, and canonicalize them to themselves) and as
   a random legal spelling (whitespace, member order, escapes; unless it happens to be the canonical one,
   every leg must refuse it as `not-canonical` and canonicalize it to the canonical bytes of the value);
3. `mutations`: byte strings (`--mutations`, default 100000) made from canonical spellings by key order
   swaps, escape variants, whitespace, exponents and fractions, `-0`, leading zeros, integers at and past
   plus or minus 2^53 minus 1, lone and paired surrogate escapes, duplicate keys, nesting at and past 128,
   invalid UTF-8, a byte order mark, truncation and random byte edits; the legs must agree;

and a fixed point check: every canonical output of the three sets is sent again and every leg must accept
it as it is and canonicalize it to itself.

A disagreement is printed with a minimised reproducer (bytes in hex and as text), every leg's line, and the
Lean line as the spec's answer. The last line is `canon2-diff: <n> documents, <d> disagreements`.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable, Dict, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from prismpath.kernel import canon2  # noqa: E402

LIMIT = 2 ** 53 - 1
LEGS = ("lean", "python", "rust", "js", "go")


# ----------------------------------------------------------------- legs
def frame(docs: Sequence[bytes]) -> bytes:
    return b"".join(b"%d\n%s\n" % (len(d), d) for d in docs)


def python_line(doc: bytes) -> str:
    try:
        strict = "ok " + canon2.dumps(canon2.loads(doc)).hex()
    except canon2.Canon2Error as error:
        strict = "refuse " + error.rule
    except RecursionError:
        return "panic recursion"
    try:
        canon = "canon " + canon2.canonicalize(doc).hex()
    except canon2.Canon2Error as error:
        canon = "refuse " + error.rule
    except RecursionError:
        return "panic recursion"
    return f"{strict} ; {canon}"


def accepted(canonical: bytes) -> str:
    """The line every leg prints for canonical bytes."""
    return f"ok {canonical.hex()} ; canon {canonical.hex()}"


def respelled(canonical: bytes) -> str:
    """The line every leg prints for another spelling of the value whose canonical bytes are given."""
    return f"refuse not-canonical ; canon {canonical.hex()}"


def run_cmd(cmd: List[str], docs: Sequence[bytes], cwd: Path) -> List[str]:
    out: List[str] = []
    for start in range(0, len(docs), 20000):
        chunk = docs[start:start + 20000]
        proc = subprocess.run(cmd, input=frame(chunk), capture_output=True, cwd=cwd, check=False)
        if proc.returncode != 0:
            raise SystemExit(f"leg {cmd[0]} exited {proc.returncode}: {proc.stderr[-400:]!r}")
        lines = proc.stdout.decode().splitlines()
        if len(lines) != len(chunk):
            raise SystemExit(f"leg {cmd[0]} printed {len(lines)} lines for {len(chunk)} documents")
        out.extend(lines)
    return out


class Legs:
    def __init__(self, lean: str, rust: str, go: str, node: str):
        self.cmds = {
            "lean": [lean, "--batch"],
            "rust": [rust],
            "js": [node, str(ROOT / "formal" / "diff" / "canon2_diff_js.mjs")],
            "go": [go],
        }

    def run(self, docs: Sequence[bytes]) -> Dict[str, List[str]]:
        result = {"python": [python_line(d) for d in docs]}
        for leg, cmd in self.cmds.items():
            result[leg] = run_cmd(cmd, docs, ROOT)
        return result


# ----------------------------------------------------------------- generation
KEY_POOL = (["", "a", "b", "A", "Z", "aa", "ab", "id", '"', "\\", "/", "\t", "__proto__", "constructor", "toString",
             "hasOwnProperty", "0", "1", "10", "a" + chr(0), "k" + chr(1)]
            + [chr(c) for c in (0x7f, 0x80, 0xe9, 0x7ff, 0x800, 0x2028, 0xd7ff, 0xe000, 0xefff, 0xff61, 0xfeff, 0xffff,
                                0x10000, 0x1f600, 0x10ffff, 0x20ac, 0x1d11e)])

# Hand written edges: prototype keys a JavaScript object would mishandle, numeric keys a JavaScript object
# reorders, whitespace JSON does not allow, and the boundaries of each rule.
PROBES = [b'{"__proto__":1}', b'{"__proto__":{"a":1}}', b'{"__proto__":1,"__proto__":2}', b'{"constructor":1}',
          b'{"toString":1,"toString":2}', b'{"a":{"__proto__":[]}}', b'{"1":1,"0":0,"10":2}', b'{"\\u0000":1}',
          b'"\\uFEFF"', b'\xef\xbb\xbf1', b'1 ', b' 1', b'-', b'[1,]', b'{"a":1,}', b'0x10', b'1_0', b'\x00', b'[\x0b]',
          b'[\x0c]', b'[\xc2\xa0]', b'"\x7f"', b'"\\u00"', b'"\\ud800\\ud800"', b'"\\udbff\\udfff"', b'"\\uDBFF\\uDFFF"',
          b'123456789012345678', b'9007199254740991', b'-9007199254740991', b'9007199254740992', b'-9007199254740992',
          b'9007199254740991.0', b'-0', b'0', b'-1', b'00', b'[-]', b'1e0', b'true', b'nulll', b'[]]', b'', b' ']


def rand_char(rng: random.Random) -> str:
    pick = rng.random()
    if pick < 0.40:
        return chr(rng.randint(0x20, 0x7e))
    if pick < 0.50:
        return chr(rng.randint(0x00, 0x1f))
    if pick < 0.58:
        return rng.choice('"\\/\u007f')
    if pick < 0.68:
        return chr(rng.randint(0x80, 0x7ff))
    if pick < 0.84:
        while True:
            c = rng.randint(0x800, 0xffff)
            if not 0xd800 <= c <= 0xdfff:
                return chr(c)
    if pick < 0.88:
        return rng.choice("\u2028\u2029\ufeff\uffff\ue000\ud7ff")
    return chr(rng.randint(0x10000, 0x10ffff))


def rand_str(rng: random.Random, n: int = 8) -> str:
    return "".join(rand_char(rng) for _ in range(rng.randint(0, n)))


def rand_int(rng: random.Random) -> int:
    pick = rng.random()
    if pick < 0.4:
        return rng.randint(-1000, 1000)
    if pick < 0.6:
        return rng.choice([0, 1, -1, LIMIT, -LIMIT, LIMIT - 1, -LIMIT + 1, 2 ** 31, -2 ** 31, 2 ** 32, 10 ** 15])
    return rng.randint(-LIMIT, LIMIT)


def rand_value(rng: random.Random, depth: int = 0, budget: List[int] = None):
    if budget is None:
        budget = [40]
    budget[0] -= 1
    pick = rng.random()
    if depth >= 6 or budget[0] <= 0 or pick < 0.45:
        kind = rng.randrange(5)
        if kind == 0:
            return None
        if kind == 1:
            return rng.random() < 0.5
        if kind == 2:
            return rand_int(rng)
        return rand_str(rng)
    if pick < 0.70:
        return [rand_value(rng, depth + 1, budget) for _ in range(rng.randint(0, 4))]
    obj = {}
    for _ in range(rng.randint(0, 5)):
        key = rng.choice(KEY_POOL) if rng.random() < 0.6 else rand_str(rng, 4)
        obj[key] = rand_value(rng, depth + 1, budget)
    return obj


def deep_value(rng: random.Random, levels: int):
    value = rand_value(rng, 6)
    for _ in range(levels):
        value = [value] if rng.random() < 0.5 else {rng.choice(KEY_POOL): value}
    return value


WS = [" ", "\t", "\n", "\r"]


def ws(rng: random.Random, p: float) -> str:
    return "".join(rng.choice(WS) for _ in range(rng.randint(1, 3))) if rng.random() < p else ""


def esc_u(rng: random.Random, code: int) -> str:
    text = "%04x" % code
    return "\\u" + "".join(c.upper() if rng.random() < 0.5 else c for c in text)


def spell_str(rng: random.Random, text: str, p: float) -> str:
    out = ['"']
    shorts = {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r", '"': '\\"', "\\": "\\\\", "/": "\\/"}
    for ch in text:
        code = ord(ch)
        must = ch in '"\\' or code < 0x20
        if must or rng.random() < p:
            if ch in shorts and rng.random() < 0.6:
                out.append(shorts[ch])
            elif code >= 0x10000:
                c = code - 0x10000
                out.append(esc_u(rng, 0xd800 + (c >> 10)) + esc_u(rng, 0xdc00 + (c & 0x3ff)))
            else:
                out.append(esc_u(rng, code))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def spell(rng: random.Random, value, p: float = 0.3) -> str:
    """A legal spelling of `value`: random whitespace, member order and escapes."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return spell_str(rng, value, p)
    if isinstance(value, list):
        if not value:
            return "[" + ws(rng, p) + "]"
        return "[" + ",".join(ws(rng, p) + spell(rng, x, p) + ws(rng, p) for x in value) + "]"
    keys = list(value)
    rng.shuffle(keys)
    if not keys:
        return "{" + ws(rng, p) + "}"
    return "{" + ",".join(ws(rng, p) + spell_str(rng, k, p) + ws(rng, p) + ":" + ws(rng, p) + spell(rng, value[k], p)
                          + ws(rng, p) for k in keys) + "}"


TOKENS = [b"-0", b"-0.0", b"0.0", b"1e5", b"1E5", b"1e+2", b"1e-2", b"0.5", b"1.", b".5", b"00", b"01", b"-01", b"+1",
          b"9007199254740991", b"-9007199254740991", b"9007199254740992", b"-9007199254740992",
          b"99999999999999999999", b"18446744073709551616", b"1" * 40,
          b'"\\ud800"', b'"\\udc00"', b'"\\ud800\\u0041"', b'"\\uDBFF\\uDFFF"', b'"\\udbff"', b'"\\ud83d\\ude00"',
          b'"\\ud83d"', b'"\\u00e9"', b'"\\/"', b'"\\x"', b'"\\u12"', b'"\\U0041"', b'"\\u0000"', b'"\x01"', b'"\x7f"',
          b"NaN", b"Infinity", b"-Infinity", b"nul", b"tru", b"True", b"null", b"[]", b"{}", b'{"a":1,"a":2}',
          b'{"a":1,"b":2,"a":3}', b'{"\\u0061":1,"a":2}', b'"\xed\xa0\x80"', b'"\xc0\x80"', b'"\xe0\x80\x80"',
          b'"\xf4\x90\x80\x80"', b'"\xf5\x80\x80\x80"', b'"\x80"', b'"\xe2\x82"', b'"\xef\xbb\xbf"', b"\xef\xbb\xbf"]
BYTES = b'"\\/{}[],:-+.0123456789eE \t\n\r\x00\x7f\x80\xbf\xc0\xc1\xc2\xe0\xed\xef\xf0\xf4\xf5\xffu'


def mutate(rng: random.Random, doc: bytes) -> bytes:
    data = bytearray(doc)
    for _ in range(rng.randint(1, 3)):
        op = rng.randrange(9)
        pos = rng.randint(0, len(data))
        if op == 0 and data:
            del data[min(pos, len(data) - 1)]
        elif op == 1:
            data[pos:pos] = bytes([rng.choice(BYTES)])
        elif op == 2 and data:
            data[min(pos, len(data) - 1)] = rng.choice(BYTES)
        elif op == 3:
            data[pos:pos] = rng.choice(TOKENS)
        elif op == 4 and data:
            end = rng.randint(pos, len(data))
            data[pos:end] = rng.choice(TOKENS)
        elif op == 5:
            data[pos:pos] = rng.choice([b" ", b"\t", b"\n", b"\r", b"\x0b", b"\x0c", b"\xc2\xa0"])
        elif op == 6:
            del data[pos:]
        elif op == 7 and len(data) > 1:
            a = rng.randint(0, len(data) - 1)
            b = rng.randint(a, len(data))
            data[pos:pos] = data[a:b]
        else:
            data[0:0] = rng.choice([b"\xef\xbb\xbf", b" ", b"[", b"{\"k\":"])
    return bytes(data)


def structured(rng: random.Random) -> bytes:
    """A near canonical document made at the value level: a key swap, a duplicate key, a number variant,
    an escape variant or nesting at the bound."""
    kind = rng.randrange(6)
    if kind == 0:   # two members out of key order, otherwise canonical
        keys = sorted({rng.choice(KEY_POOL) for _ in range(rng.randint(2, 4))}, key=lambda k: k.encode("utf-16-be"))
        if len(keys) < 2:
            keys = ["a", "b"]
        i = rng.randrange(len(keys) - 1)
        keys[i], keys[i + 1] = keys[i + 1], keys[i]
        return ("{" + ",".join(canon2.dumps(k).decode() + ":" + canon2.dumps(rand_int(rng)).decode() for k in keys)
                + "}").encode()
    if kind == 1:   # a duplicate key, possibly spelled differently
        k = rng.choice(KEY_POOL)
        a = canon2.dumps(k).decode()
        b = spell_str(rng, k, 0.8)
        return ("{" + a + ":1," + b + ":2}").encode()
    if kind == 2:   # number variants
        n = rand_int(rng)
        variant = rng.choice([f"{n}.0", f"{n}e0", f"{n}E+0", f"{n}e-0", f"-{abs(n)}" if n == 0 else str(n), "-0",
                              str(LIMIT + rng.randint(1, 10)), str(-LIMIT - rng.randint(1, 10)), "0" + str(abs(n)),
                              str(n) + "0" * rng.randint(1, 5), f"{n}.5"])
        return ("[" + variant + "]").encode()
    if kind == 3:   # escape variants of a canonical string
        s = rand_str(rng)
        return spell_str(rng, s, 0.9).encode()
    if kind == 4:   # nesting at and past the bound
        levels = rng.choice([126, 127, 128, 129, 130, 200])
        opener, closer = (b"[", b"]") if rng.random() < 0.5 else (b'{"a":', b"}")
        return opener * levels + b"0" + closer * levels
    # a canonical document with whitespace in one place
    doc = canon2.dumps(rand_value(rng))
    pos = rng.randint(0, len(doc))
    return doc[:pos] + rng.choice([b" ", b"\n", b"\t", b"\r"]) + doc[pos:]


# ----------------------------------------------------------------- comparison and minimisation
def shape(line: str) -> str:
    """A line without its bytes: the strict verb and rule and the canonicalize verb and rule."""
    return " ".join(word for word in line.split() if word in ("ok", "canon", "refuse", ";", "panic") or
                    not all(c in "0123456789abcdef" for c in word))


def signature(lines: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
    """Which legs differ from the Lean line, and how (the line's shape)."""
    lean = lines["lean"]
    return tuple(sorted((leg, shape(lines[leg])) for leg in LEGS if lines[leg] != lean)) + (("lean", shape(lean)),)


def minimise(legs: Legs, doc: bytes, sig) -> bytes:
    def same(candidates: List[bytes]) -> List[bool]:
        res = legs.run(candidates)
        return [signature({leg: res[leg][i] for leg in LEGS}) == sig for i in range(len(candidates))]

    current = doc
    size = max(1, len(current) // 2)
    while size >= 1:
        cands = [current[:i] + current[i + size:] for i in range(0, len(current), size)]
        cands = [c for c in cands if c != current]
        ok = same(cands) if cands else []
        hit = next((c for c, good in zip(cands, ok) if good), None)
        if hit is not None:
            current = hit
            size = max(1, min(size, len(current) // 2))
            continue
        if size == 1:
            break
        size //= 2
    return current


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lean", default=str(ROOT / "formal" / ".lake" / "build" / "bin" / "canon2-oracle"))
    ap.add_argument("--rust", default=os.environ.get("PRISMPATH_CANON2_RS", ""))
    ap.add_argument("--go", default=os.environ.get("PRISMPATH_CANON2_GO", ""))
    ap.add_argument("--node", default="node")
    ap.add_argument("--values", type=int, default=100000)
    ap.add_argument("--mutations", type=int, default=100000)
    ap.add_argument("--seed", type=int, default=20261110)
    ap.add_argument("--max-findings", type=int, default=12)
    args = ap.parse_args()
    if not args.rust or not args.go:
        ap.error("--rust and --go (or PRISMPATH_CANON2_RS, PRISMPATH_CANON2_GO) name the built legs")
    legs = Legs(args.lean, args.rust, args.go, args.node)
    rng = random.Random(args.seed)

    sets: Dict[str, List[bytes]] = {}
    expect: Dict[str, List[Callable[[str], bool]]] = defaultdict(list)

    vectors = json.loads((ROOT / "prismpath" / "portable" / "conformance" / "canon2.json").read_text())["cases"]
    sets["vectors"] = []
    for case in vectors:
        doc = bytes.fromhex(case["hex"])
        sets["vectors"].append(doc)
        strict = "refuse " + case["refuse"] if "refuse" in case else "ok " + case["hex"]
        canon = "canon " + case["canonical_hex"] if "canonical_hex" in case else "refuse " + case["refuse"]
        expect["vectors"].append(lambda line, want=f"{strict} ; {canon}": line == want)

    sets["probes"] = list(PROBES)
    expect["probes"] = [lambda line: True] * len(PROBES)

    sets["values"] = []
    for i in range(args.values):
        value = deep_value(rng, rng.choice([120, 127])) if i % 5000 == 0 else rand_value(rng)
        canon = canon2.dumps(value)
        spelt = spell(rng, value, rng.choice([0.0, 0.2, 0.5])).encode()
        sets["values"].append(canon)
        expect["values"].append(lambda line, want=accepted(canon): line == want)
        sets["values"].append(spelt)
        want = accepted(canon) if spelt == canon else respelled(canon)
        expect["values"].append(lambda line, want=want: line == want)

    sets["mutations"] = []
    for i in range(args.mutations):
        if rng.random() < 0.35:
            sets["mutations"].append(structured(rng))
        else:
            base = canon2.dumps(rand_value(rng)) if rng.random() < 0.8 else spell(rng, rand_value(rng)).encode()
            sets["mutations"].append(mutate(rng, base))
        expect["mutations"].append(lambda line: True)

    total = 0
    findings: Dict[Tuple, List[Tuple[str, bytes, Dict[str, str]]]] = defaultdict(list)
    expect_fail: List[Tuple[str, bytes, str]] = []
    canon_out: set = set()
    for name, docs in sets.items():
        res = legs.run(docs)
        total += len(docs)
        outcome = Counter()
        disagree = 0
        for i, doc in enumerate(docs):
            lines = {leg: res[leg][i] for leg in LEGS}
            words = lines["lean"].split()
            outcome[shape(lines["lean"])] += 1
            if "canon" in words:
                after = words[words.index("canon") + 1:]
                canon_out.add(bytes.fromhex(after[0]) if after else b"")
            if len(set(lines.values())) != 1:
                disagree += 1
                findings[signature(lines)].append((name, doc, lines))
            if not expect[name][i](lines["lean"]):
                expect_fail.append((name, doc, lines["lean"]))
        print(f"{name}: {len(docs)} documents, {disagree} disagreements; lean: "
              + ", ".join(f"{k} {v}" for k, v in sorted(outcome.items())))

    fixed = sorted(canon_out)
    res = legs.run(fixed)
    total += len(fixed)
    fixed_bad = 0
    for i, doc in enumerate(fixed):
        lines = {leg: res[leg][i] for leg in LEGS}
        want = accepted(doc)
        if any(line != want for line in lines.values()):
            fixed_bad += 1
            findings[signature(lines)].append(("fixed-point", doc, lines))
    print(f"fixed point: {len(fixed)} canonical outputs sent again, {fixed_bad} not accepted as they are and canonicalized to themselves")
    print(f"expectations (vectors and generated values against the Lean line): {len(expect_fail)} failed")
    for name, doc, line in expect_fail[:5]:
        print(f"  {name}: {doc[:80].hex()} -> {line[:120]}")

    disagreements = sum(len(v) for v in findings.values())
    for n, (sig, items) in enumerate(sorted(findings.items(), key=lambda kv: -len(kv[1]))):
        if n >= args.max_findings:
            print(f"... {len(findings) - n} more classes")
            break
        name, doc, lines = items[0]
        small = minimise(legs, doc, sig)
        res = legs.run([small])
        print(f"finding {n + 1}: {len(items)} documents ({Counter(i[0] for i in items).most_common()}); minimised "
              f"reproducer {small.hex()} {small!r}")
        for leg in LEGS:
            print(f"  {leg}: {res[leg][0][:160]}")
    print(f"canon2-diff: {total} documents, {disagreements} disagreements")
    return 0 if disagreements == 0 and not expect_fail else 1


if __name__ == "__main__":
    sys.exit(main())
