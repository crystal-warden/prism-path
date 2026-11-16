# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Freeze cross-language vectors for the streaming form of the RFC 6962 Merkle root.

Every port that keeps a root as leaves arrive (`root_statement.MerkleAccumulator` in Python,
`prismpath_rs::merkle::Accumulator` in Rust, `ppt_merkle_acc` in `prismpath-ebpf/merkle.h`) must reach,
after each leaf, the root the tree gives over the leaves so far. This writes a few fixed leaf sequences and
the root over every prefix of each, computed by RUNNING the Python batch reference (`ledger_ots.merkle_root`,
RFC 6962 section 2.1 recursion) and checked against the Python accumulator before anything is written.

    python prismpath/portable/gen_merkle_stream_fixtures.py   ->  conformance/merkle_stream.json

The leaves are fixed, so regeneration is byte identical. `prismpath/tests/test_merkle_stream.py` regenerates
the set and refuses drift; `prismpath-rs/tests/test_merkle_stream.rs` replays its crate copy, and
`prismpath-ebpf/test_merkle.c` replays it in C.

Each set is `{"name", "leaves": [hex], "roots": [null, hex, ...]}`, where `roots[n]` is the root over the
first n leaves (null for none, as RFC 6962 has no root over nothing):

    rfc6962          the eight inputs of the Certificate Transparency reference tests
    hash_leaves      300 leaves, each the SHA-256 of its index as 4 big-endian bytes (past 256, so the
                     ninth peak and its carries are crossed)
    varied_lengths   70 leaves of 0 to 69 bytes, so a leaf is hashed whatever its length
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

from prismpath.ledgers import ledger_ots, root_statement as rs  # noqa: E402

OUT = HERE / "conformance" / "merkle_stream.json"
FORMAT_VERSION = 1

RFC6962_INPUTS = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657",
                  "606162636465666768696a6b6c6d6e6f"]


def hash_leaves(count: int = 300) -> list[str]:
    return [hashlib.sha256(index.to_bytes(4, "big")).hexdigest() for index in range(count)]


def varied_lengths(count: int = 70) -> list[str]:
    return [bytes((index * 7 + offset) % 256 for offset in range(index)).hex() for index in range(count)]


def prefix_roots(leaves: list[str]) -> list[str | None]:
    """The batch root over every prefix, held to the accumulator fed the same leaves one at a time."""
    roots = [ledger_ots.merkle_root(leaves[:count]) for count in range(len(leaves) + 1)]
    accumulator = rs.MerkleAccumulator()
    assert accumulator.root() == "" and roots[0] is None
    for count, leaf in enumerate(leaves, start=1):
        accumulator.add(leaf)
        assert accumulator.root() == roots[count], f"accumulator and tree differ at {count} leaves"
    return roots


def build() -> dict:
    sets = [
        ("rfc6962", RFC6962_INPUTS),
        ("hash_leaves", hash_leaves()),
        ("varied_lengths", varied_lengths()),
    ]
    return {
        "version": FORMAT_VERSION,
        "scheme": ledger_ots.MERKLE_SCHEME,
        "note": "Streaming Merkle root vectors. roots[n] is the RFC 6962 root over the first n leaves, null for "
        "none, computed by the Python batch reference. An accumulator fed the leaves one at a time must "
        "give roots[n] after the nth leaf, byte for byte.",
        "sets": [{"name": name, "leaves": list(leaves), "roots": prefix_roots(list(leaves))} for name, leaves in sets],
    }


def render() -> str:
    return json.dumps(build(), indent=1, sort_keys=True) + "\n"


def main() -> int:
    OUT.write_text(render())
    doc = json.loads(OUT.read_text())
    print(f"wrote {OUT.relative_to(REPO)}: " + ", ".join(f"{s['name']} {len(s['leaves'])} leaves" for s in doc["sets"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
