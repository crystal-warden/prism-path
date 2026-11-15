#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""OpenTimestamps anchoring for the Flow-Ledger (task #36 / docs/design/spec-ledger-opentimestamps.md).

Upgrades the ledger from ACCIDENT-tamper-evident to ADVERSARIAL temporal integrity: batches the
per-unit `PrismPath-Output-Hash` values into a Merkle tree, stamps the single ROOT via OpenTimestamps
(free Bitcoin anchoring via calendar servers), and stores per-unit inclusion proofs. Verification
walks: output-hash -> Merkle path -> root -> OTS proof -> Bitcoin block time. Out-of-band by design
(network I/O), so the pure engine is never touched. Two-phase: stamp returns a PENDING calendar proof
immediately; `upgrade` promotes it to a full Bitcoin proof after ~1-6h.
"""

import hashlib
import json

from prismpath import canon
import os
import subprocess

_OTSENV = {**os.environ, "PATH": os.path.expanduser("~/.local/bin") + ":" + os.environ.get("PATH", "")}


# The Merkle tree every PrismPath ledger shares: RFC 6962's (Certificate Transparency, section 2.1). A
# leaf hashes as SHA-256(0x00 || leaf) and an inner node as SHA-256(0x01 || left || right), so no leaf
# can be presented as a node or the reverse, and a tree over n leaves splits at k, the largest power of
# two below n: the root of the first k leaves on the left, the root of the rest on the right. Nothing is
# ever duplicated, so [a, b, c] and [a, b, c, c] have different roots and a root fixes its leaf count.
# The tree before this one (Bitcoin style: no prefixes, the last node of an odd layer paired with itself)
# is retired; the formats that carry these roots were bumped with it, and a verifier refuses the old ones.
MERKLE_SCHEME = "rfc6962-sha256"
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(leaf):
    """The hash of a Merkle leaf: SHA-256 of 0x00 and the leaf's bytes (here a 32 byte hash itself)."""
    return hashlib.sha256(LEAF_PREFIX + leaf).digest()


def node_hash(left, right):
    """The hash of an inner node: SHA-256 of 0x01, then the left child's hash, then the right's. Public
    because `root_statement` keeps the same root as leaves arrive and every port must hash a node the
    same way, or a root signed from one would not verify against another."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def split_point(count):
    """RFC 6962's k for a tree over `count` (at least 2) leaves: the largest power of two below it."""
    return 1 << ((count - 1).bit_length() - 1)


def _subtree(hashes):
    """(root, [path per leaf]) over leaf hashes, each path from the leaf up as (side, sibling hex)."""
    if len(hashes) == 1:
        return hashes[0], [[]]
    k = split_point(len(hashes))
    left, left_paths = _subtree(hashes[:k])
    right, right_paths = _subtree(hashes[k:])
    paths = [path + [("R", right.hex())] for path in left_paths] + \
            [path + [("L", left.hex())] for path in right_paths]
    return node_hash(left, right), paths


def _subtree_root(hashes):
    if len(hashes) == 1:
        return hashes[0]
    k = split_point(len(hashes))
    return node_hash(_subtree_root(hashes[:k]), _subtree_root(hashes[k:]))


def merkle_root(leaves_hex):
    """The RFC 6962 root over hex leaves, or None for no leaves: `merkle_root_and_paths`'s root without
    the paths, computed straight from the definition (RFC 6962 section 2.1, MTH)."""
    if not leaves_hex:
        return None
    return _subtree_root([leaf_hash(bytes.fromhex(hash_hex)) for hash_hex in leaves_hex]).hex()


def merkle_root_and_paths(leaves_hex):
    """RFC 6962 Merkle tree over hex leaves -> (root_hex, [path per leaf]), (None, []) for no leaves. A path
    is the siblings from the leaf up, each ("R", hex) when the sibling is on the right, ("L", hex) when on
    the left; `verify_leaf` folds it. A leaf deep in an unbalanced tree has a shorter path than one in its
    complete left part."""
    if not leaves_hex:
        return None, []
    root, paths = _subtree([leaf_hash(bytes.fromhex(hash_hex)) for hash_hex in leaves_hex])
    return root.hex(), paths


def verify_leaf(leaf_hex, path, root_hex):
    """Whether `leaf_hex` sits under `root_hex` along `path`: its leaf hash, folded with each sibling."""
    cur = leaf_hash(bytes.fromhex(leaf_hex))
    for side, sib in path:
        sibling = bytes.fromhex(sib)
        cur = node_hash(cur, sibling) if side == "R" else node_hash(sibling, cur)
    return cur.hex() == root_hex


def _leaf_hex(value):
    """The bare hex of a hash written as `sha256:<hex>`, which is how the Flow-Ledger records an output
    hash; a bare hex string passes through. The Merkle tree is built over the bytes, so the prefix goes."""
    value = value.strip()
    return value[len("sha256:"):] if value.startswith("sha256:") else value


def from_ledger(ledger_repo, ref="refs/prismpath/runs"):
    """Enumerate PrismPath-Output-Hash values from a Flow-Ledger bare repo (git log trailers)."""
    env = {**os.environ, "GIT_DIR": ledger_repo}
    refs = subprocess.run(
        ["git", "for-each-ref", "--format=%(refname)", ref], capture_output=True, text=True, env=env
    ).stdout.split()
    out = []
    for ref_name in refs:
        log = subprocess.run(
            ["git", "log", "--format=%(trailers:key=PrismPath-Output-Hash,valueonly)", ref_name],
            capture_output=True,
            text=True,
            env=env,
        ).stdout
        out += [_leaf_hex(trailer_line) for trailer_line in log.splitlines() if trailer_line.strip()]
    return out


def anchor(hashes, out_dir, label):
    """Build Merkle root over `hashes`, write root file + manifest, and OTS-stamp the root."""
    os.makedirs(out_dir, exist_ok=True)
    root, paths = merkle_root_and_paths(hashes)
    rootfile = os.path.join(out_dir, f"root_{label}.txt")
    open(rootfile, "w").write(root + "\n")
    manifest = canon.tagged(dict(label=label, merkle=MERKLE_SCHEME, root=root, leaf_count=len(hashes),
                                 leaves={hash_hex: paths[index] for index, hash_hex in enumerate(hashes)}))
    canon.atomic_write_bytes(os.path.join(out_dir, f"manifest_{label}.json"), canon.canon2_bytes(manifest) + b"\n")
    ots_run = subprocess.run(["ots", "stamp", rootfile], capture_output=True, text=True, env=_OTSENV)
    return dict(
        root=root,
        leaf_count=len(hashes),
        rootfile=rootfile,
        stamped=(ots_run.returncode == 0 and os.path.exists(rootfile + ".ots")),
        ots_rc=ots_run.returncode,
        ots_msg=(ots_run.stdout + ots_run.stderr).strip()[-200:],
    )


def upgrade(out_dir, label):
    ots_run = subprocess.run(
        ["ots", "upgrade", os.path.join(out_dir, f"root_{label}.txt.ots")],
        capture_output=True,
        text=True,
        env=_OTSENV,
    )
    return dict(ots_rc=ots_run.returncode, ots_msg=(ots_run.stdout + ots_run.stderr).strip()[-200:])


def verify_unit(leaf_hex, out_dir, label):
    """Full chain: Merkle path to the anchored root, then OTS-verify the root against Bitcoin."""
    with open(os.path.join(out_dir, f"manifest_{label}.json"), encoding="utf-8", newline="") as manifest_file:
        manifest = canon.loads_document(manifest_file.read())
    if manifest.get("merkle") != MERKLE_SCHEME:
        # an anchor written before the RFC 6962 tree: its paths are of the retired tree, so none would fold
        return dict(merkle_ok=False, reason=f"this anchor batch uses the retired Merkle tree, not {MERKLE_SCHEME}; "
                                            "re-anchor its leaves")
    leaf_hex = _leaf_hex(leaf_hex)
    path = manifest["leaves"].get(leaf_hex)
    if path is None:
        return dict(merkle_ok=False, reason="output-hash not in this anchor batch")
    merkle_ok = verify_leaf(leaf_hex, path, manifest["root"])
    ots_run = subprocess.run(
        ["ots", "verify", os.path.join(out_dir, f"root_{label}.txt.ots")],
        capture_output=True,
        text=True,
        env=_OTSENV,
    )
    return dict(
        merkle_ok=merkle_ok,
        root=manifest["root"],
        ots_ok=(ots_run.returncode == 0),
        ots_rc=ots_run.returncode,
        ots_verify=(ots_run.stdout + ots_run.stderr).strip()[-300:],
    )
