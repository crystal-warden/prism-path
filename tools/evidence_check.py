#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""evidence_check.py: every anchored manifest in the tree, checked against the files it names.

A manifest is a SHA256SUMS file, most with an OpenTimestamps proof beside it. Two kinds live here:

  artifact manifests   name files that never change once anchored (logs, bitstreams, corpora, tables);
                       every named file that is in the tree must still hash the same. These are the
                       STRICT set below and a mismatch fails the check.
  snapshot manifests   name sources, documents or build products as they were at that anchor (the
                       ledger at each revision, a milestone's source files, a BPF object as one clang
                       emitted it); the tree has moved on by design, so they are reported, never failed. Files named but not in the tree (private corpora,
                       recordings, keys) are counted as absent, which is the expected state.

Paths inside a manifest are resolved against the manifest's directory, then its parent, then the repo
root, because the manifests were written from different working directories over time.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STRICT = {
    "prismpath-hw/evidence/SHA256SUMS",
    "prismpath-hw/hyst-cert/evidence/SHA256SUMS",
    "prismpath-hw/evidence/openflow_2026-08-20.SHA256SUMS",
    "prismpath-hw/evidence/wcet_2026-08-20.SHA256SUMS",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve(manifest: Path, name: str) -> Path | None:
    for base in (manifest.parent, manifest.parent.parent, ROOT):
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def main() -> int:
    manifests = sorted(path for path in ROOT.rglob("*SHA256SUMS") if ".venv" not in path.parts and "build" not in path.parts)
    failed = 0
    print(f"{'manifest':60s} {'ok':>4s} {'bad':>4s} {'absent':>6s}  ots  kind")
    for manifest in manifests:
        rel = manifest.relative_to(ROOT).as_posix()
        ok = bad = absent = 0
        for line in manifest.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, _, name = line.partition("  ")
            name = name.strip().lstrip("*")
            path = resolve(manifest, name)
            if path is None:
                absent += 1
            elif sha256(path) == digest.strip():
                ok += 1
            else:
                bad += 1
        strict = rel in STRICT
        ots = "yes" if manifest.with_name(manifest.name + ".ots").exists() else "no"
        kind = "artifact" if strict else "snapshot"
        flag = "  MISMATCH" if (bad and strict) else ""
        print(f"{rel:60s} {ok:4d} {bad:4d} {absent:6d}  {ots:3s}  {kind}{flag}")
        if bad and strict:
            failed += 1
    print(f"\n{len(manifests)} manifests, {len(STRICT)} strict; {'ok' if not failed else f'{failed} strict manifest(s) do not match the tree'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
