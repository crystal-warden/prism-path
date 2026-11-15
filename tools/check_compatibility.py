# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The compatibility check: is this tree compatible with the research revision it adopted?

Four things, all from files in this repository, no network and no research checkout:

1. Reference hashes. prismpath/tests/fixtures/reference_hashes.json records the adopted sha256 of the
   research files the product depends on. A file marked byte_identical (the frozen corpora, the
   historical image) must hash to exactly that; a specification document only has its adopted hash
   recorded, and a product edit to the copy is reported as information, not failure, because the
   product may reword a document with the meanings preserved.
2. The cause registry hash, the same value the registry test pins.
3. The compiler references. The frozen manifest under prismpath/tests/fixtures/compiler must hash to
   the recorded value, every fixture must match the inventory, and compiling each source flow into a
   temporary file must reproduce the fixture bytes. Nothing here ever regenerates a reference.
4. Crate fixture equality, through tools/fixture_sync.py.

Passing means compatible with the adopted revision, not current with research.

    python -m tools.check_compatibility
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from tools import fixture_sync, product_inventory

REPO_ROOT = product_inventory.REPO_ROOT
REFERENCE_HASHES = "prismpath/tests/fixtures/reference_hashes.json"
COMPILER_FIXTURES = "prismpath/tests/fixtures/compiler"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_reference_hashes(repo_root: Path, reference: dict) -> tuple[list[str], list[str]]:
    failures, notes = [], []
    for research_path, item in sorted(reference["files"].items()):
        product_path = item.get("product_path")
        if not product_path:
            continue
        target = repo_root / product_path
        if not target.exists():
            failures.append(f"{product_path}: missing")
            continue
        actual = sha256_of(target)
        if actual == item["adopted_sha256"]:
            continue
        if item.get("byte_identical"):
            failures.append(f"{product_path}: sha256 {actual} differs from the adopted {item['adopted_sha256']}")
        else:
            notes.append(f"{product_path}: edited since adoption (adopted {item['adopted_sha256'][:12]}, now {actual[:12]}); meanings must be preserved")
    return failures, notes


def check_cause_registry(reference: dict) -> list[str]:
    from prismpath.kernel import causes
    actual = causes.registry_sha256()
    if actual != reference["cause_registry_sha256"]:
        return [f"cause registry sha256 {actual} differs from the adopted {reference['cause_registry_sha256']}"]
    return []


def fixture_source_flow(stem: str) -> str:
    """A fixture stem such as gallery__incident_severity__incident_severity names its source flow
    prismpath/gallery/incident_severity/incident_severity.md."""
    return "prismpath/" + stem.replace("__", "/") + ".md"


def compile_to_temporary(repo_root: Path, flow: Path, out_dir: Path, stem: str) -> tuple[Path, Path]:
    image = out_dir / f"{stem}.ppt"
    names = out_dir / f"{stem}.names.json"
    # The subprocess runs from the repository root so a source tree resolves the package the same way
    # an installed one does; the output paths are absolute, so the working directory changes nothing else.
    completed = subprocess.run([sys.executable, "-m", "prismpath.kernel.ppt_compile", str(flow), "-o", str(image), "--json", str(names)],
                               capture_output=True, text=True, cwd=str(repo_root))
    if completed.returncode != 0:
        raise RuntimeError(f"compiling {flow} failed: {completed.stderr.strip()}")
    return image, names


def check_compiler_references(repo_root: Path, reference: dict) -> list[str]:
    failures = []
    fixture_dir = repo_root / COMPILER_FIXTURES
    manifest = fixture_dir / "SHA256SUMS"
    if not manifest.exists():
        return [f"{COMPILER_FIXTURES}/SHA256SUMS: missing"]
    if sha256_of(manifest) != reference["compiler_references"]["checksum_list_sha256"]:
        failures.append("the compiler reference checksum list differs from the recorded hash; references are frozen, never regenerated")
    listed = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
        target = fixture_dir / name
        if not target.exists():
            failures.append(f"{COMPILER_FIXTURES}/{name}: listed in SHA256SUMS but missing")
        elif sha256_of(target) != digest:
            failures.append(f"{COMPILER_FIXTURES}/{name}: differs from SHA256SUMS")
    on_disk = {path.relative_to(fixture_dir).as_posix() for path in fixture_dir.rglob("*") if path.is_file() and path.name != "SHA256SUMS"}
    for name in sorted(on_disk - set(listed)):
        failures.append(f"{COMPILER_FIXTURES}/{name}: on disk but not in SHA256SUMS")
    if failures:
        return failures
    with tempfile.TemporaryDirectory() as temporary:
        out_dir = Path(temporary)
        for name in sorted(listed):
            if not name.endswith(".ppt") or name.startswith("anchored/"):
                continue
            stem = name[:-4]
            flow = repo_root / fixture_source_flow(stem)
            if not flow.exists():
                failures.append(f"{name}: source flow {flow.relative_to(repo_root)} is missing")
                continue
            try:
                image, names = compile_to_temporary(repo_root, flow, out_dir, stem)
            except RuntimeError as error:
                failures.append(str(error))
                continue
            if image.read_bytes() != (fixture_dir / name).read_bytes():
                failures.append(f"{name}: the compiler no longer reproduces the reference image")
            if names.read_bytes() != (fixture_dir / f"{stem}.names.json").read_bytes():
                failures.append(f"{stem}.names.json: the compiler no longer reproduces the reference sidecar")
        anchored = fixture_dir / "anchored" / "incident_severity.ppt"
        image, names = compile_to_temporary(repo_root, repo_root / "prismpath/gallery/incident_severity/incident_severity.md", out_dir, "anchored_incident_severity")
        if image.read_bytes() != anchored.read_bytes():
            failures.append("anchored/incident_severity.ppt: the compiler no longer reproduces the historical image")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=str(REPO_ROOT))
    args = parser.parse_args(argv)
    repo_root = Path(args.repo).resolve()
    reference = json.loads((repo_root / REFERENCE_HASHES).read_text(encoding="utf-8"))
    failures, notes = check_reference_hashes(repo_root, reference)
    failures += check_cause_registry(reference)
    failures += check_compiler_references(repo_root, reference)
    failures += [f"crate fixture: {problem}" for problem in fixture_sync.check(repo_root)]
    for note in notes:
        print(f"note     {note}")
    for failure in failures:
        print(f"FAIL     {failure}")
    if failures:
        print(f"compatibility: {len(failures)} failure(s) against adopted revision {reference['adopted_revision']}")
        return 1
    print(f"compatibility ok against adopted revision {reference['adopted_revision']}: reference hashes, cause registry, "
          f"compiler references, crate fixtures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
