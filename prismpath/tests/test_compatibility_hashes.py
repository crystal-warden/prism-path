# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The retained references match what the product adopted: every corpus and the historical image hash
to the adopted sha256, the cause registry hashes to the recorded value, and the compiler reference
manifest is the frozen one. This runs from the installed package, so it reads the reference file and
the fixtures through the package directory, never through a repository path."""
import hashlib
import json
from pathlib import Path

from prismpath.kernel import causes

PACKAGE = Path(__file__).resolve().parent.parent
REFERENCE = json.loads((PACKAGE / "tests" / "fixtures" / "reference_hashes.json").read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _product_file(product_path: str) -> Path:
    # product paths in the reference file are repository relative and start with prismpath/
    assert product_path.startswith("prismpath/"), product_path
    return PACKAGE / product_path[len("prismpath/"):]


def test_byte_identical_references_hash_to_the_adopted_values():
    checked = 0
    for research_path, item in REFERENCE["files"].items():
        if not item.get("byte_identical") or not item.get("product_path"):
            continue
        target = _product_file(item["product_path"])
        assert target.exists(), f"{item['product_path']} is missing from the installed package"
        assert _sha256(target) == item["adopted_sha256"], f"{item['product_path']} differs from the adopted {research_path}"
        checked += 1
    assert checked >= 18, "the corpora and the historical image are all expected to be byte identical references"


def test_cause_registry_hash_is_the_adopted_one():
    assert causes.registry_sha256() == REFERENCE["cause_registry_sha256"]


def test_compiler_reference_manifest_is_frozen():
    manifest = PACKAGE / "tests" / "fixtures" / "compiler" / "SHA256SUMS"
    assert _sha256(manifest) == REFERENCE["compiler_references"]["checksum_list_sha256"]
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        assert _sha256(manifest.parent / name) == digest, f"{name} differs from the frozen manifest"
