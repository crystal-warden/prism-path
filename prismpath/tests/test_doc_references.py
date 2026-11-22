# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every `docs/...` path the sources name exists, so a document that is removed or renamed cannot leave a reference behind."""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUFFIXES = (".py", ".lean", ".yml", ".yaml", ".rs")
# Files that name a `docs/` path as the content of a fixture they build, and paths that are real but not tracked.
FIXTURE_FILES = {"prismpath/tests/test_docs_health.py", "tools/tests/test_check_boundary.py",
                 "integrations/governed_intent/cases_r2.py", "prismpath/tests/test_doc_references.py",
                 "tools/tests/test_export.py"}
NOT_TRACKED = {"docs/design/arch-scorecard.md",                   # written by tools/arch_guard.py, git ignored
               "docs/research/CLAIMS_detection_metrics.md"}       # optional, kept in the private lab repo
REFERENCE = re.compile(r"(?<![A-Za-z0-9_./-])docs/[A-Za-z0-9_][A-Za-z0-9_./-]*")


def _sources():
    try:
        listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
        names = [Path(n.decode()) for n in listed.split(b"\0") if n]
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout, so the sources cannot be listed")
    return [ROOT / n for n in names if n.suffix in SUFFIXES and (ROOT / n).is_file()]


def _missing(files, root=ROOT):
    out = []
    for path in files:
        if root == ROOT and path.relative_to(ROOT).as_posix() in FIXTURE_FILES:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for match in REFERENCE.finditer(line):
                target = match.group(0).rstrip(".,:;)-")
                if "*" in target or target.endswith("/"):
                    target = target.rstrip("/")
                if not target or target == "docs" or target in NOT_TRACKED:
                    continue
                if not (root / target).exists():
                    out.append(f"{path.name if root != ROOT else path.relative_to(ROOT)}:{number}: {target}")
    return out


def test_every_docs_path_the_sources_name_exists():
    if not (ROOT / "docs").is_dir():
        pytest.skip("docs/ is not beside this package (an installed wheel)")
    files = _sources()
    assert files, "no source files were listed"
    missing = _missing(files)
    assert not missing, "references to documents that do not exist:\n" + "\n".join(missing)


def test_the_check_finds_a_reference_to_a_missing_document(tmp_path):
    (tmp_path / "docs" / "design").mkdir(parents=True)
    (tmp_path / "docs" / "design" / "architecture.md").write_text("x")
    source = tmp_path / "x.py"
    source.write_text("# see docs/design/removed-plan.md, section 3\n# and docs/design/architecture.md.\n"
                      "# and docs/design/architecture.md and `docs/missing/` and a docs/ folder\n")
    assert _missing([source], tmp_path) == ["x.py:1: docs/design/removed-plan.md", "x.py:3: docs/missing"]
