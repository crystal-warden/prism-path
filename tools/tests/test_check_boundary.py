# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The three boundary rules on a fixture tree: a dangling relative link is reported, an unpinned
research link is reported, a pinned one and a home link are not; and the package check rejects a held
member and a missing required member."""
import zipfile
from pathlib import Path

from tools import check_boundary

PINNED = "https://github.com/crystal-warden/prism-path/blob/40a9b05b3523cb4943b583b77c6fb86f93d795ee/docs/POSITION.md"


def test_links(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text(
        "[ok](../README.md) [gone](missing.md) [pinned](" + PINNED + ") "
        "[home](https://github.com/crystal-warden/prism-path) "
        "[unpinned](https://github.com/crystal-warden/prism-path/blob/main/SPEC.md)")
    (tmp_path / "README.md").write_text("# x")
    problems = check_boundary.check_links(tmp_path, ["docs/guide.md", "README.md"])
    assert any("dangling link missing.md" in problem for problem in problems)
    assert any("not pinned" in problem and "blob/main" in problem for problem in problems)
    assert len(problems) == 2


def test_package_members(tmp_path):
    wheel = tmp_path / "prismpath-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("prismpath/kernel/engine.py", "")
        archive.writestr("prismpath/comparisons/results.json", "{}")
    problems = check_boundary.check_package(check_boundary.REPO_ROOT, wheel, ["prismpath/kernel/engine.py", "prismpath/absent.py"])
    assert any("carries held path prismpath/comparisons/results.json" in problem for problem in problems)
    assert any("required member missing: prismpath/absent.py" in problem for problem in problems)
    assert not any("prismpath/kernel/engine.py" in problem for problem in problems)


def test_the_real_repository_passes():
    assert check_boundary.check_repository(check_boundary.REPO_ROOT) == []
