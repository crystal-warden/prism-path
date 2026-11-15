# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The tree digest is over sorted paths, git modes and exact bytes, excludes the two self paths, and
changes when a byte or a mode changes; SHA256SUMS renders in the sha256sum format; a symlink is refused."""
import os
import subprocess
from pathlib import Path

import pytest

from tools import provenance


def _repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    (tmp_path / "a.txt").write_text("alpha\n")
    (tmp_path / "run.sh").write_text("#!/bin/sh\n")
    os.chmod(tmp_path / "run.sh", 0o755)
    (tmp_path / "PROVENANCE.md").write_text("provenance")
    (tmp_path / "SHA256SUMS").write_text("sums")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "seed"], check=True)
    return tmp_path


def test_digest_excludes_self_paths_and_tracks_mode_and_bytes(tmp_path):
    repo = _repo(tmp_path)
    lines = provenance.tree_lines(repo)
    assert [path for _, _, path in lines] == ["a.txt", "run.sh"]
    assert dict((path, mode) for mode, _, path in lines)["run.sh"] == "100755"
    first = provenance.tree_digest(lines)
    (repo / "PROVENANCE.md").write_text("changed")
    assert provenance.tree_digest(provenance.tree_lines(repo)) == first
    (repo / "a.txt").write_text("beta\n")
    assert provenance.tree_digest(provenance.tree_lines(repo)) != first
    (repo / "a.txt").write_text("alpha\n")
    subprocess.run(["git", "-C", str(repo), "update-index", "--chmod=-x", "run.sh"], check=True)
    assert provenance.tree_digest(provenance.tree_lines(repo)) != first


def test_sha256sums_format(tmp_path):
    repo = _repo(tmp_path)
    text = provenance.render_sha256sums(provenance.tree_lines(repo))
    for line in text.splitlines():
        digest, path = line.split("  ", 1)
        assert len(digest) == 64 and path in ("a.txt", "run.sh")


def test_symlink_is_refused(tmp_path):
    repo = _repo(tmp_path)
    os.symlink("a.txt", repo / "link")
    subprocess.run(["git", "-C", str(repo), "add", "link"], check=True)
    with pytest.raises(ValueError):
        provenance.tree_lines(repo)


def test_the_real_tree_has_only_regular_files():
    provenance.index_entries(provenance.REPO_ROOT)
