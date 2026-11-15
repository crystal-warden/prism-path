# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""SHA256SUMS renders in the sha256sum format and parses back; the hash check names an edited, an
extra and a missing file; PROVENANCE.md must name a commit; and the research comparison refuses a
checkout at another commit."""
import hashlib
import subprocess

import pytest

from tools import provenance

COMMIT = "a" * 40


def _tree(root):
    (root / "a.txt").write_bytes(b"alpha")
    (root / "sub").mkdir()
    (root / "sub" / "b.txt").write_bytes(b"beta")
    (root / "PROVENANCE.md").write_text(f"# Provenance\n\nResearch commit: `{COMMIT}`\n")
    files = {path: (root / path).read_bytes() for path in ("a.txt", "sub/b.txt", "PROVENANCE.md")}
    (root / "SHA256SUMS").write_text(provenance.sha256_lines(files))


def test_sums_render_in_the_sha256sum_format_and_parse_back():
    text = provenance.sha256_lines({"b": b"2", "a": b"1"})
    assert text == f"{hashlib.sha256(b'1').hexdigest()}  a\n{hashlib.sha256(b'2').hexdigest()}  b\n"
    assert provenance.parse_sums(text) == {"a": hashlib.sha256(b"1").hexdigest(), "b": hashlib.sha256(b"2").hexdigest()}


def test_a_malformed_or_repeated_line_is_refused():
    with pytest.raises(ValueError):
        provenance.parse_sums("not a sum\n")
    line = f"{'0' * 64}  a\n"
    with pytest.raises(ValueError):
        provenance.parse_sums(line + line)


def test_an_untouched_tree_passes(tmp_path):
    _tree(tmp_path)
    assert provenance.check_hashes(tmp_path) == []
    assert provenance.recorded_commit(tmp_path) == COMMIT


def test_an_edited_extra_and_missing_file_are_each_named(tmp_path):
    _tree(tmp_path)
    (tmp_path / "a.txt").write_bytes(b"edited")
    (tmp_path / "extra.txt").write_bytes(b"x")
    (tmp_path / "sub" / "b.txt").unlink()
    problems = provenance.check_hashes(tmp_path)
    assert "a.txt: differs from SHA256SUMS" in problems
    assert "extra.txt: in the tree but not in SHA256SUMS" in problems
    assert "sub/b.txt: in SHA256SUMS but not in the tree" in problems


def test_provenance_without_a_commit_is_a_problem(tmp_path):
    _tree(tmp_path)
    (tmp_path / "PROVENANCE.md").write_text("# Provenance\n")
    files = {path: (tmp_path / path).read_bytes() for path in ("a.txt", "sub/b.txt", "PROVENANCE.md")}
    (tmp_path / "SHA256SUMS").write_text(provenance.sha256_lines(files))
    assert provenance.check_hashes(tmp_path) == ["PROVENANCE.md names no research commit"]


def test_a_research_checkout_at_another_commit_is_refused(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    _tree(tree)
    research = tmp_path / "research"
    research.mkdir()
    for args in (["init", "-q"], ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "x"]):
        subprocess.run(["git", "-C", str(research), *args], check=True)
    problems = provenance.check_against_research(tree, research)
    assert len(problems) == 1 and "check out that commit" in problems[0]
