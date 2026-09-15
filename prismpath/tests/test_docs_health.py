# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The docs-health lint over a fixture tree, not over this repo: each check is a function taking the
tree root, so a dead link, a leaked pre-rename name and a backticked path that does not resolve can be
planted deliberately and the exit code, the report file and the JSON payload read back.

The missing-ledger case is the regression that matters: the guard used to be an `assert`, so under
`python -O` a stale ledger path reported every task as a gap instead of failing."""
import importlib.util
import json

import pytest

from prismpath.tests._repo import repo_file

_spec = importlib.util.spec_from_file_location("docs_health", repo_file("tools", "docs_health.py"))
docs_health = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(docs_health)

LEDGER = "\n".join(["# Supporting evidence (fixture)", ""]
                   + [f"Task {task} captured." for task in docs_health.TASKS]
                   + [f"Artifact {artifact} captured." for artifact in docs_health.ARTIFACTS]) + "\n"


def _tree(tmp_path, guide, extra=None):
    """A minimal repo-shaped tree: the evidence ledger, one real tool file, and the doc under test."""
    (tmp_path / "docs" / "research").mkdir(parents=True)
    (tmp_path / "docs" / "research" / "supporting-evidence.md").write_text(LEDGER, encoding="utf-8")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "real_tool.py").write_text("# a tool that exists\n", encoding="utf-8")
    (tmp_path / "docs" / "other.md").write_text("# Other\n\nA link target that resolves.\n", encoding="utf-8")
    (tmp_path / "docs" / "guide.md").write_text(guide, encoding="utf-8")
    for name, text in (extra or {}).items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


GUIDE = """# Guide

A link that resolves: [other](other.md).
A link that does not: [gone](nowhere.md).

The tool that exists is `tools/real_tool.py` and the one that does not is `tools/ghost_tool.py`.
A bare name like `read_text` and a glob like `tools/*.py` are not path claims.
"""


def test_dead_link_is_found_and_a_live_one_is_not(tmp_path):
    base = _tree(tmp_path, GUIDE)
    md_paths = docs_health.collect_markdown(str(base))
    dead = docs_health.dead_doc_links(str(base), md_paths)
    assert dead == [("docs/guide.md", "nowhere.md")]


def test_backticked_path_that_does_not_resolve_is_found(tmp_path):
    base = _tree(tmp_path, GUIDE)
    md_paths = docs_health.collect_markdown(str(base))
    missing = docs_health.backticked_missing_paths(str(base), md_paths)
    assert missing == [("docs/guide.md", "tools/ghost_tool.py")]


def test_dead_link_fails_the_gate_and_lands_in_the_report(tmp_path, capsys):
    base = _tree(tmp_path, GUIDE)
    assert docs_health.main(str(base)) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["dead_doc_links"] == [["docs/guide.md", "nowhere.md"]]
    assert report["backticked_missing_paths_advisory"] == [["docs/guide.md", "tools/ghost_tool.py"]]
    assert report["task_coverage_gaps"] == []
    assert report["artifact_coverage_gaps"] == []
    rendered = (base / "docs_health_report.md").read_text(encoding="utf-8")
    assert "## Dead doc-links" in rendered
    assert "nowhere.md" in rendered
    assert "ADVISORY" in rendered


def test_clean_tree_passes_and_the_generated_report_is_not_rescanned(tmp_path, capsys):
    clean = "# Guide\n\nA link that resolves: [other](other.md), and `tools/real_tool.py` exists.\n"
    base = _tree(tmp_path, clean)
    assert docs_health.main(str(base)) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["dead_doc_links"] == []
    assert first["brand_residue_count"] == 0
    assert first["backticked_missing_paths_advisory"] == []
    # the report is excluded from the scan, so a second run sees the same file count, not one more
    assert docs_health.main(str(base)) == 0
    assert json.loads(capsys.readouterr().out) == first


def test_a_leaked_pre_rename_name_fails_the_gate(tmp_path, capsys):
    clean = "# Guide\n\nA link that resolves: [other](other.md).\n"
    base = _tree(tmp_path, clean, extra={"docs/leak.md": "# Leak\n\nRun the MDFlow engine.\n"})
    assert docs_health.main(str(base)) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["brand_residue_count"] == 1
    assert report["brand_residue_in_prismpath"] == [["docs/leak.md", 3, "Run the MDFlow engine."]]


def test_allowlisted_paths_keep_their_legitimate_mentions(tmp_path, capsys):
    clean = "# Guide\n\nA link that resolves: [other](other.md).\n"
    base = _tree(tmp_path, clean, extra={"CHANGELOG.md": "# Changelog\n\nInterop with mdflow.\n"})
    assert docs_health.main(str(base)) == 0
    assert json.loads(capsys.readouterr().out)["brand_residue_count"] == 0


def test_duplicate_docs_are_grouped(tmp_path, capsys):
    clean = "# Guide\n\nA link that resolves: [other](other.md).\n"
    base = _tree(tmp_path, clean, extra={"docs/copy.md": clean})
    assert docs_health.main(str(base)) == 0   # dupes are reported, never gated
    dupes = json.loads(capsys.readouterr().out)["lingering_dupes"]
    assert [sorted(group) for group in dupes] == [["docs/copy.md", "docs/guide.md"]]


def test_a_missing_ledger_fails_loudly_rather_than_reporting_every_task_as_a_gap(tmp_path):
    base = _tree(tmp_path, GUIDE)
    (base / "docs" / "research" / "supporting-evidence.md").unlink()
    with pytest.raises(docs_health.DocsHealthError, match="evidence ledger missing"):
        docs_health.coverage_gaps(str(base))
