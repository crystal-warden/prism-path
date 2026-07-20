"""ci-report — the PR comment builder (validate + fixtures + before/after Mermaid).

Runs against a REAL temp git repo: pins that changed-flow detection excludes fixtures/prose/
deleted files, that the base version renders as the "before" graph, that edge edits flip the
report to before→after while prose-only edits report "topology unchanged", and that the exit
gate trips on error findings and failing fixture rows but not on advisories.
"""
import os
import subprocess

import pytest

from prismpath.ci_report import FlowReport, MARKER, changed_flows, render, report_flow

FLOW_V1 = """---
name: t
start: a
---

## a
Do the thing.
-> b: when ok
-> c: when not ok

## b
Done.

## c
Failed path.
"""

TESTS = """| node | outcome | fields   | expect |
|------|---------|----------|--------|
| a    | worked  | ok=true  | b      |
| a    | broke   | ok=false | c      |
"""


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, capture_output=True, check=True)


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "flow.md").write_text(FLOW_V1)
    (tmp_path / "flow.tests.md").write_text(TESTS)
    (tmp_path / "README.md").write_text("# prose only\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_changed_flow_detection_excludes_fixtures_and_prose(repo):
    (repo / "flow.md").write_text(FLOW_V1.replace("when ok", "when ok and n > 1"))
    (repo / "flow.tests.md").write_text(TESTS + "| a | again | ok=true | b |\n")
    (repo / "README.md").write_text("# prose only, edited\n")
    assert changed_flows("HEAD") == ["flow.md"]


def test_edge_edit_reports_before_and_after(repo):
    (repo / "flow.md").write_text(FLOW_V1.replace("-> c: when not ok", "-> retry: when not ok")
                                  .replace("## c\nFailed path.", "## retry\nTry again.\n-> a: always"))
    r = report_flow("flow.md", "HEAD")
    assert r.mermaid_before and r.mermaid_after and r.mermaid_before != r.mermaid_after
    out = render([r])
    assert MARKER in out and "before" in out and "after" in out
    assert out.count("```mermaid") == 2

def test_prose_only_edit_reports_topology_unchanged(repo):
    (repo / "flow.md").write_text(FLOW_V1.replace("Do the thing.", "Do the thing, carefully."))
    r = report_flow("flow.md", "HEAD")
    assert r.mermaid_before == r.mermaid_after
    assert "Topology unchanged" in render([r])

def test_new_flow_has_no_before(repo):
    (repo / "new.md").write_text(FLOW_V1.replace("name: t", "name: new"))
    r = report_flow("new.md", "HEAD")
    assert r.mermaid_before is None
    assert "new flow" in render([r])

def test_fixtures_run_and_gate(repo):
    r = report_flow("flow.md", "HEAD")
    assert (r.tests_passed, r.tests_total) == (2, 2) and r.ok
    (repo / "flow.tests.md").write_text(TESTS.replace("| a    | broke   | ok=false | c      |",
                                                      "| a    | broke   | ok=false | b      |"))
    r2 = report_flow("flow.md", "HEAD")
    assert r2.tests_passed == 1 and not r2.ok                      # a failing row trips the gate
    assert "✗ 1/2" in render([r2])

def test_advisories_do_not_trip_the_gate():
    class W:                                                   # a warning-severity finding
        severity, code, node, message = "warning", "possible-stuck", "a", "advisory only"
    r = FlowReport(path="f.md", findings=[W()], tests_passed=2, tests_total=2,
                   mermaid_before="g", mermaid_after="g")
    assert r.warnings and not r.errors and r.ok                # warnings alone never gate
    assert "⚠" in render([r])
    W.severity = "error"
    assert not FlowReport(path="f.md", findings=[W()], mermaid_after="g").ok

def test_deleted_flow_is_skipped(repo):
    os.unlink(repo / "flow.md")
    assert changed_flows("HEAD") == []

def test_render_empty():
    assert "No flow files changed" in render([])
