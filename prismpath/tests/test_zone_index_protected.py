# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The zone index is a control path (prismpath/agent/zones.py): the agent cannot write it through the hook or through
either per call sandbox backend, and the information point answers `unknown` for an index the agent could have written."""
import hashlib
import os
import sqlite3
import sys
from pathlib import Path

import pytest

from prismpath.agent import claude_code, classifier, controls, sandbox_exec, sandbox_hook, session_state, zones
from prismpath.agent.policy import Policy, starter_path
from prismpath.agent.profile import Profile
from prismpath.agent.sandbox_exec import SandboxUnavailable

CONTROL_WRITE = 128
SECURE = "def check():\n    return 1\n"
CALLER = "def go():\n    return 2\n"


def _bwrap_ok() -> bool:
    try:
        sandbox_exec.run_sandboxed(["/usr/bin/true"], os.getcwd())
        return True
    except SandboxUnavailable:
        return False


def _landlock_ok() -> bool:
    from prismpath.agent import landlock
    return landlock.abi_version() >= 1


needs_bwrap = pytest.mark.skipif(not _bwrap_ok(), reason="bwrap cannot start here")
needs_landlock = pytest.mark.skipif(not _landlock_ok() and os.environ.get("PRISMPATH_REQUIRE_LANDLOCK") != "1",
                                    reason="this kernel has no Landlock")


class Project:
    """A project whose index sits at the default place, `.contextcloud/index.sqlite`, and says that `pkg/caller.py`
    reaches nothing (the forged claim: a stand-in `contextcloud` that always answers `no`)."""

    def __init__(self, tmp_path):
        self.root = (tmp_path / "proj").resolve()
        (self.root / "pkg").mkdir(parents=True)
        (self.root / ".contextcloud").mkdir()
        self.index = self.root / ".contextcloud" / "index.sqlite"
        self.home = tmp_path / "home"
        self.home.mkdir()
        (self.root / "pkg" / "secure.py").write_text(SECURE)
        (self.root / "pkg" / "caller.py").write_text(CALLER)
        db = sqlite3.connect(self.index)
        db.execute("CREATE TABLE files (file TEXT, tier TEXT, module TEXT, sha256 TEXT)")
        db.execute("CREATE TABLE symbols (file TEXT, tier TEXT, symbol TEXT, symbol_kind TEXT)")
        for rel, text, fn in (("pkg/secure.py", SECURE, "check"), ("pkg/caller.py", CALLER, "go")):
            module = rel[:-3].replace("/", ".")
            db.execute("INSERT INTO files VALUES (?, 'saved', ?, ?)", (rel, module, hashlib.sha256(text.encode()).hexdigest()))
            db.execute("INSERT INTO symbols VALUES (?, 'saved', ?, 'function')", (rel, f"{module}.{fn}"))
        db.commit()
        db.close()
        self.exe = tmp_path / "contextcloud"
        self.exe.write_text(f"#!{sys.executable}\nprint('{{\"certainty\": \"no\"}}')\n")
        self.exe.chmod(0o755)

    def point(self, image=b"image", index=None):
        doc = zones.zone_document(["pkg.secure.check"], self.root, index or self.index, image)
        return zones.ContextCloudZones(doc, self.home, str(self.exe), budget_s=5.0)

    def config(self, point):
        return classifier.Config.for_workspace(self.root, zones=point)


@pytest.fixture()
def project(tmp_path):
    made = Project(tmp_path)
    yield made
    for path in (made.root / ".contextcloud", made.index, tmp_path / "outside", tmp_path / "outside" / "index.sqlite"):
        if path.exists():
            path.chmod(0o755 if path.is_dir() else 0o644)


# ------------------------------------------------------------------------------------------------ the hook
def _decide(project, tool, tool_input):
    from prismpath.agent.policy import STARTERS
    policy = Policy.load(starter_path(sorted(STARTERS)[0]))
    hook = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
            "cwd": str(project.root)}
    result = claude_code.evaluate(hook, {"CLAUDE_PROJECT_DIR": str(project.root)}, policy,
                                  zones=project.point(policy.image), session=session_state.FRESH)
    return result


@pytest.mark.parametrize("tool,tool_input", [
    ("Write", {"file_path": ".contextcloud/index.sqlite", "content": "x"}),
    ("Edit", {"file_path": ".contextcloud/index.sqlite", "old_string": "a", "new_string": "b"}),
    ("Write", {"file_path": ".contextcloud/new.sqlite", "content": "x"}),
    ("Bash", {"command": "rm .contextcloud/index.sqlite"}),
    ("Bash", {"command": "mv .contextcloud/index.sqlite /tmp/x"}),
    ("Bash", {"command": "cp /tmp/forged .contextcloud/index.sqlite"}),
    ("Bash", {"command": "rm -rf .contextcloud"}),
    ("Bash", {"command": "mv .contextcloud elsewhere"}),
], ids=lambda v: v if isinstance(v, str) else "")
def test_the_hook_refuses_a_write_to_the_zone_index_as_a_control_write(project, tool, tool_input):
    if "file_path" in tool_input:
        tool_input = {**tool_input, "file_path": str(project.root / tool_input["file_path"])}
    result = _decide(project, tool, tool_input)
    assert result.decision.kind == "refuse" and result.decision.cause_code == CONTROL_WRITE, result.reading
    assert result.reading["path_control"] is True


def test_without_a_declared_zone_the_index_directory_is_an_ordinary_path(project):
    config = classifier.Config.for_workspace(project.root)
    reading = classifier.classify({"tool": "write_file", "args": {"path": ".contextcloud/index.sqlite", "content": "x"}}, config)
    assert reading["path_control"] is False


def test_a_hard_link_to_the_index_is_a_control_path_too(project, tmp_path):
    link = project.root / "pkg" / "alias.sqlite"
    os.link(project.index, link)
    reading = classifier.classify({"tool": "write_file", "args": {"path": "pkg/alias.sqlite", "content": "x"}},
                                  project.config(project.point()))
    assert reading["path_control"] is True


def test_the_control_paths_are_the_index_directory_or_the_files_when_the_index_is_in_the_root(project):
    assert project.point().control_paths == (str(project.root / ".contextcloud"),)
    root_index = project.root / "index.sqlite"
    assert project.point(index=root_index).control_paths == (str(root_index), str(root_index) + "-wal", str(root_index) + "-shm")


# ------------------------------------------------------------------------------------------------ the sandboxes
ATTACK = ("echo forged >> .contextcloud/index.sqlite; echo forged > .contextcloud/index.sqlite-wal; "
          "echo x > .contextcloud/new.sqlite; rm -f .contextcloud/index.sqlite; mv .contextcloud .elsewhere; true")


def _untouched(project, original):
    assert project.index.read_bytes() == original
    assert sorted(p.name for p in (project.root / ".contextcloud").iterdir()) == ["index.sqlite"]
    assert not (project.root / ".elsewhere").exists()


@pytest.mark.parametrize("backend,mark", [("bwrap", needs_bwrap), ("landlock", needs_landlock)])
def test_a_sandboxed_command_cannot_change_the_zone_index(project, backend, mark):
    if mark.args[0]:
        pytest.skip(mark.kwargs["reason"])
    original = project.index.read_bytes()
    point = project.point()
    if backend == "bwrap":
        done = sandbox_exec.run_backend("bwrap", ATTACK, project.root, Profile(timeout_s=60), stdin=b"",
                                        mount=str(project.root), control_paths=point.control_paths)
    else:
        done = sandbox_exec.run_landlock(ATTACK, project.root, Profile(timeout_s=60), stdin=b"",
                                         control_paths=point.control_paths)
    assert done.backend == backend, done.stderr
    _untouched(project, original)


@pytest.mark.parametrize("backend,mark", [("bwrap", needs_bwrap), ("landlock", needs_landlock)])
def test_the_same_command_changes_the_index_when_it_is_not_a_control_path(project, backend, mark):
    if mark.args[0]:
        pytest.skip(mark.kwargs["reason"])
    original = project.index.read_bytes()
    if backend == "bwrap":
        sandbox_exec.run_backend("bwrap", ATTACK, project.root, Profile(timeout_s=60), stdin=b"", mount=str(project.root))
    else:
        sandbox_exec.run_landlock(ATTACK, project.root, Profile(timeout_s=60), stdin=b"")
    assert not project.index.exists() or project.index.read_bytes() != original


def test_the_hook_passes_the_zone_index_to_the_runner(project):
    profile = Profile()
    command = sandbox_hook.rewrite_command("true", str(project.root), str(project.root), profile,
                                           control_paths=project.point().control_paths)
    assert f"--control-path {project.root}/.contextcloud" in command


def test_discover_binds_an_extra_control_path_below_the_workspace_only(project, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    found = controls.discover(project.root, [str(project.root / ".contextcloud"), str(outside)])
    assert str(project.root / ".contextcloud") in found.binds and str(outside) not in found.binds


# ------------------------------------------------------------------------------------------------ the information point
def test_an_index_in_the_project_is_trusted_where_the_sandbox_confines_the_agent(project):
    point = project.point()
    assert point.why == ""
    assert point.reach("pkg/caller.py", project.config(point)) == "none"


def test_a_forged_index_that_claims_no_reach_reads_unknown_when_the_agent_could_have_written_it(project, monkeypatch):
    monkeypatch.setattr(sandbox_hook, "supported", lambda: False)       # a host with no per call sandbox: the file's mode decides
    point = project.point()
    assert "can write" in point.why
    for rel in ("pkg/caller.py", "pkg/secure.py"):
        assert point.reach(rel, project.config(point)) == "unknown"
    assert zones.status(project.home, b"x", project.root) is not None


def test_the_same_index_made_read_only_is_trusted_without_a_sandbox(project, monkeypatch):
    monkeypatch.setattr(sandbox_hook, "supported", lambda: False)
    project.index.chmod(0o444)
    (project.root / ".contextcloud").chmod(0o555)
    point = project.point()
    assert point.why == ""
    assert point.reach("pkg/caller.py", project.config(point)) == "none"


def test_a_writable_sibling_or_directory_alone_makes_the_index_untrusted(project, monkeypatch):
    monkeypatch.setattr(sandbox_hook, "supported", lambda: False)
    project.index.chmod(0o444)
    assert project.point().why                                          # the directory is still writable
    (project.root / ".contextcloud").chmod(0o555)
    assert project.point().why == ""
    (project.root / ".contextcloud").chmod(0o755)
    (project.root / ".contextcloud" / "index.sqlite-wal").write_text("")
    (project.root / ".contextcloud").chmod(0o555)
    assert project.point().why                                          # a writable -wal file


def _outside(project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "index.sqlite"
    target.write_bytes(project.index.read_bytes())
    return outside, target


def test_an_index_outside_the_project_is_trusted_under_the_sandbox_and_not_when_the_profile_writes_the_host(project, tmp_path):
    outside, target = _outside(project, tmp_path)
    point = project.point(index=target)
    assert point.why == "" and point.reach("pkg/caller.py", project.config(point)) == "none"
    doc = zones.zone_document(["pkg.secure.check"], project.root, target, b"image")
    writes_host = zones.ContextCloudZones(doc, project.home, str(project.exe), host_write=True)
    assert "can write" in writes_host.why and writes_host.reach("pkg/caller.py", project.config(writes_host)) == "unknown"
    target.chmod(0o444)
    outside.chmod(0o555)
    read_only = zones.ContextCloudZones(doc, project.home, str(project.exe), host_write=True)
    assert read_only.why == "" and read_only.reach("pkg/caller.py", project.config(read_only)) == "none"


def test_an_index_outside_the_project_is_untrusted_without_a_sandbox_unless_read_only(project, tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox_hook, "supported", lambda: False)
    outside, target = _outside(project, tmp_path)
    assert "can write" in project.point(index=target).why
    target.chmod(0o444)
    outside.chmod(0o555)
    assert project.point(index=target).why == ""


def test_an_index_directly_in_the_project_root_needs_no_write_permission(project):
    root_index = project.root / "index.sqlite"
    root_index.write_bytes(project.index.read_bytes())
    assert "can write" in project.point(index=root_index).why          # the sandbox cannot protect the root directory
    root_index.chmod(0o444)
    project.root.chmod(0o555)
    try:
        assert project.point(index=root_index).why == ""
    finally:
        project.root.chmod(0o755)


def test_the_information_point_passes_the_profile_to_the_adapter(project, monkeypatch):
    class Profile:
        host_write = True
    monkeypatch.setattr(sandbox_hook, "profile_for", lambda home, image: Profile())
    assert zones._host_write(project.home, b"image") is True
    monkeypatch.setattr(sandbox_hook, "profile_for", lambda home, image: (_ for _ in ()).throw(ValueError("x")))
    assert zones._host_write(project.home, b"image") is True


def test_an_index_path_that_goes_through_a_link_is_not_trusted(project, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "index.sqlite").write_bytes(project.index.read_bytes())
    (real / "index.sqlite").chmod(0o444)
    real.chmod(0o555)
    try:
        link = tmp_path / "link"
        link.symlink_to(real)
        doc = zones.zone_document(["pkg.secure.check"], project.root, real / "index.sqlite", b"image")
        doc["index"] = str(link / "index.sqlite")                        # the signed document names a path through a link
        point = zones.ContextCloudZones(doc, project.home, str(project.exe))
        assert "link" in point.why and point.reach("pkg/caller.py", project.config(point)) == "unknown"
    finally:
        real.chmod(0o755)
