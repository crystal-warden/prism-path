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
        self.bin = tmp_path / "ccbin"
        self.bin.mkdir()
        self.exe = self.bin / "contextcloud"
        self.exe.write_text(f"#!{sys.executable}\nprint('{{\"certainty\": \"no\"}}')\n")
        self.exe.chmod(0o555)
        self.pkg = self.bin / "ccpkg"
        self.pkg.mkdir()
        self.pkg.chmod(0o555)
        self.bin.chmod(0o555)

    def doc(self, index=None, image=b"image", exe=None, package=None):
        """A zone document that records the program and its package, as `zones set` does."""
        record = {"path": os.path.realpath(exe or self.exe), "package": str(package or self.pkg)}
        return zones.zone_document(["pkg.secure.check"], self.root, index or self.index, image, program=record)

    def point(self, image=b"image", index=None):
        return zones.ContextCloudZones(self.doc(index, image), self.home, str(self.exe), budget_s=5.0)

    def config(self, point):
        return classifier.Config.for_workspace(self.root, zones=point)


@pytest.fixture()
def project(tmp_path):
    made = Project(tmp_path)
    yield made
    for path in (made.bin, made.pkg, made.root / ".contextcloud", made.index, tmp_path / "outside", tmp_path / "outside" / "index.sqlite"):
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
    assert project.point().control_paths == (str(project.root / ".contextcloud") + "/",)
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
@pytest.fixture()
def other_user(monkeypatch):
    """The agent runs as another user than the one that made the files, so only the modes decide."""
    monkeypatch.setattr(zones, "_agent_uid", lambda: os.getuid() + 1)


def _no_sandbox(monkeypatch):
    monkeypatch.setattr(sandbox_hook, "supported", lambda: False)


def test_an_index_in_a_direct_subdirectory_of_the_project_is_trusted_where_the_sandbox_confines_the_agent(project):
    point = project.point()
    assert point.why == ""
    assert point.reach("pkg/caller.py", project.config(point)) == "none"


def test_a_forged_index_that_claims_no_reach_reads_unknown_when_the_agent_could_have_written_it(project, monkeypatch):
    _no_sandbox(monkeypatch)                                           # no per call sandbox: only the file's owner and mode decide
    point = project.point()
    assert "owns or can write" in point.why
    for rel in ("pkg/caller.py", "pkg/secure.py"):
        assert point.reach(rel, project.config(point)) == "unknown"


def test_an_index_the_agents_user_owns_is_untrusted_even_when_read_only(project, monkeypatch):
    _no_sandbox(monkeypatch)
    project.index.chmod(0o444)
    (project.root / ".contextcloud").chmod(0o555)                      # the owner can chmod it back
    point = project.point()
    assert "owns or can write" in point.why and point.reach("pkg/caller.py", project.config(point)) == "unknown"


def test_the_same_index_owned_by_another_user_and_read_only_is_trusted_without_a_sandbox(project, monkeypatch, other_user):
    _no_sandbox(monkeypatch)
    project.index.chmod(0o444)
    (project.root / ".contextcloud").chmod(0o555)
    point = project.point()
    assert point.why == ""
    assert point.reach("pkg/caller.py", project.config(point)) == "none"


def test_a_writable_sibling_or_directory_alone_makes_the_index_untrusted(project, monkeypatch, other_user):
    _no_sandbox(monkeypatch)
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


def test_an_index_outside_the_project_is_trusted_under_the_sandbox_and_not_when_the_profile_writes_the_host(project, tmp_path, other_user):
    outside, target = _outside(project, tmp_path)
    point = project.point(index=target)
    assert point.why == "" and point.reach("pkg/caller.py", project.config(point)) == "none"
    doc = project.doc(target)
    writes_host = zones.ContextCloudZones(doc, project.home, str(project.exe), host_write=True)
    assert "owns or can write" in writes_host.why and writes_host.reach("pkg/caller.py", project.config(writes_host)) == "unknown"
    target.chmod(0o444)
    outside.chmod(0o555)
    read_only = zones.ContextCloudZones(doc, project.home, str(project.exe), host_write=True)
    assert read_only.why == "" and read_only.reach("pkg/caller.py", project.config(read_only)) == "none"


def test_an_index_outside_the_project_is_untrusted_without_a_sandbox_unless_read_only(project, tmp_path, monkeypatch, other_user):
    _no_sandbox(monkeypatch)
    outside, target = _outside(project, tmp_path)
    assert "owns or can write" in project.point(index=target).why
    target.chmod(0o444)
    outside.chmod(0o555)
    assert project.point(index=target).why == ""


def test_an_index_directly_in_the_project_root_is_trusted_by_permissions_only(project, other_user):
    root_index = project.root / "index.sqlite"
    root_index.write_bytes(project.index.read_bytes())
    assert "owns or can write" in project.point(index=root_index).why     # the sandbox cannot protect the root directory
    root_index.chmod(0o444)
    project.root.chmod(0o555)
    try:
        assert project.point(index=root_index).why == ""
    finally:
        project.root.chmod(0o755)


def test_an_index_path_that_goes_through_a_link_is_not_trusted(project, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "index.sqlite").write_bytes(project.index.read_bytes())
    link = tmp_path / "link"
    link.symlink_to(real)
    doc = project.doc(real / "index.sqlite")
    doc["index"] = str(link / "index.sqlite")                        # the signed document names a path through a link
    point = zones.ContextCloudZones(doc, project.home, str(project.exe))
    assert "link" in point.why and point.reach("pkg/caller.py", project.config(point)) == "unknown"


# ------------------------------------------------------------------------------------------------ the review's seven fixes
def _signed_world(project, tmp_path):
    from prismpath.agent import commands
    from prismpath.agent.policy import starter_path as sp
    home = tmp_path / "config"
    home.mkdir(mode=0o700)
    for role in commands.KEY_ROLES:
        commands._ensure_key(home, role)
    image = sp("default").read_bytes().rstrip(b"\n")
    zones.sign(home, zones.zone_document(["pkg.secure.check"], project.root, None, image, program={"path": str(project.exe), "package": str(project.pkg)}))
    return home, image


def test_1_an_unusable_point_keeps_the_control_paths_of_the_signed_document(project, tmp_path):
    home, image = _signed_world(project, tmp_path)
    no_program = zones.information_point(home, image, project.root, {"PATH": ""})
    assert no_program.answer == "unknown" and no_program.control_paths == (str(project.root / ".contextcloud") + "/",)
    project.index.unlink()
    no_index = zones.information_point(home, image, project.root, {"CONTEXTCLOUD": str(project.exe)})
    assert no_index.answer == "unknown" and no_index.control_paths == (str(project.root / ".contextcloud") + "/",)
    reading = classifier.classify({"tool": "write_file", "args": {"path": ".contextcloud/index.sqlite", "content": "x"}},
                                  project.config(no_index))
    assert reading["path_control"] is True


def test_1_a_missing_index_directory_is_made_empty_to_be_bound_and_removed_after(project):
    (project.root / ".contextcloud" / "index.sqlite").unlink()
    (project.root / ".contextcloud").rmdir()
    made = controls.Controls()
    found = controls.prepare(project.root, made, directory=project.home / "markers", extra=[str(project.root / ".contextcloud") + "/"])
    assert str(project.root / ".contextcloud") in found.binds and (project.root / ".contextcloud").is_dir()
    made.remove_created()
    assert not (project.root / ".contextcloud").exists()


@pytest.mark.parametrize("backend,mark", [("bwrap", needs_bwrap), ("landlock", needs_landlock)])
def test_1_a_script_cannot_create_the_missing_index_directory(project, backend, mark):
    if mark.args[0]:
        pytest.skip(mark.kwargs["reason"])
    (project.root / ".contextcloud" / "index.sqlite").unlink()
    (project.root / ".contextcloud").rmdir()
    paths = (str(project.root / ".contextcloud") + "/",)
    attack = "mkdir .contextcloud; echo forged > .contextcloud/index.sqlite; true"
    if backend == "bwrap":
        sandbox_exec.run_backend("bwrap", attack, project.root, Profile(timeout_s=60), stdin=b"", mount=str(project.root), control_paths=paths)
    else:
        sandbox_exec.run_landlock(attack, project.root, Profile(timeout_s=60), stdin=b"", control_paths=paths)
    assert not (project.root / ".contextcloud" / "index.sqlite").exists()


def test_2_a_deeper_index_directory_is_not_trusted_by_the_sandbox(project, monkeypatch, other_user):
    deep = project.root / "a" / "b" / ".cc"
    deep.mkdir(parents=True)
    (deep / "index.sqlite").write_bytes(project.index.read_bytes())
    point = project.point(index=deep / "index.sqlite")
    assert "owns or can write" in point.why                            # the parent a/b can be renamed under bwrap
    assert point.reach("pkg/caller.py", project.config(point)) == "unknown"


@pytest.mark.skipif(not _bwrap_ok(), reason="bwrap cannot start here")
def test_2_under_bwrap_a_nested_directory_can_be_swapped_which_is_why_it_is_not_trusted(project):
    deep = project.root / "a" / "b" / ".cc"
    deep.mkdir(parents=True)
    (deep / "index.sqlite").write_text("real")
    sandbox_exec.run_backend("bwrap", "mv a/b a/b2; mkdir -p a/b/.cc; echo forged > a/b/.cc/index.sqlite; true", project.root,
                             Profile(timeout_s=60), stdin=b"", mount=str(project.root), control_paths=(str(deep) + "/",))
    assert (project.root / "a" / "b" / ".cc" / "index.sqlite").read_text().strip() == "forged"


def test_3_an_index_with_another_hard_link_is_untrusted(project):
    os.link(project.index, project.root / "pkg" / "alias.sqlite")
    point = project.point()
    assert "one link" in point.why and point.reach("pkg/caller.py", project.config(point)) == "unknown"


def test_3_an_existing_wal_with_another_hard_link_is_untrusted(project):
    (project.root / ".contextcloud" / "index.sqlite-wal").write_text("")
    os.link(project.root / ".contextcloud" / "index.sqlite-wal", project.root / "pkg" / "w")
    assert "one link" in project.point().why


def test_4_under_host_write_an_inner_directory_is_not_trusted_and_the_cache_is_not_read(project, other_user):
    doc = project.doc()
    point = zones.ContextCloudZones(doc, project.home, str(project.exe), host_write=True)
    assert "owns or can write" in point.why and point.reach("pkg/caller.py", project.config(point)) == "unknown"
    trusted = zones.ContextCloudZones(doc, project.home, str(project.exe))
    assert trusted.reach("pkg/caller.py", project.config(trusted)) == "none"        # filled the cache
    assert any(project.home.glob(zones.CACHE_FILE))
    trusted_ro = zones.ContextCloudZones(doc, project.home, str(project.exe), host_write=True)
    trusted_ro.why = ""                                                              # as if the index were read only
    calls = []
    trusted_ro._run = lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(OSError("asked"))
    assert trusted_ro.reach("pkg/caller.py", project.config(trusted_ro)) == "unknown" and calls   # asked, not the cache


def test_5_the_owner_of_a_read_only_index_is_not_trusted_but_another_owner_is(project, monkeypatch):
    _no_sandbox(monkeypatch)
    project.index.chmod(0o444)
    (project.root / ".contextcloud").chmod(0o555)
    assert "owns or can write" in project.point().why
    monkeypatch.setattr(zones, "_agent_uid", lambda: os.getuid() + 1)
    assert project.point().why == ""


def test_6_a_program_inside_the_project_is_never_trusted_and_runs_outside_the_workspace(project, tmp_path):
    inside = project.root / "venv-cc"
    inside.write_text(project.exe.read_text())
    inside.chmod(0o755)
    doc = project.doc(exe=inside)
    point = zones.ContextCloudZones(doc, project.home, str(inside))
    assert "inside the project" in point.why and point.reach("pkg/caller.py", project.config(point)) == "unknown"
    link = tmp_path / "linked-cc"
    link.symlink_to(inside)
    assert "inside the project" in zones.ContextCloudZones(doc, project.home, str(link)).why      # the real path is tested
    seen = {}
    good = zones.ContextCloudZones(project.doc(), project.home, str(project.exe))

    def run(command, **kwargs):
        seen.update(kwargs)
        raise OSError("stop")
    good._run = run
    good.reach("pkg/caller.py", project.config(good))
    assert seen["cwd"] == str(project.home)


def test_6_a_program_outside_is_untrusted_without_a_sandbox_when_its_directory_is_writable(project, monkeypatch, other_user):
    _no_sandbox(monkeypatch)
    project.index.chmod(0o444)
    (project.root / ".contextcloud").chmod(0o555)
    assert project.point().why == ""
    project.bin.chmod(0o755)
    point = project.point()
    assert "part of the Context Cloud program" in point.why and point.reach("pkg/caller.py", project.config(point)) == "unknown"


def test_7_zones_set_deletes_and_rebuilds_an_existing_index_after_signing(project, tmp_path, monkeypatch):
    home, image = _signed_world(project, tmp_path)
    order = []
    rebuilt = tmp_path / "rebuilt"
    exe = tmp_path / "cc-index"
    exe.write_text(f"#!{sys.executable}\nimport sys\nopen({str(rebuilt)!r}, 'w').write(' '.join(sys.argv[1:]))\nopen(sys.argv[sys.argv.index('--index') + 1], 'w').write('new')\n")
    exe.chmod(0o755)
    (project.root / ".contextcloud" / "index.sqlite-wal").write_text("forged")
    doc = zones.zone_document(["pkg.secure.check"], project.root, None, image, program={"path": str(project.exe), "package": str(project.pkg)})
    zones.rebuild_index_after_signing(home, doc, lambda: order.append("signed"), {"CONTEXTCLOUD": str(exe)})
    assert order == ["signed"] and project.index.read_text() == "new"
    assert not (project.root / ".contextcloud" / "index.sqlite-wal").exists()
    assert "index" in rebuilt.read_text() and "--index" in rebuilt.read_text()


def test_7_zones_set_refuses_an_existing_index_it_cannot_rebuild_and_records_nothing(project, tmp_path):
    home, image = _signed_world(project, tmp_path)
    doc = zones.zone_document(["pkg.secure.check"], project.root, None, image, program={"path": str(project.exe), "package": str(project.pkg)})
    recorded = []
    with pytest.raises(zones.ZoneError, match="cannot be trusted"):
        zones.rebuild_index_after_signing(home, doc, lambda: recorded.append(1), {"PATH": ""})
    assert recorded == [] and project.index.exists()
    project.index.unlink()
    zones.rebuild_index_after_signing(home, doc, lambda: recorded.append(1), {"PATH": ""})   # nothing to rebuild
    assert recorded == [1]


# ------------------------------------------------------------------------------------------------ the second review
def test_the_cache_follows_the_index_rule_so_a_planted_entry_is_not_used_without_a_sandbox(project, monkeypatch, other_user):
    point = project.point()
    assert point.reach("pkg/caller.py", project.config(point)) == "none"           # confined: asked, then cached
    assert (project.home / zones.CACHE_FILE).exists()
    _no_sandbox(monkeypatch)
    project.index.chmod(0o444)
    (project.root / ".contextcloud").chmod(0o555)
    unconfined = project.point()
    assert unconfined.why == "" and not unconfined._confined()                      # trusted by owner and mode, not by the sandbox
    calls = []
    unconfined._run = lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(OSError("asked"))
    assert unconfined.reach("pkg/caller.py", project.config(unconfined)) == "unknown" and calls    # the cache entry was not used
    (project.home / zones.CACHE_FILE).unlink()
    unconfined._run = lambda *a, **k: type("R", (), {"returncode": 0, "stdout": '{"certainty": "no"}'})()
    assert unconfined.reach("pkg/caller.py", project.config(unconfined)) == "none"
    assert not (project.home / zones.CACHE_FILE).exists()                           # and none was written


def test_a_package_inside_the_project_reads_unknown(project):
    inside = project.root / "vendor" / "contextcloud"
    inside.mkdir(parents=True)
    point = zones.ContextCloudZones(project.doc(package=inside), project.home, str(project.exe))
    assert "package" in point.why and "inside the project" in point.why
    assert point.reach("pkg/caller.py", project.config(point)) == "unknown"


def test_recorded_paths_that_no_longer_match_the_program_read_unknown(project, tmp_path):
    other = tmp_path / "other-cc"
    other.write_text(project.exe.read_text())
    other.chmod(0o755)
    point = zones.ContextCloudZones(project.doc(), project.home, str(other))
    assert "not the" in point.why and point.reach("pkg/caller.py", project.config(point)) == "unknown"


def test_a_zone_document_without_the_program_reads_unknown(project):
    doc = project.doc()
    del doc["program"]
    point = zones.ContextCloudZones(doc, project.home, str(project.exe))
    assert "does not record" in point.why and point.reach("pkg/caller.py", project.config(point)) == "unknown"
    doc["program"] = {"path": 3}
    assert zones.ContextCloudZones(doc, project.home, str(project.exe)).why


def test_a_package_of_a_host_without_a_sandbox_is_tested_by_owner_and_mode(project, monkeypatch, other_user):
    _no_sandbox(monkeypatch)
    project.index.chmod(0o444)
    (project.root / ".contextcloud").chmod(0o555)
    assert project.point().why == ""
    project.pkg.chmod(0o755)
    assert "part of the Context Cloud program" in project.point().why


def test_zones_set_finds_the_program_and_package_with_the_programs_own_interpreter(tmp_path):
    exe = tmp_path / "venv" / "bin" / "contextcloud"
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/opt/venv/bin/python3\n")
    seen = {}

    def run(command, **kwargs):
        seen.update(command=command, **kwargs)
        return type("R", (), {"returncode": 0, "stdout": str(tmp_path / "site" / "contextcloud") + "\n", "stderr": ""})()
    home = tmp_path / "config"
    home.mkdir()
    found = zones.find_program(str(exe), home, run=run)
    assert found == {"path": str(exe), "package": str(tmp_path / "site" / "contextcloud")}
    assert seen["command"][:2] == ["/opt/venv/bin/python3", "-I"] and seen["cwd"] == str(home)
    exe.write_text("#!/usr/bin/env python3\n")                      # no shebang interpreter: the python beside the program
    (exe.parent / "python").write_text("")
    (exe.parent / "python").chmod(0o755)
    zones.find_program(str(exe), home, run=run)
    assert seen["command"][0] == str(exe.parent / "python")
    with pytest.raises(zones.ZoneError):
        zones.find_program(str(exe), home, run=lambda *a, **k: type("R", (), {"returncode": 1, "stdout": "", "stderr": "no module"})())


def test_status_says_what_is_checked(project, tmp_path):
    home, image = _signed_world(project, tmp_path)
    report = zones.status(home, image, project.root, {"CONTEXTCLOUD": str(project.exe)})
    assert report["point"] == "contextcloud" and report["checked"]["program"] == {"path": str(project.exe), "package": str(project.pkg)}
    assert report["checked"]["confined"] is True and report["checked"]["index"] == str(project.index)
    zones.sign(home, zones.zone_document(["pkg.secure.check"], project.root, None, image))      # no program recorded
    bare = zones.status(home, image, project.root, {"CONTEXTCLOUD": str(project.exe)})
    assert bare["point"] == "unknown" and "does not record" in bare["detail"]


def test_the_program_that_runs_is_the_real_path_that_was_tested(project, tmp_path):
    link = tmp_path / "cc-link"
    link.symlink_to(project.exe)
    point = zones.ContextCloudZones(project.doc(), project.home, str(link))
    seen = []
    point._run = lambda command, **k: seen.append(command) or type("R", (), {"returncode": 0, "stdout": '{"certainty": "no"}'})()
    assert point.reach("pkg/caller.py", project.config(point)) == "none"
    assert seen and seen[0][:3] == [sys.executable, "-I", os.path.realpath(project.exe)]     # its own interpreter, -I, the real path


# ------------------------------------------------------------------------------------------------ the third review
def _planting_program(project, tmp_path):
    """A program that imports `contextcloud` if it can, like the real one, and a planted package in the project that
    leaves a marker when imported."""
    marker = tmp_path / "marker"
    plant = project.root / "plant" / "contextcloud"
    plant.mkdir(parents=True)
    (plant / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('imported')\n")
    exe = project.bin / "contextcloud-imports"
    project.bin.chmod(0o755)
    exe.write_text(f"#!{sys.executable}\ntry:\n    import contextcloud\nexcept ImportError:\n    pass\nprint('{{\"certainty\": \"no\"}}')\n")
    exe.chmod(0o555)
    project.bin.chmod(0o555)
    return exe, marker, project.root / "plant"


def test_a_pythonpath_inside_the_project_never_reaches_the_program(project, tmp_path, monkeypatch):
    import subprocess
    exe, marker, plant = _planting_program(project, tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(plant))
    monkeypatch.setenv("PYTHONSTARTUP", str(plant / "contextcloud" / "__init__.py"))
    subprocess.run([sys.executable, str(exe)], capture_output=True, text=True)       # the plant works against an unscrubbed run
    assert marker.exists()
    marker.unlink()
    point = zones.ContextCloudZones(project.doc(exe=exe), project.home, str(exe))
    assert point.why == "" and point.reach("pkg/caller.py", project.config(point)) == "none"
    assert not marker.exists()                                                        # never imported
    env = zones.clean_env(project.home)
    assert not [k for k in env if k.startswith("PYTHON")] and env["PATH"] == "/usr/local/bin:/usr/bin:/bin"


def test_the_rebuild_and_the_package_lookup_run_in_the_clean_environment(project, tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", str(project.root))
    seen = {}

    def run(command, **kwargs):
        seen.update(kwargs)
        return type("R", (), {"returncode": 0, "stdout": str(project.pkg) + "\n", "stderr": ""})()
    zones.find_program(str(project.exe), project.home, run=run)
    assert "PYTHONPATH" not in seen["env"] and seen["env"] == zones.clean_env(project.home)
    doc = project.doc()
    (project.root / ".contextcloud" / "index.sqlite-wal").write_text("")
    rebuilt = []
    monkeypatch.setattr(zones.subprocess, "run", lambda command, **kw: rebuilt.append((command, kw)) or type("R", (), {"returncode": 0, "stderr": ""})())
    zones.rebuild_index_after_signing(project.home, doc, lambda: None, {"CONTEXTCLOUD": str(project.exe)})
    command, kwargs = rebuilt[0]
    assert kwargs["env"] == zones.clean_env(project.home) and command[:2] == [sys.executable, "-I"]


def test_zones_set_refuses_a_package_the_agents_user_could_change_where_nothing_confines_it(project, tmp_path, monkeypatch):
    package = tmp_path / "site" / "contextcloud"
    package.mkdir(parents=True)
    (package / "deep").mkdir()
    (package / "deep" / "x.py").write_text("")
    assert zones.package_tree_problem(str(package), project.root, confined=True) == ""         # the sandbox holds
    assert "owns or can write" in zones.package_tree_problem(str(package), project.root, confined=False)
    monkeypatch.setattr(zones, "_agent_uid", lambda: os.getuid() + 1)
    assert "owns or can write" in zones.package_tree_problem(str(package), project.root, confined=False)   # writable by mode
    for path in [package / "deep" / "x.py", package / "deep", package, package.parent]:
        path.chmod(0o555 if path.is_dir() else 0o444)
    try:
        assert zones.package_tree_problem(str(package), project.root, confined=False) == ""
        (package / "deep").chmod(0o755)                                                          # one writable directory deep down
        assert "deep" in zones.package_tree_problem(str(package), project.root, confined=False)
    finally:
        for path in [package.parent, package, package / "deep"]:
            path.chmod(0o755)
    assert "inside the project" in zones.package_tree_problem(str(project.root / "vendor"), project.root, confined=True)
