# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath agent doctor`: a fresh init reports all ok, and each failure mode is produced and reported with
its fix line. Every process and every in-process call uses a throwaway HOME with XDG_CONFIG_HOME and APPDATA
removed and a throwaway project, never the real configuration or a real project."""
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands, doctor  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
SLOW = 10_000      # a budget no loaded machine exceeds, so the all-ok tests do not depend on the machine's speed


def _env(home: Path):
    env = {k: v for k, v in os.environ.items() if k not in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR")}
    env.update(HOME=str(home), USERPROFILE=str(home), PYTHONPATH=str(REPO))
    return env


def _cli(home, *args):
    return subprocess.run([sys.executable, "-m", "prismpath", *args], capture_output=True, env=_env(home),
                          cwd=str(home), timeout=180)


@pytest.fixture()
def setup(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    (project / "README.md").write_text("# demo\n")
    for name in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    done = _cli(home, "agent", "init", "--project", str(project), "--yes")
    assert done.returncode == 0, done.stderr
    return {"home": home, "project": project, "agent": home / ".config" / "prismpath" / "agent",
            "settings": project / ".claude" / "settings.json"}


def _report(setup, **kw):
    return doctor.diagnose(setup["project"], kw.pop("budget_ms", SLOW), **kw)


def _by(report):
    return {row["check"]: row for row in report["checks"]}


def _only_problem(report, check, status):
    rows = _by(report)
    assert rows[check]["status"] == status, rows[check]
    assert [c for c, r in rows.items() if r["status"] != "ok"] == [check], {c: r["status"] for c, r in rows.items()}
    assert rows[check]["fix"]
    return rows[check]


def _edit_settings(setup, change):
    data = json.loads(setup["settings"].read_text())
    change(data)
    setup["settings"].write_text(json.dumps(data))


def _hook_command(data, event="PreToolUse"):
    return data["hooks"][event][0]["hooks"][0]


def test_a_fresh_init_reports_everything_ok(setup):
    report = _report(setup)
    assert report["ok"] and report["counts"] == {"ok": len(report["checks"]), "warn": 0, "fail": 0}
    assert set(_by(report)) == {"config-dir", "key-files", "authority-key", "instance-key", "policy", "hook-PreToolUse",
                                "hook-SessionEnd", "hook-dry-run", "runs", "disk"}
    assert all(r["fix"] is None for r in report["checks"])


@pytest.mark.parametrize("starter", ["strict", "default", "review"])
def test_every_starter_is_current_and_the_dry_run_read_is_allowed_under_it(setup, starter):
    done = _cli(setup["home"], "agent", "init", "--project", str(setup["project"]), "--yes", "--policy", starter)
    assert done.returncode == 0, done.stderr
    report = _report(setup)
    rows = _by(report)
    assert report["ok"] and all(r["status"] == "ok" for r in rows.values()), {c: r["status"] for c, r in rows.items()}
    from prismpath.agent.policy import STARTERS
    assert rows["policy"]["starter"] == starter and f"the {starter} starter ({STARTERS[starter]})" in rows["policy"]["detail"]
    assert "answered allow" in rows["hook-dry-run"]["detail"]


def test_doctor_changes_nothing(setup):
    def snapshot():
        out = {}
        for root in (setup["agent"], setup["project"]):
            for p in sorted(root.rglob("*")):
                out[str(p)] = (p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None)
        return out
    before = snapshot()
    _report(setup)
    assert snapshot() == before


def test_the_cli_exits_0_when_nothing_fails_and_prints_a_line_per_check(setup):
    done = _cli(setup["home"], "agent", "doctor", "--project", str(setup["project"]))
    text = done.stdout.decode()
    # the budget is the real 150 ms here, so the dry run may warn on a slow machine, which still exits 0
    assert done.returncode == 0, text + done.stderr.decode()
    assert text.count("\n") == 11 and "0 fail" in text
    assert "budget" in text and "150 ms" in text


@pytest.mark.parametrize("path,wanted", [("agent", "chmod 700"), ("authority.key", "chmod 600"), ("instance.pub", "chmod 600")])
def test_loose_modes_fail_with_the_chmod(setup, path, wanted):
    target = setup["agent"] if path == "agent" else setup["agent"] / path
    os.chmod(target, 0o755 if path == "agent" else 0o644)
    row = _only_problem(_report(setup), "config-dir" if path == "agent" else "key-files", "fail")
    assert wanted in row["fix"] and str(target) in row["fix"]


def test_a_key_pair_that_does_not_match_fails(setup):
    other = setup["home"] / "other"
    other.mkdir()
    done = _cli(setup["home"], "swap", "keygen", "--out", str(other), "--name", "authority")
    pub = other / "authority.pub"
    if not pub.exists():
        pytest.skip("swap keygen has another shape")
    (setup["agent"] / "authority.pub").write_bytes(pub.read_bytes())
    rows = _by(_report(setup))
    assert rows["authority-key"]["status"] == "fail" and "does not match" in rows["authority-key"]["detail"]
    assert "prismpath agent init" in rows["authority-key"]["fix"]
    assert rows["instance-key"]["status"] == "ok"


def test_an_instance_key_that_does_not_match_fails(setup):
    from prismpath.ledgers import root_statement
    other = setup["home"] / "other"
    other.mkdir()
    root_statement.keygen(str(other), "instance")
    (setup["agent"] / "instance.pub").write_bytes((other / "instance.pub").read_bytes())
    rows = _by(_report(setup))
    assert rows["instance-key"]["status"] == "fail" and rows["instance-key"]["fix"]
    assert rows["authority-key"]["status"] == "ok"


def test_an_edited_attestation_fails(setup):
    path = setup["agent"] / commands.ATTESTATION_FILE
    path.write_bytes(path.read_bytes().replace(b'"sig":"', b'"sig":"00', 1))
    rows = _by(_report(setup))
    row = rows["policy"]
    assert row["status"] == "fail" and "attestation" in row["detail"] and row["fix"] == "prismpath agent init"
    assert rows["hook-dry-run"]["status"] == "fail"     # the hook itself would deny every call


def test_an_older_shipped_image_warns_and_names_it(setup):
    # record an attested policy that is not the shipped one, with the older image's hash as its name
    from prismpath.agent import doctor as d
    image = (setup["agent"] / commands.POLICY_FILE).read_bytes() + b"\n"
    (setup["agent"] / commands.POLICY_FILE).write_bytes(image)
    (setup["agent"] / commands.ATTESTATION_FILE).write_bytes(commands._attestation(setup["agent"], image))
    row = _only_problem(_report(setup), "policy", "warn")
    assert "is custom" in row["detail"] and row["starter"] == "custom"
    older = commands._sha256_hex(image)[:16]
    d.OLDER_IMAGES[older] = ("review", "the test's older image")
    try:
        row = _only_problem(_report(setup), "policy", "warn")
    finally:
        del d.OLDER_IMAGES[older]
    assert "older shipped image, the test's older image" in row["detail"]
    assert "current review starter (agent_review)" in row["detail"] and row["fix"] == "prismpath agent init --policy review"


def test_a_missing_hook_entry_fails_naming_the_event(setup):
    _edit_settings(setup, lambda d: d["hooks"].pop("SessionEnd"))
    rows = _by(_report(setup))
    assert rows["hook-SessionEnd"]["status"] == "fail" and "no PrismPath SessionEnd entry" in rows["hook-SessionEnd"]["detail"]
    assert "prismpath agent init --project" in rows["hook-SessionEnd"]["fix"] and "--yes" in rows["hook-SessionEnd"]["fix"]
    assert rows["hook-PreToolUse"]["status"] == "ok"


def test_a_missing_settings_file_fails_both_events(setup):
    setup["settings"].unlink()
    rows = _by(_report(setup))
    assert rows["hook-PreToolUse"]["status"] == rows["hook-SessionEnd"]["status"] == "fail"


@pytest.mark.skipif(os.name == "nt", reason="the hook command is a POSIX shell line")
def test_a_hook_command_without_exit_2_fails(setup):
    def strip(data):
        hook = _hook_command(data)
        hook["command"] = hook["command"].replace(" || exit 2", "")
    _edit_settings(setup, strip)
    rows = _by(_report(setup))
    assert rows["hook-PreToolUse"]["status"] == "fail" and "|| exit 2" in rows["hook-PreToolUse"]["detail"]
    assert "agent init" in rows["hook-PreToolUse"]["fix"]
    assert rows["hook-SessionEnd"]["status"] == "ok"


@pytest.mark.skipif(os.name == "nt", reason="the hook command is a POSIX shell line")
def test_an_interpreter_that_does_not_exist_fails_and_the_dry_run_is_not_run(setup):
    def point(data):
        for event in doctor.EVENTS:
            hook = data["hooks"][event][0]["hooks"][0]
            hook["command"] = hook["command"].replace(sys.executable, "/nonexistent/python")
    _edit_settings(setup, point)
    rows = _by(_report(setup))
    assert rows["hook-PreToolUse"]["status"] == "fail" and "/nonexistent/python" in rows["hook-PreToolUse"]["detail"]
    assert rows["hook-dry-run"]["status"] == "fail" and "not run" in rows["hook-dry-run"]["detail"]


@pytest.mark.skipif(os.name == "nt", reason="the hook command is a POSIX shell line")
def test_an_interpreter_that_cannot_import_prismpath_fails(setup, tmp_path):
    broken = tmp_path / "python"
    broken.write_text("#!/bin/sh\necho 'ModuleNotFoundError: No module named prismpath' >&2\nexit 1\n")
    broken.chmod(0o755)

    def point(data):
        hook = _hook_command(data)
        hook["command"] = hook["command"].replace(sys.executable, str(broken))
    _edit_settings(setup, point)
    row = _by(_report(setup))["hook-PreToolUse"]
    assert row["status"] == "fail" and "cannot import prismpath" in row["detail"]


def test_the_dry_run_over_budget_warns_and_shows_the_budget(setup):
    report = _report(setup, budget_ms=0.001)
    row = _only_problem(report, "hook-dry-run", "warn")
    assert "0.001 ms budget" in row["detail"] and row["budget_ms"] == 0.001 and row["elapsed_ms"] > 0.001
    assert report["ok"] is True            # a warning is not a failure
    ok = _by(_report(setup))["hook-dry-run"]
    assert "budget 10000 ms" in ok["detail"] and ok["elapsed_ms"] < SLOW


def _make_run(setup, session="s1"):
    raw = json.dumps({"session_id": session, "cwd": str(setup["project"]), "hook_event_name": "PreToolUse",
                      "tool_name": "Read", "tool_input": {"file_path": str(setup["project"] / "README.md")}}).encode()
    done = subprocess.run([sys.executable, "-m", "prismpath", "agent", "hook"], input=raw, capture_output=True,
                          env=_env(setup["home"]), cwd=str(setup["project"]))
    assert json.loads(done.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"
    return setup["agent"] / commands.RUNS_DIR / session


def test_an_open_run_older_than_a_day_warns_and_a_fresh_one_does_not(setup):
    run = _make_run(setup)
    rows = _by(_report(setup))
    assert rows["runs"]["status"] == "ok" and "1 still open" in rows["runs"]["detail"]
    row = _only_problem(_report(setup, now=time.time() + 3 * 86400), "runs", "warn")
    assert "open for more than a day" in row["detail"] and "s1" in row["detail"] and row["fix"] == "prismpath agent verify"
    assert not (run / "run.json").exists()          # the doctor did not seal it


def test_a_sealed_run_verifies_and_a_tampered_one_fails(setup):
    run = _make_run(setup)
    assert _cli(setup["home"], "agent", "verify").returncode == 0
    assert _by(_report(setup))["runs"]["status"] == "ok"
    target = run / "receipts.jsonl"
    data = bytearray(target.read_bytes())
    data[len(data) // 2] ^= 1
    target.write_bytes(bytes(data))
    row = _only_problem(_report(setup), "runs", "fail")
    assert "s1" in row["detail"] and row["fix"] == "prismpath agent verify"
    assert bytes(data) == target.read_bytes()       # still as tampered: nothing was repaired


def test_a_tampered_open_run_fails(setup):
    run = _make_run(setup)
    journal = run / "journal.jsonl"
    journal.write_bytes(journal.read_bytes().replace(b'"receipt"', b'"recei9t"', 1))
    _only_problem(_report(setup), "runs", "fail")


def test_low_disk_warns(setup, monkeypatch):
    import shutil
    from collections import namedtuple
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda p: usage(100 << 30, 99 << 30, 1 << 29))
    row = _only_problem(_report(setup), "disk", "warn")
    assert "under 1 GiB" in row["detail"]


def test_no_configuration_fails_with_the_init_command(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    for name in ("XDG_CONFIG_HOME", "APPDATA"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(home))
    report = doctor.diagnose(project, SLOW)
    rows = _by(report)
    assert report["ok"] is False and rows["config-dir"]["fix"] == "prismpath agent init"
    assert not (home / ".config").exists()          # reporting created nothing


def test_json_shape(setup):
    done = _cli(setup["home"], "agent", "doctor", "--project", str(setup["project"]), "--json")
    report = json.loads(done.stdout)
    assert set(report) == {"config_dir", "project", "budget_ms", "ok", "counts", "checks"}
    assert report["budget_ms"] == 150 and report["project"] == str(setup["project"])
    for row in report["checks"]:
        assert {"check", "status", "detail", "fix"} <= set(row) and row["status"] in ("ok", "warn", "fail")
    assert done.returncode == (0 if report["ok"] else 1)
    os.chmod(setup["agent"] / "authority.key", 0o644)
    failed = _cli(setup["home"], "agent", "doctor", "--project", str(setup["project"]), "--json")
    assert failed.returncode == 1 and json.loads(failed.stdout)["ok"] is False


def test_the_text_output_puts_the_fix_under_each_problem(setup):
    os.chmod(setup["agent"] / "instance.key", 0o640)
    out = io.StringIO()
    assert doctor.doctor(setup["project"], False, SLOW, out=out) == 1
    text = out.getvalue()
    assert "FAIL  key-files:" in text and f"      fix: chmod 600 {setup['agent'] / 'instance.key'}" in text
