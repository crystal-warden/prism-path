# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath agent status` and `doctor` warn when the recorded policy does not refuse a change to the agent's own
control files (cause 128). An image attested before that rule shipped has no `path_control` field and keeps
allowing a write to `.claude/settings.json`. The check is the oracle's `control_refused` property evaluated through
the reference decision path, and the hook itself decides as before. The older starters are stored as fixtures, taken
from git history."""
import hashlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands, doctor  # noqa: E402
from prismpath.agent.policy import (OLDER_STARTERS, STARTERS, Policy, control_check, control_gap, older_date, older_starter_of,  # noqa: E402
                                    starter_of, starter_path)
from prismpath.kernel import canon2  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
OLD = sorted((Path(__file__).parent / "fixtures" / "agent_old_starters").glob("*.core.json"))
# the three recorded between the control-file rule and the connect rule (commit ccf2f60): they have path_control and
# refuse its changes, and bound classifier_version to 1
OLD_NET = [p for p in OLD if "ccf2f60" in p.name]
OLD_ZONE = [p for p in OLD if "2ae3627" in p.name]       # the three from before the zone rule (cause 132)
OLD_CONTROL = [p for p in OLD if "ccf2f60" not in p.name and "2ae3627" not in p.name]


def _image(path: Path) -> bytes:
    data = path.read_bytes()
    return data[:-1] if data.endswith(b"\n") else data


def _with_extra_rule(image: bytes) -> bytes:
    """A custom image: the same rules with one harmless rule appended, in its canonical bytes."""
    doc = canon2.loads(image)
    doc["rules"].append({"target": "refuse_104", "when": ["truthy", "kill_by_pattern"]})
    return canon2.dumps(doc)


def test_the_fixtures_are_the_ten_known_older_starters():
    assert len(OLD) == 10 and len(OLD_NET) == 3 and len(OLD_ZONE) == 3
    found = {hashlib.sha256(_image(p)).hexdigest()[:16]: p.name.split("-")[0] for p in OLD}
    assert found == {key: value[0] for key, value in OLDER_STARTERS.items()}
    for path in OLD:
        assert starter_of(_image(path)) is None and older_starter_of(_image(path)) is not None


@pytest.mark.parametrize("path", OLD_CONTROL, ids=lambda p: p.name)
def test_an_older_starter_fails_the_check_and_is_named(path):
    image = _image(path)
    assert "no path_control field" in control_gap(Policy(image))      # evaluated, not only looked up by hash
    result = control_check(image)
    name = older_starter_of(image)[0]
    assert result["refuses_control_changes"] is False
    assert result["policy"] == f"the {name} starter from before 2026-11-19"
    assert result["fix"] == f"prismpath agent init --policy {name}"
    assert "rewrite .claude/settings.json" in result["message"] and result["fix"] in result["message"]


@pytest.mark.parametrize("path", OLD_NET, ids=lambda p: p.name)
def test_a_starter_from_before_the_connect_rule_still_refuses_control_changes_and_is_named(path):
    image = _image(path)
    assert control_check(image) == {"refuses_control_changes": True}      # evaluated over every reading, not looked up
    name, what = older_starter_of(image)
    assert name == path.name.split("-")[0] and "before the connect rule (cause 130" in what
    assert older_date(image) == "2026-11-20"


@pytest.mark.parametrize("path", OLD_ZONE, ids=lambda p: p.name)
def test_a_starter_from_before_the_zone_rule_is_named_and_has_no_zone_field(path):
    image = _image(path)
    name, what = older_starter_of(image)
    assert name == path.name.split("-")[0] and "before the zone rule (cause 132" in what
    assert older_date(image) == "2026-11-21"
    assert "zone_reach" not in Policy(image).doc["fields"]
    assert control_check(image) == {"refuses_control_changes": True}


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_each_current_starter_refuses_every_control_change(name):
    assert control_gap(Policy.load(starter_path(name))) is None        # over every reading, nothing assumed
    assert control_check(_image(starter_path(name))) == {"refuses_control_changes": True}


def test_a_custom_image_that_refuses_control_changes_gives_no_warning():
    image = _with_extra_rule(_image(starter_path("default")))
    assert starter_of(image) is None and older_starter_of(image) is None
    assert control_check(image) == {"refuses_control_changes": True}


def test_a_custom_image_without_path_control_fails_outright():
    image = _with_extra_rule(_image(OLD_CONTROL[0]))
    result = control_check(image)
    assert result["refuses_control_changes"] is False and result["policy"] == "a custom policy"
    assert "no path_control field" in result["reason"] and "replaces its rules" in result["message"]


def test_a_custom_image_with_the_field_but_not_the_rule_names_the_reading_it_allows():
    doc = canon2.loads(_image(starter_path("default")))
    doc["rules"] = [r for r in doc["rules"] if r["target"] != "refuse_128"]
    gap = control_gap(Policy(canon2.dumps(doc)))
    assert gap is not None and "does not refuse a change to a control file" in gap


# ------------------------------------------------------------------------------ status and doctor
def _env(home: Path):
    env = {k: v for k, v in os.environ.items() if k not in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR")}
    env.update(HOME=str(home), USERPROFILE=str(home), PYTHONPATH=str(REPO))
    return env


def _cli(home, *args):
    return subprocess.run([sys.executable, "-m", "prismpath", *args], capture_output=True, env=_env(home),
                          cwd=str(home), timeout=300)


@pytest.fixture()
def setup(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    for name in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("PYTHONPATH", str(REPO))
    done = _cli(home, "agent", "init", "--project", str(project), "--yes")
    assert done.returncode == 0, done.stderr
    return {"home": home, "project": project, "agent": home / ".config" / "prismpath" / "agent"}


def _record(setup, image: bytes):
    (setup["agent"] / commands.POLICY_FILE).write_bytes(image)
    (setup["agent"] / commands.ATTESTATION_FILE).write_bytes(commands._attestation(setup["agent"], image))


def _status(setup):
    done = _cli(setup["home"], "agent", "status", "--json", "--project", str(setup["project"]))
    return json.loads(done.stdout), _cli(setup["home"], "agent", "status", "--project", str(setup["project"])).stdout.decode()


def test_a_fresh_init_has_no_warning_in_status_or_doctor(setup):
    report, text = _status(setup)
    assert report["policy"]["control"] == {"refuses_control_changes": True} and "warning" not in text
    rows = {r["check"]: r for r in doctor.diagnose(setup["project"], 10_000)["checks"]}
    assert rows["policy-control"]["status"] == "ok" and rows["policy-control"]["refuses_control_changes"] is True


def test_a_starter_from_before_the_connect_rule_is_named_by_status_and_doctor(setup):
    _record(setup, _image(OLD_NET[0]))
    report, text = _status(setup)
    assert report["policy"]["name"] == "default (before 2026-11-20)" and report["policy"]["attested"] is True
    assert report["policy"]["control"] == {"refuses_control_changes": True}
    row = {r["check"]: r for r in doctor.diagnose(setup["project"], 10_000)["checks"]}["policy"]
    assert row["status"] == "warn" and "before the connect rule (cause 130" in row["detail"]
    assert row["fix"] == "prismpath agent init --policy default" and row["starter"] == "default"


def test_an_old_starter_warns_in_status_and_doctor_and_the_json_carries_it(setup):
    _record(setup, _image(next(p for p in OLD if p.name.startswith("default-d9dbfea"))))
    report, text = _status(setup)
    control = report["policy"]["control"]
    assert report["policy"]["name"] == "default (before 2026-11-19)" and report["policy"]["attested"] is True
    assert control["refuses_control_changes"] is False and control["policy"] == "the default starter from before 2026-11-19"
    assert "warning: This policy (the default starter from before 2026-11-19) does not refuse a change" in text
    assert "prismpath agent init --policy default" in text
    report = doctor.diagnose(setup["project"], 10_000)
    row = {r["check"]: r for r in report["checks"]}["policy-control"]
    assert row["status"] == "warn" and row["refuses_control_changes"] is False
    assert row["fix"] == "prismpath agent init --policy default"
    # the older image also bounds classifier_version to 1, so the doctor's own Read is denied: a failure that names it
    dry = {r["check"]: r for r in report["checks"]}["hook-dry-run"]
    assert dry["status"] == "fail" and "did not answer allow (deny)" in dry["detail"] and report["ok"] is False
    out = io.StringIO()
    doctor.doctor(setup["project"], True, 10_000, out=out)
    printed = {r["check"]: r for r in json.loads(out.getvalue())["checks"]}
    assert printed["policy-control"]["status"] == "warn" and printed["policy-control"]["refuses_control_changes"] is False


def test_the_hook_denies_every_call_under_an_image_from_before_classifier_version_2(setup):
    """The hook decides by the recorded image, and an older starter bounds `classifier_version` to 1, so the core
    refuses every reading of the current classifier at its boundary: nothing runs until `agent init` records a current
    starter. It fails closed, it never allows."""
    for path in (next(p for p in OLD if p.name.startswith("default-d9dbfea")), OLD_NET[0]):
        _record(setup, _image(path))
        for tool, tool_input in (("Write", {"file_path": str(setup["project"] / ".claude" / "settings.json")}),
                                 ("Read", {"file_path": str(setup["project"] / "a.txt")})):
            hook = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
                    "cwd": str(setup["project"])}
            answer = commands.hook(json.dumps(hook).encode(),
                                   {"HOME": str(setup["home"]), "CLAUDE_PROJECT_DIR": str(setup["project"])})
            assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"
            reason = answer["hookSpecificOutput"]["permissionDecisionReason"]
            assert "classifier version 1" in reason and "prismpath agent init" in reason, reason


def test_re_recording_keeps_the_old_runs_verifying_and_the_open_session_on_its_old_image(setup):
    """What the warning promises: a sealed run keeps its own image and verifies after `init --policy`; a session
    that is still open is refused its next call (it began under another image)."""
    old = _image(next(p for p in OLD if p.name.startswith("default-d9dbfea")))
    _record(setup, old)
    env = {"HOME": str(setup["home"]), "CLAUDE_PROJECT_DIR": str(setup["project"])}

    def call(session, event="PreToolUse"):
        hook = {"session_id": session, "hook_event_name": event, "tool_name": "Read",
                "tool_input": {"file_path": str(setup["project"] / "a.txt")}, "cwd": str(setup["project"])}
        return commands.hook(json.dumps(hook).encode(), env)
    os.environ["HOME"] = str(setup["home"])
    (setup["project"] / "a.txt").write_text("x\n")
    assert call("sealed")["hookSpecificOutput"]["permissionDecision"] == "deny"       # the old image refuses version 2
    call("sealed", "SessionEnd")
    assert call("open")["hookSpecificOutput"]["permissionDecision"] == "deny"
    done = _cli(setup["home"], "agent", "init", "--policy", "default", "--project", str(setup["project"]), "--yes")
    assert done.returncode == 0, done.stderr
    # under an image the classifier cannot use, the hook refused before opening a run, so neither session left a
    # run behind and both go on under the current starter
    assert call("open")["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert call("fresh")["hookSpecificOutput"]["permissionDecision"] == "allow"
    verified = _cli(setup["home"], "agent", "verify", "--json")
    rows = {r["session"]: r for r in json.loads(verified.stdout)["runs"]} if verified.stdout.strip().startswith(b"{") else {}
    assert verified.returncode == 0, (verified.stdout, verified.stderr)
    assert rows and all(r.get("ok", True) for r in rows.values())


def test_init_without_a_name_keeps_the_older_starter_it_replaces(setup):
    _record(setup, _image(next(p for p in OLD if p.name.startswith("strict-"))))
    assert _cli(setup["home"], "agent", "init", "--project", str(setup["project"]), "--yes").returncode == 0
    assert (setup["agent"] / commands.POLICY_FILE).read_bytes() == _image(starter_path("strict"))
