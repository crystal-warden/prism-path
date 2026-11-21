# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath agent rules`: the installed policy's rules with their hits, counted from receipts that verify.

Every process runs with HOME set to a throwaway directory, as in tests/test_agent_cli.py, so the keys, the policy
and the runs are the test's own. The receipts are made by running the real hook on recorded-style inputs.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import rules  # noqa: E402
from prismpath.agent.policy import STARTERS, Policy, starter_path  # noqa: E402
from prismpath.kernel import policy_source  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def _env(home: Path):
    env = {k: v for k, v in os.environ.items()
           if k not in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR", "PRISMPATH_DEBUG")}
    env.update(HOME=str(home), USERPROFILE=str(home), PYTHONPATH=str(REPO), TMPDIR=str(home / "tmp"))
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    return env


def _cli(home, *args, stdin=b""):
    return subprocess.run([sys.executable, "-m", "prismpath", *args], input=stdin, capture_output=True,
                          env=_env(home), cwd=str(home), timeout=120)


def _hook(home, ws, session, tool, tool_input):
    payload = {"session_id": session, "cwd": str(ws), "hook_event_name": "PreToolUse", "tool_name": tool,
               "tool_input": tool_input}
    done = _cli(home, "agent", "hook", stdin=json.dumps(payload).encode())
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)["hookSpecificOutput"]["permissionDecision"]


def _end(home, ws, session):
    _cli(home, "agent", "hook", stdin=json.dumps({"session_id": session, "cwd": str(ws),
                                                   "hook_event_name": "SessionEnd"}).encode())


def _rules(home, *args):
    done = _cli(home, "agent", "rules", "--json", *args)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _tree(root: Path):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.fixture()
def project(tmp_path):
    home, ws = tmp_path / "home", tmp_path / "ws"
    home.mkdir()
    ws.mkdir()
    (ws / "notes.txt").write_text("a note\n")
    done = _cli(home, "agent", "init", "--project", str(ws), "--yes")
    assert done.returncode == 0, done.stderr
    return home, ws


def _by_rule(data):
    return {row["rule"]: row for row in data["rules"]}


def _numbers(data):
    """The rule numbers the demo hits, found by target so a rule added to the starter does not move them."""
    rows = data["rules"]
    net = next(r["rule"] for r in rows if r["target"] == "refuse_106")
    out = next(r["rule"] for r in rows if r["target"] == "refuse_111")
    allow = next(r["rule"] for r in rows if r["target"] == "allow" and "read_file" in r["condition"])
    return net, out, allow


def _fill(home, ws):
    """Session s1: two reads and a write (the workspace file allow, x3). Session s2: a curl (the network refusal) and /etc/passwd
    (the outside refusal)."""
    note = {"file_path": str(ws / "notes.txt")}
    assert _hook(home, ws, "s1", "Read", note) == "allow"
    assert _hook(home, ws, "s1", "Read", note) == "allow"
    assert _hook(home, ws, "s1", "Write", {"file_path": str(ws / "new.txt"), "content": "x\n"}) == "allow"
    assert _hook(home, ws, "s2", "Bash", {"command": "curl http://example.com"}) == "deny"
    assert _hook(home, ws, "s2", "Read", {"file_path": "/etc/passwd"}) == "deny"


def test_hits_are_counted_per_rule_from_the_hooks_receipts(project):
    home, ws = project
    _fill(home, ws)
    _end(home, ws, "s1")                                  # s1 sealed, s2 left open
    before = _tree(home / ".config")
    data = _rules(home)
    assert _tree(home / ".config") == before              # read only: not even the open run was sealed
    by = _by_rule(data)
    net, out, allow = _numbers(data)
    assert [by[n]["hits"] for n in (net, out, allow)] == [1, 1, 3]
    assert sum(row["hits"] for row in data["rules"]) == 5 and data["receipts"]["counted"] == 5
    assert data["receipts"]["not_verified"] == 0 and data["receipts"]["runs_counted"] == 2
    assert by[net]["cause"] == "agent:network" and by[net]["decision"] == "refuse"
    assert by[allow]["decision"] == "allow" and by[allow]["cause"] is None
    assert by[allow]["last_hit"] and by[1]["last_hit"] is None
    assert {1, 2} <= set(data["never_matched"]) and not {net, out, allow} & set(data["never_matched"])
    assert [row["cause"] for row in data["core_refusals"]][:2] == ["route:no-matching-edge",
                                                                  "route:contract-violation"]
    assert all(row["hits"] == 0 for row in data["core_refusals"])
    assert data["unreachable"]["checked"] is True and data["unreachable"]["rules"] == []


def test_a_core_refusal_is_its_own_row(project):
    home, ws = project
    # a reading the policy has no rule for: a git push to an unlisted remote in a tool the classifier calls unknown
    from prismpath.agent import commands
    policy, store = commands.load_checked(commands.config_dir({"HOME": str(home)}, "linux"))
    reading = {"classifier_version": 2, "net_dest": "none", "proc_class": "none", "tool": "git", "path_scope": "none", "path_in_toolchain": False,
               "path_glob": False, "path_traversal": False, "path_symlink": False, "path_control": False,
               "command_class": "none",
               "kill_by_pattern": False, "git_op": "none", "remote_class": "none", "zone_reach": "none"}
    assert rules.rule_index(policy, policy.reading_bytes(reading)) is None       # no rule holds: the core refuses
    run = store.open("core", policy.image)
    run.append(policy.reading_bytes(reading), policy.verdict(policy.reading_bytes(reading)))
    data = _rules(home)
    rows = {row["cause"]: row for row in data["core_refusals"]}
    assert rows["route:no-matching-edge"]["hits"] == 1 and rows["route:no-matching-edge"]["last_hit"]
    assert sum(row["hits"] for row in data["rules"]) == 0


def test_a_receipt_that_does_not_verify_is_skipped_and_counted(project):
    home, ws = project
    _fill(home, ws)
    _end(home, ws, "s1")
    _end(home, ws, "s2")
    receipts = home / ".config" / "prismpath" / "agent" / "runs" / "s2" / "receipts.jsonl"
    data = bytearray(receipts.read_bytes())
    data[len(data) // 2] ^= 0x01
    receipts.write_bytes(bytes(data))
    out = _rules(home)
    assert out["receipts"]["counted"] == 3 and out["receipts"]["not_verified"] == 2
    assert out["receipts"]["runs_counted"] == 1
    assert [s["session"] for s in out["receipts"]["skipped"]] == ["s2"]
    by = _by_rule(out)
    net, outside, allow = _numbers(out)
    assert by[net]["hits"] == 0 and by[outside]["hits"] == 0 and by[allow]["hits"] == 3
    text = _cli(home, "agent", "rules").stdout.decode()
    assert "2 receipts did not verify" in text and "skipped s2" in text


def test_a_run_under_another_policy_is_not_counted(project):
    home, ws = project
    _fill(home, ws)
    assert _cli(home, "agent", "init", "--project", str(ws), "--yes", "--policy", "strict").returncode == 0
    out = _rules(home)
    assert out["receipts"]["counted"] == 0 and out["receipts"]["other_policy"] == 5 and out["policy"]["name"] == "strict"


def test_since_keeps_only_runs_at_or_after_the_time(project):
    home, ws = project
    _fill(home, ws)
    assert _rules(home, "--since", "2999-01-01")["receipts"]["counted"] == 0
    assert _rules(home, "--since", "2000-01-01T00:00:00Z")["receipts"]["counted"] == 5
    done = _cli(home, "agent", "rules", "--since", "yesterday-ish")
    assert done.returncode != 0 and b"ISO 8601" in done.stderr


def test_the_text_table_lists_every_rule_and_the_findings(project):
    home, ws = project
    _fill(home, ws)
    text = _cli(home, "agent", "rules").stdout.decode()
    lines = text.splitlines()
    assert lines[0].startswith("policy default ")
    for n, row in enumerate(_by_rule(_rules(home)).values(), 1):
        assert any(line.split()[:1] == [str(n)] and row["target"] in line for line in lines)
    assert "route:no-matching-edge" in text and "Never matched:" in text and "Unreachable" in text


def test_without_setup_it_says_so(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    done = _cli(home, "agent", "rules")
    assert done.returncode != 0 and b"prismpath agent init" in done.stderr


# --------------------------------------------------------------------------------------- unreachable
def _policy(rules_text, extra_fields=""):
    source = ("---\nname: t\nstart: core_decision\nfield.classifier_version: int min=1 max=1\n"
              "field.tool: category\nfield.path_scope: category\nfield.kill_by_pattern: bool\n" + extra_fields +
              "---\n## core_decision\n" + rules_text)
    return Policy(policy_source.compile_source(source))


def test_a_shadowed_rule_is_unreachable():
    policy = _policy('-> refuse agent:network: when tool in ["git", "read_file"]\n'
                     '-> allow: when tool == "git" and path_scope == "workspace"\n'
                     '-> refuse agent:outside-workspace: when kill_by_pattern or tool == "write_file"\n'
                     '-> allow: when tool == "list_dir"\n')
    found = rules.unreachable(policy)
    assert found["rules"] == [2] and found["not_checked"] == [] and found["checked"]


def test_a_rule_covered_by_two_earlier_rules_together_is_unreachable():
    policy = _policy('-> refuse agent:network: when path_scope == "outside" and kill_by_pattern\n'
                     '-> refuse agent:network: when path_scope == "outside" and not kill_by_pattern\n'
                     '-> allow: when path_scope == "outside"\n'
                     '-> allow: when path_scope == "workspace"\n')
    assert rules.unreachable(policy)["rules"] == [3]


def test_a_field_with_no_finite_set_of_values_is_not_checked():
    policy = _policy('-> refuse agent:network: when mood == "calm"\n'
                     '-> refuse agent:network: when tool == "git"\n'
                     '-> allow: when tool == "git" and path_scope == "none"\n',
                     "field.mood: category\n")
    found = rules.unreachable(policy)
    assert found["not_checked"] == [{"rule": 1, "fields": ["mood"]}]
    assert found["rules"] == [3]          # the earlier rule that reads mood is left out, which can only hide


@pytest.mark.parametrize("name", sorted(STARTERS))
def test_the_shipped_starters_have_no_unreachable_rule(name):
    policy = Policy.load(starter_path(name))
    found = rules.unreachable(policy)
    assert found["not_checked"] == []
    assert found["rules"] == []
    # every rule is reached by some reading, so each starter's every rule can fire
    assert found["readings"] > 1000
