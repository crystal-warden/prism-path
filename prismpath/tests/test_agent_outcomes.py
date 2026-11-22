# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""What became of each receipt: the tool_use_id bound to the journal line, the PostToolUse and PostToolUseFailure
outcomes, the end of session inference, the counts of `agent rules` and `agent status`, and `agent approvals`.

The inputs are shaped as https://code.claude.com/docs/en/hooks documents them: a PreToolUse input carries
`tool_use_id`; a PostToolUse input carries `tool_name`, `tool_input`, `tool_response` and the same `tool_use_id`; a
PostToolUseFailure input carries `error`, `is_interrupt` and the same `tool_use_id`. Every process runs with HOME set
to a throwaway directory, as in tests/test_agent_rules.py. Outcomes are records: no test here shows a verdict that
changed because of one.
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

from prismpath.agent import commands, hook_client, rules, run as run_module  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
ERROR_TEXT = "Exit code 1\nError: Cannot find module 'express' SECRET-OUTPUT-MARKER"
RESPONSE_TEXT = "SECRET-OUTPUT-MARKER file content"


def _env(home: Path):
    env = {k: v for k, v in os.environ.items()
           if k not in ("XDG_CONFIG_HOME", "APPDATA", "CLAUDE_PROJECT_DIR", "PRISMPATH_DEBUG")}
    env.update(HOME=str(home), USERPROFILE=str(home), PYTHONPATH=str(REPO), TMPDIR=str(home / "tmp"))
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    return env


def _cli(home, *args, stdin=b""):
    return subprocess.run([sys.executable, "-m", "prismpath", *args], input=stdin, capture_output=True,
                          env=_env(home), cwd=str(home), timeout=120)


def _send(home, payload):
    done = _cli(home, "agent", "hook", stdin=json.dumps(payload).encode())
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _pre(home, ws, session, tool, tool_input, use_id):
    answer = _send(home, {"session_id": session, "transcript_path": "/x/t.jsonl", "cwd": str(ws),
                          "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": tool,
                          "tool_input": tool_input, "tool_use_id": use_id})
    return answer["hookSpecificOutput"]["permissionDecision"]


def _post(home, ws, session, tool, tool_input, use_id):
    """A PostToolUse input as the hooks reference shows it (tool_response is the tool's own result)."""
    return _send(home, {"session_id": session, "transcript_path": "/x/t.jsonl", "cwd": str(ws),
                        "permission_mode": "default", "hook_event_name": "PostToolUse", "tool_name": tool,
                        "tool_input": tool_input, "tool_response": {"content": RESPONSE_TEXT},
                        "tool_use_id": use_id, "duration_ms": 12})


def _fail(home, ws, session, tool, tool_input, use_id, error=ERROR_TEXT, interrupt=False):
    """A PostToolUseFailure input as the hooks reference shows it."""
    return _send(home, {"session_id": session, "transcript_path": "/x/t.jsonl", "cwd": str(ws),
                        "permission_mode": "default", "hook_event_name": "PostToolUseFailure", "tool_name": tool,
                        "tool_input": tool_input, "tool_use_id": use_id, "error": error,
                        "is_interrupt": interrupt, "duration_ms": 4187})


def _end(home, ws, session):
    return _send(home, {"session_id": session, "cwd": str(ws), "hook_event_name": "SessionEnd"})


def _run_dir(home, session):
    return home / ".config" / "prismpath" / "agent" / "runs" / session


def _outcomes(home, session):
    path = _run_dir(home, session) / "outcomes.jsonl"
    return [canon2.loads(line) for line in path.read_bytes().split(b"\n")[:-1]] if path.exists() else []


def _journal(home, session):
    return [canon2.loads(line) for line in (_run_dir(home, session) / "journal.jsonl").read_bytes().split(b"\n")[:-1]]


def _verify(home):
    done = _cli(home, "agent", "verify", "--json")
    return done.returncode, json.loads(done.stdout)


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


READ = lambda ws: ("Read", {"file_path": str(ws / "notes.txt")})                    # allow (a file in the workspace)
TOUCH = ("Bash", {"command": "touch made.txt", "description": "Make a file"})       # ask (agent:shell-mutation-asked)
CURL = ("Bash", {"command": "curl http://example.com"})                             # deny (agent:network)


# ------------------------------------------------------------------------------------------- the binding
def test_the_journal_line_carries_the_tool_use_id_and_the_receipt_is_unchanged(project):
    home, ws = project
    tool, tool_input = READ(ws)
    assert _pre(home, ws, "with-id", tool, tool_input, "toolu_01ABCdef") == "allow"
    assert _send(home, {"session_id": "no-id", "cwd": str(ws), "hook_event_name": "PreToolUse", "tool_name": tool,
                        "tool_input": tool_input})["hookSpecificOutput"]["permissionDecision"] == "allow"
    with_id, without = _journal(home, "with-id")[0], _journal(home, "no-id")[0]
    assert with_id["tool_use_id"] == "toolu_01ABCdef" and "tool_use_id" not in without
    assert set(with_id["receipt"]) == set(without["receipt"])            # core-receipt/1 has no new member
    assert {k: v for k, v in with_id["receipt"].items() if k != "case"} == {k: v for k, v in without["receipt"].items() if k != "case"}
    code, report = _verify(home)
    assert code == 0 and report["verified"] is True                       # the oracle replays it; the root statement is signed


def test_an_id_that_is_not_shaped_like_one_is_not_kept(project):
    home, ws = project
    tool, tool_input = READ(ws)
    assert _pre(home, ws, "odd", tool, tool_input, "toolu 01 with spaces\n{") == "allow"
    assert "tool_use_id" not in _journal(home, "odd")[0]


# --------------------------------------------------------------------------------------------- outcomes
def test_allow_then_ran(project):
    home, ws = project
    tool, tool_input = READ(ws)
    assert _pre(home, ws, "s", tool, tool_input, "toolu_A") == "allow"
    assert _post(home, ws, "s", tool, tool_input, "toolu_A") == {}        # the answer is nothing: the call already ran
    (entry,) = _outcomes(home, "s")
    assert entry["outcome"] == "ran" and entry["source"] == "hook" and entry["event"] == "PostToolUse"
    assert entry["receipt"] == 0 and entry["decision"] == "allow" and entry["tool"] == "Read"
    assert entry["tool_use_id"] == "toolu_A"
    assert entry["receipt_sha256"] == hashlib.sha256(canon2.dumps(_journal(home, "s")[0]["receipt"])).hexdigest()
    assert RESPONSE_TEXT.split()[0] not in (_run_dir(home, "s") / "outcomes.jsonl").read_text()    # no tool output kept
    assert _verify(home)[0] == 0


def test_ask_then_approved_and_ran(project):
    home, ws = project
    tool, tool_input = TOUCH
    assert _pre(home, ws, "s", tool, tool_input, "toolu_B") == "ask"
    assert _post(home, ws, "s", tool, tool_input, "toolu_B") == {}
    (entry,) = _outcomes(home, "s")
    assert entry["outcome"] == "ran" and entry["decision"] == "escalate" and entry["receipt"] == 0
    counts = _status(home)["runs"][0]["outcomes"]
    assert counts["asked"] == 1 and counts["asked_approved"] == 1 and counts["asked_no_outcome"] == 0


def test_a_failure_is_an_outcome_of_a_class_and_never_the_error_text(project):
    home, ws = project
    tool, tool_input = TOUCH
    assert _pre(home, ws, "s", tool, tool_input, "toolu_C") == "ask"
    assert _fail(home, ws, "s", tool, tool_input, "toolu_C") == {}
    (entry,) = _outcomes(home, "s")
    assert entry["outcome"] == "failed" and entry["event"] == "PostToolUseFailure" and entry["failure"] == "exit-nonzero"
    raw = (_run_dir(home, "s") / "outcomes.jsonl").read_text()
    assert "SECRET-OUTPUT-MARKER" not in raw and "express" not in raw
    assert _verify(home)[0] == 0
    # an interrupt and a bare error message are classes too
    assert _pre(home, ws, "t", tool, tool_input, "toolu_D") == "ask"
    _fail(home, ws, "t", tool, tool_input, "toolu_D", error="could not start the shell", interrupt=True)
    assert _outcomes(home, "t")[0]["failure"] == "interrupt"


def test_ask_then_no_outcome_is_declined_or_not_run_and_an_allow_with_none_is_no_outcome(project):
    home, ws = project
    tool, tool_input = READ(ws)
    assert _pre(home, ws, "s", tool, tool_input, "toolu_E1") == "allow"            # no PostToolUse ever arrives
    assert _pre(home, ws, "s", *TOUCH, "toolu_E2") == "ask"                        # the person said no
    assert _pre(home, ws, "s", *CURL, "toolu_E3") == "deny"                        # refused: has no outcome at all
    assert _outcomes(home, "s") == []
    assert _end(home, ws, "s") == {}
    entries = _outcomes(home, "s")
    assert [(e["receipt"], e["outcome"], e["source"]) for e in entries] == [
        (0, "no outcome", "session-end"), (1, "no outcome (declined or not run)", "session-end")]
    assert _end(home, ws, "s") == {} and len(_outcomes(home, "s")) == 2            # a second end adds nothing
    counts = _status(home)["runs"][0]["outcomes"]
    assert (counts["allowed_no_outcome"], counts["asked_no_outcome"], counts["asked_approved"], counts["refused"]) == (1, 1, 0, 1)
    assert _verify(home)[0] == 0


def test_a_real_outcome_after_the_inferred_one_counts_and_verifies(project):
    home, ws = project
    assert _pre(home, ws, "s", *TOUCH, "toolu_F") == "ask"
    _end(home, ws, "s")
    assert _outcomes(home, "s")[0]["outcome"] == "no outcome (declined or not run)"
    _post(home, ws, "s", *TOUCH, "toolu_F")                                         # a resumed session finally reports it
    assert _status(home)["runs"][0]["outcomes"]["asked_approved"] == 1
    assert _verify(home)[0] == 0


def test_a_refused_call_has_no_outcome_and_a_forged_one_is_unbound(project):
    home, ws = project
    assert _pre(home, ws, "s", *CURL, "toolu_G") == "deny"
    assert _post(home, ws, "s", *CURL, "toolu_G") == {}                             # the refusal never ran, so this is forged
    (entry,) = _outcomes(home, "s")
    assert entry["outcome"] == "unbound" and entry["reason"] == "receipt-was-a-refusal" and "receipt" not in entry
    counts = _status(home)["runs"][0]["outcomes"]
    assert counts["refused"] == 1 and counts["unbound"] == 1 and counts["allowed_ran"] == counts["asked_approved"] == 0
    assert _verify(home)[0] == 0


def test_outcomes_that_cannot_be_bound_are_recorded_unbound_and_change_nothing(project):
    home, ws = project
    tool, tool_input = READ(ws)
    assert _pre(home, ws, "s", tool, tool_input, "toolu_H") == "allow"
    before = (_run_dir(home, "s") / "journal.jsonl").read_bytes()
    assert _post(home, ws, "s", tool, tool_input, "toolu_FORGED") == {}             # no receipt has this id
    assert _post(home, ws, "s", tool, tool_input, "bad id!") == {}                  # not shaped like an id
    assert _send(home, {"session_id": "s", "hook_event_name": "PostToolUse", "tool_name": tool}) == {}   # no id at all
    assert _post(home, ws, "s", tool, tool_input, "toolu_H") == {}                  # bound
    assert _post(home, ws, "s", tool, tool_input, "toolu_H") == {}                  # a repeat for the same receipt
    assert _post(home, ws, "nobody", tool, tool_input, "toolu_H") == {}             # a session with no run: nothing made
    assert not _run_dir(home, "nobody").exists()
    assert [e.get("reason", e["outcome"]) for e in _outcomes(home, "s")] == [
        "no-receipt", "no-tool-use-id", "no-tool-use-id", "ran", "duplicate"]
    assert (_run_dir(home, "s") / "journal.jsonl").read_bytes() == before           # no decision, receipt or verdict moved
    assert _pre(home, ws, "s", tool, tool_input, "toolu_I") == "allow"               # decisions go on as before
    assert _status(home)["runs"][0]["outcomes"]["allowed_ran"] == 1
    assert _verify(home)[0] == 0


def test_an_outcome_event_that_cannot_run_says_so_and_never_denies(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    # no keys at all: a PreToolUse is a deny, a PostToolUse is only a message
    answer = _send(home, {"session_id": "s", "hook_event_name": "PostToolUse", "tool_name": "Read", "tool_use_id": "toolu_J"})
    assert "hookSpecificOutput" not in answer and "Nothing was changed" in answer["systemMessage"]


def test_the_thin_client_answers_nothing_when_an_outcome_cannot_be_sent():
    for event in ("PostToolUse", "PostToolUseFailure"):
        raw = json.dumps({"hook_event_name": event, "session_id": "s"}).encode()
        assert hook_client.ask("/nonexistent/decider.sock", raw) == {}
    pre = hook_client.ask("/nonexistent/decider.sock", json.dumps({"hook_event_name": "PreToolUse"}).encode())
    assert pre["hookSpecificOutput"]["permissionDecision"] == "deny"


# --------------------------------------------------------------------------------------------- the runner
def test_the_runner_reports_a_shell_command_as_an_outcome_with_or_without_signals(project):
    home, ws = project
    env = {"HOME": str(home)}
    policy, store = commands.load_checked(commands.config_dir(env, "linux"))
    from prismpath.ledgers import core_evidence
    image = core_evidence.sha256_hex(policy.image)
    run = store.open("r", policy.image)
    raw = policy.reading_bytes(_reading_of(policy, ws))
    verdict = policy.decide(raw).verdict
    for n in range(3):
        run.append(raw, verdict, extras=run_module.Extras(sandbox_profile="a" * 64, tool_use_id=f"toolu_R{n}"))

    def report(receipt, returncode, stderr="", timed_out=False, profile="a" * 64):
        data = {"hook_event_name": "PrismPathObservation", "session_id": "r", "receipt": receipt, "image_sha256": image,
                "profile_sha256": profile, "returncode": returncode, "timed_out": timed_out, "stderr": stderr}
        return commands.hook(json.dumps(data).encode(), env, nested=object())

    assert report(0, 0) == {"recorded": True}                                       # nothing observed, still an outcome
    assert report(1, 2, "ls: cannot open: Permission denied\n") == {"recorded": True}
    assert report(1, 2, "again") == {"recorded": True}                              # a second report for one receipt is dropped
    assert report(2, 0, profile="b" * 64)["recorded"] is False                      # not the call's profile: refused
    lines = run.outcomes()
    assert [(l["receipt"], l["outcome"], l["source"], l.get("failure"), l["tool_use_id"]) for l in lines] == [
        (0, "ran", "runner", None, "toolu_R0"), (1, "failed", "runner", "exit-nonzero", "toolu_R1")]
    assert len(run.observations()) == 1                                             # the signal is also an observation
    assert run.outcome_map() == {0: "ran", 1: "failed"}
    assert run.verify_outcomes() == 2


def _reading_of(policy, ws):
    from prismpath.agent import claude_code
    return claude_code.evaluate({"session_id": "r", "cwd": str(ws), "hook_event_name": "PreToolUse", "tool_name": "Read",
                                 "tool_input": {"file_path": str(ws / "notes.txt")}}, None, policy).reading


# ---------------------------------------------------------------------------------------------- verify
def _rewrite(path: Path, edit):
    """Rewrite the outcomes file with `edit(lines)` and the chain rehashed, so only the binding can catch it."""
    lines = [canon2.loads(l) for l in path.read_bytes().split(b"\n")[:-1]]
    edit(lines)
    prev, out = "", b""
    for n, line in enumerate(lines):
        line.pop("sha256", None)
        line["i"], line["prev"] = n, prev
        line["sha256"] = hashlib.sha256(canon2.dumps(line)).hexdigest()
        prev = line["sha256"]
        out += canon2.dumps(line) + b"\n"
    path.write_bytes(out)


def _two_outcomes(project):
    home, ws = project
    _pre(home, ws, "s", *READ(ws), "toolu_K1")
    _pre(home, ws, "s", *TOUCH, "toolu_K2")
    _post(home, ws, "s", *READ(ws), "toolu_K1")
    _post(home, ws, "s", *TOUCH, "toolu_K2")
    assert _verify(home)[0] == 0
    return home, _run_dir(home, "s") / "outcomes.jsonl"


def test_verify_detects_a_flipped_byte_in_the_outcomes_file(project):
    home, path = _two_outcomes(project)
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))
    code, report = _verify(home)
    assert code == 1 and report["verified"] is False and "outcome" in report["runs"][0]["error"]


def test_verify_detects_an_outcome_moved_to_another_receipt_though_the_chain_is_rehashed(project):
    home, path = _two_outcomes(project)
    _rewrite(path, lambda lines: lines[0].update(receipt=1))                 # moved to a receipt it is not about
    code, report = _verify(home)
    assert code == 1 and "not about the receipt it names" in report["runs"][0]["error"]


def test_verify_detects_a_swapped_tool_use_id_a_wrong_decision_and_a_second_outcome(project):
    home, path = _two_outcomes(project)
    original = path.read_bytes()
    _rewrite(path, lambda lines: lines[0].update(tool_use_id="toolu_OTHER"))
    code, report = _verify(home)
    assert code == 1 and "tool_use_id" in report["runs"][0]["error"]
    path.write_bytes(original)
    _rewrite(path, lambda lines: lines[0].update(decision="escalate"))
    code, report = _verify(home)
    assert code == 1 and "decision" in report["runs"][0]["error"]
    path.write_bytes(original)
    _rewrite(path, lambda lines: lines.append(dict(lines[0])))
    code, report = _verify(home)
    assert code == 1 and "second hook outcome" in report["runs"][0]["error"]
    path.write_bytes(original)
    assert _verify(home)[0] == 0


def test_verify_says_how_many_outcome_entries_it_checked(project):
    home, path = _two_outcomes(project)
    done = _cli(home, "agent", "verify")
    assert done.returncode == 0 and "2 outcome entries chained and bound to their receipts" in done.stdout.decode()


def test_an_unfinished_outcome_line_is_refused(project):
    home, path = _two_outcomes(project)
    path.write_bytes(path.read_bytes()[:-5])
    assert _verify(home)[0] == 1


# ------------------------------------------------------------------------------------ counts and status
def _status(home):
    done = _cli(home, "agent", "status", "--json", "--project", str(home))
    return json.loads(done.stdout)


def test_rules_counts_what_became_of_each_rule(project):
    home, ws = project
    for n in range(2):                                                          # allowed, one ran and one has no outcome
        _pre(home, ws, "s", *READ(ws), f"toolu_L{n}")
    _post(home, ws, "s", *READ(ws), "toolu_L0")
    for n in range(2):                                                          # asked, one approved and one declined
        _pre(home, ws, "s", *TOUCH, f"toolu_M{n}")
    _post(home, ws, "s", *TOUCH, "toolu_M0")
    _pre(home, ws, "s", *CURL, "toolu_N")                                       # refused
    _end(home, ws, "s")
    data = _rules(home)
    by = {row["target"] + (row["cause"] or ""): row for row in data["rules"]}
    allow = next(r for r in data["rules"] if r["target"] == "allow" and "read_file" in r["condition"])
    ask = next(r for r in data["rules"] if r["cause"] == "agent:shell-mutation-asked")
    refuse = next(r for r in data["rules"] if r["cause"] == "agent:network")
    assert (allow["allowed_ran"], allow["allowed_no_outcome"]) == (1, 1) and allow["hits"] == 2
    assert (ask["asked_approved"], ask["asked_no_outcome"]) == (1, 1) and ask["hits"] == 2
    assert refuse["refused"] == 1 and refuse["allowed_ran"] == 0
    assert all(set(r) >= set(rules.OUTCOME_KEYS) for r in data["rules"]) and by
    assert all("refused" in c for c in data["core_refusals"])
    text = _cli(home, "agent", "rules").stdout.decode()
    assert "1 ran, 1 none" in text and "1 approved and ran, 0 failed, 1 none" in text and "1 refused" in text
    assert "decide nothing" in text
    status = _status(home)
    assert status["outcomes"]["allowed"] == 2 and status["outcomes"]["asked_approved"] == 1
    plain = _cli(home, "agent", "status", "--project", str(ws)).stdout.decode()
    assert "allowed 2 (1 ran, 1 no outcome); asked 2 (1 approved and ran, 0 failed or interrupted, 1 no outcome); refused 1" in plain
    assert "PostToolUse yes, PostToolUseFailure yes" in plain


def test_rules_is_still_read_only_with_outcomes(project):
    home, ws = project
    _pre(home, ws, "s", *READ(ws), "toolu_O")
    _post(home, ws, "s", *READ(ws), "toolu_O")
    before = _tree(home / ".config")
    _rules(home)
    _cli(home, "agent", "approvals")
    assert _tree(home / ".config") == before


# ------------------------------------------------------------------------------------------ approvals
def _approve(home, ws, session, times, command="touch made.txt", approve=True):
    for n in range(times):
        use_id = f"toolu_{session}{n}"
        assert _pre(home, ws, session, "Bash", {"command": command}, use_id) == "ask"
        if approve:
            _post(home, ws, session, "Bash", {"command": command}, use_id)


def test_a_failed_or_interrupted_asked_call_is_not_an_approval_that_ran(project):
    home, ws = project
    _approve(home, ws, "a", 2)                                                  # approved and ran twice
    for n, interrupt in enumerate((False, True)):                               # asked, then failed once and interrupted once
        use_id = f"toolu_f{n}"
        assert _pre(home, ws, "f", *TOUCH, use_id) == "ask"
        _fail(home, ws, "f", *TOUCH, use_id, interrupt=interrupt)
    data = json.loads(_cli(home, "agent", "approvals", "--min", "3", "--json").stdout)
    assert data["candidates"] == []                                             # two ran, two failed: below three on `ran` only
    data = json.loads(_cli(home, "agent", "approvals", "--min", "2", "--json").stdout)
    (candidate,) = data["candidates"]
    assert (candidate["approved"], candidate["asked_failed"], candidate["asked"]) == (2, 2, 4)
    assert candidate["examples"][0]["approved"] == 2                            # the examples count the calls that ran
    ask = next(r for r in _rules(home)["rules"] if r["cause"] == "agent:shell-mutation-asked")
    assert (ask["asked_approved"], ask["asked_failed"], ask["asked_no_outcome"]) == (2, 2, 0)
    counts = _status(home)["outcomes"]
    assert (counts["asked"], counts["asked_approved"], counts["asked_failed"]) == (4, 2, 2)
    assert "2 failed or interrupted" in _cli(home, "agent", "approvals", "--min", "2").stdout.decode()


def test_approvals_lists_a_rule_approved_three_times_with_classes_only(project):
    home, ws = project
    _approve(home, ws, "a", 3)
    _approve(home, ws, "b", 2, command="rm old.log")           # asked twice, approved twice, below three
    _approve(home, ws, "c", 1, approve=False)                  # asked and declined
    policy_before = (home / ".config" / "prismpath" / "agent" / "policy.core.json").read_bytes()
    done = _cli(home, "agent", "approvals", "--json")
    assert done.returncode == 0, done.stderr
    data = json.loads(done.stdout)
    assert data["note"] == "candidates for the owner to sign; nothing is changed" and data["minimum"] == 3
    (candidate,) = data["candidates"]
    assert candidate["cause"] == "agent:shell-mutation-asked"
    assert candidate["approved"] == 5 and candidate["asked"] == 6 and candidate["asked_no_outcome"] == 1
    assert candidate["asked_failed"] == 0
    assert candidate["examples"] and candidate["examples"][0]["approved"] == 5
    assert candidate["examples"][0]["reading"] == "command_class=mutating path_scope=workspace proc_class=single tool=run_command"
    assert "touch" not in done.stdout.decode() and "old.log" not in done.stdout.decode()      # classes only, never the command
    text = _cli(home, "agent", "approvals").stdout.decode()
    assert text.startswith("Candidates for the owner to sign; nothing is changed.")
    assert "approved and ran 5 of 6 asked" in text
    only_three = json.loads(_cli(home, "agent", "approvals", "--json", "--min", "6").stdout)
    assert only_three["candidates"] == []
    assert (home / ".config" / "prismpath" / "agent" / "policy.core.json").read_bytes() == policy_before     # nothing adopted


def test_approvals_lists_a_rule_approved_exactly_three_times(project):
    home, ws = project
    _approve(home, ws, "a", 3)
    data = json.loads(_cli(home, "agent", "approvals", "--json").stdout)
    assert [c["approved"] for c in data["candidates"]] == [3]
    _approve(home, ws, "z", 0)
    data = json.loads(_cli(home, "agent", "approvals", "--json", "--min", "4").stdout)
    assert data["candidates"] == []


def test_approvals_never_counts_a_run_that_does_not_verify(project):
    home, ws = project
    _approve(home, ws, "a", 3)
    path = _run_dir(home, "a") / "outcomes.jsonl"
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))
    out = json.loads(_cli(home, "agent", "approvals", "--json").stdout)
    assert out["candidates"] == [] and out["receipts"]["not_verified"] == 3


def test_approvals_rejects_a_minimum_below_one(project):
    home, _ = project
    done = _cli(home, "agent", "approvals", "--min", "0")
    assert done.returncode != 0 and b"at least 1" in done.stderr


# ----------------------------------------------------------------------------------------------- settings
def test_merged_settings_adds_the_two_outcome_events_once():
    merged = commands.merged_settings({}, "prismpath agent hook || exit 2")
    assert set(merged["hooks"]) == {"PreToolUse", "SessionEnd", "PostToolUse", "PostToolUseFailure"}
    assert merged["hooks"]["PostToolUse"][0]["matcher"] == "*"
    assert commands.merged_settings(merged, "prismpath agent hook || exit 2") == merged


def test_the_doctor_warns_when_the_outcome_hooks_are_missing(project):
    home, ws = project
    settings = ws / ".claude" / "settings.json"
    data = json.loads(settings.read_text())
    data["hooks"].pop("PostToolUse")
    settings.write_text(json.dumps(data))
    done = _cli(home, "agent", "doctor", "--json", "--project", str(ws))
    rows = {r["check"]: r for r in json.loads(done.stdout)["checks"]}
    assert rows["hook-PostToolUse"]["status"] == "warn" and "not recorded" in rows["hook-PostToolUse"]["detail"]
    assert rows["hook-PostToolUseFailure"]["status"] == "ok" and rows["hook-PreToolUse"]["status"] == "ok"
