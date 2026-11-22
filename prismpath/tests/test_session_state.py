# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""State across calls (prismpath/agent/session_state.py, the `session` starter, causes 133 and 134).

What a session already did enters a decision as two reading fields computed from the session's own journal. These tests hold
the derivation (a pure function of the journal lines), the fail safe (a history that cannot be read is the most restrictive
state), the hook end to end (state read, decided and appended against the same count, a parallel append noticed), and the
starter (the stateless default plus two questions, never a relaxation). The proof that a state only ever adds
restriction is formal/Classifier/Session.lean, checked per image by the oracle (tests/test_classifier_diff.py).
"""
import json
import os
import threading
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import claude_code, classifier, commands, run as run_module, sandbox_hook, session_state, zones  # noqa: E402
from prismpath.agent.policy import STARTERS, Policy, starter_path  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402

BASE = classifier.base_reading()
FRESH, RESTRICTIVE = session_state.FRESH, session_state.RESTRICTIVE


class Table:
    """A zone point that answers per path (`unknown` for a path it was not given)."""

    def __init__(self, **answers):
        self.answers = answers

    def reach(self, raw, config=None):
        return self.answers.get(os.path.basename(raw), "unknown")


def _policy(name="session"):
    return Policy.load(starter_path(name))


def _append(run, policy, reading, state=None):
    """Decide `reading` (with `state`, FRESH when None) and journal it as the hook does; return the decision."""
    reading = {**BASE, **reading, **(state or FRESH)} if policy.stateful else {**BASE, **reading}
    decision = policy.decide(policy.reading_bytes(reading))
    run.append(policy.reading_bytes(reading), decision.verdict)
    return decision


@pytest.fixture()
def store(tmp_path):
    return run_module.RunStore(tmp_path / "runs")


@pytest.fixture()
def session(store):
    policy = _policy()
    return policy, store.open("s1", policy.image)


WRITE = {"tool": "write_file", "path_scope": "workspace"}
SHELL = {"tool": "run_command", "path_scope": "workspace", "command_class": "read_only"}


# ----------------------------------------------------------------------------------------------- the derivation
def test_a_session_with_no_run_has_not_begun_and_reads_fresh(store):
    assert session_state.read(store, "nobody") == (FRESH, 0)


def test_a_change_that_reached_a_zone_or_whose_reach_was_unknown_makes_the_session_protected_whether_asked_or_allowed(store):
    for reach in ("protected", "unknown"):
        policy = _policy()
        run = store.open(f"s-{reach}", policy.image)
        _append(run, policy, {**WRITE, "zone_reach": "none"})
        assert session_state.read(store, f"s-{reach}") == (FRESH, 1)
        decision = _append(run, policy, {**WRITE, "zone_reach": reach})
        assert decision.cause_code == 132                          # asked, not run until the person says
        state, held = session_state.read(store, f"s-{reach}")
        assert state == {session_state.CHANGES: "some", session_state.SHELL: "none"} and held == 2


def test_a_refused_call_is_not_counted(store):
    policy = _policy()
    run = store.open("s", policy.image)
    outside = {**WRITE, "path_scope": "outside", "zone_reach": "protected"}
    assert _append(run, policy, outside).kind == "refuse"
    assert _append(run, policy, {**SHELL, "path_scope": "outside"}).kind == "refuse"
    assert session_state.read(store, "s") == (FRESH, 2)


def test_a_change_with_no_zone_reach_in_its_reading_counts_as_protected(store):
    """A journal written under a policy that has no `zone_reach` cannot say; the fail safe is `some`."""
    policy = _policy("default")
    run = store.open("s", policy.image)
    reading = {k: v for k, v in {**BASE, **WRITE}.items() if k != "zone_reach"}
    run.append(canon2.dumps(reading), {"verdict": "route", "target": "allow", "edge": 0})
    assert session_state.read(store, "s")[0][session_state.CHANGES] == "some"


@pytest.mark.parametrize("runs,band", [(0, "none"), (1, "few"), (session_state.SHELL_MANY - 1, "few"),
                                       (session_state.SHELL_MANY, "many"), (session_state.SHELL_MANY + 5, "many")])
def test_shell_runs_are_banded(store, runs, band):
    policy = _policy()
    run = store.open("s", policy.image)
    for _ in range(runs):
        assert _append(run, policy, SHELL).kind == "allow"
    state, held = session_state.read(store, "s") if runs else (FRESH, 0)
    assert state[session_state.SHELL] == band and held == runs


def test_asked_shell_calls_count_and_calls_of_other_tools_do_not(store):
    policy = _policy()
    run = store.open("s", policy.image)
    assert _append(run, policy, {**SHELL, "command_class": "mutating"}).kind == "escalate"
    _append(run, policy, {"tool": "read_file", "path_scope": "workspace"})
    _append(run, policy, {"tool": "git", "path_scope": "workspace", "git_op": "local_read"})
    assert session_state.read(store, "s")[0][session_state.SHELL] == "few"
    assert session_state.derive(run._entries())[session_state.SHELL] == "few"


def test_outcomes_and_observations_are_never_read(store):
    """What a hook event or the runner reports is a claim; writing them, or garbage in their place, changes nothing."""
    policy = _policy()
    run = store.open("s", policy.image)
    _append(run, policy, WRITE)
    before = session_state.read(store, "s")
    (run.dir / run_module.OUTCOMES).write_bytes(b"not a line\n")
    (run.dir / run_module.OBSERVATIONS).write_bytes(b"{}\n")
    assert session_state.read(store, "s") == before


# ----------------------------------------------------------------------------------------------- the fail safe
def _journal_path(store, session_id="s"):
    return store.root / run_module.run_dir_name(session_id) / run_module.JOURNAL


@pytest.fixture()
def begun(store):
    policy = _policy()
    run = store.open("s", policy.image)
    _append(run, policy, WRITE)
    _append(run, policy, WRITE)
    return policy, run


def test_a_line_that_does_not_verify_reads_the_most_restrictive_state_and_no_count(store, begun):
    """The last line, which the validated-prefix record hashes, damaged: the record no longer matches, every line is
    validated, and the damage is found."""
    path = _journal_path(store)
    lines = path.read_bytes().split(b"\n")
    lines[1] = lines[1].replace(b'"i":1', b'"i":7')
    path.write_bytes(b"\n".join(lines))
    assert session_state.read(store, "s") == (RESTRICTIVE, None)


def test_an_earlier_line_damaged_after_it_was_counted_keeps_the_counts_it_was_counted_with(store, begun):
    """A line the record covers was validated and counted when it was appended, so changing it later changes no count
    (the state cannot be loosened that way); with the record gone the whole journal is validated and the damage found;
    `seal` and `verify` always validate every line."""
    before = session_state.read(store, "s")
    path = _journal_path(store)
    lines = path.read_bytes().split(b"\n")
    lines[0] = lines[0].replace(b'"i":0', b'"i":7')
    path.write_bytes(b"\n".join(lines))
    assert session_state.read(store, "s") == before
    (path.parent / run_module.PREFIX).unlink()
    assert session_state.read(store, "s") == (RESTRICTIVE, None)


def test_a_journal_that_is_missing_while_the_run_shows_there_was_one_reads_the_most_restrictive_state(store, begun):
    _journal_path(store).unlink()
    assert session_state.read(store, "s") == (RESTRICTIVE, None)


def test_a_run_directory_with_no_image_reads_the_most_restrictive_state(store, begun):
    (store.root / "s" / run_module.IMAGE).unlink()
    assert session_state.read(store, "s") == (RESTRICTIVE, None)


def test_a_torn_tail_means_a_call_may_have_run_without_a_receipt_so_the_history_reads_the_most_restrictive_state(store, begun):
    path = _journal_path(store)
    path.write_bytes(path.read_bytes() + b'{"i":2,"reading":"ab')            # a writer killed inside append
    assert session_state.read(store, "s") == (RESTRICTIVE, None)
    assert (path.parent / run_module.TORN).exists()                          # the tail is recovered and kept
    assert session_state.read(store, "s") == (RESTRICTIVE, None)             # and the record of it stays


def test_the_core_refuses_a_reading_of_a_stateful_policy_that_lacks_the_fields_and_reading_bytes_never_leaves_one_out():
    policy = _policy()
    raw = canon2.dumps({**BASE, **WRITE})
    assert policy.decide(raw).cause == "route:contract-violation"
    assert policy.decide(policy.reading_bytes({**BASE, **WRITE})).cause_code == 133   # the most restrictive state
    stateless = _policy("default")
    assert stateless.reading_bytes({**BASE, **WRITE}) == canon2.dumps({**BASE, **WRITE})


def test_evaluate_reads_the_most_restrictive_state_when_given_none():
    policy = _policy()
    hook = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": "/ws",
            "tool_input": {"file_path": "/ws/a.txt", "content": ""}}
    env = {"CLAUDE_PROJECT_DIR": "/ws"}
    assert claude_code.evaluate(hook, env, policy).decision.cause_code == 133
    fresh = claude_code.evaluate(hook, env, policy, session=FRESH)
    assert fresh.decision.kind == "allow" and fresh.reading["session_protected_changes"] == "none"
    other = claude_code.evaluate(hook, env, _policy("default"), session=RESTRICTIVE)
    assert other.decision.kind == "allow" and "session_shell_runs" not in other.reading     # a stateless policy never sees it


# ----------------------------------------------------------------------------------------------- the starter
def test_the_session_starter_is_the_default_starter_and_two_rules_and_two_fields():
    session, default = (canon2.loads(_policy(n).image) for n in ("session", "default"))
    stripped = {"fields": {k: v for k, v in session["fields"].items() if k not in session_state.FIELDS},
                "rules": [r for r in session["rules"] if r["target"] not in ("escalate_133", "escalate_134")]}
    assert stripped["fields"] == default["fields"] and stripped["rules"] == default["rules"]
    assert {r["target"] for r in session["rules"]} - {r["target"] for r in default["rules"]} == {"escalate_133", "escalate_134"}
    assert [r["target"] for r in session["rules"]].index("escalate_133") > max(
        n for n, r in enumerate(session["rules"]) if r["target"].startswith("refuse_"))     # after every refusal


def test_every_state_decides_as_the_default_starter_does_or_asks_where_it_would_have_run():
    policy, default = _policy(), _policy("default")
    probes = [{**WRITE}, {**SHELL}, {"tool": "git", "git_op": "local_write", "path_scope": "workspace"},
              {"tool": "run_command", "command_class": "git", "git_op": "push", "remote_class": "allowed"},
              {"tool": "run_command", "command_class": "git", "git_op": "push", "remote_class": "other"},
              {**WRITE, "path_scope": "outside"}, {**WRITE, "zone_reach": "protected"}, {"tool": "unknown"},
              {"tool": "connect", "net_dest": "model_api"}, {"tool": "connect", "net_dest": "other"}]
    for probe in probes:
        base = default.decide(default.reading_bytes({**BASE, **probe}))
        for changes in session_state.CHANGES_VALUES:
            for shell in session_state.SHELL_VALUES:
                got = policy.decide(policy.reading_bytes({**BASE, **probe, session_state.CHANGES: changes,
                                                          session_state.SHELL: shell}))
                if (changes, shell) == ("none", "none"):
                    assert (got.kind, got.cause_code) == (base.kind, base.cause_code), probe
                elif got.kind != base.kind:
                    assert (base.kind, got.kind) == ("allow", "escalate") and got.cause_code in (133, 134), (probe, changes, shell)


def test_the_two_rules_fire_on_what_the_default_allows():
    policy = _policy()

    def cause(state, **reading):
        return policy.decide(policy.reading_bytes({**BASE, **reading, **state})).cause_code

    protected = {session_state.CHANGES: "some", session_state.SHELL: "none"}
    assert cause(protected, **WRITE) == 133
    assert cause(protected, tool="write_file", path_scope="workspace", zone_reach="none") == 133
    assert cause(protected, tool="git", git_op="local_write", path_scope="workspace") == 133
    assert cause(protected, tool="git", git_op="push", remote_class="allowed", path_scope="none") == 133
    assert cause(protected, tool="read_file", path_scope="workspace") is None            # reading stays free
    assert cause(protected, **SHELL) is None
    many = {session_state.CHANGES: "none", session_state.SHELL: "many"}
    assert cause(many, **SHELL) == 134
    assert cause(many, tool="run_command", command_class="git", git_op="local_read", path_scope="none") == 134
    assert cause(many, **WRITE) is None                                                   # the budget is about shell runs
    assert cause(many, tool="read_file", path_scope="workspace") is None


def test_the_session_starter_compiles_to_the_same_sandbox_as_the_default():
    from prismpath.agent.profile import compile_profile
    assert compile_profile(_policy().image).hash() == compile_profile(_policy("default").image).hash()
    assert compile_profile(_policy().image, "agent").hash() == compile_profile(_policy("default").image, "agent").hash()


def test_the_source_compiles_to_the_shipped_image_byte_for_byte():
    from prismpath.kernel import policy_source
    here = Path(starter_path("session")).parent
    image = policy_source.compile_source((here / "agent_session.rules.md").read_text(encoding="utf-8"), "agent_session.rules.md")
    assert image + b"\n" == (here / "agent_session.core.json").read_bytes()


# ----------------------------------------------------------------------------------------------- the hook, end to end
@pytest.fixture()
def hooked(tmp_path, monkeypatch):
    """A recorded `session` policy, a workspace, and a function that sends the hook one PreToolUse input."""
    home, ws = tmp_path / "home", tmp_path / "ws"
    (home / "tmp").mkdir(parents=True)
    ws.mkdir()
    for name in ("CLAUDE_PROJECT_DIR", "XDG_CONFIG_HOME", "APPDATA"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(sandbox_hook, "supported", lambda: False)         # decided and not confined: the state is the point here
    import io
    assert commands.init(ws, yes=True, as_json=True, policy="session", out=io.StringIO()) == 0
    env = dict(os.environ)

    class World:
        pass
    world = World()
    world.home, world.ws, world.env = commands.config_dir(env), ws, env
    world.point = Table(**{"secure.py": "protected", "plain.py": "none"})
    monkeypatch.setattr(zones, "information_point", lambda *args, **kwargs: world.point)
    counter = iter(range(10 ** 6))

    world.launch = None

    def send(tool, tool_input, session="sess", event="PreToolUse"):
        payload = {"session_id": session, "transcript_path": "/x/t.jsonl", "cwd": str(ws), "permission_mode": "default",
                   "hook_event_name": event, "tool_name": tool, "tool_input": tool_input,
                   "tool_use_id": f"toolu_{next(counter)}"}
        answer = commands.hook(json.dumps(payload).encode(), env, launch=world.launch)
        out = answer["hookSpecificOutput"]
        return out["permissionDecision"], out.get("permissionDecisionReason", "")

    world.send = send
    world.write = lambda name, session="sess": send("Write", {"file_path": str(ws / name), "content": "x"}, session)
    world.shell = lambda cmd="ls", session="sess": send("Bash", {"command": cmd}, session)
    world.journal = lambda session="sess": [canon2.loads(line) for line in
                                            (world.home / "runs" / session / "journal.jsonl").read_bytes().split(b"\n")[:-1]]
    return world


def test_a_protected_change_makes_the_next_change_in_the_session_wait_and_another_session_is_unaffected(hooked):
    assert hooked.write("plain.py")[0] == "allow"
    assert hooked.write("secure.py")[0] == "ask"                                   # 132: the zone rule
    decision, reason = hooked.write("plain.py")
    assert decision == "ask" and "133 agent:session-change-asked" in reason         # allowed before, asked now
    assert hooked.shell("ls")[0] == "allow"                                          # reading stays free
    assert hooked.write("plain.py", session="other")[0] == "allow"
    readings = [canon2.loads(bytes.fromhex(line["reading"])) for line in hooked.journal()]
    assert [r["session_protected_changes"] for r in readings] == ["none", "none", "some", "some"]
    assert all(r["session_shell_runs"] in ("none", "few") for r in readings)


def test_a_session_that_ran_many_shell_commands_is_asked_about_the_next_one(hooked):
    for _ in range(session_state.SHELL_MANY):
        assert hooked.shell("ls")[0] == "allow"
    decision, reason = hooked.shell("ls")
    assert decision == "ask" and "134 agent:session-shell-asked" in reason
    assert hooked.write("plain.py")[0] == "allow"                                    # a budget of shell runs, not of calls
    assert len(hooked.journal()) == session_state.SHELL_MANY + 2


def test_a_history_that_cannot_be_read_asks_about_what_would_run(hooked):
    assert hooked.write("plain.py")[0] == "allow"
    torn = hooked.home / "runs" / "sess" / run_module.JOURNAL
    torn.write_bytes(torn.read_bytes() + b'{"i":1')
    decision, reason = hooked.write("plain.py")
    assert decision == "ask" and "133" in reason
    decision, reason = hooked.shell("ls")
    assert decision == "ask" and "134" in reason
    assert hooked.send("Read", {"file_path": str(hooked.ws / "plain.py")})[0] == "allow"      # a read is not restricted by it


def test_a_corrupt_journal_denies_rather_than_decides(hooked):
    assert hooked.write("plain.py")[0] == "allow"
    path = hooked.home / "runs" / "sess" / run_module.JOURNAL
    path.write_bytes(path.read_bytes().replace(b'"i":0', b'"i":9'))
    assert hooked.write("plain.py")[0] == "deny"


def test_a_receipt_appended_between_the_read_and_the_append_makes_the_decision_again(hooked, monkeypatch):
    """Two parallel tool calls of one turn: the second must not be decided on the state from before the first."""
    real, injected = run_module.Run.append, []

    def racing(self, reading, verdict, *args, **kwargs):
        if not injected:             # a protected change slips in after this call read the state and before it appends
            injected.append(True)
            policy = _policy()
            real(self, policy.reading_bytes({**BASE, **WRITE, "zone_reach": "protected", **FRESH}),
                 policy.decide(policy.reading_bytes({**BASE, **WRITE, "zone_reach": "protected", **FRESH})).verdict)
        return real(self, reading, verdict, *args, **kwargs)
    monkeypatch.setattr(run_module.Run, "append", racing)
    decision, reason = hooked.write("plain.py")
    assert decision == "ask" and "133" in reason                                      # decided again on the new state
    readings = [canon2.loads(bytes.fromhex(line["reading"])) for line in hooked.journal()]
    assert [r["session_protected_changes"] for r in readings] == ["none", "some"] and len(readings) == 2


def test_concurrent_hooks_of_one_session_each_see_every_receipt_before_them(hooked):
    """Ten parallel writes to the one protected file and then one: the later ones are decided with the earlier receipts counted."""
    results = []

    def one():
        results.append(hooked.write("secure.py")[0])
    threads = [threading.Thread(target=one) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ["ask"] * 6
    assert hooked.write("plain.py")[0] == "ask"
    readings = [canon2.loads(bytes.fromhex(line["reading"])) for line in hooked.journal()]
    assert len(readings) == 7 and sorted(r["session_protected_changes"] for r in readings).count("some") >= 1


def test_a_stateless_starter_writes_no_session_field_and_decides_as_before(tmp_path, monkeypatch):
    home, ws = tmp_path / "home", tmp_path / "ws"
    home.mkdir()
    ws.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(sandbox_hook, "supported", lambda: False)
    import io
    assert commands.init(ws, yes=True, as_json=True, policy="default", out=io.StringIO()) == 0
    payload = {"session_id": "s", "cwd": str(ws), "hook_event_name": "PreToolUse", "tool_name": "Write",
               "tool_input": {"file_path": str(ws / "a.txt"), "content": ""}, "tool_use_id": "toolu_1"}
    assert commands.hook(json.dumps(payload).encode(), dict(os.environ))["hookSpecificOutput"]["permissionDecision"] == "allow"
    line = (commands.config_dir(dict(os.environ)) / "runs" / "s" / "journal.jsonl").read_bytes().split(b"\n")[0]
    assert "session_" not in bytes.fromhex(canon2.loads(line)["reading"]).decode()


# ----------------------------------------------------------------------------------------------- the counts the prefix keeps
MIX = [{**WRITE, "zone_reach": "none"}, SHELL, {**SHELL, "command_class": "mutating"}, {**WRITE, "path_scope": "outside"},
       {"tool": "read_file", "path_scope": "workspace"}, {**WRITE, "zone_reach": "protected"}, {**SHELL, "path_scope": "outside"}]


def test_the_counts_the_prefix_record_keeps_are_the_counts_of_every_line(store):
    import random
    rng = random.Random(5)
    policy = _policy()
    run = store.open("s", policy.image)
    for n in range(1, 80):
        state = session_state.read(store, "s")[0]
        _append(run, policy, rng.choice(MIX[:5]) if n < 60 else rng.choice(MIX), state)
        count, counts = run.session_counts()
        assert count == n and session_state.fields(counts) == session_state.derive(run.snapshot()[1])
        assert canon2.loads((run.dir / run_module.PREFIX).read_bytes())["state"] == counts


def test_a_call_reads_only_the_lines_appended_since_the_record(store, monkeypatch):
    policy = _policy()
    run = store.open("s", policy.image)
    for _ in range(40):
        _append(run, policy, SHELL)
    stepped = []
    real = session_state.step
    monkeypatch.setattr(session_state, "step", lambda counts, entry: stepped.append(1) or real(counts, entry))
    assert run.session_counts() == (40, {"changes": 0, "shell": 40}) and stepped == []
    _append(run, policy, SHELL)
    assert len(stepped) == 1 and run.session_counts()[1]["shell"] == 41 and len(stepped) == 1


@pytest.mark.parametrize("state", [None, {"changes": 2, "shell": 0}, {"changes": 0, "shell": -1}, {"changes": 0},
                                   {"changes": True, "shell": 0}, "x"])
def test_a_record_with_no_counts_or_counts_of_the_wrong_shape_means_the_whole_journal_is_read(store, state):
    policy = _policy()
    run = store.open("s", policy.image)
    _append(run, policy, {**WRITE, "zone_reach": "protected"})
    _append(run, policy, SHELL)
    path = run.dir / run_module.PREFIX
    record = canon2.loads(path.read_bytes())
    record.pop("state")
    if state is not None:
        record["state"] = state
    path.write_bytes(canon2.dumps(record))
    assert run.session_counts() == (2, {"changes": 1, "shell": 1})
    assert canon2.loads(path.read_bytes())["state"] == {"changes": 1, "shell": 1}


def test_an_unreadable_reading_leaves_the_counts_unknown_and_the_state_the_most_restrictive(store):
    policy = _policy("default")
    run = store.open("s", policy.image)
    run.append(canon2.dumps([1, 2]), {"verdict": "route", "target": "allow", "edge": 0})
    assert "state" not in canon2.loads((run.dir / run_module.PREFIX).read_bytes())
    assert session_state.read(store, "s") == (RESTRICTIVE, None)


# ----------------------------------------------------------------------------------------------- one launch, many sessions
def test_under_one_launch_a_new_session_keeps_the_state_of_the_sessions_before_it(hooked):
    hooked.launch = []
    assert hooked.write("secure.py", session="first")[0] == "ask"
    decision, reason = hooked.write("plain.py", session="after-clear")
    assert decision == "ask" and "133" in reason
    assert hooked.launch == ["first", "after-clear"]
    reading = canon2.loads(bytes.fromhex(hooked.journal("after-clear")[0]["reading"]))
    assert reading["session_protected_changes"] == "some"
    hooked.launch = None                                               # the stdin hook: each session its own
    assert hooked.write("plain.py", session="elsewhere")[0] == "allow"


def test_under_one_launch_shell_runs_add_up_across_sessions(hooked):
    hooked.launch = []
    for k in range(session_state.SHELL_MANY):
        assert hooked.shell("ls", session=f"s{k % 3}")[0] == "allow"
    decision, reason = hooked.shell("ls", session="s9")
    assert decision == "ask" and "134" in reason


def test_under_one_launch_an_earlier_session_that_cannot_be_read_makes_the_state_the_most_restrictive(hooked):
    hooked.launch = []
    assert hooked.write("plain.py", session="first")[0] == "allow"
    path = hooked.home / "runs" / "first" / run_module.JOURNAL
    path.write_bytes(path.read_bytes() + b'{"i":1')
    decision, reason = hooked.shell("ls", session="second")
    assert decision == "ask" and "134" in reason


def test_the_decider_keeps_one_launch_list_for_every_call(monkeypatch, tmp_path):
    from prismpath.agent import decider
    seen = []
    monkeypatch.setattr(commands, "hook", lambda raw, env, nested=None, launch=None: seen.append(launch) or {})
    d = decider.Decider(tmp_path / "d.sock", env={})
    d._handler(b"{}")
    d._handler(b"{}")
    assert seen[0] is d.launch and seen[1] is d.launch and isinstance(d.launch, list)


def test_the_starters_are_the_four():
    assert sorted(STARTERS) == ["default", "review", "session", "strict"]
