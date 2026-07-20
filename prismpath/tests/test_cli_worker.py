"""The generic CLI-worker contract (cli_worker.py): any command-line program as a flow worker.

A fake CLI (a tiny Python script written into tmp_path) exercises every leg: JSON-on-stdout ->
dict outcome feeding `when` predicates; plain stdout -> text; nonzero exit -> CliWorkerError ->
the flow's ERROR TIER routes it (retry budget as edges); timeout -> routable error_message;
per-node command maps (engine-heterogeneous routing); state passing via stdin.
"""
import json
import sys
import textwrap

import pytest

from prismpath.cli_worker import CliWorker, CliWorkerError, cli_agent
from prismpath.engine import run
from prismpath.parser import parse

PY = sys.executable


def fake_cli(tmp_path, body: str) -> list:
    """A one-file CLI: `body` runs with stdin available as `data` and helpers imported."""
    script = tmp_path / "fake_cli.py"
    script.write_text(textwrap.dedent(f"""\
        import json, sys, time
        data = sys.stdin.read() if not sys.stdin.isatty() else ""
        {textwrap.indent(textwrap.dedent(body), "        ").strip()}
        """))
    return [PY, str(script)]


def test_json_stdout_becomes_dict_outcome(tmp_path):
    cmd = fake_cli(tmp_path, 'print(json.dumps({"text": "all green", "tests_pass": True}))')
    w = CliWorker(cmd)
    out = w("run_tests", "run the suite", {})
    assert out["tests_pass"] is True and out["text"] == "all green"


def test_plain_stdout_becomes_text(tmp_path):
    cmd = fake_cli(tmp_path, 'print("wrote the fix, two files changed")')
    assert CliWorker(cmd)("implement", "fix it", {}) == "wrote the fix, two files changed"


def test_non_object_json_stays_text(tmp_path):
    cmd = fake_cli(tmp_path, 'print("[1, 2, 3]")')                # array is NOT an outcome contract
    assert CliWorker(cmd)("n", "i", {}) == "[1, 2, 3]"


def test_nonzero_exit_raises_with_stderr_tail(tmp_path):
    cmd = fake_cli(tmp_path, 'sys.stderr.write("rate limited by upstream"); sys.exit(3)')
    with pytest.raises(CliWorkerError) as ei:
        CliWorker(cmd)("n", "i", {})
    assert "exit 3" in str(ei.value) and "rate limited" in str(ei.value)


def test_timeout_raises_routable_message(tmp_path):
    cmd = fake_cli(tmp_path, "time.sleep(5)")
    with pytest.raises(CliWorkerError) as ei:
        CliWorker(cmd, timeout=0.5)("n", "i", {})
    assert "timeout" in str(ei.value)


def test_unlaunchable_command_raises(tmp_path):
    with pytest.raises(CliWorkerError):
        CliWorker(["/nonexistent/binary"])("n", "i", {})


def test_instruction_and_state_arrive_on_stdin(tmp_path):
    cmd = fake_cli(tmp_path, 'print(json.dumps({"text": "echo", "got": data}))')
    w = CliWorker(cmd, pass_state=["ticket"])
    out = w("classify", "triage this ticket", {"ticket": {"id": 7}, "private": "hidden"})
    assert "triage this ticket" in out["got"]
    assert '"id": 7' in out["got"]                        # requested state passed
    assert "hidden" not in out["got"]                     # unrequested state is NOT leaked


def test_argv_templating(tmp_path):
    marker = tmp_path / "seen.txt"
    script = tmp_path / "argv_cli.py"
    script.write_text("import sys\nopen(sys.argv[2], 'w').write(sys.argv[1])\nprint('ok')\n")
    w = CliWorker([PY, str(script), "task-{node}", str(marker)], stdin=False)
    assert w("review", "look at it", {}) == "ok"
    assert marker.read_text() == "task-review"


def test_per_node_map_and_default(tmp_path):
    a = fake_cli(tmp_path, 'print(json.dumps({"text": "engine A", "engine": "a"}))')
    (tmp_path / "b.py").write_text('print("engine B")')
    agent = cli_agent({"implement": a}, default=[PY, str(tmp_path / "b.py")])
    assert agent("implement", "x", {})["engine"] == "a"
    assert agent("review", "x", {}) == "engine B"
    strict = cli_agent({"implement": a})                  # no default -> unmapped raises (error tier)
    with pytest.raises(CliWorkerError):
        strict("review", "x", {})


def test_cli_failures_ride_the_error_tier_in_a_real_flow(tmp_path):
    # the whole point: a flaky CLI gets a retry budget and an escalation path as EDGES.
    state_file = tmp_path / "attempts.txt"
    cmd = fake_cli(tmp_path, f"""\
        n = int(open({str(state_file)!r}).read() or 0) if __import__('os').path.exists({str(state_file)!r}) else 0
        open({str(state_file)!r}, 'w').write(str(n + 1))
        if n < 2:
            sys.stderr.write("503 upstream"); sys.exit(1)
        print(json.dumps({{"text": "200 OK", "ok": True}}))
        """)
    flow = parse("""---
name: resilient
start: call
---

## call
Call the flaky CLI.
-> done: when ok
-> gave_up: on error when error_count >= 3
-> call: on error

## done
Done.

## gave_up
Escalated.
""")
    res = run(flow, cli_agent(cmd))
    assert res.stopped == "terminal" and res.path[-1] == "done"
    assert state_file.read_text() == "3"                  # failed twice, succeeded third — as edges
