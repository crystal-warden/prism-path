# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The stdio MCP proxy: every tools/call decided and receipted before the server sees it, everything else
relayed as the same bytes. Driven over pipes against a fake server that records what reaches it."""
import io
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import classifier, mcp_map, mcp_proxy, policy as policymod  # noqa: E402
from prismpath.agent.run import RunStore  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FAKE = Path(__file__).resolve().parent / "fixtures" / "mcp_fake_server.py"
RULES = policymod.POLICY_PATH          # agent_rules: unknown refuses (104), a push escalates (113)


def make_home(path, policy=RULES):
    """An agent directory as `agent init` leaves it: both key pairs, and `policy` recorded with its attestation."""
    from prismpath.agent import commands
    commands._make_dir(path)
    for role in commands.KEY_ROLES:
        commands._ensure_key(path, role)
    image = policymod.Policy.load(policy).image
    (path / commands.POLICY_FILE).write_bytes(image)
    (path / commands.ATTESTATION_FILE).write_bytes(commands._attestation(path, image))
    return path


class Client:
    """The proxy as a child process, with its answers collected by id."""

    def __init__(self, tmp_path, policy=RULES, session="s1", keys=None, home=None, explicit=False):
        home = home or make_home(tmp_path / "agenthome", policy)
        self.log = tmp_path / "server"
        self.log.mkdir(exist_ok=True)
        self.workspace = tmp_path / "ws"
        self.workspace.mkdir(exist_ok=True)
        self.runs, self.session = tmp_path / "runs", session
        env = dict(os.environ, PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
        cmd = [sys.executable, "-m", "prismpath.agent.mcp_proxy", "--home", str(home), "--runs", str(self.runs),
               "--session", session, "--workspace", str(self.workspace)]
        if explicit:
            cmd += ["--policy", str(policy)]
        if keys is not None:
            cmd += ["--keys", str(keys)]
        cmd += ["--", sys.executable, str(FAKE), str(self.log)]
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=str(self.workspace),
                                     env=env)
        self.lines = queue.Queue()
        self.raw = []
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in iter(self.proc.stdout.readline, b""):
            self.raw.append(line)
            self.lines.put(line)

    def send_bytes(self, data: bytes):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def send(self, message):
        self.send_bytes(json.dumps(message).encode() + b"\n")

    def recv(self, timeout=20):
        return json.loads(self.lines.get(timeout=timeout))

    def call(self, ident, name, arguments, meta=None):
        params = {"name": name, "arguments": arguments}
        if meta is not None:
            params["_meta"] = meta
        self.send({"jsonrpc": "2.0", "id": ident, "method": "tools/call", "params": params})
        return self.recv()

    def close(self):
        self.proc.stdin.close()
        code = self.proc.wait(timeout=20)
        return code

    def calls(self):
        path = self.log / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def run(self):
        return RunStore(self.runs).get(self.session)


def _text(answer):
    return answer["result"]["content"][0]["text"]


@pytest.fixture
def client(tmp_path):
    c = Client(tmp_path)
    yield c
    if c.proc.poll() is None:
        c.proc.kill()


INIT = (b'{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-11-25", '
        b'"capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}\n')
LIST = b'{"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}}\n'
NOTE = b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
DISCOVER = (b'{"jsonrpc":"2.0","id":9,"method":"server/discover","params":{"_meta":'
            b'{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}\n')


def test_initialize_tools_list_and_notifications_pass_through_byte_for_byte(client):
    for line in (INIT, NOTE, LIST, DISCOVER):
        client.send_bytes(line)
    answers = [client.recv() for _ in range(3)]
    assert [a["id"] for a in answers] == [0, "list-1", 9]
    assert client.close() == 0
    assert (client.log / "received.bin").read_bytes() == INIT + NOTE + LIST + DISCOVER
    assert b"".join(client.raw) == (client.log / "sent.bin").read_bytes()
    assert [t["name"] for t in answers[1]["result"]["tools"]][:3] == ["list_dir", "read_file", "git"]


def test_an_allowed_call_reaches_the_server_and_its_answer_returns(client):
    answer = client.call(1, "list_dir", {"path": "."})
    assert answer == {"jsonrpc": "2.0", "id": 1,
                      "result": {"content": [{"type": "text", "text": 'ran list_dir {"path": "."}'}], "isError": False}}
    answer = client.call(2, "read_text_file", {"path": str(client.workspace / "notes.txt")})
    assert not answer["result"]["isError"]
    client.close()
    assert [c["id"] for c in client.calls()] == [1, 2]
    assert b"".join(client.raw) == (client.log / "sent.bin").read_bytes()


def test_a_refused_call_never_reaches_the_server(client):
    answer = client.call(1, "read_file", {"path": "/etc/passwd"})
    assert answer["id"] == 1 and answer["result"]["isError"] is True
    assert "agent:outside-workspace (111)" in _text(answer) and "Receipt 0 of run s1" in _text(answer)
    unknown = client.call(2, "fetch_url", {"url": "https://example.com"})
    assert "agent:unclassifiable (104)" in _text(unknown) and "Receipt 1 of run s1" in _text(unknown)
    client.close()
    assert client.calls() == []


def test_an_escalated_call_never_reaches_the_server(client):
    answer = client.call("p", "git", {"subcommand": "push", "args": ["origin", "main"]})
    text = _text(answer)
    assert answer["result"]["isError"] is True and answer["id"] == "p"
    assert "approval" in text and "agent:push-escalated (113)" in text and "Receipt 0" in text
    client.close()
    assert client.calls() == []


def test_a_proxy_answer_carries_result_type_in_the_2026_era(client):
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    answer = client.call(1, "read_file", {"path": "/etc/passwd"}, meta=meta)
    assert answer["result"]["resultType"] == "complete" and answer["result"]["isError"] is True
    assert "resultType" not in client.call(2, "read_file", {"path": "/etc/passwd"})["result"]
    client.close()


def _refused_everything(c):
    try:
        c.send_bytes(INIT)
        assert c.recv()["id"] == 0
        answer = c.call(1, "list_dir", {"path": "."})
        assert answer["result"]["isError"] is True
        assert "the policy could not be loaded" in _text(answer) and "No receipt was written" in _text(answer)
    finally:
        c.close()
    assert c.calls() == []


def test_no_recorded_policy_refuses_every_call_and_relays_the_rest(tmp_path):
    _refused_everything(Client(tmp_path, home=tmp_path / "empty"))


def test_a_policy_that_does_not_verify_refuses_every_call(tmp_path):
    home = make_home(tmp_path / "agenthome")
    from prismpath.agent import commands
    image = (home / commands.POLICY_FILE).read_bytes()
    (home / commands.POLICY_FILE).write_bytes(image + b" ")     # no longer the attested bytes
    _refused_everything(Client(tmp_path, home=home))


def test_an_explicit_policy_that_is_not_the_recorded_one_is_refused(tmp_path):
    other = policymod.HERE / "policy" / "agent_default.core.json"
    assert policymod.Policy.load(other).image != policymod.Policy.load(RULES).image
    _refused_everything(Client(tmp_path, policy=other, home=make_home(tmp_path / "agenthome", RULES), explicit=True))


def test_an_explicit_policy_that_is_the_recorded_one_is_used(tmp_path):
    c = Client(tmp_path, explicit=True)
    try:
        assert c.call(1, "list_dir", {"path": "."})["result"].get("isError") is not True
        assert c.call(2, "read_file", {"path": "/etc/passwd"})["result"]["isError"] is True
    finally:
        c.close()


def test_receipts_are_in_the_run_and_it_verifies_with_both_keys_pinned(tmp_path):
    keys = tmp_path / "keys"
    c = Client(tmp_path, keys=keys)
    c.call(1, "list_dir", {"path": "."})
    c.call(2, "read_file", {"path": "/etc/passwd"})
    c.call(3, "git", {"subcommand": "push", "args": ["origin", "main"]})
    c.call(4, "git", {"subcommand": "status", "args": []})
    c.call(5, "nope", {})
    assert c.close() == 0
    run = c.run()
    assert not run.is_open()                       # sealed by the proxy at its end
    summary = run.verify(keys)
    assert summary["receipts"] == 5 and summary["replayed"] == 5 and summary["disagree"] == 0
    assert summary["root_statement"] == "signed"
    receipts = [json.loads(line) for line in (run.dir / "receipts.jsonl").read_text().splitlines()]
    assert [r["idx"] for r in receipts] == [0, 1, 2, 3, 4]
    assert [c2["id"] for c2 in c.calls()] == [1, 4]
    # the pins are the keys': another key pair does not verify this run
    from prismpath.ledgers import core_evidence
    other = tmp_path / "other"
    core_evidence.ensure_keys(other)
    with pytest.raises(core_evidence.Bad):
        core_evidence.verify(run.dir, sample=None, pin_authority=other / "authority.pub",
                             pin_instance=other / "instance.pub")


def test_concurrent_requests_with_interleaved_ids_keep_their_ids(tmp_path):
    allow_all = tmp_path / "allow.core.json"
    from prismpath.kernel import canon2
    src = json.loads(policymod.SOURCE_PATH.read_text())
    src["rules"] = [{"target": "allow", "when": ["cmp", "tool", "==", ["str", "unknown"]]}] + src["rules"]
    allow_all.write_bytes(canon2.canonicalize(json.dumps(src).encode()) + b"\n")
    c = Client(tmp_path, policy=allow_all)
    requests = []
    for n in range(8):
        ident = n if n % 2 else f"req-{n}"
        requests.append(ident)
        c.send({"jsonrpc": "2.0", "id": ident, "method": "tools/call",
                "params": {"name": "slow_echo", "arguments": {"token": f"t{n}", "delay": (8 - n) * 0.25}}})
        if n == 3:
            c.send({"jsonrpc": "2.0", "id": "refused", "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}})
    c.send_bytes(LIST)
    answers = [c.recv() for _ in range(10)]
    c.close()
    by_id = {a["id"]: a for a in answers}
    assert len(answers) == 10 and set(by_id) == set(requests) | {"refused", "list-1"}
    for n, ident in enumerate(requests):
        assert _text(by_id[ident]) == f"echo t{n}"
    assert "agent:outside-workspace (111)" in _text(by_id["refused"])
    order = [a["id"] for a in answers]
    # the proxy's own answer and the passthrough come back before the slow calls, which return out of order;
    # the delays leave over a second between them, so a slow runner's receipt appends (each fsynced) cannot reorder them
    assert order.index("refused") < order.index("req-0") and order.index(7) < order.index("req-0")
    assert sorted(map(str, (x["id"] for x in c.calls()))) == sorted(map(str, requests))


def test_unreadable_lines_and_repeated_keys_are_never_forwarded(client):
    sneaky = (b'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file",'
              b'"arguments":{"path":"/etc/passwd"}},"method":"tools/list"}\n')
    client.send_bytes(sneaky)
    assert client.recv()["error"]["code"] == -32600
    client.send_bytes(b"not json\n")
    assert client.recv()["error"]["code"] == -32700
    client.send_bytes(b'{"jsonrpc":"2.0","id":6,"method":"tools/list"}\xff\n')
    assert client.recv()["error"]["code"] == -32700
    client.send_bytes(b"7\n")
    assert client.recv()["error"]["code"] == -32600
    client.close()
    assert not (client.log / "received.bin").exists()


def test_a_tools_call_notification_is_decided_and_forwarded_only_when_allowed(client):
    client.send({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}})
    client.send({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "list_dir", "arguments": {}}})
    client.send_bytes(LIST)
    assert client.recv()["id"] == "list-1"     # nothing is answered for a notification
    client.close()
    assert client.calls() == [{"id": None, "params": {"name": "list_dir", "arguments": {}}}]
    assert len(client.run()._entries()) == 2


def test_a_batch_is_split_into_what_runs_and_what_is_withheld(client):
    plain = b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]\n'
    client.send_bytes(plain)
    plain_answer = client.recv()
    assert isinstance(plain_answer, list) and plain_answer[0]["id"] == 1 and "tools" in plain_answer[0]["result"]
    batch = [{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_dir", "arguments": {}}},
             {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}},
             {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}]
    client.send(batch)
    first, second = client.recv(), client.recv()
    withheld = first if any(a["id"] == 3 for a in first) else second
    ran = second if withheld is first else first
    assert [a["id"] for a in withheld] == [3] and withheld[0]["result"]["isError"] is True
    assert sorted(a["id"] for a in ran) == [2, 4]
    client.close()
    assert (client.log / "received.bin").read_bytes().startswith(plain)
    assert [c["id"] for c in client.calls()] == [2]


# ------------------------------------------------------------------ in process: receipts fail closed
def _proxy(tmp_path, run_append=None):
    gov = mcp_proxy.Governor(make_home(tmp_path / "agenthome"), tmp_path / "runs", "s", tmp_path, str(tmp_path))
    if run_append is not None:
        gov.run.append = run_append
    child, out = io.BytesIO(), io.BytesIO()
    return mcp_proxy.Proxy(gov, child, out), child, out


def test_a_call_whose_receipt_is_not_appended_is_refused_and_not_forwarded(tmp_path):
    def broken(*_a, **_k):
        raise OSError("disk full")
    proxy, child, out = _proxy(tmp_path, broken)
    proxy.client_line(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_dir","arguments":{}}}\n')
    answer = json.loads(out.getvalue())
    assert answer["result"]["isError"] is True and "receipt could not be written" in _text(answer)
    assert child.getvalue() == b""


def test_a_decision_failure_refuses(tmp_path, monkeypatch):
    proxy, child, out = _proxy(tmp_path)
    monkeypatch.setattr(proxy.governor.policy, "decide", lambda raw: (_ for _ in ()).throw(RuntimeError("boom")))
    proxy.client_line(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_dir","arguments":{}}}\n')
    assert "could not be decided" in _text(json.loads(out.getvalue())) and child.getvalue() == b""


def test_a_run_that_cannot_be_opened_refuses(tmp_path):
    RunStore(tmp_path / "runs").open("s", b"another image")
    gov = mcp_proxy.Governor(make_home(tmp_path / "agenthome"), tmp_path / "runs", "s", tmp_path, str(tmp_path))
    assert gov.failure and "run could not be opened" in gov.failure
    assert gov.decide({"name": "list_dir", "arguments": {}}).kind == "refuse"


def test_the_proxy_has_no_unattested_default_policy():
    assert not hasattr(mcp_proxy, "default_policy_path")


# ------------------------------------------------------------------ the mapping
@pytest.mark.parametrize("params, call", [
    ({"name": "list_dir", "arguments": {"path": "src"}}, {"tool": "list_dir", "args": {"path": "src"}}),
    ({"name": "git", "arguments": {"subcommand": "status"}}, {"tool": "git", "args": {"subcommand": "status"}}),
    ({"name": "read_text_file", "arguments": {"path": "/workspace/a", "head": 3}},
     {"tool": "read_file", "args": {"path": "/./workspace/a"}}),
    ({"name": "read_text_file", "arguments": {"path": "a"}}, {"tool": "read_file", "args": {"path": "/srv/a"}}),
    ({"name": "edit_file", "arguments": {"path": "/srv/a", "edits": []}},
     {"tool": "write_file", "args": {"path": "/srv/a", "content": ""}}),
    ({"name": "search_files", "arguments": {"path": "/srv", "pattern": "*.py"}},
     {"tool": "list_dir", "args": {"path": "/srv/*.py"}}),
    ({"name": "list_allowed_directories", "arguments": {}}, {"tool": "list_dir", "args": {}}),
    ({"name": "move_file", "arguments": {"source": "a", "destination": "b"}}, {"tool": "unknown", "args": {}}),
    ({"name": "read_text_file", "arguments": {"path": "~/.ssh/id"}}, {"tool": "unknown", "args": {}}),
    ({"name": "read_text_file", "arguments": {"path": "a", "extra": 1}}, {"tool": "unknown", "args": {}}),
    ({"name": "list_dir", "arguments": "x"}, {"tool": "unknown", "args": {}}),
    ({"arguments": {}}, {"tool": "unknown", "args": {}}),
    (None, {"tool": "unknown", "args": {}}),
])
def test_the_mapping(params, call):
    assert mcp_map.classifier_call(params, "/srv") == call


def test_a_classifier_name_with_another_schema_reads_as_unknown(tmp_path):
    call = mcp_map.classifier_call({"name": "read_file", "arguments": {"path": "a", "head": 2}}, str(tmp_path))
    assert classifier.classify(call, classifier.Config.for_workspace(tmp_path))["tool"] == "unknown"
