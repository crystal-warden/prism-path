# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The operating interface of Mission Control (the operator and the engineer): event delivery to a
`waiting` run, the human queue with its nested fan-out children, the policy host read from a state
directory under the evidence roots, the cause monitor's series, and the labels the lens reads from the
records the producers write.

These are the WP6 tests of the Mission Control plan (docs/design/mission-control-plan.md, section 4).
An event is recorded into a waiting checkpoint the way a decision is recorded into a suspended one, and
the run's next resume applies it, so the console never needs the flow's worker. The server is driven
through fastapi.testclient only and never bound to an address."""
import json
import os
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from prismpath.kernel import canon2  # noqa: E402
from prismpath.ledgers import checkpoint  # noqa: E402
from prismpath.tests.test_queue_event import (GATE, WATCH, _gate_agent, _scripted_worker,  # noqa: E402
                                              _waiting_agent, _write)
from prismpath.ledgers import audit_log  # noqa: E402
from prismpath.mission_control import app as app_module  # noqa: E402
from prismpath.mission_control import core  # noqa: E402
from prismpath.mission_control.session import TOKEN_HEADER  # noqa: E402

API_V1 = "/api/v1"
FLOW = "---\nname: triage\nstart: a\n---\n## a\n-> b: when score > 5\n-> c: else\n## b\nDone.\n## c\nDone.\n"


def _client(application):
    return TestClient(application, base_url=f"http://127.0.0.1:{core.SETTINGS.port}",
                      headers={TOKEN_HEADER: application.state.session.token})


@pytest.fixture
def console(tmp_path, monkeypatch):
    """The console following one project, with the queue, an evidence root and its own audit log in
    tmp_path. Returns (queue dir, evidence root, the console's log)."""
    project = tmp_path / "proj"
    (project / "flows").mkdir(parents=True)
    (project / "flows" / "triage.md").write_text(FLOW, encoding="utf-8")
    (project / "status.json").write_text(json.dumps({"iteration": 1, "valid": True}), encoding="utf-8")
    queue = tmp_path / "queue"
    queue.mkdir()
    root = tmp_path / "evidence"
    root.mkdir()
    console_log = audit_log.AuditLog(str(tmp_path / "console" / "mission_audit.log"))
    monkeypatch.setenv("PRISMPATH_QUEUE_DIR", str(queue))
    monkeypatch.setattr(core.audit, "LOG", console_log)
    monkeypatch.setattr(core.SETTINGS, "scan", str(project / "status.json"))
    monkeypatch.setattr(core.SETTINGS, "registry", str(tmp_path / "no-registry.json"))
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [str(root)])
    core.STATE.update({"proc": None, "proj": str(project), "cfg": {}, "pinned": True})
    return queue, root, console_log


@pytest.fixture
def client(console):
    return _client(app_module.app)


def _actor():
    return f"console/operating/{app_module.app.state.session.fingerprint}"


def _run(tmp_path, queue, name, flow, agent, sub=None):
    folder = queue / sub if sub else queue
    folder.mkdir(parents=True, exist_ok=True)
    ckpt = folder / f"{name}.json"
    checkpoint.run_durable(_write(tmp_path, f"{name}.md", flow), agent, str(ckpt))
    return ckpt


def test_queue_event_records_the_event_decided_by_the_session_actor(client, console, tmp_path):
    queue, _root, log = console
    ckpt = _run(tmp_path, queue, "w1", WATCH, _waiting_agent)
    response = client.post(API_V1 + "/queue/event", json={"id": "w1", "event": "stand_down"})
    assert response.status_code == 200, response.text
    assert response.json() == {"ok": True, "id": "w1", "event": "stand_down"}
    saved = json.loads(ckpt.read_text(encoding="utf-8"))
    assert saved["pending_event"] == {"event": "stand_down", "decided_by": _actor()}
    assert [event["action"] for event in log.events] == ["queue.event", "queue.event.result"]
    intent, result = log.events
    assert intent["actor"] == result["actor"] == _actor()
    assert intent["data"] == {"id": "w1", "event": "stand_down"}
    assert result["data"]["intent"] == intent["idx"] and result["data"]["ok"] is True
    assert checkpoint.resume(str(ckpt), _scripted_worker([])).path == ["hold", "clear"]


def test_the_event_intent_is_written_before_the_checkpoint_changes(client, console, tmp_path, monkeypatch):
    queue, _root, log = console
    _run(tmp_path, queue, "w1", WATCH, _waiting_agent)
    seen = {}
    real = checkpoint.record_event

    def spy(path, event, decided_by="human"):
        seen["actions"] = [entry["action"] for entry in log.events]
        return real(path, event, decided_by=decided_by)
    monkeypatch.setattr(checkpoint, "record_event", spy)
    assert client.post(API_V1 + "/queue/event", json={"id": "w1", "event": "stand_down"}).status_code == 200
    assert seen["actions"] == ["queue.event"]


def test_an_audit_write_failure_leaves_the_waiting_checkpoint_unchanged(client, console, tmp_path, monkeypatch):
    queue, _root, _log = console
    ckpt = _run(tmp_path, queue, "w1", WATCH, _waiting_agent)
    before = ckpt.read_bytes()

    def refuse(self, actor, action, data):
        raise audit_log.AuditWriteError("disk full")
    monkeypatch.setattr(audit_log.AuditLog, "append", refuse)
    response = client.post(API_V1 + "/queue/event", json={"id": "w1", "event": "stand_down"})
    assert response.status_code == 503, response.text
    assert ckpt.read_bytes() == before


def test_queue_event_to_a_run_awaiting_a_human_is_refused_with_a_failed_result(client, console, tmp_path):
    queue, _root, log = console
    ckpt = _run(tmp_path, queue, "h1", GATE, _gate_agent)
    before = ckpt.read_bytes()
    response = client.post(API_V1 + "/queue/event", json={"id": "h1", "event": "stand_down"})
    assert response.status_code == 400
    assert "not waiting for an event" in response.json()["error"]["message"]
    assert ckpt.read_bytes() == before
    assert [event["action"] for event in log.events] == ["queue.event", "queue.event.result"]
    assert log.events[-1]["data"]["ok"] is False


def test_queue_event_refuses_an_id_outside_the_queue(client, console):
    response = client.post(API_V1 + "/queue/event", json={"id": "../outside", "event": "stand_down"})
    assert response.status_code == 400
    assert "escapes the queue dir" in response.json()["error"]["message"]


def test_the_queue_shows_waiting_runs_and_nested_children_and_both_are_actionable(client, console, tmp_path):
    queue, _root, _log = console
    _run(tmp_path, queue, "h1", GATE, _gate_agent)
    _run(tmp_path, queue, "w1", WATCH, _waiting_agent)
    _run(tmp_path, queue, "c1", GATE, _gate_agent, sub="p.children")
    _run(tmp_path, queue, "c2", WATCH, _waiting_agent, sub="p.children")
    items = {item["id"]: item for item in client.get(API_V1 + "/queue").json()["items"]}
    assert set(items) == {"h1", "w1", "p.children/c1", "p.children/c2"}
    assert items["p.children/c1"]["child_of"] == "p" and items["p.children/c1"]["stopped"] == "needs_human"
    assert items["p.children/c2"]["child_of"] == "p" and items["p.children/c2"]["awaiting"] == ["stand_down", "__timeout__"]
    assert {candidate["target"] for candidate in items["h1"]["candidates"]} == {"approve", "deny"}
    assert client.post(API_V1 + "/queue/decide", json={"id": "p.children/c1", "choose": "approve"}).status_code == 200
    assert client.post(API_V1 + "/queue/event", json={"id": "p.children/c2", "event": "__timeout__"}).status_code == 200
    items = {item["id"]: item for item in client.get(API_V1 + "/queue").json()["items"]}
    assert items["p.children/c1"]["decision"]["decided_by"] == _actor()
    assert items["p.children/c2"]["pending_event"] == {"event": "__timeout__", "decided_by": _actor()}


# ── the read only posture ──────────────────────────────────────────────────────────────────────
def test_the_read_only_posture_mounts_no_queue_post_route(console, tmp_path):
    queue, _root, log = console
    ckpt = _run(tmp_path, queue, "w1", WATCH, _waiting_agent)
    before = ckpt.read_bytes()
    read_only = app_module.create_app(read_only=True)
    schema = read_only.openapi()["paths"]
    assert not [path for path, operations in schema.items() if path.startswith(API_V1 + "/queue") and "post" in operations]
    full = app_module.create_app(read_only=False).openapi()["paths"]
    assert full[API_V1 + "/queue/event"]["post"]["x-prismpath-capability"] == "write"
    reader = _client(read_only)
    for path, body in (("/queue/event", {"id": "w1", "event": "stand_down"}), ("/queue/decide", {"id": "w1", "choose": "x"})):
        response = reader.post(API_V1 + path, json=body)
        assert response.status_code == 403, path
        assert "read-only" in response.json()["error"]["message"]
    assert ckpt.read_bytes() == before and log.events == []
    assert reader.get(API_V1 + "/queue").json()["items"][0]["id"] == "w1"


def test_the_operating_reads_stay_mounted_in_the_read_only_posture(console):
    reader = _client(app_module.create_app(read_only=True))
    for path in ("/queue", "/fanouts", "/interactions", "/status", "/trail/causes", "/policy/active?state_dir=."):
        assert reader.get(API_V1 + path).status_code == 200, path


# ── the cause monitor ──────────────────────────────────────────────────────────────────────────
def _fixture_log(path):
    text = b""
    for number, (seconds, action, cause) in enumerate(((0, "decision", 2), (30, "decision", 2), (59, "swap", None),
                                                       (60, "decision", 34), (185, "decision", 0))):
        data = {"cause": cause} if cause is not None else {"version": 1}
        event = {"idx": number, "id": str(number), "ts_us": (1_000_020 + seconds) * 1_000_000, "actor": "a",
                 "action": action, "data": data, "encoding": "canon/2"}
        text += canon2.dumps(event) + b"\n"
    path.write_bytes(text)


def test_the_cause_series_buckets_a_fixture_log(client, console):
    _queue, root, _log = console
    _fixture_log(root / "run.audit.jsonl")
    response = client.get(API_V1 + "/trail/causes", params={"path": "run.audit.jsonl", "bucket_s": 60})
    assert response.status_code == 200, response.text
    series = response.json()
    base = 1_000_020 // 60 * 60
    assert [bucket["start"] for bucket in series["buckets"]] == [base, base + 60, base + 180]
    assert series["buckets"][0]["by_cause"] == {"2": 2}
    assert series["buckets"][0]["by_action"] == {"decision": 2, "swap": 1}
    assert series["buckets"][1]["by_cause"] == {"34": 1}
    assert series["causes"]["34"]["name"] == "route:needs-human" and series["causes"]["0"]["clean"] is True
    assert series["verdict_of"] == "console" and series["events"] == 5
    assert client.get(API_V1 + "/trail/causes", params={"path": "run.audit.jsonl", "last": 1}).json()["events"] == 1


def test_the_cause_series_with_no_path_is_the_consoles_own_log(client, console):
    _queue, _root, log = console
    client.post(API_V1 + "/sprint/pause")
    series = client.get(API_V1 + "/trail/causes").json()
    assert series["path"] == os.path.realpath(log.path)
    assert sum(sum(bucket["by_action"].values()) for bucket in series["buckets"]) == 2


@pytest.mark.parametrize("params, status", [({"path": "/etc/hostname"}, 403), ({"path": "missing.jsonl"}, 404),
                                            ({"path": "run.audit.jsonl", "bucket_s": 0}, 400)])
def test_the_cause_series_refuses_what_it_may_not_read(client, console, params, status):
    _queue, root, _log = console
    _fixture_log(root / "run.audit.jsonl")
    response = client.get(API_V1 + "/trail/causes", params=params)
    assert response.status_code == status, response.text
    assert "error" in response.json()


# ── the policy host ────────────────────────────────────────────────────────────────────────────
def _swapped_state(state_dir, tmp_path):
    pytest.importorskip("cryptography")
    from prismpath.hotswap import policy_host, policy_pack
    from prismpath.kernel import ppt_compile
    from prismpath.kernel.parser import parse
    keys = policy_pack.keygen(str(tmp_path / "keys"))
    envelope = policy_pack.build_envelope("env1", {"temp": "int"}, None, keys["private"], keys["public"],
                                          str(tmp_path / "env"))
    ppt = tmp_path / "v1.ppt"
    ppt.write_bytes(ppt_compile.compile_flow(parse(
        "# f\n## start\n-> hot: when temp >= 100\n-> cold: else\n## hot\n-> end\n## cold\n-> end\n## end\n")).serialize())
    policy_pack.build_pack(str(ppt), {"temp": "int"}, version=1, envelope_id="env1",
                           priv_path=keys["private"], pub_path=keys["public"])
    host = policy_host.PolicyHost(str(state_dir), [keys["public"]], envelope)
    return host.swap(str(ppt))


def test_policy_active_reads_a_state_directory_under_the_evidence_roots(client, console, tmp_path):
    _queue, root, log = console
    swapped = _swapped_state(root / "edge" / "state", tmp_path)
    swaps_log = root / "edge" / "state" / "swaps.log"
    before, listing = swaps_log.read_bytes(), sorted(os.listdir(root / "edge" / "state"))
    response = client.get(API_V1 + "/policy/active", params={"state_dir": "edge/state"})
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["active"] == swapped["active"] and report["version"] == 1 and report["image_ok"] is True
    assert report["log"]["verifies"] is True and [event["action"] for event in report["history"]] == ["swap"]
    assert report["signing"]["status"] in ("unsigned", "signed-unpinned", "unchecked")
    assert report["evidence_root"] == os.path.realpath(root)
    assert swaps_log.read_bytes() == before and sorted(os.listdir(root / "edge" / "state")) == listing
    assert log.events == []


def test_policy_active_refuses_a_state_directory_outside_the_roots(client, console, tmp_path):
    outside = tmp_path / "elsewhere" / "state"
    response = client.get(API_V1 + "/policy/active", params={"state_dir": str(outside)})
    assert response.status_code == 403
    assert not outside.exists()


def test_policy_active_refuses_a_state_directory_that_links_out_of_the_roots(client, console, tmp_path):
    _queue, root, _log = console
    secret = tmp_path / "elsewhere.log"
    secret.write_text('{"idx": 0}\n', encoding="utf-8")
    (root / "edge").mkdir()
    os.symlink(secret, root / "edge" / "swaps.log")
    response = client.get(API_V1 + "/policy/active", params={"state_dir": "edge"})
    assert response.status_code == 403
    assert "idx" not in response.text


def test_policy_active_for_a_missing_directory_creates_nothing(client, console):
    _queue, root, _log = console
    response = client.get(API_V1 + "/policy/active", params={"state_dir": "no-such-state"})
    assert response.status_code == 404
    assert not (root / "no-such-state").exists()


# ── the lens reads its labels from the records the producers write ────────────────────────────
def test_the_served_chat_records_the_model_it_called(monkeypatch, tmp_path):
    from prismpath.orchestration import run_sprint
    recorded = []
    monkeypatch.setattr(run_sprint, "_ix", type("Ix", (), {"record": staticmethod(
        lambda *args, **meta: recorded.append(meta))}))

    class Answer:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": "ok"}}]}
    monkeypatch.setattr(run_sprint.requests, "post", lambda *args, **kwargs: Answer())
    config = SimpleNamespace(llm_base="http://127.0.0.1:1/v1", llm_model="a-model-of-record", enable_thinking=False)
    assert run_sprint.chat("system", "user", 8, 0.0, config) == "ok"
    assert recorded and recorded[0]["model"] == "a-model-of-record"


def test_the_lens_labels_a_call_with_the_model_its_record_names(client, console):
    project = core.current_project()
    with open(os.path.join(project, "interactions.jsonl"), "w", encoding="utf-8") as records:
        records.write(json.dumps({"kind": "served", "role": "planner", "prompt": "p", "output": "o",
                                  "model": "a-model-of-record"}) + "\n")
        records.write(json.dumps({"kind": "swarm", "role": "coder", "prompt": "p", "output": "o",
                                  "worker": "hermes:coder"}) + "\n")
    events = client.get(API_V1 + "/interactions").json()["events"]
    assert [event["to"] for event in events] == ["a-model-of-record", "hermes:coder"]
