# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control's own evidence: every effect the console causes is an audit event written before
the effect, naming the interface and session that asked, its inputs and content hashes, with the
effect's result recorded after; every write path is audited and locked.

These are the WP2 tests of the Mission Control plan (docs/design/mission-control-plan.md, section 4)
and the soundness findings of its section 2.4 they close: audit after the effect, a `file.edit` event
with no content, `quality.lock` unaudited and unlocked, `pack-attest` writing the evidence it reads,
`/attest/trail` with no source a 500, and model names as literals in the lens. The server is driven
through fastapi.testclient only and never bound to an address."""
import hashlib
import json
import os

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from prismpath.ledgers import audit_log  # noqa: E402
from prismpath.mission_control import app as app_module  # noqa: E402
from prismpath.mission_control import core, edit  # noqa: E402
from prismpath.mission_control.session import TOKEN_HEADER  # noqa: E402

API_V1 = "/api/v1"
FLOW = "---\nname: triage\nstart: a\n---\n## a\n-> b: when score > 5\n-> c: else\n## b\nDone.\n## c\nDone.\n"
EDITED = FLOW.replace("score > 5", "score > 7")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _client(application):
    return TestClient(application, base_url=f"http://127.0.0.1:{core.SETTINGS.port}",
                      headers={TOKEN_HEADER: application.state.session.token})


@pytest.fixture
def proj(tmp_path):
    project = tmp_path / "proj"
    (project / "flows").mkdir(parents=True)
    (project / "flows" / "triage.md").write_text(FLOW, encoding="utf-8")
    (project / "status.json").write_text(json.dumps({"iteration": 1, "valid": True}), encoding="utf-8")
    return project


@pytest.fixture
def log(proj, monkeypatch):
    console_log = audit_log.AuditLog(str(proj.parent / "mission_audit.log"))
    monkeypatch.setattr(core.audit, "LOG", console_log)
    monkeypatch.setattr(core.SETTINGS, "scan", str(proj / "status.json"))
    core.STATE.update({"proc": None, "proj": str(proj), "cfg": {}, "pinned": True})
    return console_log


@pytest.fixture
def client(log):
    return _client(app_module.app)


def _fingerprint():
    return app_module.app.state.session.fingerprint


# ── intent before the effect ──────────────────────────────────────────────────────────────────
def test_an_audit_write_failure_leaves_the_flow_file_unchanged(client, proj, monkeypatch):
    def refuse(self, actor, action, data):
        raise audit_log.AuditWriteError("disk full")
    monkeypatch.setattr(audit_log.AuditLog, "append", refuse)
    response = client.post(API_V1 + "/file", json={"path": "flows/triage.md", "content": EDITED})
    assert response.status_code == 503, response.text
    assert "audit" in response.json()["error"]["message"]
    assert (proj / "flows" / "triage.md").read_text(encoding="utf-8") == FLOW


def test_an_audit_write_failure_drops_no_stop_marker(client, proj, monkeypatch):
    def refuse(self, actor, action, data):
        raise audit_log.AuditWriteError("disk full")
    monkeypatch.setattr(audit_log.AuditLog, "append", refuse)
    assert client.post(API_V1 + "/sprint/stop").status_code == 503
    assert not (proj / "STOP").exists()


def test_the_intent_event_precedes_the_effect(client, proj, log, monkeypatch):
    """The intent is in the log when the file is written, and the result only after. The file's mtime
    is not compared with the event's clock, since the kernel stamps files from a coarser clock than
    `time.time()`; the write itself is observed instead."""
    seen = []
    real_write = edit._write_atomically

    def observing_write(resolved, content):
        seen.append([(event["action"], dict(event["data"])) for event in log.events])
        real_write(resolved, content)
    monkeypatch.setattr(edit, "_write_atomically", observing_write)
    assert client.post(API_V1 + "/file", json={"path": "flows/triage.md", "content": EDITED}).status_code == 200
    assert seen and [action for action, _ in seen[0]] == ["file.edit"]
    intent, result = log.events[-2], log.events[-1]
    assert intent["action"] == "file.edit" and result["action"] == "file.edit.result"
    assert result["data"]["intent"] == intent["idx"] and result["data"]["intent_leaf"] == log.leaves[intent["idx"]]
    assert result["data"]["ok"] is True and intent["ts_us"] <= result["ts_us"]
    mtime_us = os.stat(proj / "flows" / "triage.md").st_mtime_ns // 1000
    assert result["ts_us"] >= mtime_us - 50_000           # the result is written after the file


def test_a_stop_marker_is_dropped_between_its_intent_and_its_result(client, proj, log, monkeypatch):
    marker_at_append = []
    real_append = audit_log.AuditLog.append

    def observing_append(self, actor, action, data):
        marker_at_append.append((action, (proj / "STOP").exists()))
        return real_append(self, actor, action, data)
    monkeypatch.setattr(audit_log.AuditLog, "append", observing_append)
    assert client.post(API_V1 + "/sprint/stop").json()["ok"] is True
    assert marker_at_append == [("sprint.stop", False), ("sprint.stop.result", True)]


def test_a_sprint_start_records_its_intent_before_it_spawns(client, proj, log, monkeypatch):
    from prismpath.mission_control import launch
    spawned_after = []

    class _Proc:
        pid = 4242

        def poll(self):
            return None

    def fake_popen(argv, **kwargs):
        spawned_after.append([event["action"] for event in log.events])
        return _Proc()
    monkeypatch.setattr(launch.subprocess, "Popen", fake_popen)
    (proj / "status.json").write_text(json.dumps({"iteration": 1, "done": True}), encoding="utf-8")
    reply = client.post(API_V1 + "/sprint/start", json={"proj": str(proj)}).json()
    assert reply["ok"] is True
    assert spawned_after == [["sprint.start"]]
    assert log.events[-1]["action"] == "sprint.start.result" and log.events[-1]["data"]["detail"]["pid"] == 4242
    core.STATE.update({"proc": None})


# ── what the events say ───────────────────────────────────────────────────────────────────────
def test_a_file_edit_event_carries_the_content_hashes_and_the_flow(client, proj, log):
    before = (proj / "flows" / "triage.md").read_bytes()
    assert client.post(API_V1 + "/file", json={"path": "flows/triage.md", "content": EDITED}).status_code == 200
    after = (proj / "flows" / "triage.md").read_bytes()
    intent = log.events[-2]
    assert intent["action"] == "file.edit"
    assert intent["data"]["sha256_before"] == _sha(before)
    assert intent["data"]["sha256_after"] == _sha(after) == _sha(EDITED.encode("utf-8"))
    assert intent["data"]["flow"] == "triage" and intent["data"]["kind"] == "flow"
    assert log.events[-1]["data"]["detail"]["sha256"] == _sha(after)


def test_a_new_file_has_no_hash_before(client, proj, log):
    assert client.post(API_V1 + "/file", json={"path": "flows/new.md", "content": FLOW}).status_code == 200
    assert log.events[-2]["data"]["sha256_before"] is None


def test_the_actor_is_the_interface_and_the_session_never_the_literal_operator(client, proj, log):
    client.post(API_V1 + "/file", json={"path": "flows/triage.md", "content": EDITED})
    client.post(API_V1 + "/sprint/pause")
    client.post(API_V1 + "/sprint/resume")
    fingerprint = _fingerprint()
    assert fingerprint not in app_module.app.state.session.token
    actors = {event["action"]: event["actor"] for event in log.events}
    assert actors["file.edit"] == f"console/authoring/{fingerprint}"
    assert actors["file.edit.result"] == f"console/authoring/{fingerprint}"
    assert actors["sprint.pause"] == actors["sprint.resume"] == f"console/operating/{fingerprint}"
    assert not any(event["actor"] == "operator" for event in log.events)
    from prismpath.mission_control import audit
    assert not hasattr(audit, "ACTOR")


def test_a_queue_decision_is_decided_by_the_session_actor(client, log, tmp_path, monkeypatch):
    from prismpath.ledgers import checkpoint
    monkeypatch.setattr(checkpoint, "resolve_queue_item", lambda item: str(tmp_path / "item.json"))
    decided = {}
    monkeypatch.setattr(checkpoint, "record_decision",
                        lambda path, choose, decided_by: decided.update(choose=choose, by=decided_by))
    assert client.post(API_V1 + "/queue/decide", json={"id": "run-1", "choose": "approve"}).json()["ok"] is True
    assert decided == {"choose": "approve", "by": f"console/operating/{_fingerprint()}"}
    assert [event["action"] for event in log.events] == ["queue.decide", "queue.decide.result"]


def test_a_refused_queue_decision_records_a_failed_result(client, log, tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMPATH_QUEUE_DIR", str(tmp_path / "queue"))
    assert client.post(API_V1 + "/queue/decide", json={"id": "nope", "choose": "x"}).status_code == 400
    assert log.events[-1]["action"] == "queue.decide.result" and log.events[-1]["data"]["ok"] is False


def test_the_audit_log_stays_tamper_evident(client, proj, log):
    client.post(API_V1 + "/file", json={"path": "flows/triage.md", "content": EDITED})
    client.post(API_V1 + "/sprint/stop")
    reread = audit_log.AuditLog(log.path)
    assert reread.verify_log() and reread.current_root() == log.current_root() and len(reread.events) == 4
    lines = open(log.path, encoding="utf-8").read().splitlines()
    event = json.loads(lines[0])
    event["data"]["sha256_after"] = "0" * 64
    lines[0] = json.dumps(event)
    open(log.path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    assert audit_log.AuditLog(log.path).current_root() != log.current_root()


# ── the trail ────────────────────────────────────────────────────────────────────────────────
def test_the_trail_with_no_source_is_the_consoles_own(client, log):
    client.post(API_V1 + "/sprint/stop")
    walked = client.post(API_V1 + "/attest/trail", json={})
    assert walked.status_code == 200, walked.text
    report = walked.json()
    assert report["log"]["verifies"] is True
    assert report["by_action"] == {"sprint.stop": 1, "sprint.stop.result": 1}


# ── the policy host, read only ───────────────────────────────────────────────────────────────
def _swapped_state(tmp_path):
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
    host = policy_host.PolicyHost(str(tmp_path / "state"), [keys["public"]], envelope)
    return host.swap(str(ppt))


def test_pack_active_reads_the_active_policy_and_appends_nothing(client, proj):
    swapped = _swapped_state(proj)
    swaps_log = proj / "state" / "swaps.log"
    before = swaps_log.read_bytes()
    listing = sorted(os.listdir(proj / "state"))
    response = client.post(API_V1 + "/policy/pack-active", json={"state_dir": "state"})
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["active"] == swapped["active"] and report["version"] == 1 and report["image_ok"] is True
    assert report["log"]["verifies"] is True and [event["action"] for event in report["history"]] == ["swap"]
    assert swaps_log.read_bytes() == before and sorted(os.listdir(proj / "state")) == listing


def test_pack_active_creates_no_state_directory(client, proj):
    response = client.post(API_V1 + "/policy/pack-active", json={"state_dir": "no-such-state"})
    assert response.status_code == 200, response.text
    assert response.json()["active"] is None
    assert not (proj / "no-such-state").exists()


def test_the_attesting_route_is_gone(client, proj):
    response = client.post(API_V1 + "/policy/pack-attest", json={"state_dir": "state"})
    assert response.status_code in (404, 405)
    assert not (proj / "state").exists()


def test_pack_active_is_a_read_route_mounted_in_read_only_posture(log, proj):
    reader = _client(app_module.create_app(read_only=True))
    assert reader.post(API_V1 + "/policy/pack-active", json={"state_dir": "state"}).status_code == 200


# ── quality.lock ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def stub_lock(monkeypatch):
    from prismpath.routing import lockfile
    held = []

    def fake_save(flow_path, lock_doc):
        held.append(core.FILE_LOCK.locked())
        path = lockfile.lock_path(flow_path)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(lock_doc, handle)
        return path
    monkeypatch.setattr(lockfile, "lock_tree", lambda flow_path, **kwargs: {"conditions": {"a": 1}, "embedder": "stub"})
    monkeypatch.setattr(lockfile, "save_lock", fake_save)
    return held


def test_quality_lock_in_write_mode_is_audited_and_locked(client, proj, log, stub_lock):
    response = client.post(API_V1 + "/quality/lock", json={"flow_md": "flows/triage.md"})
    assert response.status_code == 200, response.text
    assert stub_lock == [True]
    intent, result = log.events[-2], log.events[-1]
    assert intent["action"] == "quality.lock" and intent["data"]["flow_md"] == "flows/triage.md"
    assert intent["data"]["sha256_flow"] == _sha((proj / "flows" / "triage.md").read_bytes())
    assert intent["actor"] == f"console/operating/{_fingerprint()}"
    lock_bytes = open(response.json()["path"], "rb").read()
    assert result["action"] == "quality.lock.result" and result["data"]["detail"]["sha256"] == _sha(lock_bytes)


def test_quality_lock_is_absent_in_read_only_posture_and_its_check_is_not(log, proj, monkeypatch):
    read_only = app_module.create_app(read_only=True)
    paths = read_only.openapi()["paths"]
    assert "post" not in paths.get(API_V1 + "/quality/lock", {})
    reader = _client(read_only)
    assert reader.post(API_V1 + "/quality/lock", json={"flow_md": "flows/triage.md"}).status_code == 403
    checked = reader.post(API_V1 + "/quality/lock-check", json={"flow_md": "flows/triage.md"})
    assert checked.status_code == 200, checked.text
    assert checked.json()["mode"] == "check" and checked.json()["ok"] is False   # no lockfile yet
    assert log.events == []


# ── the lens names no model ──────────────────────────────────────────────────────────────────
def test_the_lens_takes_worker_labels_from_the_records(client, proj):
    records = [{"kind": "served", "role": "product-manager", "model": "model-a", "prompt": "p", "output": "o"},
               {"kind": "swarm", "role": "engineer", "prompt": "p", "output": "o"},
               {"kind": "cecli", "role": "build", "model": "model-b", "prompt": "p", "output": "o"}]
    (proj / "interactions.jsonl").write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    events = client.get(API_V1 + "/interactions").json()["events"]
    assert [event["to"] for event in events] == ["model-a", "swarm", "model-b"]
    from prismpath.mission_control import lens
    source = open(lens.__file__, encoding="utf-8").read().lower()
    for literal in ("qwen", "gemma", ":8888", ":8889"):
        assert literal not in source, literal


# ── no dead registration comments ────────────────────────────────────────────────────────────
def test_no_router_carries_a_dead_registration_comment():
    from prismpath.mission_control import attest, inspect, policy, quality
    for module in (attest, inspect, policy, quality):
        assert "include_router" not in open(module.__file__, encoding="utf-8").read(), module.__name__
