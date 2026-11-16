# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control's auditing interface over HTTP: the `/evidence` routes (U1, U2, U4, U5, U6, U7) the
assessor's screens read, mounted in both postures and driven through fastapi.testclient only.

Each route wraps one evidence reader (`prismpath.mission_control.evidence`), so these tests hold the
transport to its contract rather than the readers to their verifiers (test_mission_control_evidence.py
does that): every route reads and is mounted read only, every refusal maps to its status (outside the
roots 403, missing 404, too large 413, anything else malformed 400), bytes come back as base64 beside
their text, every verdict says it is the console's, and a pinned key is named only as a public key file
under the evidence roots, never sent as key material. The console's own log is read by the same routes,
and its actions are counted in pairs, an intent with its `.result`, so an intent with no result is named
as an outcome the console did not record."""
import base64
import os
import shutil
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")
from fastapi.testclient import TestClient  # noqa: E402

from prismpath import canon  # noqa: E402
from prismpath.hotswap import flow_authority, policy_pack  # noqa: E402
from prismpath.kernel import causes, ppt_compile  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402
from prismpath.ledgers import audit_log, core_evidence, root_statement  # noqa: E402
from prismpath.mission_control import app as app_module  # noqa: E402
from prismpath.mission_control import core  # noqa: E402
from prismpath.mission_control.posture import CAPABILITY_KEY  # noqa: E402

API_V1 = "/api/v1"
HEADER = "X-PrismPath-Session"
CASES = Path(__file__).resolve().parent / "fixtures" / "core_evidence" / "cases.jsonl"
FLOW = "---\nname: f\nstart: a\n---\n## a\n-> b: when score > 5\n-> c: else\n## b\nDone.\n## c\nDone.\n"
ROUTES = {("GET", "/evidence/logs"), ("POST", "/evidence/trail"), ("POST", "/evidence/receipt"),
          ("POST", "/evidence/raw"), ("POST", "/evidence/run"), ("POST", "/evidence/manifest"),
          ("POST", "/evidence/pack"), ("POST", "/evidence/anchor"), ("GET", "/evidence/causes")}


def _origin():
    return f"http://127.0.0.1:{core.SETTINGS.port}"


@pytest.fixture
def keys(tmp_path):
    made = root_statement.keygen(str(tmp_path / "keys"), "instance")
    return root_statement.InstanceKey.load(made["private"]), made["public"]


@pytest.fixture
def root(tmp_path, monkeypatch):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [str(evidence_root)])
    console_dir = tmp_path / "state"
    console_dir.mkdir()
    monkeypatch.setattr(core.audit, "LOG", audit_log.AuditLog(str(console_dir / "mission_audit.log")))
    return evidence_root


def _client(read_only):
    application = app_module.create_app(read_only=read_only)
    return TestClient(application, base_url=_origin(), headers={HEADER: application.state.session.token})


@pytest.fixture(params=[False, True], ids=["full", "read-only"])
def client(request, root):
    return _client(request.param)


def _signed_log(path, key, decisions=((2, "refuse"), (0, "route"), (34, "escalate")), policy=None):
    log = audit_log.AuditLog(str(path), instance_key=key, sign_appends=True,
                             policy_of=(lambda: policy) if policy else None)
    for code, outcome in decisions:
        log.append("engine", "decision", {"outcome": outcome, "cause": code, "rule": "r1"})
    return log


def _pin(root, public_path, name="instance.pub"):
    (root / "pins").mkdir(exist_ok=True)
    shutil.copy(public_path, root / "pins" / name)
    return str(root / "pins" / name)


def _listing(base):
    out = {}
    for dirpath, dirnames, filenames in os.walk(base):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            stat = os.lstat(full)
            out[os.path.relpath(full, base)] = (stat.st_size, stat.st_mtime_ns)
    return out


def _refused(response, status, reason):
    assert response.status_code == status, (response.status_code, response.text)
    error = response.json()["error"]
    assert error["code"] == status and error["reason"] == reason, error
    return error


# ── the routes and the posture ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("read_only", [False, True], ids=["full", "read-only"])
def test_every_auditing_route_reads_and_is_mounted_in_both_postures(read_only):
    schema = app_module.create_app(read_only=read_only).openapi()["paths"]
    for method, path in ROUTES:
        operation = schema.get(API_V1 + path, {}).get(method.lower())
        assert operation is not None, (method, path, read_only)
        assert operation.get(CAPABILITY_KEY, "read") == "read", (method, path)
        assert "auditing" in operation.get("tags", []), (method, path)


def test_the_attest_and_policy_read_routes_are_tagged_auditing():
    schema = app_module.create_app(read_only=True).openapi()["paths"]
    for path in ("/attest/trail", "/attest/ledger-verify", "/attest/model-check", "/policy/pack-verify"):
        assert "auditing" in schema[API_V1 + path]["post"]["tags"], path


def test_no_auditing_route_writes(client, root, keys):
    """Every route, called with a well formed body, leaves the roots and the console's log as they were."""
    _signed_log(root / "run.audit.jsonl", keys[0])
    core_evidence.produce(CASES, root / "run", root.parent / "run-keys")
    pin = _pin(root, keys[1])
    core.audit.LOG.append("console/operating/abcd", "sprint.stop", {"proj": "p"})
    before, logged = _listing(root), len(core.audit.LOG.events)
    for method, path, body in (
            ("GET", "/evidence/logs", None), ("GET", "/evidence/causes", None),
            ("POST", "/evidence/trail", {"path": "run.audit.jsonl", "pins": [pin]}),
            ("POST", "/evidence/receipt", {"path": "run.audit.jsonl", "index": 1}),
            ("POST", "/evidence/raw", {"path": "run.audit.jsonl", "start": 0, "count": 2}),
            ("POST", "/evidence/run", {"path": "run", "sample": 2}),
            ("POST", "/evidence/trail", {"console": True})):
        response = client.request(method, API_V1 + path, json=body)
        assert response.status_code == 200, (path, response.text)
    assert _listing(root) == before
    assert len(core.audit.LOG.events) == logged


# ── U1 trails ──────────────────────────────────────────────────────────────────────────────────
def test_logs_lists_the_trails_runs_and_the_consoles_own_log(client, root, keys):
    (root / "deploy").mkdir()
    _signed_log(root / "deploy" / "run.audit.jsonl", keys[0])
    audit_log.AuditLog(str(root / "deploy" / "swaps.log")).append("host", "swap", {"version": 1})
    core_evidence.produce(CASES, root / "runs" / "one", root.parent / "run-keys")
    core.audit.LOG.append("console/operating/abcd", "sprint.stop", {"proj": "p"})
    listed = client.get(API_V1 + "/evidence/logs")
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert {Path(entry["path"]).name for entry in body["logs"]} == {"run.audit.jsonl", "swaps.log"}
    assert [Path(run["path"]).name for run in body["runs"]] == ["one"]
    assert body["console"]["path"] == core.audit.LOG.path and body["console"]["events"] == 1
    assert body["console"]["verifies"] is True and body["console"]["present"] is True


def test_a_trail_is_the_consoles_unpinned_verdict_by_default(client, root, keys):
    _signed_log(root / "run.audit.jsonl", keys[0])
    response = client.post(API_V1 + "/evidence/trail", json={"path": "run.audit.jsonl"})
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["verdict_of"] == "console"
    assert report["signing"]["status"] == "signed-unpinned" and report["log"]["verifies"] is True
    assert report["command"].startswith("prismpath trail ")
    assert {entry["code"] for entry in report["causes_decoded"]} == {0, 2, 34}
    assert {entry["name"] for entry in report["causes_decoded"] if entry["registered"]} == {causes.name(2), causes.name(34)}


def test_a_trail_pinned_by_a_key_file_under_the_roots_is_signed(client, root, keys):
    _signed_log(root / "run.audit.jsonl", keys[0])
    report = client.post(API_V1 + "/evidence/trail",
                         json={"path": "run.audit.jsonl", "pins": [_pin(root, keys[1])]}).json()
    assert report["signing"]["status"] == "signed" and report["verdict_of"] == "console"
    assert "--pub" in report["command"]
    other = root_statement.keygen(str(root.parent / "other"), "instance")["public"]
    wrong = client.post(API_V1 + "/evidence/trail",
                        json={"path": "run.audit.jsonl", "pins": [_pin(root, other, "other.pub")]}).json()
    assert wrong["signing"]["status"] == "invalid"


def test_a_tampered_trail_is_an_invalid_report_not_a_refusal(client, root, keys):
    log_path = root / "run.audit.jsonl"
    _signed_log(log_path, keys[0])
    lines = log_path.read_bytes().split(b"\n")
    lines[1] = lines[1].replace(b'"route"', b'"refuse"')
    log_path.write_bytes(b"\n".join(lines))
    response = client.post(API_V1 + "/evidence/trail", json={"path": "run.audit.jsonl"})
    assert response.status_code == 200
    assert response.json()["signing"]["status"] == "invalid" and response.json()["signing"]["findings"]


def test_the_consoles_own_trail_counts_each_intent_with_its_result(client, root):
    log = core.audit.LOG
    stop = log.append("console/operating/abcd", "sprint.stop", {"proj": "p"})
    log.append("console/operating/abcd", "sprint.stop.result",
               {"intent": stop["idx"], "intent_leaf": log.leaves[stop["idx"]], "ok": True, "outcome": "done", "detail": None})
    edit = log.append("console/authoring/abcd", "file.edit", {"path": "f.md"})
    log.append("console/authoring/abcd", "file.edit.result",
               {"intent": edit["idx"], "intent_leaf": log.leaves[edit["idx"]], "ok": False, "outcome": "failed", "detail": None})
    log.append("console/operating/abcd", "sprint.start", {"proj": "p"})          # no result: outcome unknown
    log.append("console/operating/abcd", "sprint.refused", {"proj": "p"})        # complete in itself
    log.append("console/operating/abcd", "queue.decide.result",                  # a result naming nothing
               {"intent": 0, "intent_leaf": "00" * 32, "ok": True, "outcome": "done", "detail": None})
    response = client.post(API_V1 + "/evidence/trail", json={"console": True})
    assert response.status_code == 200, response.text
    actions = response.json()["console_actions"]
    assert actions["by_action"]["sprint.stop"] == {"intents": 1, "done": 1, "failed": 0, "unrecorded": 0}
    assert actions["by_action"]["file.edit"] == {"intents": 1, "done": 0, "failed": 1, "unrecorded": 0}
    assert actions["by_action"]["sprint.start"] == {"intents": 1, "done": 0, "failed": 0, "unrecorded": 1}
    assert actions["refusals"] == {"sprint.refused": 1}
    assert [entry["index"] for entry in actions["unrecorded"]] == [4]
    assert [entry["index"] for entry in actions["orphans"]] == [6]
    assert response.json()["verdict_of"] == "console"


def test_a_log_with_no_console_actor_has_no_action_pairs(client, root, keys):
    _signed_log(root / "run.audit.jsonl", keys[0])
    assert client.post(API_V1 + "/evidence/trail", json={"path": "run.audit.jsonl"}).json()["console_actions"] is None


# ── U2 one receipt, and the raw bytes ──────────────────────────────────────────────────────────
def test_a_receipt_carries_its_bundle_its_raw_bytes_and_both_commands(client, root, keys):
    _signed_log(root / "run.audit.jsonl", keys[0])
    response = client.post(API_V1 + "/evidence/receipt", json={"path": "run.audit.jsonl", "index": 0})
    assert response.status_code == 200, response.text
    view = response.json()
    raw = base64.b64decode(view["raw"]["b64"])
    assert raw == (root / "run.audit.jsonl").read_bytes().split(b"\n")[0]
    assert view["raw"]["text"] == raw.decode("utf-8")
    assert view["leaf"] == core_evidence.sha256_hex(raw)
    assert view["cause"]["name"] == causes.name(2)
    assert view["verdict"]["status"] == "signed-unpinned" and view["verdict"]["verdict_of"] == "console"
    assert root_statement.verify_receipt_bundle(view["bundle"], [root_statement.load_public(keys[1])])["ok"] is True
    assert view["command"].startswith("prismpath trail --verify-bundle bundle.json")
    assert "--receipt 0 --bundle-out bundle.json" in view["export"]


def test_a_receipt_index_out_of_range_is_a_400(client, root, keys):
    _signed_log(root / "run.audit.jsonl", keys[0])
    _refused(client.post(API_V1 + "/evidence/receipt", json={"path": "run.audit.jsonl", "index": 9}), 400, "bad-request")


def test_raw_lines_are_the_bytes_as_written_in_base64(client, root):
    (root / "bytes.jsonl").write_bytes(b"first\n\xff\xfe second\nthird\n")
    response = client.post(API_V1 + "/evidence/raw", json={"path": "bytes.jsonl", "start": 1, "count": 5})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 3 and body["count"] == 2 and body["start"] == 1
    assert [base64.b64decode(line["b64"]) for line in body["lines"]] == [b"\xff\xfe second", b"third"]
    assert body["lines"][0]["text"].endswith(" second")
    assert body["sha256"] == core_evidence.sha256_hex((root / "bytes.jsonl").read_bytes())


def test_the_consoles_raw_statements_are_readable_and_nothing_else_beside_them(client, root):
    core.audit.LOG.append("console/operating/abcd", "sprint.stop", {"proj": "p"})
    (Path(core.audit.LOG.path).parent / "session.token").write_text("secret", encoding="utf-8")
    response = client.post(API_V1 + "/evidence/raw", json={"console": True})
    assert response.status_code == 200 and response.json()["total"] == 1
    # the console flag names the log (or its statements), never another file of the state directory
    refused = client.post(API_V1 + "/evidence/raw", json={"console": True, "path": "session.token"})
    _refused(refused, 400, "bad-request")


# ── refusal mappings ───────────────────────────────────────────────────────────────────────────
def test_each_refusal_maps_to_its_status(client, root, tmp_path, keys, monkeypatch):
    outside = tmp_path / "elsewhere.audit.jsonl"
    _signed_log(outside, keys[0])
    _refused(client.post(API_V1 + "/evidence/trail", json={"path": str(outside)}), 403, "outside-roots")
    _refused(client.post(API_V1 + "/evidence/raw", json={"path": "../elsewhere.audit.jsonl"}), 403, "outside-roots")
    _refused(client.post(API_V1 + "/evidence/trail", json={"path": "absent.audit.jsonl"}), 404, "not-found")
    (root / "adir").mkdir()
    _refused(client.post(API_V1 + "/evidence/raw", json={"path": "adir"}), 400, "not-a-file")
    _refused(client.post(API_V1 + "/evidence/trail", json={"path": "x", "since": "not a time"}), 400, "bad-request")
    _signed_log(root / "big.audit.jsonl", keys[0])
    monkeypatch.setattr(core.SETTINGS, "max_evidence_bytes", 64)
    _refused(client.post(API_V1 + "/evidence/trail", json={"path": "big.audit.jsonl"}), 413, "too-large")


def test_no_evidence_root_refuses_every_read(client, root, keys, monkeypatch):
    _signed_log(root / "run.audit.jsonl", keys[0])
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [])
    _refused(client.post(API_V1 + "/evidence/trail", json={"path": str(root / "run.audit.jsonl")}), 403, "outside-roots")
    assert client.get(API_V1 + "/evidence/logs").json()["logs"] == []


def test_a_path_or_the_console_flag_is_named_not_both_or_neither(client, root):
    _refused(client.post(API_V1 + "/evidence/trail", json={}), 400, "bad-request")
    _refused(client.post(API_V1 + "/evidence/trail", json={"console": True, "path": "x"}), 400, "bad-request")


# ── pinned keys: files under the roots only, never key material ────────────────────────────────
def test_key_material_in_a_request_body_is_refused(client, root, keys):
    _signed_log(root / "run.audit.jsonl", keys[0])
    raw_key = root_statement.load_public(keys[1])
    for body in ({"path": "run.audit.jsonl", "pinned": [raw_key.hex()]},
                 {"path": "run.audit.jsonl", "public_key": raw_key.hex()}):
        assert client.post(API_V1 + "/evidence/trail", json=body).status_code == 422, body
    _refused(client.post(API_V1 + "/evidence/trail", json={"path": "run.audit.jsonl", "pins": [raw_key.hex()]}),
             400, "bad-pin")
    # Key material in `pins` is only ever a path. Base64 starts with "/" for one key in 64, which names an
    # absolute path outside the roots (403); without it the path is relative to a root and absent (404).
    # Both forms are sent, so the outcome no longer depends on the key drawn.
    encoded = base64.b64encode(raw_key).decode()
    for pin, status, reason in (("/" + encoded.lstrip("/"), 403, "outside-roots"),
                                (encoded.lstrip("/"), 404, "not-found")):
        _refused(client.post(API_V1 + "/evidence/receipt", json={"path": "run.audit.jsonl", "index": 0,
                                                                  "pins": [pin]}), status, reason)


def test_a_pin_file_outside_the_roots_or_not_a_key_is_refused(client, root, keys):
    _signed_log(root / "run.audit.jsonl", keys[0])
    _refused(client.post(API_V1 + "/evidence/trail", json={"path": "run.audit.jsonl", "pins": [keys[1]]}),
             403, "outside-roots")
    (root / "not-a-key.pub").write_bytes(b"short")
    _refused(client.post(API_V1 + "/evidence/trail", json={"path": "run.audit.jsonl", "pins": ["not-a-key.pub"]}),
             400, "bad-pin")


# ── U5 evidence runs ───────────────────────────────────────────────────────────────────────────
@pytest.fixture
def run(root, tmp_path):
    keys_dir = tmp_path / "run-keys"
    core_evidence.produce(CASES, root / "run", keys_dir)
    return root / "run", {"authority": _pin(root, keys_dir / "authority.pub", "authority.pub"),
                          "instance": _pin(root, keys_dir / "instance.pub", "instance.pub")}


def test_a_run_verifies_unpinned_by_default_and_signed_under_pin_files(client, run):
    run_dir, pins = run
    unpinned = client.post(API_V1 + "/evidence/run", json={"path": "run", "sample": 3})
    assert unpinned.status_code == 200, unpinned.text
    assert unpinned.json()["ok"] is True and unpinned.json()["status"] == "signed-unpinned"
    assert unpinned.json()["verdict_of"] == "console" and "prismpath evidence verify" in unpinned.json()["command"]
    pinned = client.post(API_V1 + "/evidence/run", json={"path": "run", "sample": 3, "pins": pins}).json()
    assert pinned["ok"] is True and pinned["status"] == "signed"


def test_a_tampered_run_is_invalid_not_a_refusal(client, run):
    run_dir, _pins = run
    lines = (run_dir / "receipts.jsonl").read_bytes().split(b"\n")[:-1]
    (run_dir / "receipts.jsonl").write_bytes(b"".join(line + b"\n" for line in lines[:-1]))
    response = client.post(API_V1 + "/evidence/run", json={"path": "run", "sample": 1})
    assert response.status_code == 200
    assert response.json()["ok"] is False and response.json()["status"] == "invalid" and response.json()["problem"]


def test_a_run_pin_names_only_an_authority_or_an_instance(client, run):
    _run_dir, pins = run
    assert client.post(API_V1 + "/evidence/run", json={"path": "run", "pins": {"other": pins["authority"]}}).status_code == 422


# ── U6 change control ──────────────────────────────────────────────────────────────────────────
@pytest.fixture
def flow(root):
    flow_path = root / "flows" / "f.md"
    flow_path.parent.mkdir()
    flow_path.write_text(FLOW, encoding="utf-8")
    made = policy_pack.keygen(str(root / "authority"), "authority")
    return flow_path, made["private"], made["public"]


def test_change_control_reports_unsigned_signed_and_stale(client, flow):
    flow_path, private, public = flow
    assert client.post(API_V1 + "/evidence/manifest", json={"flow": "flows/f.md"}).json()["status"] == "unsigned"
    flow_authority.sign_flow(str(flow_path), 1, private, public)
    unchecked = client.post(API_V1 + "/evidence/manifest", json={"flow": "flows/f.md"}).json()
    assert unchecked["status"] == "unchecked" and unchecked["verdict_of"] == "console"
    signed = client.post(API_V1 + "/evidence/manifest", json={"flow": "flows/f.md", "pins": [public]}).json()
    assert signed["status"] == "signed" and signed["command"].startswith("prismpath authorize verify ")
    flow_path.write_text(FLOW + "\n", encoding="utf-8")
    assert client.post(API_V1 + "/evidence/manifest", json={"flow": "flows/f.md", "pins": [public]}).json()["status"] == "stale"


def test_change_control_from_a_receipt_says_whether_it_names_this_flow(client, root, flow, keys):
    flow_path, private, public = flow
    flow_authority.sign_flow(str(flow_path), 1, private, public)
    sha = flow_authority.flow_sha256(str(flow_path))
    _signed_log(root / "run.audit.jsonl", keys[0], policy={"flow": "f", "flow_sha256": sha})
    body = {"flow": "flows/f.md", "pins": [public], "log": "run.audit.jsonl", "index": 0}
    agrees = client.post(API_V1 + "/evidence/manifest", json=body).json()
    assert agrees["receipt"]["flow_sha256"] == sha and agrees["receipt"]["agrees"] is True
    flow_path.write_text(FLOW + "\n", encoding="utf-8")
    differs = client.post(API_V1 + "/evidence/manifest", json=body).json()
    assert differs["receipt"]["agrees"] is False and differs["status"] == "stale"


# ── U7 pack verify ─────────────────────────────────────────────────────────────────────────────
def _pack(root):
    made = policy_pack.keygen(str(root / "pack-keys"), "authority")
    ppt = root / "v1.ppt"
    ppt.write_bytes(ppt_compile.compile_flow(parse(
        "# f\n## start\n-> hot: when temp >= 100\n-> cold: else\n## hot\n-> end\n## cold\n-> end\n## end\n")).serialize())
    policy_pack.build_pack(str(ppt), {"temp": "int"}, version=1, envelope_id="env1",
                           priv_path=made["private"], pub_path=made["public"])
    return ppt, made["public"]


def test_pack_verify_under_the_roots(client, root):
    ppt, public = _pack(root)
    signed = client.post(API_V1 + "/evidence/pack", json={"ppt": "v1.ppt", "pins": [public]})
    assert signed.status_code == 200, signed.text
    assert signed.json()["status"] == "signed" and signed.json()["verdict_of"] == "console"
    assert signed.json()["command"].startswith("prismpath swap verify --ppt ")
    assert client.post(API_V1 + "/evidence/pack", json={"ppt": "v1.ppt"}).json()["status"] == "unchecked"
    ppt.write_bytes(ppt.read_bytes() + b"\x00")
    tampered = client.post(API_V1 + "/evidence/pack", json={"ppt": "v1.ppt", "pins": [public]}).json()
    assert tampered["status"] == "invalid" and tampered["causes"]


# ── U4 anchors ─────────────────────────────────────────────────────────────────────────────────
def test_an_anchor_verify_reads_only_under_the_roots(client, root, tmp_path):
    _refused(client.post(API_V1 + "/evidence/anchor", json={"leaf": "00" * 32, "dir": str(tmp_path)}), 403, "outside-roots")
    (root / "proofs").mkdir()
    _refused(client.post(API_V1 + "/evidence/anchor", json={"leaf": "00" * 32, "dir": "proofs"}), 404, "not-found")
    _refused(client.post(API_V1 + "/evidence/anchor", json={"leaf": "00" * 32, "dir": "proofs", "label": "../x"}),
             400, "bad-request")
    _refused(client.post(API_V1 + "/evidence/anchor", json={}), 400, "bad-request")


def test_an_anchor_that_does_not_hold_the_leaf_is_reported_without_reaching_the_network(client, root):
    from prismpath.ledgers import ledger_ots
    (root / "proofs").mkdir()
    leaf = "11" * 32
    (root / "proofs" / "manifest_v1.json").write_bytes(
        canon.canon2_bytes(canon.tagged({"merkle": ledger_ots.MERKLE_SCHEME, "root": "22" * 32, "leaves": {}})) + b"\n")
    response = client.post(API_V1 + "/evidence/anchor", json={"leaf": leaf, "dir": "proofs"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mode"] == "ots" and body["merkle_ok"] is False and body["verdict_of"] == "console"
    assert body["reason"] == "output-hash not in this anchor batch"
    assert body["command"].startswith("prismpath ledger verify --out ")


def test_an_rfc3161_verify_needs_all_three_files_under_the_roots(client, root):
    for name in ("root.txt", "root.tsr", "ca.crt"):
        (root / name).write_bytes(b"not a real artefact\n")
    _refused(client.post(API_V1 + "/evidence/anchor", json={"root": "root.txt", "tsr": "root.tsr"}), 400, "bad-request")
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    response = client.post(API_V1 + "/evidence/anchor", json={"root": "root.txt", "tsr": "root.tsr", "cafile": "ca.crt"})
    assert response.status_code == 200, response.text
    assert response.json()["mode"] == "rfc3161" and response.json()["verified"] is False


# ── the cause decoder ──────────────────────────────────────────────────────────────────────────
def test_the_cause_registry_is_served_whole(client):
    body = client.get(API_V1 + "/evidence/causes").json()
    assert body["sha256"] == causes.registry_sha256()
    assert [entry["code"] for entry in body["causes"]] == sorted(causes.CODES)
