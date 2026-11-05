# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control and signing: a sprint that runs the sprint flow honours PRISMPATH_REQUIRE_AUTHORIZATION
and the authority keys as `run` does, and `/prove/audit` says whether the console's own audit log is
signed, with the same statuses and findings `prismpath trail` reports."""
import json

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from prismpath.hotswap import flow_authority as fa, policy_pack  # noqa: E402
from prismpath.ledgers import audit_log, root_statement as rs  # noqa: E402
from prismpath.mission_control import core, launch  # noqa: E402
from prismpath.mission_control.app import app  # noqa: E402
from prismpath.orchestration import sprint_flow  # noqa: E402

API_V1 = "/api/v1"

SPRINT_LOOP = "---\nname: sprint\nstart: pick\n---\n## pick\nChoose.\n-> done: when always\n## done\nDone.\n"


@pytest.fixture(autouse=True)
def _no_ambient_settings(monkeypatch):
    for name in (rs.INSTANCE_KEY_ENV, fa.REQUIRE_ENV, fa.AUTHORITY_PUB_ENV, fa.STATE_DIR_ENV, "SPRINT_FLOW"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def console(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setattr(core.SETTINGS, "scan", str(proj / "status.json"))
    keys = rs.keygen(str(tmp_path / "keys"))
    log = audit_log.AuditLog(str(tmp_path / "console.audit.jsonl"))
    monkeypatch.setattr(core.audit, "LOG", log)
    core.STATE.update({"proc": None, "proj": str(proj), "cfg": {}, "pinned": True})
    return {"client": TestClient(app), "log": log, "proj": proj, "keys": keys, "tmp": tmp_path}


def _require(console, monkeypatch):
    authority = policy_pack.keygen(str(console["tmp"] / "authority"))
    monkeypatch.setenv("SPRINT_FLOW", "1")
    monkeypatch.setenv(fa.REQUIRE_ENV, "1")
    monkeypatch.setenv(fa.AUTHORITY_PUB_ENV, authority["public"])
    monkeypatch.setenv(fa.STATE_DIR_ENV, str(console["tmp"] / "state"))
    return authority


def test_a_sprint_that_runs_the_sprint_flow_is_refused_when_the_flow_is_not_authorized(console, monkeypatch):
    flow = console["tmp"] / "sprint_loop.md"
    flow.write_text(SPRINT_LOOP)
    monkeypatch.setattr(sprint_flow, "DEFAULT_FLOW", str(flow))
    _require(console, monkeypatch)
    started = []
    monkeypatch.setattr(launch.subprocess, "Popen", lambda *a, **k: started.append(a) or None)
    reply = console["client"].post(API_V1 + "/sprint/start", json={"proj": str(console["proj"])}).json()
    assert reply["ok"] is False and reply["refused"] == ["sig:missing"] and "not authorized" in reply["error"]
    assert started == []
    refusal = console["log"].events[-1]
    assert refusal["action"] == "sprint.refused" and refusal["data"]["reasons"] == ["sig:missing"]


def test_a_sprint_whose_flow_is_authorized_is_not_refused(console, monkeypatch):
    flow = console["tmp"] / "sprint_loop.md"
    flow.write_text(SPRINT_LOOP)
    monkeypatch.setattr(sprint_flow, "DEFAULT_FLOW", str(flow))
    authority = _require(console, monkeypatch)
    fa.sign_flow(str(flow), 1, authority["private"], authority["public"])
    assert launch.flow_refusal() is None


def test_a_sprint_that_does_not_run_the_flow_is_not_asked(console, monkeypatch):
    _require(console, monkeypatch)
    monkeypatch.delenv("SPRINT_FLOW")
    assert launch.flow_refusal() is None                        # the default loop loads no flow


def test_the_console_says_when_authorization_is_required_and_there_is_no_key(console, monkeypatch):
    monkeypatch.setenv("SPRINT_FLOW", "1")
    monkeypatch.setenv(fa.REQUIRE_ENV, "1")
    refusal = launch.flow_refusal()
    assert refusal["ok"] is False and "no trusted authority key" in refusal["error"]


# ------------------------------------------------------------------ /prove/audit

def test_prove_audit_reports_an_unsigned_log_as_unsigned(console):
    for index in range(3):
        console["log"].append("operator", "sprint.start", {"n": index})
    audit = console["client"].get(API_V1 + "/prove/audit").json()
    assert audit["valid"] is True and audit["n"] == 3 and audit["ok"] is True
    assert audit["signing"]["status"] == "unsigned" and audit["signing"]["console_key"] is None
    assert audit["signing"]["unsigned_tail"] == 3


def test_prove_audit_reports_a_signed_log_and_the_key_that_signed_it(console, monkeypatch):
    key = rs.InstanceKey.load(console["keys"]["private"])
    log = audit_log.AuditLog(console["log"].path, instance_key=key, sign_appends=True)
    monkeypatch.setattr(core.audit, "LOG", log)
    for index in range(4):
        core.audit.record("sprint.start", {"n": index})
    audit = console["client"].get(API_V1 + "/prove/audit").json()
    signing = audit["signing"]
    assert audit["valid"] is True and audit["ok"] is True
    assert signing["status"] == "signed-unpinned" and signing["statements"] == 4 and signing["signed_leaves"] == 4
    assert signing["keys"] == [key.fingerprint] and signing["console_key"] == key.fingerprint
    assert signing["console_key_signed"] is True and signing["unsigned_tail"] == 0 and signing["findings"] == []


def test_prove_audit_reports_a_rewritten_event_as_invalid(console, monkeypatch):
    key = rs.InstanceKey.load(console["keys"]["private"])
    log = audit_log.AuditLog(console["log"].path, instance_key=key, sign_appends=True)
    for index in range(3):
        log.append("operator", "sprint.start", {"n": index})
    lines = open(log.path).read().splitlines()
    event = json.loads(lines[1]); event["data"]["n"] = 99; lines[1] = json.dumps(event)
    open(log.path, "w").write("\n".join(lines) + "\n")
    monkeypatch.setattr(core.audit, "LOG", audit_log.AuditLog(log.path, instance_key=key, sign_appends=True))
    audit = console["client"].get(API_V1 + "/prove/audit").json()
    assert audit["signing"]["status"] == "invalid" and audit["ok"] is False
    assert any(finding["finding"] == "root_mismatch" for finding in audit["signing"]["findings"])


def test_prove_audit_says_when_this_install_cannot_check_signatures(console, monkeypatch):
    from prismpath.extras import MissingExtra
    key = rs.InstanceKey.load(console["keys"]["private"])
    log = audit_log.AuditLog(console["log"].path, instance_key=key, sign_appends=True)
    log.append("operator", "sprint.start", {})
    monkeypatch.setattr(core.audit, "LOG", audit_log.AuditLog(log.path))
    monkeypatch.setattr(rs, "_verify_signature", lambda statement: (_ for _ in ()).throw(MissingExtra("signing", "cryptography")))
    audit = console["client"].get(API_V1 + "/prove/audit").json()
    assert audit["signing"]["status"] == "unchecked" and "pip install" in audit["signing"]["reason"]
    assert audit["valid"] is True
