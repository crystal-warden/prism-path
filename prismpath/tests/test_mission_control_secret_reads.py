# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control never serves secret material, through the editor's read (`GET /file`) or the auditing
routes (`/evidence/*`).

The editor reads only the files its listing shows (flows, fixtures, manifests, signatures, lockfiles,
notes, public keys), and of those refuses any that is secret by kind (a private key file by its name, an
`.env` like file, anything in the console's own state directory but its audit log) or by content (a
PEM private key block, an unencrypted Ed25519 PKCS8 key in DER), after resolving symlinks, so an
innocent name cannot carry a key out. The evidence readers apply the same rule under the evidence
roots. Key material is generated at run time, never committed."""
import os
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")
from fastapi.testclient import TestClient  # noqa: E402

from prismpath.ledgers import audit_log, root_statement  # noqa: E402
from prismpath.mission_control import app as app_module  # noqa: E402
from prismpath.mission_control import core, session  # noqa: E402

API_V1 = "/api/v1"
HEADER = "X-PrismPath-Session"
FLOW = "---\nname: f\nstart: a\n---\n## a\n-> b: when score > 5\n-> c: else\n## b\nDone.\n## c\nDone.\n"
FIXTURE = "| node | outcome | fields | expect |\n|---|---|---|---|\n| a | x | score=9 | b |\n"


def _origin():
    return f"http://127.0.0.1:{core.SETTINGS.port}"


def _client(read_only=False):
    application = app_module.create_app(read_only=read_only)
    return TestClient(application, base_url=_origin(), headers={HEADER: application.state.session.token})


@pytest.fixture
def made_key(tmp_path):
    """A fresh instance keypair outside the project: (private PEM bytes, public raw bytes)."""
    made = root_statement.keygen(str(tmp_path / "keygen"), "instance")
    return Path(made["private"]).read_bytes(), Path(made["public"]).read_bytes()


@pytest.fixture
def proj(tmp_path, monkeypatch, made_key):
    """A project holding every kind of file the editor lists, its key pair, and the console's own state
    directory inside it (a non hidden name, so only the state rule keeps it out)."""
    project = tmp_path / "proj"
    (project / "flows").mkdir(parents=True)
    (project / "flows" / "f.md").write_text(FLOW, encoding="utf-8")
    (project / "flows" / "f.tests.md").write_text(FIXTURE, encoding="utf-8")
    (project / "flows" / "f.md.manifest.json").write_text("{}\n", encoding="utf-8")
    (project / "flows" / "f.md.manifest.sig").write_text("c2ln\n", encoding="utf-8")
    (project / "flows" / "routing.yaml").write_text("a: b\n", encoding="utf-8")
    (project / "prismpath.lock.json").write_text("{}\n", encoding="utf-8")
    (project / "events.jsonl").write_text("{}\n", encoding="utf-8")
    (project / "notes.txt").write_text("notes\n", encoding="utf-8")
    (project / "keys").mkdir()
    (project / "keys" / "instance.key").write_bytes(made_key[0])
    (project / "keys" / "instance.pub").write_bytes(made_key[1])
    state_dir = project / "console"
    state_dir.mkdir()
    monkeypatch.setattr(core.SETTINGS, "state_dir", str(state_dir))
    monkeypatch.setattr(core.audit, "LOG", audit_log.AuditLog(str(state_dir / "mission_audit.log")))
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [])
    core.STATE.update({"proc": None, "proj": str(project), "cfg": {}, "pinned": True})
    return project


@pytest.fixture
def client(proj):
    return _client(False)


def _refused(response, reason):
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["error"]["reason"] == reason, body
    assert "PRIVATE KEY" not in response.text


def _read(client, path):
    return client.get(API_V1 + "/file", params={"path": path})


# ── the editor's read ─────────────────────────────────────────────────────────────────────────
def test_a_private_key_file_in_the_project_is_refused(client, proj):
    _refused(_read(client, "keys/instance.key"), "secret-kind")


def test_a_symlink_to_a_private_key_is_refused_whatever_its_name(client, proj):
    (proj / "flows" / "innocent.md").symlink_to(proj / "keys" / "instance.key")
    (proj / "flows" / "notes.txt").symlink_to(proj / "keys" / "instance.key")
    _refused(_read(client, "flows/innocent.md"), "secret-kind")
    _refused(_read(client, "flows/notes.txt"), "secret-kind")


def test_a_pem_private_key_under_an_innocent_name_is_refused_by_content(client, proj, made_key):
    (proj / "flows" / "readme.md").write_bytes(made_key[0])
    (proj / "flows" / "config.json").write_bytes(b'{"key": ' + repr(made_key[0].decode()).encode() + b"}\n")
    _refused(_read(client, "flows/readme.md"), "secret-content")
    _refused(_read(client, "flows/config.json"), "secret-content")
    escaped = made_key[0].decode().replace("\n", "\\n")
    (proj / "flows" / "embedded.json").write_text('{"key": "' + escaped + '"}\n', encoding="utf-8")
    _refused(_read(client, "flows/embedded.json"), "secret-content")


def test_a_der_ed25519_private_key_under_an_innocent_name_is_refused(client, proj):
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    der = Ed25519PrivateKey.generate().private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    (proj / "flows" / "blob.txt").write_bytes(der)
    _refused(_read(client, "flows/blob.txt"), "secret-content")


def test_the_consoles_session_token_file_is_refused_directly_and_through_a_link(client, proj):
    state_dir = core.SETTINGS.state_dir
    token_path = session.token_file_path(state_dir, core.SETTINGS.port)
    Path(token_path).write_text("not-a-real-token\n", encoding="utf-8")
    # the token file under a listed name in the state directory, and a link to it from a flow folder
    Path(state_dir, "token.txt").write_text("not-a-real-token\n", encoding="utf-8")
    (proj / "flows" / "token.txt").symlink_to(token_path)
    _refused(_read(client, os.path.relpath(token_path, proj)), "console-state")
    _refused(_read(client, "console/token.txt"), "console-state")
    _refused(_read(client, "flows/token.txt"), "console-state")
    _refused(_read(client, "console/mission_audit.log"), "not-readable")


def test_env_like_and_unlisted_files_are_refused(client, proj):
    (proj / ".env").write_text("A=1\n", encoding="utf-8")
    (proj / "flows" / "prod.env").write_text("A=1\n", encoding="utf-8")
    (proj / "flows" / "secrets.yaml").write_text("a: 1\n", encoding="utf-8")
    (proj / "flows" / "store.p12").write_bytes(b"\x30\x82")
    (proj / "id_ed25519").write_text("x\n", encoding="utf-8")
    _refused(_read(client, ".env"), "secret-kind")
    _refused(_read(client, "flows/prod.env"), "secret-kind")
    _refused(_read(client, "flows/secrets.yaml"), "secret-kind")
    _refused(_read(client, "flows/store.p12"), "secret-kind")
    _refused(_read(client, "id_ed25519"), "secret-kind")
    (proj / "flows" / "data.csv").write_text("a,b\n", encoding="utf-8")
    _refused(_read(client, "flows/data.csv"), "not-readable")


def test_every_file_the_listing_shows_still_reads(client, proj):
    listed = client.get(API_V1 + "/files").json()["files"]
    paths = {entry["path"] for entry in listed}
    assert {"flows/f.md", "flows/f.tests.md", "flows/f.md.manifest.json", "flows/f.md.manifest.sig",
            "flows/routing.yaml", "prismpath.lock.json", "events.jsonl", "notes.txt", "keys/instance.pub"} <= paths
    assert "keys/instance.key" not in paths
    for path in sorted(paths):
        response = _read(client, path)
        assert response.status_code == 200, (path, response.text)
        assert response.json()["path"] == path
    assert _read(client, "flows/f.md").json()["content"] == FLOW


def test_the_listing_never_shows_what_the_read_refuses(client, proj, made_key):
    (proj / "flows" / "readme.md").write_bytes(made_key[0])
    (proj / "flows" / "secrets.yaml").write_text("a: 1\n", encoding="utf-8")
    Path(core.SETTINGS.state_dir, "token.txt").write_text("x\n", encoding="utf-8")
    paths = {entry["path"] for entry in client.get(API_V1 + "/files").json()["files"]}
    assert "flows/secrets.yaml" not in paths and "console/token.txt" not in paths
    assert "flows/readme.md" in paths          # by content: listed (the listing does not read), refused on read


# ── the auditing routes ───────────────────────────────────────────────────────────────────────
@pytest.fixture
def root(tmp_path, monkeypatch, made_key):
    evidence_root = tmp_path / "evidence"
    (evidence_root / "keys").mkdir(parents=True)
    (evidence_root / "keys" / "instance.key").write_bytes(made_key[0])
    (evidence_root / "keys" / "instance.pub").write_bytes(made_key[1])
    (evidence_root / "ok.jsonl").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [str(evidence_root)])
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    monkeypatch.setattr(core.SETTINGS, "state_dir", str(state_dir))
    monkeypatch.setattr(core.audit, "LOG", audit_log.AuditLog(str(state_dir / "mission_audit.log")))
    return evidence_root


@pytest.fixture(params=[False, True], ids=["full", "read-only"])
def auditor(request, root):
    return _client(request.param)


def _raw(client, path):
    return client.post(API_V1 + "/evidence/raw", json={"path": path})


def test_raw_refuses_a_private_key_under_an_evidence_root(auditor, root):
    assert _raw(auditor, "ok.jsonl").status_code == 200
    _refused(_raw(auditor, "keys/instance.key"), "secret-kind")
    (root / "run.audit.jsonl").symlink_to(root / "keys" / "instance.key")
    _refused(_raw(auditor, "run.audit.jsonl"), "secret-kind")


def test_raw_and_trail_refuse_a_pem_private_key_under_an_innocent_name(auditor, root, made_key):
    (root / "copy.audit.jsonl").write_bytes(made_key[0])
    _refused(_raw(auditor, "copy.audit.jsonl"), "secret-content")
    _refused(auditor.post(API_V1 + "/evidence/trail", json={"path": "copy.audit.jsonl"}), "secret-content")


def test_a_pin_naming_a_private_key_is_refused(auditor, root):
    refused = auditor.post(API_V1 + "/evidence/trail",
                           json={"path": "ok.jsonl", "pins": [str(root / "keys" / "instance.key")]})
    _refused(refused, "secret-kind")
    assert auditor.post(API_V1 + "/evidence/trail",
                        json={"path": "ok.jsonl", "pins": [str(root / "keys" / "instance.pub")]}).status_code == 200


def test_an_evidence_root_holding_the_console_state_serves_only_its_log(auditor, root, tmp_path, monkeypatch):
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [str(tmp_path)])
    core.audit.LOG.append("console/operating/abcd", "sprint.stop", {"proj": "p"})
    token_path = session.token_file_path(core.SETTINGS.state_dir, core.SETTINGS.port)
    Path(token_path).write_text("not-a-real-token\n", encoding="utf-8")
    _refused(_raw(auditor, token_path), "console-state")
    assert _raw(auditor, core.audit.LOG.path).status_code == 200
    assert auditor.post(API_V1 + "/evidence/raw", json={"console": True}).status_code == 200
