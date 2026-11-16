# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control's authoring interface over HTTP (A1, A5, A6), driven through fastapi.testclient only.

The process owner's console edits flow documents and their fixture tables and nothing else, scaffolds a
new flow from the templates `prismpath init` ships, and shows a flow's change status: its sha256, whether
a flow manifest beside it is signed by a pinned authority key and names that hash, and whether the
followed deployment's active policy and last attestation run a pack built from that text. It never signs,
packs or swaps (plan section 3.4); the status names the commands of the signed path instead. Every write
is an intent before the effect and a `.result` after, a refused write is one `.refused` event, and the
read only posture mounts no authoring write at all."""
import hashlib
import os
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from prismpath import cli  # noqa: E402
from prismpath.ledgers import audit_log  # noqa: E402
from prismpath.mission_control import app as app_module  # noqa: E402
from prismpath.mission_control import core, files  # noqa: E402
from prismpath.mission_control.posture import CAPABILITY_KEY  # noqa: E402

API_V1 = "/api/v1"
HEADER = "X-PrismPath-Session"
FLOW = "---\nname: f\nstart: a\n---\n## a\n-> b: when score > 5\n-> c: else\n## b\nDone.\n## c\nDone.\n"
FIXTURE = "| node | outcome | fields | expect |\n|---|---|---|---|\n| a | x | score=9 | b |\n"
# A Level M flow that defines its fields, so a pack built from it records the flow's sha256.
DEFINED_FLOW = ("---\nname: defined_fixture\nstart: start\n"
                "field.load: fixed scale=100 unit=ratio rounding=floor min=0 max=100\n---\n"
                "## start\n-> hot: when load >= 0.9\n-> cold: else\n## hot\n## cold\n")
READ_ROUTES = {("GET", "/author/templates"), ("POST", "/author/status")}
WRITE_ROUTES = {("POST", "/author/scaffold"), ("POST", "/file")}


def _origin():
    return f"http://127.0.0.1:{core.SETTINGS.port}"


@pytest.fixture
def proj(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    (project / "flows").mkdir(parents=True)
    (project / "flows" / "f.md").write_text(FLOW, encoding="utf-8")
    (project / "flows" / "f.tests.md").write_text(FIXTURE, encoding="utf-8")
    (project / "flows" / "f.json").write_text("{}\n", encoding="utf-8")
    (project / "notes.txt").write_text("notes\n", encoding="utf-8")
    console_dir = tmp_path / "console"
    console_dir.mkdir()
    monkeypatch.setattr(core.audit, "LOG", audit_log.AuditLog(str(console_dir / "mission_audit.log")))
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [])
    core.STATE.update({"proc": None, "proj": str(project), "cfg": {}, "pinned": True})
    return project


def _client(read_only=False):
    application = app_module.create_app(read_only=read_only)
    return TestClient(application, base_url=_origin(), headers={HEADER: application.state.session.token})


@pytest.fixture
def client(proj):
    return _client(False)


@pytest.fixture
def reader(proj):
    return _client(True)


def _events():
    return [(event["action"], event["data"]) for event in core.audit.LOG.events]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _listing(base: Path) -> dict:
    out = {}
    for dirpath, dirnames, filenames in os.walk(base):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            info = os.lstat(full)
            out[os.path.relpath(full, base)] = (info.st_size, info.st_mtime_ns)
    return out


# ── route contracts ───────────────────────────────────────────────────────────────────────────
def test_the_authoring_routes_declare_their_capability_and_interface():
    schema = app_module.create_app(read_only=False).openapi()["paths"]
    for method, path in READ_ROUTES | WRITE_ROUTES:
        operation = schema.get(API_V1 + path, {}).get(method.lower())
        assert operation is not None, (method, path)
        expected = "write" if (method, path) in WRITE_ROUTES else "read"
        assert operation.get(CAPABILITY_KEY, "read") == expected, (method, path)
        assert "authoring" in operation.get("tags", []), (method, path)
    for path in ("/inspect/validate", "/inspect/lint", "/inspect/test", "/inspect/contract", "/inspect/portable",
                 "/prove/level-m", "/prove/reach"):
        assert "authoring" in schema[API_V1 + path]["post"]["tags"], path


def test_the_read_only_posture_mounts_the_authoring_reads_and_no_authoring_write():
    schema = app_module.create_app(read_only=True).openapi()["paths"]
    for method, path in READ_ROUTES:
        assert method.lower() in schema.get(API_V1 + path, {}), (method, path)
    for method, path in WRITE_ROUTES:
        assert method.lower() not in schema.get(API_V1 + path, {}), (method, path)


def test_the_read_only_posture_refuses_a_scaffold_and_writes_nothing(reader, proj):
    before = _listing(proj)
    response = reader.post(API_V1 + "/author/scaffold", json={"name": "fresh", "template": "starter"})
    assert response.status_code == 403 and "read-only" in response.json()["error"]["message"]
    refused = reader.post(API_V1 + "/file", json={"path": "flows/f.md", "content": "x"})
    assert refused.status_code == 403
    assert _listing(proj) == before and core.audit.LOG.events == []
    assert reader.get(API_V1 + "/author/templates").status_code == 200
    assert reader.post(API_V1 + "/author/status", json={"flow_md": "flows/f.md"}).json()["manifest"]["status"] == "unsigned"


# ── A1 editable kinds ─────────────────────────────────────────────────────────────────────────
def test_the_file_tree_marks_each_entry_flow_fixture_or_other(client):
    entries = {entry["path"]: entry["kind"] for entry in client.get(API_V1 + "/files").json()["files"]}
    assert entries["flows/f.md"] == "flow"
    assert entries["flows/f.tests.md"] == "fixture"
    assert entries["flows/f.json"] == "other" and entries["notes.txt"] == "other"
    assert files.EDITABLE_SUFFIXES == (".md",)


@pytest.mark.parametrize("path", ["flows/f.json", "notes.txt", "flows/new.js", "page.html", "style.css",
                                  "flows/f.md.manifest.json", "flows/f.md.manifest.sig", "lock.yaml", "flows/f"])
def test_a_write_outside_the_editable_kinds_is_refused_and_recorded(client, proj, path):
    target = proj / path
    before = target.read_bytes() if target.exists() else None
    response = client.post(API_V1 + "/file", json={"path": path, "content": "{\"forged\": true}"})
    assert response.status_code == 403, response.text
    assert "flow documents" in response.json()["error"]["message"]
    assert (target.read_bytes() if target.exists() else None) == before
    events = _events()
    assert [action for action, _ in events] == ["file.edit.refused"]
    assert events[0][1]["path"] == path and events[0][1]["reason"] == "not-editable"


@pytest.mark.parametrize("path", [".git/config.md", "flows/.hidden.md", "tools/x.md", "last-good/f.md"])
def test_a_write_into_a_directory_the_editor_does_not_list_is_refused(client, proj, path):
    response = client.post(API_V1 + "/file", json={"path": path, "content": FLOW})
    assert response.status_code == 403, response.text
    assert not (proj / path).exists()
    assert [action for action, _ in _events()] == ["file.edit.refused"]


def test_a_flow_named_link_to_a_file_of_another_kind_is_refused(client, proj):
    manifest = proj / "flows" / "f.md.manifest.json"
    manifest.write_text("{}\n", encoding="utf-8")
    os.symlink(manifest, proj / "flows" / "alias.md")
    response = client.post(API_V1 + "/file", json={"path": "flows/alias.md", "content": "{\"forged\": true}"})
    assert response.status_code == 403, response.text
    assert manifest.read_text() == "{}\n"
    assert [action for action, _ in _events()] == ["file.edit.refused"]


def test_a_flow_and_a_fixture_are_editable(client, proj):
    assert client.post(API_V1 + "/file", json={"path": "flows/f.md", "content": FLOW + "\n"}).status_code == 200
    assert client.post(API_V1 + "/file", json={"path": "flows/f.tests.md", "content": FIXTURE}).status_code == 200
    kinds = [data["kind"] for action, data in _events() if action == "file.edit"]
    assert kinds == ["flow", "fixture"]


# ── A6 scaffold ───────────────────────────────────────────────────────────────────────────────
def test_templates_list_the_starter_and_every_gallery_template(client):
    listed = {entry["name"]: entry for entry in client.get(API_V1 + "/author/templates").json()["templates"]}
    assert listed["starter"]["files"] == ["<name>.md", "<name>.tests.md"]
    gallery = cli._gallery_templates()
    assert gallery and set(gallery) <= set(listed)
    for name, template_dir in gallery.items():
        expected = sorted(item for item in os.listdir(template_dir) if item.endswith(".md") and item != "README.md")
        assert listed[name]["files"] == [f"<name>/{item}" for item in expected], name


def test_the_starter_scaffold_writes_exactly_its_two_files_and_records_intent_then_result(client, proj):
    before = set(_listing(proj))
    response = client.post(API_V1 + "/author/scaffold", json={"name": "demo"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["files"] == ["demo.md", "demo.tests.md"] and body["flow"] == "demo.md"
    assert set(_listing(proj)) - before == {"demo.md", "demo.tests.md"}
    assert (proj / "demo.md").read_text(encoding="utf-8") == cli.STARTER_FLOW
    assert (proj / "demo.tests.md").read_text(encoding="utf-8") == cli.STARTER_TESTS
    events = core.audit.LOG.events
    assert [event["action"] for event in events] == ["author.scaffold", "author.scaffold.result"]
    intent, result = events
    assert intent["actor"].startswith("console/authoring/") and result["actor"] == intent["actor"]
    assert intent["data"]["template"] == "starter" and intent["data"]["name"] == "demo"
    assert intent["data"]["files"] == [{"path": "demo.md", "sha256": _sha(proj / "demo.md")},
                                       {"path": "demo.tests.md", "sha256": _sha(proj / "demo.tests.md")}]
    assert result["data"]["intent"] == intent["idx"] and result["data"]["ok"] is True
    assert result["data"]["detail"]["files"] == intent["data"]["files"]


def test_a_gallery_scaffold_writes_exactly_the_templates_files_into_its_own_directory(client, proj):
    template_dir = Path(cli._gallery_templates()["fanout_review"])
    expected = sorted(item.name for item in template_dir.iterdir() if item.name.endswith(".md") and item.name != "README.md")
    before = set(_listing(proj))
    body = client.post(API_V1 + "/author/scaffold", json={"name": "review", "template": "fanout_review"}).json()
    assert body["files"] == [f"review/{name}" for name in expected] and body["flow"] == "review/fanout_review.md"
    assert set(_listing(proj)) - before == {"review"} | {f"review/{name}" for name in expected}
    for name in expected:
        assert (proj / "review" / name).read_bytes() == (template_dir / name).read_bytes()
    assert [event["action"] for event in core.audit.LOG.events] == ["author.scaffold", "author.scaffold.result"]
    validate = client.post(API_V1 + "/inspect/validate", json={"flow_md": body["flow"]}).json()
    assert validate["ok"] is True, validate                    # the @spawn child came with it


def test_a_scaffold_over_an_existing_file_is_refused_whole(client, proj):
    (proj / "demo.tests.md").write_text("mine\n", encoding="utf-8")
    before = _listing(proj)
    response = client.post(API_V1 + "/author/scaffold", json={"name": "demo"})
    assert response.status_code == 409, response.text
    assert _listing(proj) == before and (proj / "demo.tests.md").read_text() == "mine\n"
    assert [action for action, _ in _events()] == ["author.scaffold.refused"]


def test_a_file_that_appears_after_the_check_is_never_written_over(client, proj, monkeypatch):
    """The intent is recorded before any file is written; a file another writer makes in that moment is
    kept, the scaffold keeps nothing it wrote, and the result says it failed."""
    record_intent = core.audit.record_intent

    def intent_then_race(action, data, actor):
        event = record_intent(action, data, actor)
        (proj / "demo.tests.md").write_text("theirs\n", encoding="utf-8")
        return event
    monkeypatch.setattr(core.audit, "record_intent", intent_then_race)
    response = client.post(API_V1 + "/author/scaffold", json={"name": "demo"})
    assert response.status_code == 409, response.text
    assert (proj / "demo.tests.md").read_text() == "theirs\n" and not (proj / "demo.md").exists()
    assert not [entry for entry in os.listdir(proj) if entry.startswith(".mc-write-")]
    events = core.audit.LOG.events
    assert [event["action"] for event in events] == ["author.scaffold", "author.scaffold.result"]
    assert events[1]["data"]["ok"] is False


@pytest.mark.parametrize("name", ["../escape", "a/b", "", ".hidden", "x" * 65, "sp ace", "flows/../x"])
def test_a_scaffold_name_that_is_not_a_plain_name_is_refused(client, proj, name):
    before = _listing(proj)
    response = client.post(API_V1 + "/author/scaffold", json={"name": name})
    assert response.status_code == 400, (name, response.text)
    assert _listing(proj) == before and not (proj.parent / "escape.md").exists()


def test_an_unknown_template_is_refused(client, proj):
    before = _listing(proj)
    response = client.post(API_V1 + "/author/scaffold", json={"name": "demo", "template": "no_such_template"})
    assert response.status_code == 404
    assert _listing(proj) == before


def test_an_audit_failure_leaves_no_scaffolded_file(client, proj, monkeypatch):
    def refuse(*args, **kwargs):
        raise audit_log.AuditWriteError("disk full")
    monkeypatch.setattr(core.audit.LOG, "append", refuse)
    before = _listing(proj)
    response = client.post(API_V1 + "/author/scaffold", json={"name": "demo"})
    assert response.status_code == 503
    assert _listing(proj) == before


# ── A5 change status ──────────────────────────────────────────────────────────────────────────
@pytest.fixture
def authority(proj):
    pytest.importorskip("cryptography")
    from prismpath.hotswap import policy_pack
    made = policy_pack.keygen(str(proj / "keys"), "authority")
    return made["private"], made["public"]


def _status(client, **body):
    response = client.post(API_V1 + "/author/status", json={"flow_md": "flows/f.md", **body})
    assert response.status_code == 200, response.text
    return response.json()


def test_status_is_unsigned_for_a_flow_with_no_manifest(client, proj):
    status = _status(client)
    assert status["flow_sha256"] == _sha(proj / "flows" / "f.md")
    assert status["manifest"]["status"] == "unsigned" and status["manifest"]["verdict_of"] == "console"
    assert status["deployment"] is None
    assert status["commands"]["sign"].startswith("prismpath authorize sign ")
    assert "--version 1" in status["commands"]["sign"]
    assert status["writes"] is False


def test_status_is_signed_under_a_pinned_key_and_stale_when_the_manifest_names_another_hash(client, proj, authority):
    from prismpath.hotswap import flow_authority
    private, public = authority
    flow_authority.sign_flow(str(proj / "flows" / "f.md"), 1, private, public)
    assert _status(client)["manifest"]["status"] == "unchecked"
    signed = _status(client, pins=["keys/authority.pub"])
    assert signed["manifest"]["status"] == "signed"
    assert signed["manifest"]["manifest_flow_sha256"] == signed["flow_sha256"]
    assert "--version 2" in signed["commands"]["sign"]
    (proj / "flows" / "f.md").write_text(FLOW + "\n", encoding="utf-8")
    stale = _status(client, pins=["keys/authority.pub"])
    assert stale["manifest"]["status"] == "stale"
    assert stale["manifest"]["manifest_flow_sha256"] != stale["flow_sha256"]


def test_status_reads_and_writes_nothing(client, proj, authority):
    from prismpath.hotswap import flow_authority
    flow_authority.sign_flow(str(proj / "flows" / "f.md"), 1, *authority)
    before = _listing(proj)
    _status(client, pins=["keys/authority.pub"])
    assert _listing(proj) == before and core.audit.LOG.events == []


def test_status_refuses_a_fixture_a_path_outside_the_project_and_a_key_outside_the_roots(client, proj, tmp_path):
    assert client.post(API_V1 + "/author/status", json={"flow_md": "flows/f.tests.md"}).status_code == 400
    assert client.post(API_V1 + "/author/status", json={"flow_md": "../outside.md"}).status_code == 400
    elsewhere = tmp_path / "elsewhere.pub"
    elsewhere.write_bytes(b"\0" * 32)
    response = client.post(API_V1 + "/author/status", json={"flow_md": "flows/f.md", "pins": [str(elsewhere)]})
    assert response.status_code == 403, response.text
    hexed = client.post(API_V1 + "/author/status", json={"flow_md": "flows/f.md", "pins": ["ab" * 32]})
    assert hexed.status_code == 400                         # a key file is named, never the key itself


def _deploy(proj, authority, flow_text, attest=True):
    """A policy host state directory under the project running a pack built from `flow_text`."""
    from prismpath.hotswap import policy_host, policy_pack
    from prismpath.kernel import ppt_compile
    from prismpath.kernel.parser import parse
    private, public = authority
    fields = policy_pack.field_dictionary_of(flow_text)
    envelope = policy_pack.build_envelope("env1", fields, None, private, public, str(proj / "env"))
    ppt = proj / "packs" / "v1.ppt"
    ppt.parent.mkdir(exist_ok=True)
    ppt.write_bytes(ppt_compile.compile_flow(parse(flow_text)).serialize())
    policy_pack.build_pack(str(ppt), {}, version=1, envelope_id="env1", priv_path=private, pub_path=public,
                           flow_text=flow_text)
    host = policy_host.PolicyHost(str(proj / "state"), [public], envelope)
    assert host.swap(str(ppt))["ok"]
    if attest:
        host.attest()
    return host


def test_status_says_whether_the_deployment_runs_a_pack_built_from_this_text(client, proj, authority):
    (proj / "flows" / "f.md").write_text(DEFINED_FLOW, encoding="utf-8")
    host = _deploy(proj, authority, DEFINED_FLOW)
    status = _status(client, pins=["keys/authority.pub"], state_dir="state")
    deployment = status["deployment"]
    assert deployment["active"] == host.active()["active"]
    assert deployment["pack"]["status"] == "signed"
    assert deployment["pack"]["flow_sha256"] == status["flow_sha256"]
    assert deployment["runs"] == "this-text"
    assert deployment["attestation"]["names_active"] is True
    (proj / "flows" / "f.md").write_text(DEFINED_FLOW + "\n", encoding="utf-8")
    after = _status(client, pins=["keys/authority.pub"], state_dir="state")["deployment"]
    assert after["runs"] == "other-text"


def test_status_says_when_no_attestation_follows_the_active_policy(client, proj, authority):
    (proj / "flows" / "f.md").write_text(DEFINED_FLOW, encoding="utf-8")
    _deploy(proj, authority, DEFINED_FLOW, attest=False)
    deployment = _status(client, pins=["keys/authority.pub"], state_dir="state")["deployment"]
    assert deployment["attestation"] is None and deployment["runs"] == "this-text"
    assert deployment["commands"]["attest"].startswith("prismpath swap attest --out ")


def test_status_of_a_state_directory_with_nothing_active(client, proj):
    (proj / "state").mkdir()
    deployment = _status(client, state_dir="state")["deployment"]
    assert deployment["active"] is None and deployment["runs"] == "nothing-active"
    assert not (proj / "state" / "swaps.log").exists()


def test_status_refuses_a_state_directory_outside_the_roots(client, tmp_path):
    outside = tmp_path / "outside-state"
    outside.mkdir()
    response = client.post(API_V1 + "/author/status", json={"flow_md": "flows/f.md", "state_dir": str(outside)})
    assert response.status_code == 403, response.text


def test_status_reads_a_state_directory_under_an_evidence_root(client, proj, tmp_path, monkeypatch):
    evidence_root = tmp_path / "evidence"
    (evidence_root / "deploy").mkdir(parents=True)
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [str(evidence_root)])
    deployment = _status(client, state_dir=str(evidence_root / "deploy"))["deployment"]
    assert deployment["runs"] == "nothing-active"


def test_the_console_never_signs_packs_or_swaps():
    """No authoring module imports the signing half of the signed path (plan section 3.4)."""
    import ast
    source = Path(app_module.__file__).with_name("authoring.py").read_text(encoding="utf-8")
    called = {node.func.attr for node in ast.walk(ast.parse(source))
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    assert not called & {"sign_flow", "build_pack", "swap", "attest", "keygen", "build_envelope"}, called
