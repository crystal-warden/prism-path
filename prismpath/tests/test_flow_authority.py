# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Flow manifests: the policy authority signs an ordinary Markdown flow, and `run` refuses one that is
not authorized when authorization is required.

Pinned here: the happy path, every refusal with its registry cause (unsigned, edited by one byte,
an unknown key, a revoked key, an edited manifest, a version below the floor or equal to it with other
content), the instance key kept apart from the authority key, the authorization recorded in the signed
root statement, a present signature reported when authorization is not required, and the one line a
missing signing extra prints."""
import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("cryptography")

import prismpath  # noqa: E402
from prismpath import cli  # noqa: E402
from prismpath.hotswap import flow_authority as fa, policy_pack  # noqa: E402
from prismpath.kernel import causes  # noqa: E402
from prismpath.ledgers import root_statement as rs  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(prismpath.__file__)))
INSTALL_LINE = "needs cryptography (the signing extra): pip install 'prismpath[signing]'"

FLOW = """---
name: triage
start: a
---

## a
Do the thing.
-> b: when tests_pass

## b
Done.
"""

DEFINED_FLOW = """---
name: defined
start: start
field.load: fixed scale=100 unit=ratio rounding=floor min=0 max=100
---
## start
-> hot: when load >= 0.9
-> cold: else
## hot
## cold
"""


@pytest.fixture(autouse=True)
def _no_ambient_keys(monkeypatch):
    for name in (rs.INSTANCE_KEY_ENV, fa.REQUIRE_ENV, fa.AUTHORITY_PUB_ENV, fa.STATE_DIR_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def setup(tmp_path):
    authority = policy_pack.keygen(str(tmp_path / "keys"))                 # authority.key / authority.pub
    instance = rs.keygen(str(tmp_path / "keys"))                           # instance.key / instance.pub
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW)
    return {"authority": authority, "instance": instance, "flow": str(flow), "tmp": tmp_path,
            "state": str(tmp_path / "state")}


def _sign(setup, version=1, keys=None):
    keys = keys or setup["authority"]
    return fa.sign_flow(setup["flow"], version, keys["private"], keys["public"])


def _verify(setup, pubs=None, revoked=frozenset(), floor=None):
    return fa.verify_flow(setup["flow"], pubs or [setup["authority"]["public"]], revoked, floor=floor)


def _main(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def _run_required(capsys, setup, *extra):
    return _main(capsys, "run", setup["flow"], "--require-authorization", "--authority-pub",
                 setup["authority"]["public"], "--state-dir", setup["state"], *extra)


# ------------------------------------------------------------------ the manifest

def test_a_signed_flow_verifies(setup):
    manifest = _sign(setup, version=3)
    ok, reasons, verified = _verify(setup)
    assert ok and reasons == [] and verified == manifest
    assert manifest["format"] == fa.FLOW_MANIFEST_FORMAT and manifest["flow"] == "triage"
    assert manifest["version"] == 3 and manifest["key_id"] == setup["authority"]["key_id"]
    assert manifest["flow_sha256"] == fa.canon.sha256_hex(FLOW.encode()) and "fields" not in manifest
    assert all(os.path.exists(path) for path in fa.manifest_paths(setup["flow"]))


def test_a_flow_that_defines_its_fields_signs_their_definitions(setup):
    with open(setup["flow"], "w") as handle:
        handle.write(DEFINED_FLOW)
    manifest = _sign(setup)
    assert manifest["fields"] == {"load": "fixed scale=100 rounding=floor unit=ratio min=0 max=100 absent=refused"}
    assert _verify(setup)[0]


def test_line_endings_do_not_unauthorize_a_flow(setup):
    _sign(setup)
    with open(setup["flow"], "w", newline="\r\n") as handle:
        handle.write(FLOW)
    assert _verify(setup)[0]


def test_an_unsigned_flow_is_refused(setup):
    assert _verify(setup)[:2] == (False, ["sig:missing"])


def test_a_flow_edited_by_one_byte_is_refused(setup):
    _sign(setup)
    with open(setup["flow"], "a") as handle:
        handle.write(" ")
    assert _verify(setup)[:2] == (False, ["flow:sha256-mismatch"])
    assert causes.code("flow:sha256-mismatch") == 87


def test_an_unknown_key_is_refused(setup, tmp_path):
    _sign(setup)
    other = policy_pack.keygen(str(tmp_path / "other"))
    assert _verify(setup, pubs=[other["public"]])[:2] == (False, ["sig:invalid"])


def test_a_revoked_key_is_refused(setup):
    _sign(setup)
    assert _verify(setup, revoked=frozenset({setup["authority"]["key_id"]}))[:2] == (False, ["sig:revoked-key"])


def test_an_edited_manifest_is_refused(setup):
    _sign(setup)
    json_path = fa.manifest_paths(setup["flow"])[0]
    manifest = json.load(open(json_path)); manifest["version"] = 9
    json.dump(manifest, open(json_path, "w"))
    assert _verify(setup)[:2] == (False, ["sig:invalid"])
    open(json_path, "w").write("{not json")
    assert _verify(setup)[:2] == (False, ["manifest:bad-format"])


def test_the_version_floor(setup):
    floor = fa.VersionFloor.in_state_dir(setup["state"])
    manifest = _sign(setup, version=2)
    assert _verify(setup, floor=floor)[0]
    floor.accept(manifest)
    assert _verify(setup, floor=fa.VersionFloor.in_state_dir(setup["state"]))[0]        # the same flow again
    _sign(setup, version=1)
    assert _verify(setup, floor=floor)[:2] == (False, ["flow:version-replay"])           # older
    with open(setup["flow"], "a") as handle:
        handle.write("\n")
    _sign(setup, version=2)
    assert _verify(setup, floor=floor)[:2] == (False, ["flow:version-replay"])           # same version, other flow
    _sign(setup, version=3)
    assert _verify(setup, floor=floor)[0]


def test_sign_refuses_a_private_key_that_is_not_the_public_one(setup):
    with pytest.raises(ValueError, match="is not the private half"):
        fa.sign_flow(setup["flow"], 1, setup["instance"]["private"], setup["authority"]["public"])


# ------------------------------------------------------------------ run

def test_run_runs_an_authorized_flow_and_the_signed_root_names_the_authorization(setup, capsys):
    manifest = _sign(setup, version=4)
    audit = str(setup["tmp"] / "run.audit.jsonl")
    code, out, _err = _run_required(capsys, setup, "--audit-log", audit, "--instance-key", setup["instance"]["private"])
    assert code == 0 and "Authorization: verified, triage version 4" in out
    statement = rs.read_statements(rs.statements_path_for(audit))[0][-1]
    assert statement["policy"]["authorization"] == {"manifest_sha256": fa.manifest_sha256(manifest),
                                                    "key_id": setup["authority"]["key_id"], "version": 4}
    receipt = json.loads(open(audit).readline())["data"]
    assert receipt["policy"] == statement["policy"]
    assert json.load(open(os.path.join(setup["state"], fa.FLOOR_FILE)))["triage"]["version"] == 4
    code, out, _err = _main(capsys, "trail", audit, "--pub", setup["instance"]["public"], "--receipt", "0")
    assert code == 0 and f"authorized by authority key {setup['authority']['key_id'][:16]} at version 4" in out


@pytest.mark.parametrize("damage, cause", [("unsigned", "sig:missing"), ("edited", "flow:sha256-mismatch"),
                                           ("unknown", "sig:invalid"), ("revoked", "sig:revoked-key"),
                                           ("older", "flow:version-replay")])
def test_run_refuses_an_unauthorized_flow_with_its_cause(setup, capsys, damage, cause):
    extra = []
    if damage != "unsigned":
        _sign(setup, version=2)
    if damage == "edited":
        with open(setup["flow"], "a") as handle:
            handle.write(" ")
    if damage == "unknown":
        other = policy_pack.keygen(str(setup["tmp"] / "other"))
        fa.sign_flow(setup["flow"], 2, other["private"], other["public"])
    if damage == "revoked":
        revoked = setup["tmp"] / "revoked.json"
        revoked.write_text(json.dumps([setup["authority"]["key_id"]]))
        extra = ["--revoked", str(revoked)]
    if damage == "older":
        assert _run_required(capsys, setup)[0] == 0
        _sign(setup, version=1)
    audit = str(setup["tmp"] / "refused.audit.jsonl")
    code, out, err = _run_required(capsys, setup, "--audit-log", audit, "--instance-key",
                                   setup["instance"]["private"], *extra)
    assert code == 2 and "Path:" not in out
    assert err.strip() == f"prismpath run: refused: the flow is not authorized: {cause} (cause {causes.code(cause)})"
    receipt = json.loads(open(audit).readline())["data"]
    assert receipt["outcome"] == "refused" and receipt["cause"] == causes.code(cause)
    assert receipt["policy"]["authorization"] == "unauthorized"
    from prismpath.ledgers.audit_log import AuditLog
    assert AuditLog(audit).verify_statements([rs.load_public(setup["instance"]["public"])])["status"] == rs.SIGNED


def test_run_refuses_the_instance_key_as_an_authority_key(setup, capsys):
    fa.sign_flow(setup["flow"], 1, setup["instance"]["private"], setup["instance"]["public"])
    code, _out, err = _main(capsys, "run", setup["flow"], "--require-authorization", "--authority-pub",
                            setup["instance"]["public"], "--state-dir", setup["state"],
                            "--audit-log", str(setup["tmp"] / "a.audit.jsonl"), "--instance-key", setup["instance"]["private"])
    assert code == 2 and "is also a policy authority key" in err


def test_authorize_sign_refuses_the_instance_key(setup, capsys, monkeypatch):
    monkeypatch.setenv(rs.INSTANCE_KEY_ENV, setup["instance"]["private"])
    code, _out, err = _main(capsys, "authorize", "sign", setup["flow"], "--priv", setup["instance"]["private"],
                            "--pub", setup["instance"]["public"], "--version", "1")
    assert code == 2 and "that is the instance key" in err
    assert not os.path.exists(fa.manifest_paths(setup["flow"])[0])


def test_required_authorization_needs_an_authority_key(setup, capsys):
    code, _out, err = _main(capsys, "run", setup["flow"], "--require-authorization")
    assert code == 2 and "needs the trusted authority key" in err


def test_required_by_the_environment(setup, capsys, monkeypatch):
    monkeypatch.setenv(fa.REQUIRE_ENV, "1")
    monkeypatch.setenv(fa.AUTHORITY_PUB_ENV, setup["authority"]["public"])
    monkeypatch.setenv(fa.STATE_DIR_ENV, setup["state"])
    code, _out, err = _main(capsys, "run", setup["flow"])
    assert code == 2 and "sig:missing (cause 1)" in err


def test_a_present_signature_is_reported_when_not_required(setup, capsys):
    _sign(setup)
    code, out, _err = _main(capsys, "run", setup["flow"])
    assert code == 0 and "a flow manifest is present (version 1" in out and "not checked" in out
    with open(setup["flow"], "a") as handle:
        handle.write(" ")
    code, out, _err = _main(capsys, "run", setup["flow"], "--authority-pub", setup["authority"]["public"],
                            "--state-dir", setup["state"])
    assert code == 0 and "Authorization: NOT verified: flow:sha256-mismatch (cause 87)" in out
    assert not os.path.exists(os.path.join(setup["state"], fa.FLOOR_FILE))     # report only, the floor is not moved


def test_an_unsigned_flow_runs_as_before_when_not_required(setup, capsys):
    code, out, _err = _main(capsys, "run", setup["flow"])
    assert code == 0 and "Authorization" not in out


def test_resume_refuses_an_unauthorized_flow(setup, capsys, tmp_path):
    from prismpath.kernel.engine import run as engine_run
    from prismpath.kernel.parser import parse_file
    from prismpath.ledgers import checkpoint
    flow = tmp_path / "wait.md"
    flow.write_text("---\nname: w\nstart: a\n---\n\n## a\nAsk.\n-> b: when tests_pass\n\n## b\nDone.\n")
    result = engine_run(parse_file(str(flow)), lambda node, instruction, state: {"needs_human": True})
    checkpoint_path = str(tmp_path / "wait.checkpoint.json")
    checkpoint.save_checkpoint(checkpoint_path, str(flow), result, "a")
    code, _out, err = _main(capsys, "resume", checkpoint_path, "--choose", "b", "--require-authorization",
                            "--authority-pub", setup["authority"]["public"], "--state-dir", setup["state"])
    assert code == 2 and "sig:missing" in err


def test_authorize_cli_round_trip(setup, capsys):
    code, out, _err = _main(capsys, "authorize", "sign", setup["flow"], "--priv", setup["authority"]["private"],
                            "--pub", setup["authority"]["public"], "--version", "5")
    signed = json.loads(out)
    assert code == 0 and signed["version"] == 5 and signed["manifest_sha256"] == fa.manifest_sha256(fa.read_manifest(setup["flow"]))
    code, out, _err = _main(capsys, "authorize", "verify", setup["flow"], "--pub", setup["authority"]["public"])
    assert code == 0 and json.loads(out)["ok"] is True
    with open(setup["flow"], "a") as handle:
        handle.write("x")
    code, out, _err = _main(capsys, "authorize", "verify", setup["flow"], "--pub", setup["authority"]["public"])
    assert code == 1 and json.loads(out)["causes"] == [87]


# ------------------------------------------------------------------ without the signing extra

def _cli(*argv, cwd=None):
    script = ("import sys\n"
              "sys.modules['cryptography'] = None\n"
              "from prismpath.cli import main\n"
              "raise SystemExit(main(sys.argv[1:]))\n")
    env = {key: value for key, value in os.environ.items()
           if key not in (rs.INSTANCE_KEY_ENV, fa.REQUIRE_ENV, fa.AUTHORITY_PUB_ENV, fa.STATE_DIR_ENV)}
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, "-c", script, *argv], capture_output=True, text=True, env=env, cwd=cwd)


@pytest.mark.parametrize("argv", [
    ["authorize", "sign", "flow.md", "--priv", "keys/authority.key", "--pub", "keys/authority.pub", "--version", "1"],
    ["authorize", "verify", "flow.md", "--pub", "keys/authority.pub"],
    ["run", "flow.md", "--require-authorization", "--authority-pub", "keys/authority.pub", "--state-dir", "state"]])
def test_no_cryptography_is_one_install_line(argv, setup):
    _sign(setup)
    res = _cli(*argv, cwd=setup["tmp"])
    assert res.returncode == 2
    assert res.stderr.strip() == f"prismpath {argv[0]}: {INSTALL_LINE}"
