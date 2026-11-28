# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The older signed forms (spec-policy-distribution.md, section 17): every writer left emits only distribution
envelopes (L1, case 100), and a reader given an older form where no envelope was committed accepts it with a
`legacy_form` audit event (L3, case 102).

The older forms are written here by test helpers, as writers before 0.3.0 made them, and never by a writer of the
package's command line."""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import legacy  # noqa: E402
from prismpath.gateway import cli as gcli, grants  # noqa: E402
from prismpath.hotswap import policy_host as ph  # noqa: E402
from prismpath.hotswap import policy_pack as pp  # noqa: E402
from prismpath.kernel import canon2, ppt_compile as pc  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402
from prismpath.ledgers.audit_log import AuditLog  # noqa: E402
from prismpath.tests.test_gateway_grants import older_grant  # noqa: E402
from prismpath.onion import keys as onion_keys

ROOT = Path(__file__).resolve().parents[2]
FIELDS = {"temp": "int"}
FLOW = "# f\n## start\n-> hot: when temp >= 100\n-> cold: else\n## hot\n-> end\n## cold\n-> end\n## end\n"
NOW = 1_800_000_000


# ------------------------------------------------------------------ the older forms, as writers before 0.3.0
def older_pack(ppt, keys, version, envelope_id="env1"):
    """A `ppt-pack/1` pack: the manifest and its detached signature beside the image."""
    return pp.build_pack(str(ppt), FIELDS, version, envelope_id, keys["private"], keys["public"])


def older_attestation(home: Path, image: bytes, case: str = commands.POLICY_CASE) -> bytes:
    """A home's `prismpath.core-image/1` attestation, signed with its authority key."""
    from prismpath.ledgers import core_evidence
    signer = onion_keys.load_signer(str(commands._key_paths(home, "authority")[0]))
    return canon2.dumps({"format": core_evidence.IMAGE_FORMAT, "case": case,
                         "image_sha256": hashlib.sha256(image).hexdigest(), "key_id": commands._key_id(home, "authority"),
                         "sig": signer.sign(core_evidence.IMAGE_DOMAIN + image).hex()}) + b"\n"


# ------------------------------------------------------------------ fixtures
@pytest.fixture
def keys(tmp_path):
    return pp.keygen(str(tmp_path / "keys"))


@pytest.fixture
def qualification(tmp_path, keys):
    return pp.build_envelope("env1", FIELDS, None, keys["private"], keys["public"], str(tmp_path / "env"))


def _image(tmp_path, name="p") -> Path:
    ppt = tmp_path / f"{name}.ppt"
    ppt.write_bytes(pc.compile_flow(parse(FLOW)).serialize())
    return ppt


def _cli(*argv):
    import subprocess
    return subprocess.run([sys.executable, "-m", "prismpath", *argv], capture_output=True, text=True, cwd=ROOT)


def _legacy(path: Path) -> list:
    return [event["data"] for event in legacy.events(AuditLog(str(path)))]


def _agent_home(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    (tmp_path / "ws").mkdir()
    assert commands.init(tmp_path / "ws", yes=True, as_json=True, out=open(os.devnull, "w")) == 0
    return commands.config_dir()


# ------------------------------------------------------------------ case 100: the writers emit envelopes
def test_case_100_swap_pack_writes_a_sealed_policy_ppt_envelope_and_no_manifest(tmp_path, keys, qualification):
    """case_100: L1, `swap pack` writes a `policy.ppt` envelope over the same image bytes, and the host reads it."""
    ppt = _image(tmp_path)
    image = ppt.read_bytes()
    done = _cli("swap", "pack", "--ppt", str(ppt), "--priv", keys["private"], "--pub", keys["public"],
                "--fields", "temp:int", "--version", "3", "--envelope-id", "env1", "--overlay-of", "baseline")
    assert done.returncode == 0, done.stderr
    printed = json.loads(done.stdout)
    assert not Path(str(ppt) + ".manifest.json").exists() and not Path(str(ppt) + ".manifest.sig").exists()
    envelope_bytes, entries = env.unseal(Path(str(ppt) + ".sealed").read_bytes())
    envelope = env.read(envelope_bytes)
    assert (envelope.artifact, envelope.targets, envelope.stream, envelope.seq) == ("policy.ppt", ("host",), "local", 3)
    assert envelope.body_sha256 == hashlib.sha256(image).hexdigest() == printed["image_sha256"]   # the same bytes (L1)
    assert envelope.meta["qualification"] == "env1" and envelope.meta["fields"] == FIELDS
    assert envelope.meta["overlay_of"] == "baseline" and envelope.meta["counts"] == printed["counts"]
    assert envelope.expires - envelope.not_before == legacy.LOCAL_LIFETIME
    assert [kid for kid, _ in entries] == [printed["key_id"]] and printed["format"] == env.FORMAT
    assert printed["dist_envelope_id"] == envelope.envelope_id and printed["sealed"] == str(ppt) + ".sealed"
    checked = _cli("swap", "verify", "--ppt", str(ppt), "--pub", keys["public"])
    assert checked.returncode == 0 and json.loads(checked.stdout) == {"ok": True, "reasons": []}
    host = ph.PolicyHost(str(tmp_path / "state"), [keys["public"]], qualification)
    result = host.swap(str(ppt))
    assert result["ok"] and result["version"] == 3 and result["overlay_of"] == "baseline"
    assert legacy.events(host.audit) == []                       # an envelope is no older form


def test_case_100_a_sealed_pack_is_refused_when_edited_expired_or_signed_by_another_key(tmp_path, keys):
    """case_100: a sealed pack is refused for each check the older manifest had, and for its time (V6)."""
    ppt = _image(tmp_path)
    pp.seal_pack(str(ppt), FIELDS, 1, "env1", keys["private"], keys["public"])
    other = pp.keygen(str(tmp_path / "other"))
    assert pp.verify_pack(str(ppt), [other["public"]])[:2] == (False, ["sig:invalid"])
    key_id = pp.load_public(keys["public"])[1]
    assert pp.verify_pack(str(ppt), [keys["public"]], frozenset({key_id}))[:2] == (False, ["sig:revoked-key"])
    raw = bytearray(ppt.read_bytes())
    raw[-1] ^= 1
    ppt.write_bytes(bytes(raw))
    assert pp.verify_pack(str(ppt), [keys["public"]])[:2] == (False, ["image:sha256-mismatch"])
    ppt.write_bytes(bytes(raw[:-1]) + bytes([raw[-1] ^ 1]))
    past = int(time.time()) - 20
    pp.seal_pack(str(ppt), FIELDS, 1, "env1", keys["private"], keys["public"], not_before=past, expires=past + 10)
    assert pp.verify_pack(str(ppt), [keys["public"]])[:2] == (False, ["dist:expired"])
    pp.seal_pack(str(ppt), FIELDS, 1, "env1", keys["private"], keys["public"],
                 not_before=int(time.time()) + 3600, expires=int(time.time()) + 7200)
    assert pp.verify_pack(str(ppt), [keys["public"]])[:2] == (False, ["dist:not-yet-valid"])
    with pytest.raises(ValueError, match="private half"):
        pp.seal_pack(str(ppt), FIELDS, 1, "env1", other["private"], keys["public"])


def test_case_100_seal_pack_replaces_an_older_manifest_and_the_envelope_is_read_first(tmp_path, keys):
    """case_100: sealing removes the older manifest, so the image has one form and the envelope is read."""
    ppt = _image(tmp_path)
    older_pack(ppt, keys, 1)
    assert pp.is_older(pp.verify_pack(str(ppt), [keys["public"]])[2])
    pp.seal_pack(str(ppt), FIELDS, 2, "env1", keys["private"], keys["public"])
    ok, reasons, manifest = pp.verify_pack(str(ppt), [keys["public"]])
    assert ok and not pp.is_older(manifest) and manifest["version"] == 2
    assert sorted(path.name for path in tmp_path.glob("p.ppt*")) == ["p.ppt", "p.ppt.sealed"]


def test_case_100_agent_init_records_a_sealed_policy_core_envelope(tmp_path, monkeypatch):
    """case_100: L1, `agent init` records the home's policy as a sealed `policy.core` envelope."""
    home = _agent_home(tmp_path, monkeypatch)
    image = (home / commands.POLICY_FILE).read_bytes()
    envelope = env.read(env.unseal((home / commands.ATTESTATION_FILE).read_bytes())[0])
    assert (envelope.artifact, envelope.targets, envelope.stream) == ("policy.core", ("agent",), "local")
    assert envelope.body_sha256 == envelope.policy_sha256 == hashlib.sha256(image).hexdigest()
    assert commands.load_checked(home)[0].image == image
    assert not (home / legacy.AUDIT_FILE).exists()               # nothing older was read


def test_case_100_gateway_init_seals_for_the_gateway_kind_and_an_edited_policy_is_refused(tmp_path):
    """case_100: L1, `gateway init` seals for the `gateway` kind, and the image is held to the body."""
    home = tmp_path / "gw"
    assert gcli.init(home, None, out=open(os.devnull, "w")) == 0
    envelope = env.read(env.unseal((home / commands.ATTESTATION_FILE).read_bytes())[0])
    assert (envelope.artifact, envelope.targets) == ("policy.core", ("gateway",))
    policy, _store = commands.load_checked(home)
    (home / commands.POLICY_FILE).write_bytes(policy.image + b" ")
    with pytest.raises(commands.AgentError, match="does not verify"):
        commands.load_checked(home)


def test_case_100_a_sealed_record_for_another_artifact_or_kind_is_refused(tmp_path):
    """case_100: a home reads only a `policy.core` envelope for its own kinds."""
    home = tmp_path / "gw"
    assert gcli.init(home, None, out=open(os.devnull, "w")) == 0
    image = (home / commands.POLICY_FILE).read_bytes()
    signer = onion_keys.load_signer(str(commands._key_paths(home, "authority")[0]))
    (home / commands.ATTESTATION_FILE).write_bytes(legacy.local_seal("policy.core", image, [signer], seq=1,
                                                                     targets=("host",)))
    with pytest.raises(commands.AgentError, match="not a policy.core for an agent or gateway home"):
        commands.load_checked(home)


# ------------------------------------------------------------------ case 102: the readers of the older forms
def test_case_102_an_older_pack_is_swapped_with_a_legacy_form_event(tmp_path, keys, qualification):
    """case_102: L3, a host with no envelope committed swaps an older pack and logs `legacy_form`."""
    ppt = _image(tmp_path)
    manifest = older_pack(ppt, keys, 1)
    host = ph.PolicyHost(str(tmp_path / "state"), [keys["public"]], qualification)
    assert host.swap(str(ppt))["ok"]
    (event,) = legacy.events(host.audit)
    assert event["actor"] == legacy.ACTOR and event["data"] == {
        "form": "ppt-pack/1", "reader": "policy_host.swap", "sha256": manifest["image_sha256"],
        "key_id": manifest["key_id"], "refused_from": "0.4.0"}


def test_case_102_the_xdp_preloader_reads_an_older_pack_with_a_legacy_form_event(tmp_path, keys):
    """case_102: L3, the XDP preloader reads the edge's older pack and logs `legacy_form`."""
    sys.path.insert(0, str(ROOT / "prismpath-ebpf"))
    try:
        import net_swap as ns
    finally:
        sys.path.remove(str(ROOT / "prismpath-ebpf"))
    ppt = _image(tmp_path)
    manifest = older_pack(ppt, keys, 1)
    pp.build_envelope("env1", FIELDS, None, keys["private"], keys["public"], str(tmp_path / "env"))
    state = tmp_path / "state"
    result = ns.preload_swap(str(ppt), "lo", [keys["public"]], str(tmp_path / "env" / "env1.envelope"), str(state),
                             dry_run=True, run=lambda *a, **k: pytest.fail("a dry run never runs the loader"))
    assert result["ok"]
    (event,) = _legacy(state / "net_swaps.log")
    assert event["form"] == "ppt-pack/1" and event["reader"] == "net_swap.preload_swap"
    assert event["sha256"] == manifest["image_sha256"]


def test_case_102_an_older_attestation_is_read_with_a_signed_legacy_form_event_each_time(tmp_path, monkeypatch):
    """case_102: L3, a home's older attestation is read with a signed `legacy_form` event each time."""
    home = _agent_home(tmp_path, monkeypatch)
    image = (home / commands.POLICY_FILE).read_bytes()
    (home / commands.ATTESTATION_FILE).write_bytes(older_attestation(home, image))
    for _ in range(2):
        assert commands.load_checked(home)[0].image == image
    events = _legacy(home / legacy.AUDIT_FILE)
    assert events == [{"form": "prismpath.core-image/1", "reader": "agent.load_checked",
                       "sha256": hashlib.sha256(image).hexdigest(), "key_id": commands._key_id(home, "authority"),
                       "refused_from": "0.4.0"}] * 2
    log = AuditLog(str(home / legacy.AUDIT_FILE))
    assert log.verify_statements([(home / "instance.pub").read_bytes()])["status"] == "signed"
    # init seals the kept policy again, and the home reads no older form from then on
    assert commands.init(tmp_path / "ws", yes=True, as_json=True, out=open(os.devnull, "w")) == 0
    assert (home / commands.ATTESTATION_FILE).read_bytes()[:4] == env.MAGIC
    read = len(_legacy(home / legacy.AUDIT_FILE))                # init read the older form once more
    assert read == 3 and commands.load_checked(home)[0].image == image
    assert len(_legacy(home / legacy.AUDIT_FILE)) == read


def test_case_102_an_older_grant_is_read_valid_with_a_legacy_form_event(tmp_path):
    """case_102: L3, an older grant read as valid writes `legacy_form`, and a refused one writes none."""
    home = tmp_path / "gw"
    assert gcli.init(home, None, out=open(os.devnull, "w")) == 0
    policy, _ = commands.load_checked(home)
    sha = hashlib.sha256(policy.image).hexdigest()
    value, doc = older_grant(home, sha, ["admin"], ["read"], 600, NOW)
    from prismpath.ledgers.root_statement import InstanceKey
    verifier = grants.Verifier(commands._key_paths(home, "authority")[1].read_bytes(), sha, home / grants.REVOKED_FILE,
                               clock=lambda: NOW, legacy_log=home / legacy.AUDIT_FILE,
                               instance_key=InstanceKey.load(str(commands._key_paths(home, "instance")[0])))
    assert verifier.read([value], "orders", "read")[0] == "invalid"      # a refusal is no successful read
    assert not (home / legacy.AUDIT_FILE).exists()
    state, record = verifier.read([value], "admin", "read")
    assert state == "valid" and record["grant_id"] == doc["grant_id"]
    (event,) = _legacy(home / legacy.AUDIT_FILE)
    assert event == {"form": "prismpath.grant/1", "reader": "gateway.grants", "sha256": record["grant_sha256"],
                     "key_id": verifier.key_id, "refused_from": "0.4.0"}
    envelope_value, _ = grants.issue(home, sha, ["admin"], ["read"], 600, now=NOW)
    assert verifier.read([envelope_value], "admin", "read")[0] == "valid"
    assert len(_legacy(home / legacy.AUDIT_FILE)) == 1             # an envelope grant writes none


def test_a_legacy_form_event_names_only_an_older_form():
    with pytest.raises(ValueError):
        legacy.event("prismpath.dist/1", reader="x", sha256="0" * 64, key_id=None)
    assert legacy.FORMS == {"ppt-pack/1", "prismpath.core-image/1", "prismpath.net_dests_pack/1", "prismpath.grant/1",
                            "prismpath.zones.attestation/1", "prismpath.cfs-table/1", "PPTM1"}
