"""CryptoHost (spec-crypto-agility.md §4) — the runtime swap governor.

A swap is Authorized + Envelope-bounded (declared suites ⊆ approved, registry_hash bound) + monotonic
+ provider-available, every attempt is one audit event, and provider absence REFUSES rather than
downgrades. Uses the real compiler + real Ed25519."""
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath import crypto_host as ch  # noqa: E402
from prismpath import crypto_registry as cr  # noqa: E402
from prismpath import policy_pack as pp  # noqa: E402
from prismpath.parser import parse  # noqa: E402

_hw = Path(__file__).resolve().parent.parent.parent / "prismpath-hw"
if not (_hw / "ppt_compile.py").exists():
    pytest.skip("prismpath-hw/ppt_compile not present", allow_module_level=True)
sys.path.insert(0, str(_hw))
import ppt_compile as pc  # noqa: E402

SUITES = {
    "cnsa2-hybrid-1":           {"kem": "x25519+ml-kem-1024", "sig": "ml-dsa-87", "aead": "aes-256-gcm",     "provider": "cryptography>=44", "strength_rank": 3},
    "tls13-hybrid-x25519mlkem": {"kem": "x25519+ml-kem-768",  "sig": "ed25519",   "aead": "chacha20poly1305", "provider": "cryptography",     "strength_rank": 2},
    "tls13-aesgcm":             {"kem": "x25519",             "sig": "ed25519",   "aead": "aes-256-gcm",      "provider": "cryptography",     "strength_rank": 1},
}

CLASSICAL_FLOW = """---
name: ca_classical
start: classify
---
## classify
-> suite-tls13-aesgcm: when data_class == "legacy"
-> suite-tls13-aesgcm: else
## suite-tls13-aesgcm
-> end: when always
## end
done
"""
CNSA2_FLOW = (Path(__file__).resolve().parent.parent / "flows" / "crypto_agility_cnsa2.md").read_text()


@pytest.fixture()
def env(tmp_path):
    keys = pp.keygen(str(tmp_path / "keys"))
    _pub, key_id = pp.load_public(keys["public"])
    registry = cr.build_registry(SUITES, key_id=key_id)
    return {"keys": keys, "registry": registry, "rh": cr.registry_hash(registry), "tmp": tmp_path}


def _envelope(env, approved, fields, envelope_id="cnsa2-2026"):
    return {"envelope_id": envelope_id, "fields": fields, "approved_suites": sorted(approved),
            "registry_hash": env["rh"], "key_id": "x"}


def _pack(env, name, flow, fields, version, suites, envelope_id="cnsa2-2026", registry_hash=None):
    ppt = env["tmp"] / f"{name}.ppt"
    ppt.write_bytes(pc.compile_flow(parse(flow)).serialize())
    ch.build_crypto_pack(str(ppt), fields, version=version, envelope_id=envelope_id,
                         suites=suites, registry_hash=registry_hash or env["rh"],
                         priv_path=env["keys"]["private"], pub_path=env["keys"]["public"])
    return str(ppt)


def _host(env, envelope):
    return ch.CryptoHost(str(env["tmp"] / "state"), [env["keys"]["public"]], envelope, env["registry"])


# ------------------------------------------------------------------ provider binding

def test_resolve_provider_classical_ok_pqc_loud_absence():
    ok, _ = ch.resolve_provider(SUITES["tls13-aesgcm"])
    assert ok is True
    ok2, reason = ch.resolve_provider(SUITES["cnsa2-hybrid-1"])
    # matches whatever the host's vetted provider actually exposes — no assumption baked in
    assert ok2 is ch._has_mlkem()
    if not ok2:
        assert "pqc-kem-unavailable" in reason


def test_measure_suite_cost_is_measured_here():
    cc = ch.measure_suite_cost(SUITES["tls13-aesgcm"], iters=100)
    assert cc["measured"] is True and cc["handshake_us"] > 0 and cc["encrypt_us_per_pkt"] > 0


# ------------------------------------------------------------------ the swap pipeline

def test_classical_policy_swaps_and_attests(env):
    fields = {"data_class": "str"}
    host = _host(env, _envelope(env, ["tls13-aesgcm"], fields))
    ppt = _pack(env, "classical", CLASSICAL_FLOW, fields, version=1, suites=["tls13-aesgcm"])
    res = host.swap(ppt)
    assert res["ok"] is True
    att = host.attest()
    assert att["suites"] == ["tls13-aesgcm"] and att["registry_hash"] == env["rh"]
    assert att["version"] == 1 and att["audit_root"]


def test_pqc_provider_absence_refuses_never_downgrades(env):
    fields = {"peer_class": "str", "data_class": "str", "migration_phase": "int", "hw_floor": "int"}
    host = _host(env, _envelope(env, list(SUITES), fields))
    # seat a classical policy first so we can prove the refused PQC swap does NOT replace it
    classical = _pack(env, "seat", CLASSICAL_FLOW, {"data_class": "str"}, version=1, suites=["tls13-aesgcm"])
    # (different envelope fields — reuse a permissive envelope that accepts both flows' fields)
    host.envelope["fields"] = {**fields, "data_class": "str"}
    assert host.swap(classical)["ok"] is True
    before = host.attest()["active"]

    cnsa2 = _pack(env, "cnsa2", CNSA2_FLOW, fields, version=2, suites=sorted(SUITES))
    res = host.swap(cnsa2)
    if ch._has_mlkem():
        assert res["ok"] is True                                   # provider present -> accepted
    else:
        assert res["ok"] is False
        assert any("pqc-kem-unavailable" in r for r in res["reasons"])
        assert host.attest()["active"] == before                   # NOT downgraded; classical stays live


def test_anti_rollback_refuses_stale_version(env):
    fields = {"data_class": "str"}
    host = _host(env, _envelope(env, ["tls13-aesgcm"], fields))
    assert host.swap(_pack(env, "v2", CLASSICAL_FLOW, fields, version=2, suites=["tls13-aesgcm"]))["ok"]
    stale = _pack(env, "v2again", CLASSICAL_FLOW, fields, version=2, suites=["tls13-aesgcm"])
    res = host.swap(stale)
    assert res["ok"] is False and any("version:not-monotonic" in r for r in res["reasons"])


def test_registry_hash_mismatch_refused(env):
    fields = {"data_class": "str"}
    host = _host(env, _envelope(env, ["tls13-aesgcm"], fields))
    ppt = _pack(env, "wrongreg", CLASSICAL_FLOW, fields, version=1, suites=["tls13-aesgcm"],
                registry_hash="dead" * 16)
    res = host.swap(ppt)
    assert res["ok"] is False and "crypto:registry-hash-mismatch" in res["reasons"]


def test_unapproved_suite_refused(env):
    fields = {"data_class": "str"}
    host = _host(env, _envelope(env, ["tls13-aesgcm"], fields))   # only classical approved
    ppt = _pack(env, "sneak", CLASSICAL_FLOW, fields, version=1,
                suites=["tls13-aesgcm", "cnsa2-hybrid-1"])         # manifest declares an unapproved one
    res = host.swap(ppt)
    assert res["ok"] is False and "crypto:unapproved-suite:cnsa2-hybrid-1" in res["reasons"]


def test_every_attempt_is_audited(env):
    fields = {"data_class": "str"}
    host = _host(env, _envelope(env, ["tls13-aesgcm"], fields))
    host.swap(_pack(env, "ok", CLASSICAL_FLOW, fields, version=1, suites=["tls13-aesgcm"]))
    host.swap(_pack(env, "bad", CLASSICAL_FLOW, fields, version=1, suites=["tls13-aesgcm"]))  # stale
    assert host.audit.verify_log() is True
    actions = [ev["action"] for ev in host.audit.events]
    assert "swap" in actions and "swap_rejected" in actions
