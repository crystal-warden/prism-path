# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""PolicyHost (spec-secure-hotswap §3.3-§3.4): a swap is authorized + in-envelope + monotonic +
atomic, every attempt is one audit event, the swap chain reconstructs from the ledger, and a
failure at any stage leaves the previous policy active. Uses the real compiler + real Ed25519."""
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath import policy_pack as pp  # noqa: E402
from prismpath import policy_host as ph  # noqa: E402
from prismpath.audit_log import AuditLog  # noqa: E402
from prismpath.parser import parse  # noqa: E402

_hw = Path(__file__).resolve().parent.parent.parent / "prismpath-hw"
if not (_hw / "ppt_compile.py").exists():
    pytest.skip("prismpath-hw/ppt_compile not present", allow_module_level=True)
sys.path.insert(0, str(_hw))
import ppt_compile as pc  # noqa: E402

FIELDS = {"temp": "int"}


def _flow(hot_thresh):
    return f"""# f
## start
-> hot: when temp >= {hot_thresh}
-> cold: else
## hot
-> end
## cold
-> end
## end
"""


@pytest.fixture()
def env(tmp_path):
    keys = pp.keygen(str(tmp_path / "keys"))
    envelope = pp.build_envelope("env1", FIELDS, None, keys["private"], keys["public"],
                                 str(tmp_path / "env"))
    return {"keys": keys, "envelope": envelope, "tmp": tmp_path}


def _pack(env, name, version, hot=100, envelope_id="env1", fields=FIELDS):
    ppt = env["tmp"] / f"{name}.ppt"
    ppt.write_bytes(pc.compile_flow(parse(_flow(hot))).serialize())
    pp.build_pack(str(ppt), fields, version=version, envelope_id=envelope_id,
                  priv_path=env["keys"]["private"], pub_path=env["keys"]["public"])
    return str(ppt)


def _host(env):
    return ph.PolicyHost(str(env["tmp"] / "state"), [env["keys"]["public"]], env["envelope"])


def test_accepted_swap_becomes_active(env):
    host = _host(env)
    r = host.swap(_pack(env, "v1", 1))
    assert r["ok"] and r["version"] == 1
    assert host.active()["active"] == r["active"]


def test_swap_chain_reconstructs_from_ledger(env):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    h2 = host.swap(_pack(env, "v2", 2, hot=80))["active"]
    swaps = [e for e in host.history() if e["action"] == "swap"]
    assert [s["data"]["to_hash"] for s in swaps] == [h1, h2]
    assert swaps[1]["data"]["from_hash"] == h1          # chain is linked
    assert host.audit.verify_log()                       # Merkle-intact


def test_rollback_replay_is_rejected_and_logged(env):
    host = _host(env)
    host.swap(_pack(env, "v2", 2))
    r = host.swap(_pack(env, "v1", 1))                    # older version -> replay
    assert not r["ok"] and any("version:not-monotonic" in x for x in r["reasons"])
    rej = [e for e in host.history() if e["action"] == "swap_rejected"]
    assert len(rej) == 1 and host.active()["version"] == 2


def test_out_of_envelope_swap_rejected_active_unchanged(env):
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    before = host.active()
    # a pack that adds a field the envelope never provisioned
    bad = _pack(env, "bad", 2, fields={"temp": "int", "humidity": "int"})
    # rewrite the flow to actually use humidity so the field lands in the manifest schema
    ppt = env["tmp"] / "bad.ppt"
    ppt.write_bytes(pc.compile_flow(parse(
        "# f\n## start\n-> hot: when humidity >= 5\n-> cold: else\n## hot\n-> end\n## cold\n-> end\n## end\n"
    )).serialize())
    pp.build_pack(str(ppt), {"humidity": "int"}, version=2, envelope_id="env1",
                  priv_path=env["keys"]["private"], pub_path=env["keys"]["public"])
    r = host.swap(str(ppt))
    assert not r["ok"] and any("unknown-field" in x for x in r["reasons"])
    assert host.active() == before                        # untouched


def test_tampered_image_rejected(env):
    host = _host(env)
    p = _pack(env, "v1", 1)
    raw = bytearray(Path(p).read_bytes()); raw[-1] ^= 1; Path(p).write_bytes(bytes(raw))
    r = host.swap(p)
    assert not r["ok"] and r["reasons"] == ["image:sha256-mismatch"]
    assert host.active()["active"] is None


def test_rollback_restores_previous(env):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    host.swap(_pack(env, "v2", 2, hot=80))
    r = host.rollback()
    assert r["ok"] and r["active"] == h1
    assert [e["action"] for e in host.history()][-1] == "rollback"


def test_strict_raises(env):
    host = _host(env)
    host.swap(_pack(env, "v2", 2))
    with pytest.raises(ph.SwapRejected):
        host.swap(_pack(env, "v1", 1), strict=True)


def test_allow_unsigned_stamps_the_event(env):
    host = _host(env)
    ppt = env["tmp"] / "raw.ppt"
    ppt.write_bytes(pc.compile_flow(parse(_flow(100))).serialize())
    r = host.swap(str(ppt), allow_unsigned=True)
    assert r["ok"] and r["unsigned"] is True
    ev = [e for e in host.history() if e["action"] == "swap"][-1]
    assert ev["data"]["unsigned"] is True


def test_attest_writes_a_ledger_row(env):
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    host.attest()
    att = [e for e in host.history() if e["action"] == "attestation"]
    assert len(att) == 1 and att[0]["data"]["version"] == 1


def test_unexpected_exception_is_atomic(env, monkeypatch):
    """The flip is the last statement: an uncaught exception mid-pipeline propagates but never
    leaves a partially-applied policy."""
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    before = host.active()
    monkeypatch.setattr(pp, "check_envelope",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError, match="boom"):
        host.swap(_pack(env, "v2", 2))
    assert host.active() == before                        # nothing flipped


def test_version_floor_persists_across_restart(env):
    host = _host(env)
    host.swap(_pack(env, "v3", 3))
    host2 = _host(env)                                    # fresh host, same state_dir
    r = host2.swap(_pack(env, "v2", 2))                  # below the persisted floor
    assert not r["ok"] and any("version:not-monotonic" in x for x in r["reasons"])
