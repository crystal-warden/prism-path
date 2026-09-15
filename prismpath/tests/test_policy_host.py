# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""PolicyHost (spec-secure-hotswap §3.3-§3.4): a swap is authorized + in-envelope + monotonic +
atomic, every attempt is one audit event, the swap chain reconstructs from the ledger, and a
failure at any stage leaves the previous policy active. Uses the real compiler + real Ed25519."""
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath.hotswap import policy_pack as pp# noqa: E402
from prismpath.hotswap import policy_host as ph# noqa: E402
from prismpath.ledgers.audit_log import AuditLog  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402

from prismpath.tests._repo import repo_file

_hw = repo_file("prismpath-hw")
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
    swap_result = host.swap(_pack(env, "v1", 1))
    assert swap_result["ok"] and swap_result["version"] == 1
    assert host.active()["active"] == swap_result["active"]


def test_swap_chain_reconstructs_from_ledger(env):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    h2 = host.swap(_pack(env, "v2", 2, hot=80))["active"]
    swaps = [event for event in host.history() if event["action"] == "swap"]
    assert [swap["data"]["to_hash"] for swap in swaps] == [h1, h2]
    assert swaps[1]["data"]["from_hash"] == h1          # chain is linked
    assert host.audit.verify_log()                       # Merkle-intact


def test_rollback_replay_is_rejected_and_logged(env):
    host = _host(env)
    host.swap(_pack(env, "v2", 2))
    swap_result = host.swap(_pack(env, "v1", 1))                    # older version -> replay
    assert not swap_result["ok"] and any("version:not-monotonic" in reason for reason in swap_result["reasons"])
    rej = [event for event in host.history() if event["action"] == "swap_rejected"]
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
    swap_result = host.swap(str(ppt))
    assert not swap_result["ok"] and any("unknown-field" in reason for reason in swap_result["reasons"])
    assert host.active() == before                        # untouched


def test_tampered_image_rejected(env):
    host = _host(env)
    pack_path = _pack(env, "v1", 1)
    raw = bytearray(Path(pack_path).read_bytes()); raw[-1] ^= 1; Path(pack_path).write_bytes(bytes(raw))
    swap_result = host.swap(pack_path)
    assert not swap_result["ok"] and swap_result["reasons"] == ["image:sha256-mismatch"]
    assert host.active()["active"] is None


def test_rollback_restores_previous(env):
    host = _host(env)
    h1 = host.swap(_pack(env, "v1", 1))["active"]
    host.swap(_pack(env, "v2", 2, hot=80))
    rollback_result = host.rollback()
    assert rollback_result["ok"] and rollback_result["active"] == h1
    assert [event["action"] for event in host.history()][-1] == "rollback"


def test_strict_raises(env):
    host = _host(env)
    host.swap(_pack(env, "v2", 2))
    with pytest.raises(ph.SwapRejected):
        host.swap(_pack(env, "v1", 1), strict=True)


def test_allow_unsigned_stamps_the_event(env):
    host = _host(env)
    ppt = env["tmp"] / "raw.ppt"
    ppt.write_bytes(pc.compile_flow(parse(_flow(100))).serialize())
    swap_result = host.swap(str(ppt), allow_unsigned=True)
    assert swap_result["ok"] and swap_result["unsigned"] is True
    ev = [event for event in host.history() if event["action"] == "swap"][-1]
    assert ev["data"]["unsigned"] is True


def test_attest_writes_a_ledger_row(env):
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    host.attest()
    att = [event for event in host.history() if event["action"] == "attestation"]
    assert len(att) == 1 and att[0]["data"]["version"] == 1


def test_unexpected_exception_is_atomic(env, monkeypatch):
    """The flip is the last statement: an uncaught exception mid-pipeline propagates but never
    leaves a partially-applied policy."""
    host = _host(env)
    host.swap(_pack(env, "v1", 1))
    before = host.active()
    monkeypatch.setattr(pp, "check_envelope",
                        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError, match="boom"):
        host.swap(_pack(env, "v2", 2))
    assert host.active() == before                        # nothing flipped


def test_version_floor_persists_across_restart(env):
    host = _host(env)
    host.swap(_pack(env, "v3", 3))
    host2 = _host(env)                                    # fresh host, same state_dir
    swap_result = host2.swap(_pack(env, "v2", 2))                  # below the persisted floor
    assert not swap_result["ok"] and any("version:not-monotonic" in reason for reason in swap_result["reasons"])
