# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""eBPF trusted pre-loader (prismpath-ebpf/net_swap.py, spec-secure-hotswap §5): the kernel loader
is reached ONLY after the host verifies the signed pack against its envelope and version floor.
The loader call is injected, so the whole authorization gate is tested without root."""
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath import policy_pack as pp  # noqa: E402
from prismpath.parser import parse  # noqa: E402

_REPO = Path(__file__).resolve().parent.parent.parent
_hw = _REPO / "prismpath-hw"
if not (_hw / "ppt_compile.py").exists():
    pytest.skip("prismpath-hw/ppt_compile not present", allow_module_level=True)
sys.path.insert(0, str(_hw))
import ppt_compile as pc  # noqa: E402

_spec = importlib.util.spec_from_file_location("net_swap", _REPO / "prismpath-ebpf" / "net_swap.py")
ns = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ns)

FIELDS = {"temp": "int"}
FLOW = "# f\n## start\n-> hot: when temp >= 100\n-> cold: else\n## hot\n-> end\n## cold\n-> end\n## end\n"


class FakeLoader:
    """Records loader invocations; returns success unless told otherwise."""
    def __init__(self, rc=0):
        self.calls = []
        self.rc = rc

    def __call__(self, argv, capture_output=True, text=True):
        self.calls.append(argv)
        class R:
            returncode = self.rc
            stdout = "OK: hot-swapped\n"
            stderr = ""
        return R()


@pytest.fixture()
def env(tmp_path):
    keys = pp.keygen(str(tmp_path / "keys"))
    pp.build_envelope("env1", FIELDS, None, keys["private"], keys["public"], str(tmp_path / "env"))
    ppt = tmp_path / "f.ppt"
    ppt.write_bytes(pc.compile_flow(parse(FLOW)).serialize())
    pp.build_pack(str(ppt), FIELDS, version=1, envelope_id="env1",
                  priv_path=keys["private"], pub_path=keys["public"])
    return {"keys": keys, "ppt": str(ppt), "envbase": str(tmp_path / "env" / "env1.envelope"),
            "state": str(tmp_path / "state"), "tmp": tmp_path}


def _swap(env, loader, **kw):
    return ns.preload_swap(env["ppt"], "lo", [env["keys"]["public"]], env["envbase"],
                           env["state"], loader="./loader", run=loader, **kw)


def test_verified_pack_reaches_the_loader_once(env):
    loader = FakeLoader()
    r = _swap(env, loader)
    assert r["ok"] and len(loader.calls) == 1
    assert loader.calls[0][1:] == [env["ppt"], "netupdate", "lo"]


def test_tampered_image_never_reaches_the_loader(env):
    raw = bytearray(Path(env["ppt"]).read_bytes()); raw[-1] ^= 1
    Path(env["ppt"]).write_bytes(bytes(raw))
    loader = FakeLoader()
    r = _swap(env, loader)
    assert not r["ok"] and loader.calls == []
    assert r["reasons"] == ["image:sha256-mismatch"]


def test_version_replay_never_reaches_the_loader(env):
    loader = FakeLoader()
    assert _swap(env, loader)["ok"]                       # v1 accepted, floor now 1
    # re-pack same file as v1 again (a replay)
    pp.build_pack(env["ppt"], FIELDS, version=1, envelope_id="env1",
                  priv_path=env["keys"]["private"], pub_path=env["keys"]["public"])
    loader2 = FakeLoader()
    r = _swap(env, loader2)
    assert not r["ok"] and loader2.calls == []
    assert any("version:not-monotonic" in x for x in r["reasons"])


def test_loader_failure_is_audited(env):
    loader = FakeLoader(rc=2)
    r = _swap(env, loader)
    assert not r["ok"] and r["reasons"] == ["loader:failed"]
    audit = ns.AuditLog(str(Path(env["state"]) / "net_swaps.log"))
    assert any(e["action"] == "loader_failed" for e in audit.events)


def test_unsigned_requires_flag_and_is_stamped(env):
    # strip the signature so only the unsigned path can proceed
    Path(env["ppt"] + ".manifest.sig").unlink()
    loader = FakeLoader()
    blocked = _swap(env, loader)
    assert not blocked["ok"] and loader.calls == []      # signed path refuses
    loader2 = FakeLoader()
    r = ns.preload_swap(env["ppt"], "lo", [env["keys"]["public"]], env["envbase"],
                        env["state"], allow_unsigned=True, run=loader2)
    assert r["ok"] and r["unsigned"] is True and len(loader2.calls) == 1
