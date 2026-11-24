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

from prismpath.hotswap import policy_pack as pp# noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402

from prismpath.tests._repo import repo_file

_hw = repo_file("prismpath-hw")
sys.path.insert(0, str(_hw))
from prismpath.kernel import ppt_compile as pc  # noqa: E402

_spec = importlib.util.spec_from_file_location("net_swap", repo_file("prismpath-ebpf", "net_swap.py"))
ns = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ns)

FIELDS = {"temp": "int"}
FLOW = "# f\n## start\n-> hot: when temp >= 100\n-> cold: else\n## hot\n-> end\n## cold\n-> end\n## end\n"


class FakeLoader:
    """Records loader invocations; returns success unless told otherwise."""
    def __init__(self, rc=0):
        self.calls = []
        self.rc = rc

    def __call__(self, argv, capture_output=True, text=True, env=None):
        self.calls.append(argv)
        self.env = env
        class LoadResult:
            returncode = self.rc
            stdout = "OK: hot-swapped\n"
            stderr = ""
        return LoadResult()


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
    swap_result = _swap(env, loader)
    assert swap_result["ok"] and len(loader.calls) == 1
    assert loader.calls[0][1:] == [env["ppt"], "netupdate", "lo"]


def test_tampered_image_never_reaches_the_loader(env):
    raw = bytearray(Path(env["ppt"]).read_bytes()); raw[-1] ^= 1
    Path(env["ppt"]).write_bytes(bytes(raw))
    loader = FakeLoader()
    swap_result = _swap(env, loader)
    assert not swap_result["ok"] and loader.calls == []
    assert swap_result["reasons"] == ["image:sha256-mismatch"]


def test_version_replay_never_reaches_the_loader(env):
    loader = FakeLoader()
    assert _swap(env, loader)["ok"]                       # v1 accepted, floor now 1
    # re-pack same file as v1 again (a replay)
    pp.build_pack(env["ppt"], FIELDS, version=1, envelope_id="env1",
                  priv_path=env["keys"]["private"], pub_path=env["keys"]["public"])
    loader2 = FakeLoader()
    swap_result = _swap(env, loader2)
    assert not swap_result["ok"] and loader2.calls == []
    assert any("version:not-monotonic" in reason for reason in swap_result["reasons"])


def test_loader_failure_is_audited(env):
    loader = FakeLoader(rc=2)
    swap_result = _swap(env, loader)
    assert not swap_result["ok"] and swap_result["reasons"] == ["loader:failed"]
    audit = ns.AuditLog(str(Path(env["state"]) / "net_swaps.log"))
    assert any(event["action"] == "loader_failed" for event in audit.events)


def test_unsigned_requires_flag_and_is_stamped(env, monkeypatch):
    """--allow-unsigned is an escape hatch: a production build refuses it and checks the signature, and only a
    dev build loads the unsigned table (spec-policy-distribution.md, D1, D2)."""
    # strip the signature so only the unsigned path can proceed
    Path(env["ppt"] + ".manifest.sig").unlink()
    loader = FakeLoader()
    blocked = _swap(env, loader)
    assert not blocked["ok"] and loader.calls == []      # signed path refuses
    refused = ns.preload_swap(env["ppt"], "lo", [env["keys"]["public"]], env["envbase"], env["state"],
                              allow_unsigned=True, run=loader)
    assert not refused["ok"] and refused["reasons"] == ["sig:missing"] and loader.calls == []
    from prismpath.distribution import devbuild
    monkeypatch.setattr(devbuild, "is_dev_build", lambda package_dir=None: True)
    loader2 = FakeLoader()
    swap_result = ns.preload_swap(env["ppt"], "lo", [env["keys"]["public"]], env["envbase"],
                        env["state"], allow_unsigned=True, run=loader2)
    assert swap_result["ok"] and swap_result["unsigned"] is True and len(loader2.calls) == 1


def test_a_dry_run_runs_every_gate_and_never_reaches_the_loader_or_moves_the_floor(env):
    loader = FakeLoader()
    result = _swap(env, loader, dry_run=True)
    assert result["ok"] and result["dry_run"] and result["version"] == 1 and loader.calls == []
    assert not (Path(env["state"]) / "active_version").exists()
    assert _swap(env, loader, dry_run=True)["ok"]                        # the floor did not move, so it repeats
    audit = ns.AuditLog(str(Path(env["state"]) / "net_swaps.log"))
    assert [event["action"] for event in audit.events] == ["swap_dry_run", "swap_dry_run"]
    raw = bytearray(Path(env["ppt"]).read_bytes()); raw[-1] ^= 1
    Path(env["ppt"]).write_bytes(bytes(raw))
    refused = _swap(env, loader, dry_run=True)                           # a gate that refuses still refuses a dry run
    assert not refused["ok"] and refused["reasons"] == ["image:sha256-mismatch"] and loader.calls == []


def test_the_floor_is_written_before_the_one_loader_call_and_the_log_takes_the_instance_key(env, tmp_path):
    """C4 of spec-policy-distribution.md: the version floor is on disk when the loader runs, so a load that fails
    part way leaves no floor below a table the kernel may hold, and the gate ends in `run_loader`, one audit event
    per load in a log the instance key signs."""
    from prismpath.ledgers import root_statement
    seen = []

    class Watching(FakeLoader):
        def __call__(self, argv, capture_output=True, text=True, env=None):
            seen.append((Path(state) / "active_version").read_text())
            return super().__call__(argv, capture_output, text, env)

    state = env["state"]
    key = root_statement.InstanceKey.load(root_statement.keygen(str(tmp_path / "instance"))["private"])
    failing = Watching(rc=2)
    result = ns.preload_swap(env["ppt"], "lo", [env["keys"]["public"]], env["envbase"], state, run=failing,
                             instance_key=key)
    assert result["reasons"] == ["loader:failed"] and seen == ["1"]
    log = str(Path(state) / "net_swaps.log")
    assert [event["action"] for event in ns.AuditLog(log).events] == ["loader_failed"]
    assert Path(root_statement.statements_path_for(log)).is_file()
    with pytest.raises(ValueError):
        ns.run_loader(b"x", "netdelete", "lo", path=str(tmp_path / "t.ppt"), audit=ns.AuditLog(log), action="swap")
