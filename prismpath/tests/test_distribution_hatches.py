# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every escape hatch of spec-policy-distribution.md D1 in both builds: `--allow-unsigned` on a swap and on the
XDP preloader, `PPT_NET_ALLOW_UNVERIFIED=1` in the XDP loader, and a verify of evidence or of in-toto envelopes
without both keys pinned. A production build refuses each with dist:hatch-refused and runs the check, and a dev
build lets it through and says so in its audit event and its state record. Which build this is comes from the
tree around the package (D2), so the tests set it on `devbuild.is_dev_build`."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath.distribution import devbuild, state_record  # noqa: E402
from prismpath.hotswap.policy_host import PolicyHost  # noqa: E402
from prismpath.kernel import ppt_compile  # noqa: E402
from prismpath.ledgers import core_evidence  # noqa: E402
from prismpath.tests import _dist  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
EBPF = REPO / "prismpath-ebpf"
CASES = Path(__file__).resolve().parent / "fixtures" / "core_evidence" / "cases.jsonl"


def _build(monkeypatch, dev: bool) -> None:
    monkeypatch.setattr(devbuild, "is_dev_build", lambda package_dir=None: dev)


def _unsigned(tmp_path) -> Path:
    ppt = tmp_path / "raw.ppt"
    ppt.write_bytes(ppt_compile.compile_predicate("when x >= 5").serialize())
    return ppt


def _net_swap():
    sys.path.insert(0, str(EBPF))
    try:
        import net_swap
    finally:
        sys.path.remove(str(EBPF))
    return net_swap


def _hatch_events(log):
    return [event["data"] for event in log.events if event["action"] == "hatch"]


@pytest.fixture(scope="module")
def produced(tmp_path_factory):
    base = tmp_path_factory.mktemp("hatch_evidence")
    core_evidence.produce(CASES, base / "run", base / "keys")
    return base


def test_case_097_a_production_build_refuses_every_hatch_and_runs_the_check(tmp_path, monkeypatch, produced):
    """case_097: D1, D2. The swap and the XDP preloader check the signature they were asked to skip (sig:missing
    for an unsigned table), the evidence verifier runs every check and then refuses the unpinned pass, and each
    refusal is written as a hatch event with dev_build false."""
    _build(monkeypatch, False)
    host = PolicyHost(str(tmp_path / "host"), [], dict(_dist.GEN.QUALIFICATION), instance_key=_dist.instance_key())
    assert host.swap(str(_unsigned(tmp_path)), allow_unsigned=True) == {"ok": False, "reasons": ["sig:missing"]}
    assert _hatch_events(host.audit) == [{"hatch": "--allow-unsigned", "dev_build": False, "result": "refused",
                                          "cause": "dist:hatch-refused"}]
    assert host.active()["active"] is None

    with pytest.raises(core_evidence.Bad, match="dist:hatch-refused"):
        core_evidence.verify(produced / "run", sample=5)
    pins = {"pin_authority": produced / "keys" / "authority.pub", "pin_instance": produced / "keys" / "instance.pub"}
    assert core_evidence.verify(produced / "run", sample=5, **pins)["root_statement"] == "signed"


@pytest.mark.skipif(not (EBPF / "loader").exists(), reason="loader not built (make -C prismpath-ebpf loader)")
def test_case_097_the_production_loader_refuses_the_unverified_bypass(tmp_path):
    """case_097: D1. PPT_NET_ALLOW_UNVERIFIED=1 is answered with dist:hatch-refused and the verified table gate."""
    table = _unsigned(tmp_path)
    env = {key: value for key, value in os.environ.items() if key != "PPT_NET_VERIFIED_SHA256"}
    result = subprocess.run([str(EBPF / "loader"), str(table), "netverify"], capture_output=True, text=True,
                            cwd=EBPF, env={**env, "PPT_NET_ALLOW_UNVERIFIED": "1"})
    assert result.returncode == 2 and "dist:hatch-refused" in result.stderr and "no verified table" in result.stderr


def test_case_098_a_dev_build_lets_every_hatch_through_and_says_so(tmp_path, monkeypatch, produced):
    """case_098: D2, D3. The unsigned swap and preload pass, the unpinned verify reports signed-unpinned, every hatch
    event carries dev_build true, and the PEP's state record sets bit 6."""
    _build(monkeypatch, True)
    host = PolicyHost(str(tmp_path / "host"), [], dict(_dist.GEN.QUALIFICATION), instance_key=_dist.instance_key())
    swapped = host.swap(str(_unsigned(tmp_path)), allow_unsigned=True)
    assert swapped["ok"] and swapped["unsigned"] is True
    assert _hatch_events(host.audit) == [{"hatch": "--allow-unsigned", "dev_build": True, "result": "allowed"}]

    assert core_evidence.verify(produced / "run", sample=5)["root_statement"] == "signed-unpinned"

    point = _dist.HostPep(tmp_path / "pep")
    assert state_record.read(point.pep.record("beat"), point.key.public_raw).dev_build


@pytest.mark.skipif(shutil.which("make") is None or not (EBPF / "loader-dev").exists(),
                    reason="dev loader not built (make -C prismpath-ebpf dev)")
def test_case_098_the_dev_loader_takes_the_unverified_bypass(tmp_path):
    """case_098: D2. The binary `make dev` compiles with PPT_DEV_BUILD loads unverified and says so on stderr."""
    table = _unsigned(tmp_path)
    env = {key: value for key, value in os.environ.items() if key != "PPT_NET_VERIFIED_SHA256"}
    result = subprocess.run([str(EBPF / "loader-dev"), str(table), "netverify"], capture_output=True, text=True,
                            cwd=EBPF, env={**env, "PPT_NET_ALLOW_UNVERIFIED": "1"})
    assert result.returncode == 0 and "UNVERIFIED" in result.stderr and "dev build" in result.stderr


@pytest.mark.skipif(not (EBPF / "net_swap.py").exists(), reason="the XDP preloader is research's own")
@pytest.mark.parametrize("dev", [False, True])
def test_case_097_and_case_098_the_xdp_preloader_s_allow_unsigned(tmp_path, monkeypatch, dev):
    """case_097, case_098: D1 to D3. A production preloader checks the signature it was asked to skip, and a dev
    one passes the unsigned table and writes its hatch event with dev_build true."""
    _build(monkeypatch, dev)
    gate = _net_swap().preload_swap(str(_unsigned(tmp_path)), "lo", [], None, str(tmp_path / "net"),
                                    allow_unsigned=True, dry_run=True)
    if dev:
        assert gate["ok"] is True and gate["unsigned"] is True
    else:
        assert gate["ok"] is False and gate["reasons"] == ["sig:missing"]
    events = [line for line in (tmp_path / "net" / "net_swaps.log").read_text().splitlines() if '"hatch"' in line]
    assert len(events) == 1 and (f'"dev_build":{str(dev).lower()}') in events[0]
