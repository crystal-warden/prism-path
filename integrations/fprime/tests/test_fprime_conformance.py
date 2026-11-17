# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The F Prime guard's C core held to the cFS app's receipts, with only a C compiler (no F Prime build needed).

The guard's decision and receipt code is the cFS app's C, compiled in place, and the F Prime component adds the C core
in PrismPathRef/Guard/GuardCore.c: the table and keys from files, and the reading of a proposed command's serialized
arguments (big endian, F Prime's) into the policy's payload (little endian, the cFS layout). This compiles that core
and the shared C alone and plays the S1 sequence, every truncation of a proposal and a grid across the policy's
thresholds through it, as the F Prime arguments the proposer would send. Checked:

  * every decision is the Python reference's;
  * built with the cFS decider (the shared header's default), every receipt is the cFS app's receipt for the same
    reading, byte for byte (`reference.receipt_line`, which test_cfs_run.py holds the cFS C to), and the root is
    the RFC 6962 root of those lines;
  * built as the deployment builds it (decider `fprime:prismpath_guard`), the receipts are the same bytes with that
    one member changed, and the run verifies with `prismpath evidence verify` with both keys pinned;
  * a tampered table is refused as sig:invalid, and a cFE table file (headers and all) loads like the raw table.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from integrations.cfs.ground import downlink, reference, table
from integrations.cfs.prismpath_app.policy import gen_image
from integrations.cfs.tests import run_scenario
from integrations.fprime.ground import conform, provision
from prismpath.agent.policy import Policy
from prismpath.ledgers import core_evidence, root_statement

HERE = Path(__file__).resolve().parent
FPRIME = HERE.parent
REPO = HERE.parents[2]
GUARD = FPRIME / "PrismPathRef" / "Guard"
CFS_SRC = REPO / "integrations" / "cfs" / "prismpath_app" / "fsw"
MONO = REPO / "prismpath-hw" / "mesh" / "main"
TIME_US = 1_234_567_890_123_456
KINDS = {"allow": 0, "refuse": 1, "escalate": 2}


def args_of_payload(payload: bytes) -> bytes:
    """The serialized arguments (big endian, declaration order) of the proposal whose cFS payload is this."""
    out = b""
    for _name, _kind, off, width in reference.layout():
        if off + width > len(payload):
            break
        out += payload[off:off + width][::-1]
    return out


def _payloads():
    """The S1 sequence, every truncation of one proposal, and a grid across the policy's thresholds."""
    out = [run_scenario.payload_of(case) for _n, case in run_scenario.SEQUENCE]
    whole = run_scenario.reading_payload(dict(cmd_class=2, ground_contact=1, slew_deg=10, thrust_pct=60))
    out += [whole[:n] for n in range(len(whole) + 1)]
    for cls in (0, 1, 2, 3, 4, 11):
        for gc in (0, 1, 2):
            for slew in (0, 46, 91, 181):
                for thrust in (0, 51, 101, 201):
                    out.append(run_scenario.reading_payload(dict(cmd_class=cls, ground_contact=gc, slew_deg=slew,
                                                                 thrust_pct=thrust)))
    return out


def _cc():
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.skip("no C compiler")
    return cc


def _build(tmp: Path, decider: str = None) -> Path:
    cc = _cc()
    probe = subprocess.run([cc, "-x", "c", "-", "-lcrypto", "-o", str(tmp / "probe")],
                           input="#include <openssl/sha.h>\nint main(void){return 0;}", capture_output=True, text=True)
    if probe.returncode != 0:
        pytest.skip("no OpenSSL development files (merkle.h's SHA-256 is OpenSSL's by default)")
    exe = tmp / ("guard_check_" + ("cfs" if decider is None else "fprime"))
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-g", "-O1"]
    if decider is not None:
        flags.append(f'-DPP_RUN_DECIDER="{decider}"')
    subprocess.run([cc, *flags, "-I", str(GUARD), "-I", str(CFS_SRC / "inc"), "-I", str(REPO / "prismpath-hw"),
                    "-I", str(REPO / "prismpath-ebpf"), "-I", str(MONO), "-o", str(exe), str(HERE / "guard_check.c"),
                    str(GUARD / "GuardCore.c"), str(CFS_SRC / "src" / "prismpath_app_kernel.c"),
                    str(CFS_SRC / "src" / "prismpath_app_run.c"), str(MONO / "monocypher.c"),
                    str(MONO / "monocypher-ed25519.c"), "-lcrypto"], check=True)
    return exe


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    pytest.importorskip("cryptography", reason="signing and verifying a core run needs the signing extra")
    out = tmp_path_factory.mktemp("keys")
    core_evidence.ensure_keys(out)
    return out


@pytest.fixture(scope="module")
def onboard(tmp_path_factory, keys):
    out = tmp_path_factory.mktemp("onboard")
    provision.provision(out, keys)
    return out


def _run(exe: Path, tmp: Path, onboard: Path, name: str, payloads, policy_name: str = "pp_policy.tbl"):
    run = tmp / name
    run.mkdir()
    (tmp / f"{name}.args").write_text("".join(args_of_payload(p).hex() + "\n" for p in payloads))
    done = subprocess.run([str(exe), str(onboard / policy_name), str(onboard), str(run), str(tmp / f"{name}.args"),
                           str(TIME_US)], capture_output=True, text=True)
    return done, run


def _decisions(stdout: str):
    return [tuple(line.split()) for line in stdout.splitlines() if line and line[0].isdigit()]


def test_every_decision_is_the_references_and_the_cfs_decider_build_writes_the_cfs_receipts(tmp_path, onboard, keys):
    exe = _build(tmp_path)
    payloads = _payloads()
    done, run = _run(exe, tmp_path, onboard, "cfs", payloads)
    assert done.returncode == 0, done.stdout + done.stderr
    policy = Policy.load(gen_image.CORE)
    rows = _decisions(done.stdout)
    assert len(rows) == len(payloads)
    for idx, (row, payload) in enumerate(zip(rows, payloads)):
        decision = policy.decide(reference.reading_bytes(payload))
        assert int(row[0]) == KINDS[decision.kind], f"proposal {idx} ({payload.hex()}): {row}"
        assert row[1] == str(decision.cause_code or 0) or decision.kind == "allow", f"proposal {idx}: {row}"
        assert int(row[4]) == idx
    lines = core_evidence._lines(run / "receipts.jsonl")
    assert len(lines) == len(payloads)
    for idx, (line, payload) in enumerate(zip(lines, payloads)):
        assert line == reference.receipt_line(policy, idx, f"v{gen_image.VERSION}", idx, payload), \
            f"receipt {idx} for payload {payload.hex()}"
    root = root_statement.merkle_root([core_evidence.sha256_hex(line) for line in lines])
    assert f"root {root}" in done.stdout
    # the same cFS decider means a verifier sees the cFS app's own run
    ground = downlink.fetch(run, tmp_path / "cfs.ground")
    summary = downlink.verify(ground, keys)
    assert summary["agree"] == len(payloads) and summary["disagree"] == 0 and summary["root"] == root


def test_the_deployment_build_differs_from_the_cfs_receipts_only_in_the_decider_and_verifies(tmp_path, onboard, keys):
    exe = _build(tmp_path, conform.FPRIME_DECIDER)
    payloads = _payloads()
    done, run = _run(exe, tmp_path, onboard, "fprime", payloads)
    assert done.returncode == 0, done.stdout + done.stderr
    policy = Policy.load(gen_image.CORE)
    assert conform.compare(run, policy, gen_image.VERSION, payloads) == []
    for line in core_evidence._lines(run / "receipts.jsonl"):
        assert b'"decider":"fprime:prismpath_guard"' in line
    ground = downlink.fetch(run, tmp_path / "fprime.ground")
    summary = downlink.verify(ground, keys)
    assert summary["receipts"] == len(payloads) and summary["agree"] == len(payloads) and summary["disagree"] == 0
    cli = subprocess.run([sys.executable, "-m", "prismpath", "evidence", "verify", str(ground), "--sample", "all",
                          "--pin-authority", str(keys / "authority.pub"), "--pin-instance", str(keys / "instance.pub")],
                         capture_output=True, text=True, cwd=REPO)
    assert cli.returncode == 0, cli.stdout + cli.stderr
    assert "verified" in cli.stdout


def test_a_tampered_table_is_refused_and_a_cfe_table_file_loads_like_the_raw_table(tmp_path, onboard):
    exe = _build(tmp_path, conform.FPRIME_DECIDER)
    done, _run_dir = _run(exe, tmp_path, onboard, "tampered", _payloads()[:1], "pp_policy_tampered.tbl")
    assert done.returncode == 1 and done.stdout.startswith("load 2 "), done.stdout          # sig:invalid
    wrapped = tmp_path / "wrapped"
    wrapped.mkdir()
    for name in ("pp_authority.pub", "pp_instance.key"):
        shutil.copy(onboard / name, wrapped / name)
    (wrapped / "pp_policy.tbl").write_bytes(b"\0" * table.HEADERS + (onboard / "pp_policy.tbl").read_bytes())
    done, _run_dir = _run(exe, tmp_path, wrapped, "wrapped_run", _payloads()[:1])
    assert done.returncode == 0 and done.stdout.startswith(f"loaded {gen_image.VERSION} "), done.stdout
