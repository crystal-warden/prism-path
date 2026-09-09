# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Test for OPA policy revision floor glue."""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

from prismpath.comparisons.glue import opa_revision_floor


def count_non_blank_non_comment(filepath: Path) -> int:
    count = 0
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                count += 1
    return count


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_glue_opa_revision_floor(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    opa_bin = repo_root / "prismpath" / "comparisons" / ".toolchain" / "bin" / "opa"
    if not opa_bin.exists() or not os.access(opa_bin, os.X_OK):
        pytest.skip("OPA binary missing")

    priv_pem = tmp_path / "priv.pem"
    pub_pem = tmp_path / "pub.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(priv_pem), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(priv_pem), "-pubout", "-out", str(pub_pem)], check=True, capture_output=True)

    rego_src = repo_root / "prismpath" / "comparisons" / "systems" / "opa" / "generated" / "network_admission" / "policy.rego"
    src_dir = tmp_path / "bundle_src"
    src_dir.mkdir()
    shutil.copy(rego_src, src_dir / "policy.rego")

    def build_bundle(rev: str, out_name: str, signed: bool) -> Path:
        out_path = tmp_path / out_name
        cmd = [str(opa_bin), "build", "-b", str(src_dir), "-r", rev, "-o", str(out_path)]
        if signed:
            cmd += ["--signing-key", str(priv_pem), "--signing-alg", "RS256"]
        subprocess.run(cmd, check=True, capture_output=True)
        return out_path

    v2_path = build_bundle("2", "v2.tar.gz", True)
    v1_path = build_bundle("1", "v1.tar.gz", True)
    v3_path = build_bundle("3", "v3.tar.gz", True)
    _v4_path = build_bundle("4", "unsigned.tar.gz", False)

    state_path = tmp_path / "floor_state.json"
    floor = opa_revision_floor.Floor(state_path)

    ok2, msg2 = floor.check(v2_path)
    assert ok2 is True
    assert "accepted: revision 2 (floor was none)" in msg2

    ok1, msg1 = floor.check(v1_path)
    assert ok1 is False
    assert "refused: stale revision 1 below floor 2" in msg1

    ok3, msg3 = floor.check(v3_path)
    assert ok3 is True
    assert "accepted: revision 3 (floor was 2)" in msg3

    ok1_again, msg1_again = floor.check(v1_path)
    assert ok1_again is False
    assert "refused: stale revision 1 below floor 3" in msg1_again

    assert state_path.exists()
    state_data = json.loads(state_path.read_text(encoding="utf-8"))
    assert state_data == {"revision": "3"}

    port = find_free_port()
    proc = opa_revision_floor.activate(v3_path, state_path, opa_bin, pub_pem, port)
    assert proc is not None

    try:
        url = f"http://127.0.0.1:{port}/v1/data/comparison/network_admission/decision"
        payload = {"input": {"protocol": 6, "dst_port": 443, "pkt_len": 800, "src_internal": False}}
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        start_t = time.time()
        ready = False
        res_data = None
        while time.time() - start_t < 10:
            try:
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                with opener.open(req, timeout=2) as r:
                    if r.status == 200:
                        res_data = json.loads(r.read().decode("utf-8"))
                        if "result" in res_data:
                            ready = True
                            break
            except Exception:
                time.sleep(0.2)
        assert ready is True, "OPA server failed to respond within timeout"
        assert res_data.get("result") == {"outcome": "allow", "rule": "r6"}
    finally:
        if proc and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=5)
            except Exception:
                pass

    proc_stale = opa_revision_floor.activate(v1_path, state_path, opa_bin, pub_pem, port)
    assert proc_stale is None

    glue_file = repo_root / "prismpath" / "comparisons" / "glue" / "opa_revision_floor.py"
    line_count = count_non_blank_non_comment(glue_file)
    assert line_count <= 60, f"Line count {line_count} exceeds budget limit of 60"
