# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Test for OPA decision log receipt sink glue."""
from __future__ import annotations

import copy
import json
import os
import signal
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

from prismpath.comparisons.glue import opa_receipts


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


def test_glue_opa_receipts(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    opa_bin = repo_root / "prismpath" / "comparisons" / ".toolchain" / "bin" / "opa"
    if not opa_bin.exists() or not os.access(opa_bin, os.X_OK):
        pytest.skip("OPA binary missing")

    priv_pem_path = tmp_path / "priv.pem"
    pub_pem_path = tmp_path / "pub.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(priv_pem_path), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(priv_pem_path), "-pubout", "-out", str(pub_pem_path)], check=True, capture_output=True)
    priv_pem = priv_pem_path.read_bytes()
    pub_pem = pub_pem_path.read_bytes()

    priv2_pem_path = tmp_path / "priv2.pem"
    pub2_pem_path = tmp_path / "pub2.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(priv2_pem_path), "2048"], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(priv2_pem_path), "-pubout", "-out", str(pub2_pem_path)], check=True, capture_output=True)
    pub2_pem = pub2_pem_path.read_bytes()

    sink = opa_receipts.Sink(private_key_pem=priv_pem)
    sink_port = sink.start()

    config_content = f"""services:
  sink:
    url: http://127.0.0.1:{sink_port}
decision_logs:
  service: sink
  reporting:
    min_delay_seconds: 1
    max_delay_seconds: 2
"""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(config_content, encoding="utf-8")

    policy_path = repo_root / "prismpath" / "comparisons" / "systems" / "opa" / "generated" / "network_admission" / "policy.rego"
    opa_port = find_free_port()
    cmd = [
        str(opa_bin),
        "run",
        "-s",
        "-a",
        f"127.0.0.1:{opa_port}",
        "-c",
        str(config_path),
        str(policy_path),
    ]

    env = os.environ.copy()
    env["http_proxy"] = ""
    env["https_proxy"] = ""
    env["HTTP_PROXY"] = ""
    env["HTTPS_PROXY"] = ""
    env["no_proxy"] = "127.0.0.1,localhost"
    env["NO_PROXY"] = "127.0.0.1,localhost"

    proc = subprocess.Popen(cmd, start_new_session=True, env=env)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    try:
        health_url = f"http://127.0.0.1:{opa_port}/health"
        start_t = time.time()
        ready = False
        while time.time() - start_t < 10:
            try:
                probe_req = urllib.request.Request(health_url, method="GET")
                with opener.open(probe_req, timeout=2) as r:
                    if r.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.2)
        assert ready, "OPA server failed to start within timeout"

        url = f"http://127.0.0.1:{opa_port}/v1/data/comparison/network_admission/decision"
        inputs_and_expected = [
            ({"input": {"protocol": 6, "dst_port": 443, "pkt_len": 800, "src_internal": False}}, {"outcome": "allow", "rule": "r6"}),
            ({"input": {"protocol": 6, "dst_port": 23, "pkt_len": 100, "src_internal": True}}, {"outcome": "deny", "rule": "r1"}),
            ({"input": {"protocol": 17, "dst_port": 53, "pkt_len": 600, "src_internal": False}}, {"outcome": "deny", "rule": "r5"}),
        ]

        decision_ids = []
        for body, expected_result in inputs_and_expected:
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers={"content-type": "application/json"},
                method="POST",
            )
            with opener.open(req, timeout=5) as r:
                res_data = json.loads(r.read().decode("utf-8"))
                assert "decision_id" in res_data
                assert res_data.get("result") == expected_result
                decision_ids.append(res_data["decision_id"])

        start_t = time.time()
        while time.time() - start_t < 15:
            if len(sink.records) >= 3:
                break
            time.sleep(0.2)

        assert len(sink.records) == 3, f"Expected 3 records in sink, got {len(sink.records)}"

        records_by_did = {rec["decision_id"]: rec for rec in sink.records if "decision_id" in rec}
        for did, (_, exp_res) in zip(decision_ids, inputs_and_expected):
            assert did in records_by_did
            rec = records_by_did[did]
            assert rec.get("result") == exp_res

        receipts = []
        for did in decision_ids:
            rcpt = sink.receipt_for(did)
            assert opa_receipts.verify_receipt(rcpt, pub_pem) is True
            receipts.append(rcpt)

        mutated_rcpt = copy.deepcopy(receipts[0])
        mutated_rcpt["record"]["result"]["outcome"] = "tampered_outcome"
        assert opa_receipts.verify_receipt(mutated_rcpt, pub_pem) is False

        assert opa_receipts.verify_receipt(receipts[0], pub2_pem) is False

        glue_file = repo_root / "prismpath" / "comparisons" / "glue" / "opa_receipts.py"
        line_count = count_non_blank_non_comment(glue_file)
        assert line_count <= 150, f"Line count {line_count} exceeds 150 budget limit"

    finally:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            pass
        sink.stop()
