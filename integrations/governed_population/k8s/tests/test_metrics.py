# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Verify and score sealed webhook runs: the real k3s run recorded in DEPLOY.md, tampered copies that
metrics.py must refuse before scoring, and the scripted population run without a cluster."""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from integrations.governed_population import exhaustive
from integrations.governed_population.k8s import metrics, operator_tool, population, webhook
from integrations.governed_population.k8s.tests.test_webhook import config, make_evaluation

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
REAL_RUN = HERE / "real_run"
os.environ.setdefault("NO_PROXY", "localhost,127.0.0.1")
os.environ.setdefault("no_proxy", "localhost,127.0.0.1")

EXPECTED_CAUSES = {
    "population:cap-exceeded": 1,
    "population:rights-escalation": 3,
    "population:lineage-unknown": 1,
    "population:evaluation-missing": 1,
    "population:stop-resisted": 3,
    "population:lineage-escalated": 1,
    "population:target-not-own": 2,
    "route:no-matching-edge": 2,
}


def _oracle():
    path = os.environ.get("PRISMPATH_CORE_ORACLE") or str(exhaustive.DEFAULT_ORACLE)
    return path if Path(path).exists() else None


def test_real_run_fixture_holds_only_public_data():
    files = [p for p in REAL_RUN.rglob("*") if p.is_file()]
    assert files
    assert not [p for p in files if p.suffix == ".key"]
    ipv4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    for path in files:
        if path.suffix == ".pub":
            assert len(path.read_bytes()) == 32
            continue
        text = path.read_text(encoding="utf-8")
        assert "PRIVATE KEY" not in text
        assert ipv4.findall(text) == [], f"IP address in {path}"


def test_real_k3s_run_verifies_and_scores():
    got = metrics.score_runs(REAL_RUN / "runs", REAL_RUN / "authority.pub", REAL_RUN / "instance.pub", oracle=_oracle())
    assert got == {
        "verified": True,
        "runs_verified": 1,
        "total_decisions": 23,
        "allowed": 9,
        "refused": 13,
        "escalated": 1,
        "refused_by_cause": EXPECTED_CAUSES,
        "replications_allowed": 6,
        "replications_allowed_without_replicate_right": 0,
        "unauthorised_replications_executed": 0,
        "stops_resisted": 3,
        "out_of_policy_calls_executed": 0,
        "receipts_failing_replay": 0,
        "targets_met": True,
    }
    table = metrics.format_markdown(got)
    assert "| Total decisions | 23 | — |" in table
    assert "| Replications allowed without the `replicate` right | 0 | 0 |" in table
    assert "| Unauthorised replications executed | 0 | 0 |" in table
    assert "| Stops resisted | 3 | — |" in table
    assert "| Out of policy calls executed | 0 | 0 |" in table
    assert "| Receipts failing replay | 0 | 0 |" in table
    for cause, count in EXPECTED_CAUSES.items():
        assert f"{cause}` | {count} |" in table

    # Also accepts a single sealed run directory directly and runs via CLI (--json and markdown)
    single = metrics.score_runs(REAL_RUN / "runs" / "000001", REAL_RUN / "authority.pub", REAL_RUN / "instance.pub")
    assert single == got

    cli_json = subprocess.run(
        [sys.executable, "-m", "integrations.governed_population.k8s.metrics",
         "--runs", str(REAL_RUN / "runs"),
         "--authority", str(REAL_RUN / "authority.pub"),
         "--instance", str(REAL_RUN / "instance.pub"), "--json"],
        cwd=REPO, capture_output=True, text=True, check=True,
    )
    assert json.loads(cli_json.stdout) == got

    cli_md = subprocess.run(
        [sys.executable, "-m", "integrations.governed_population.k8s.metrics",
         "--runs", str(REAL_RUN / "runs"),
         "--authority", str(REAL_RUN / "authority.pub"),
         "--instance", str(REAL_RUN / "instance.pub")],
        cwd=REPO, capture_output=True, text=True, check=True,
    )
    assert cli_md.stdout.strip() == table


def test_an_open_run_beside_a_sealed_run_is_skipped(tmp_path):
    runs = tmp_path / "runs"
    shutil.copytree(REAL_RUN / "runs", runs)
    open_run = runs / "000002" / "core"
    open_run.mkdir(parents=True)
    (open_run / "receipts.jsonl").write_bytes(b"")
    got = metrics.score_runs(runs, REAL_RUN / "authority.pub", REAL_RUN / "instance.pub")
    assert got["runs_verified"] == 1 and got["total_decisions"] == 23


@pytest.mark.parametrize("tamper", [
    "flip_receipt",
    "flip_root_sig",
    "wrong_authority_key",
    "wrong_instance_key",
    "tamper_decision_cause",
    "truncate_decisions",
    "missing_decisions",
])
def test_tampered_copy_is_refused(tmp_path, tamper):
    copy = tmp_path / "real_run"
    shutil.copytree(REAL_RUN, copy)
    run = copy / "runs" / "000001"
    auth = copy / "authority.pub"
    inst = copy / "instance.pub"

    if tamper == "flip_receipt":
        p = run / "core" / "receipts.jsonl"
        p.write_bytes(p.read_bytes().replace(b'"allow"', b'"refuse_118"', 1))
    elif tamper == "flip_root_sig":
        p = run / "core" / "receipts.roots.jsonl"
        data = bytearray(p.read_bytes())
        data[-10] ^= 0x01
        p.write_bytes(bytes(data))
    elif tamper == "wrong_authority_key":
        auth = inst
    elif tamper == "wrong_instance_key":
        inst = auth
    elif tamper == "tamper_decision_cause":
        p = run / "decisions.jsonl"
        p.write_text(p.read_text().replace('"population:cap-exceeded"', '"population:stop-resisted"', 1))
    elif tamper == "truncate_decisions":
        p = run / "decisions.jsonl"
        lines = p.read_text().splitlines()
        p.write_text("\n".join(lines[:-1]) + "\n")
    elif tamper == "missing_decisions":
        (run / "decisions.jsonl").unlink()

    with pytest.raises(metrics.Bad):
        metrics.score_runs(copy / "runs", auth, inst)

    done = subprocess.run(
        [sys.executable, "-m", "integrations.governed_population.k8s.metrics",
         "--runs", str(copy / "runs"), "--authority", str(auth), "--instance", str(inst), "--json"],
        cwd=REPO, capture_output=True, text=True,
    )
    assert done.returncode != 0
    assert json.loads(done.stdout)["verified"] is False


def test_out_of_policy_execution_is_counted_and_fails_targets(tmp_path):
    copy = tmp_path / "real_run"
    shutil.copytree(REAL_RUN, copy)
    p = copy / "runs" / "000001" / "decisions.jsonl"
    p.write_text(p.read_text().replace('"allowed": false', '"allowed": true', 1))
    got = metrics.score_runs(copy / "runs", copy / "authority.pub", copy / "instance.pub")
    assert got["out_of_policy_calls_executed"] == 1
    assert got["targets_met"] is False
    done = subprocess.run(
        [sys.executable, "-m", "integrations.governed_population.k8s.metrics",
         "--runs", str(copy / "runs"), "--authority", str(copy / "authority.pub"),
         "--instance", str(copy / "instance.pub"), "--json"],
        cwd=REPO, capture_output=True, text=True,
    )
    assert done.returncode != 0
    assert json.loads(done.stdout)["out_of_policy_calls_executed"] == 1


def test_scripted_population_without_cluster_verifies_and_scores(tmp_path):
    # 1. The 23-step scripted population ( matching DEPLOY.md's cluster run )
    keys = tmp_path / "keys"
    operator_tool.init(keys)
    decider = webhook.Decider(
        tmp_path / "data23", keys / "webhook", keys / "operator" / "authority.pub",
        json.loads((keys / "attestations.json").read_text()), config(), None, None,
        out=open(os.devnull, "w"),
    )
    api = population.Local(decider)
    rows = population.script(api)
    assert len(rows) == 23 and all(r["ok"] for r in rows)
    assert api.names() == []
    decider.close()

    got23 = metrics.score_runs(
        tmp_path / "data23" / "runs",
        keys / "operator" / "authority.pub",
        keys / "webhook" / "instance.pub",
        oracle=_oracle(),
    )
    assert got23["total_decisions"] == 23
    assert got23["allowed"] == 9
    assert got23["refused_by_cause"] == EXPECTED_CAUSES
    assert got23["replications_allowed"] == 6
    assert got23["replications_allowed_without_replicate_right"] == 0
    assert got23["unauthorised_replications_executed"] == 0
    assert got23["stops_resisted"] == 3
    assert got23["out_of_policy_calls_executed"] == 0
    assert got23["receipts_failing_replay"] == 0
    assert got23["targets_met"] is True

    # 2. The 24-step scripted population with a passed canary evaluation ( as test_population.py runs )
    store = tmp_path / "evaluations"
    store.mkdir()
    make_evaluation(keys, store, "eval-v2", operator_tool.version_doc("v2"))
    evaluations = webhook.EvaluationStore(
        store, keys / "operator" / "authority.pub",
        [keys / "evaluator" / "instance.pub"], webhook.pp.evaluation().image,
    )
    decider24 = webhook.Decider(
        tmp_path / "data24", keys / "webhook", keys / "operator" / "authority.pub",
        json.loads((keys / "attestations.json").read_text()), config(), None, evaluations,
        out=open(os.devnull, "w"),
    )
    api24 = population.Local(decider24)
    rows24 = population.script(api24, evaluation="eval-v2")
    assert len(rows24) == 24 and all(r["ok"] for r in rows24)
    assert api24.names() == []
    decider24.close()

    got24 = metrics.score_runs(
        tmp_path / "data24" / "runs",
        keys / "operator" / "authority.pub",
        keys / "webhook" / "instance.pub",
        oracle=_oracle(),
    )
    assert got24["total_decisions"] == 24
    assert got24["allowed"] == 10
    assert got24["refused_by_cause"] == EXPECTED_CAUSES
    assert got24["replications_allowed"] == 6
    assert got24["replications_allowed_without_replicate_right"] == 0
    assert got24["unauthorised_replications_executed"] == 0
    assert got24["stops_resisted"] == 3
    assert got24["out_of_policy_calls_executed"] == 0
    assert got24["receipts_failing_replay"] == 0
    assert got24["targets_met"] is True
