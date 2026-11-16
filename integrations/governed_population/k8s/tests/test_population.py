# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The scripted population DEPLOY.md runs against the cluster, run here against the webhook's decider
behind an in-process stand-in for the API server: every step answered as the script expects, the
receipts sealed and verified, and the population gone after the operator's stop."""
import json
import os

from integrations.governed_population import evidence
from integrations.governed_population.k8s import operator_tool, population, webhook
from integrations.governed_population.k8s.tests.test_webhook import config, make_evaluation


def test_the_scripted_population_gets_every_answer_it_expects(tmp_path):
    keys = tmp_path / "keys"
    operator_tool.init(keys)
    store = tmp_path / "evaluations"
    store.mkdir()
    make_evaluation(keys, store, "eval-v2", operator_tool.version_doc("v2"))
    evaluations = webhook.EvaluationStore(store, keys / "operator" / "authority.pub",
                                          [keys / "evaluator" / "instance.pub"], webhook.pp.evaluation().image)
    decider = webhook.Decider(tmp_path / "data", keys / "webhook", keys / "operator" / "authority.pub",
                              json.loads((keys / "attestations.json").read_text()), config(), None, evaluations,
                              out=open(os.devnull, "w"))
    api = population.Local(decider)
    rows = population.script(api, evaluation="eval-v2")
    assert all(row["ok"] for row in rows), [r for r in rows if not r["ok"]]
    got = {row["got"] for row in rows}
    assert {"population:cap-exceeded", "population:rights-escalation", "population:lineage-unknown",
            "population:evaluation-missing", "population:stop-resisted", "population:lineage-escalated",
            "route:no-matching-edge", "allow"} == got
    assert api.names() == []
    decider.close()
    [run] = sorted((tmp_path / "data" / "runs").iterdir())
    evidence.verify(run / "core", keys / "operator" / "authority.pub", keys / "webhook" / "instance.pub")
    assert len(evidence.receipts(run / "core")) == len(rows) + 0


def test_the_kubectl_backend_impersonates_members_and_the_controller():
    api = population.Kubectl()
    assert api._as(population.OPERATOR) == []
    member = api._as("a1")
    assert member[0] == "--as=system:serviceaccount:prismpath-population:a1"
    assert "--as-group=system:serviceaccounts:prismpath-population" in member
    assert api._as(population.CONTROLLER)[0] == \
        "--as=system:serviceaccount:prismpath-population-system:population-controller"
    assert population.outcome(False, 'Error from server: admission webhook "decide.population.prismpath.dev" '
                                     'denied the request: population: refuse 118 population:rights-escalation '
                                     '(replicate; receipt 000001/3)') == "population:rights-escalation"
    assert population.outcome(True, "created") is None
