# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The operator's side, run outside the cluster: keys, image attestations, versions and canary evaluations.

    python -m integrations.governed_population.k8s.operator_tool init --out DIR
    python -m integrations.governed_population.k8s.operator_tool version --name v1 [--tools write,exec,replicate]
    python -m integrations.governed_population.k8s.operator_tool evaluate --keys DIR --version FILE --store DIR --ref NAME

`init` makes, under DIR: `operator/` (the authority key, which never enters the cluster), `webhook/` and
`evaluator/` (instance keys, each beside the authority's public key only), `attestations.json` (the
operator's signatures over the admission, evaluation and harness images, under the core's image domain)
and `config.json` (who is the operator and the controller, and the population's namespace). Only the
webhook's instance key, the authority's public key, the evaluator's public key, the attestations and the
config go into the cluster.

`version` prints a version document under the shipped harness image, for a GovernedAgent's `spec.version`.

`evaluate` runs the version's canary against the harness's 51 case adversary set (`canary.evaluate`, the
simulation's own, in bubblewrap on this host), decides the evaluation with the signed evaluation image under
the evaluator's key, and copies the sealed evaluation run to STORE/NAME, for the webhook's evaluation store.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from integrations.governed_harness.policy import Policy as HarnessPolicy
from prismpath.ledgers import root_statement

from .. import canary as canary_mod
from .. import identity as ident
from .. import policy as pp
from ..agent import Version
from ..limits import RIGHTS
from .classify import NAME, Config

DEFAULT_CONFIG = {"namespace": Config.namespace, "operator_groups": list(Config.operator_groups),
                  "controller_users": list(Config.controller_users)}


def init(out: Path) -> dict:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    operator = ident.Operator(out / "operator")
    for name in ("webhook", "evaluator"):
        root_statement.keygen(str(out / name), "instance")
        (out / name / "authority.pub").write_bytes(operator.public_raw)
    attestations = {"admission": operator.attest(pp.admission().image),
                    "evaluation": operator.attest(pp.evaluation().image),
                    "harness": operator.attest(HarnessPolicy.load().image)}
    (out / "attestations.json").write_text(json.dumps(attestations, indent=1, sort_keys=True) + "\n")
    (out / "config.json").write_text(json.dumps(DEFAULT_CONFIG, indent=1) + "\n")
    return {"authority_key_id": operator.key_id,
            "webhook_key_id": ident.sha256_hex((out / "webhook" / "instance.pub").read_bytes()),
            "evaluator_key_id": ident.sha256_hex((out / "evaluator" / "instance.pub").read_bytes())}


def version_doc(name: str, tools=RIGHTS, system_message: str = "", behaviour: str = "worker") -> dict:
    harness = ident.sha256_hex(HarnessPolicy.load().image)
    return Version(name, system_message or f"You are member version {name}.", harness, tuple(sorted(tools)),
                   behaviour).doc()


def evaluate(keys: Path, version: dict, store: Path, ref: str, work: Path) -> dict:
    if not NAME.match(ref):
        raise ValueError("the evaluation's name must be a DNS label")
    parsed = Version.from_doc(version)
    if parsed is None:
        raise ValueError("not a version document")
    keys = Path(keys)
    authority_pub = (keys / "operator" / "authority.pub").read_bytes()
    attestations = json.loads((keys / "attestations.json").read_text())
    evaluator = ident.InstanceIdentity(keys / "evaluator")
    result = canary_mod.evaluate(parsed, Path(work), evaluator, authority_pub, HarnessPolicy.load(),
                                 attestations["harness"], pp.evaluation(), attestations["evaluation"])
    target = Path(store) / ref
    shutil.copytree(result.run, target)
    return {"version_sha256": parsed.sha256, "passed": result.passed, "sums": result.sums, "run": str(target)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init")
    p_init.add_argument("--out", required=True, type=Path)
    p_version = sub.add_parser("version")
    p_version.add_argument("--name", required=True)
    p_version.add_argument("--tools", default=",".join(RIGHTS))
    p_version.add_argument("--system-message", default="")
    p_version.add_argument("--behaviour", default="worker")
    p_eval = sub.add_parser("evaluate")
    p_eval.add_argument("--keys", required=True, type=Path)
    p_eval.add_argument("--version", required=True, type=Path)
    p_eval.add_argument("--store", required=True, type=Path)
    p_eval.add_argument("--ref", required=True)
    p_eval.add_argument("--work", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.cmd == "init":
        print(json.dumps(init(args.out), indent=1))
    elif args.cmd == "version":
        tools = [t for t in args.tools.split(",") if t]
        print(json.dumps(version_doc(args.name, tools, args.system_message, args.behaviour), sort_keys=True))
    else:
        print(json.dumps(evaluate(args.keys, json.loads(args.version.read_text()), args.store, args.ref, args.work),
                         indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
