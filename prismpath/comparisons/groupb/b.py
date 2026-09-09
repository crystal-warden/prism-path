# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Group B, where PrismPath is expected to lose (PREREGISTRATION.md section 6). Mandatory, and graded
with the same rubric and the same result file contract as Group A.

B1 policy expressiveness and B3 relationship modeling are graded per scenario from the Phase 2
conformance rows (systems/<id>/generated/conformance.json): every system's translator either
expressed the policy and matched the neutral expectation, dropped rules it could not express, or
declared the policy not expressible with its reason. Nothing is re run here; the rows are the run.
B2 formal verification, B4 ecosystem and integrations, and B5 maturity are documentation rows
(policy none, scenario matrix-row) with the sources written beside the results.

Grade meanings on the documentation rows, fixed here before the rows were written:
  B2  NATIVE: the decision engine's semantics (authorizer and validator or equivalent) are machine
      checked, with the proof artifacts public and tied to the shipped implementation. NOT: no machine
      checked proof of the decision engine. Proofs about other components are recorded in the notes and
      do not lift the grade, because the dimension is verification of the decision engine.
  B4  NATIVE: documented, maintained integrations across at least three of: orchestration admission
      (Kubernetes), a proxy or gateway (Envoy), infrastructure as code, and three or more language
      SDKs or implementations. WITH-WORK: the integration an adopter needs is buildable under the
      section 4 glue budget; the glue is recorded. NOT: no integration surface.
  B5  NATIVE: three or more years of public history, thirty or more contributors, and a foundation home
      or a named production operator. WITH-WORK: a younger or smaller project an adopter can take on
      with mitigation (pin, self host, own the upgrade path); the mitigation is the recorded glue.
      NOT: under one year of public history from one organization with no external production use.

Usage: python -m prismpath.comparisons.groupb.b
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List

from prismpath.comparisons.groupa.common import RESULTS, evidence_dir, write_result
from prismpath.comparisons.harness import HERE

SYSTEMS = ("prismpath", "opa", "cedar", "cerbos", "openfga")
B1_POLICY = "access_control_rbac_abac"
B3_POLICY = "document_sharing_rebac"


def conformance(system: str) -> Dict[str, dict]:
    path = HERE / "systems" / system / "generated" / "conformance.json"
    rows = json.loads(path.read_text())["rows"]
    return {(r["policy"], r["scenario"]): r for r in rows}


def conf_path(system: str) -> Path:
    return HERE / "systems" / system / "generated" / "conformance.json"


# ----------------------------------------------------------------------------- B1 expressiveness
FLATTEN_GLUE = {"description": "the role hierarchy is flattened at authoring into an explicit in list (user_role in (manager, admin)); "
                               "the policy states the consequence of the hierarchy, not the hierarchy",
                "components": ["authoring step"], "loc": 1, "hours": 0.1}
OPENFGA_B1_GLUE = {"description": "an authorization model with owner and member relations, tuple writes for ownership and group "
                                  "membership, conditions (CEL) for the business hours window and the sensitivity guard, and a caller "
                                  "side shim that issues one Check per rule and applies the first match order; documented and costed, "
                                  "not built in Phase 2 because a Check answers one relation",
                   "components": ["authorization model with conditions", "tuple writes", "caller side rule ordering shim"],
                   "loc": 120, "hours": 6}
B1_SYSTEM_NOTES = {
    "opa": "Rego expresses every construct directly: field against field comparison, set intersection over runtime "
           "collections, the role hierarchy as data, and the hour window; first match order as an else chain. 8/8 match.",
    "cedar": "Cedar expresses ownership as principal == resource.owner, groups as entity membership with containsAny, the "
             "hierarchy through the entity store, and the hour window in context; one permit or forbid per rule with the "
             "prior negation carried in each policy so first match order holds. 8/8 match.",
    "cerbos": "Cerbos expresses every construct in CEL over principal and resource attributes. The idiomatic form for a role "
              "hierarchy is derived roles, but a derived role cannot join the negation chain that reproduces first match "
              "order, so the hierarchy is flattened in CEL; recorded idiomatic=false by the translator. 8/8 match.",
}


def run_b1() -> None:
    for system in SYSTEMS:
        rows = conformance(system)
        for (pol, sid), r in sorted(rows.items()):
            if pol != B1_POLICY:
                continue
            exp = r["expected"]["outcome"]
            obs = r["observed"]["observed"] if isinstance(r["observed"], dict) else str(r["observed"])
            rule = r["expected"].get("rule")
            if system == "prismpath":
                if r["class"] == "DROPPED":
                    grade, glue = "NOT", None
                    obs = obs  # the engine decided deny because the rule that should have fired was never written
                    note = (f"Rule {rule} is outside the predicate language (corpus prismpath_expressibility): "
                            + ("field against field comparison (eq_fields)" if rule == "r3" else "set intersection over runtime collections (intersects)")
                            + ". The translator dropped it (dropped_rules) rather than force it, so the flow falls through to the "
                              f"default deny; expected {exp}, observed {obs}. The caller would have to precompute a boolean field "
                              "such as is_owner or shares_group, which moves the rule out of the policy; pre registered NOT.")
                elif rule == "r5":
                    grade, glue = "WITH-WORK", FLATTEN_GLUE
                    note = (f"Rule r5 uses role_at_least; the hierarchy contractor < employee < manager < admin is flattened at "
                            f"authoring into user_role in (manager, admin). Decision matches ({obs}), but the policy no longer states "
                            "the hierarchy; pre registered WITH-WORK for this construct.")
                else:
                    grade, glue = "NATIVE", None
                    note = (f"Rule {rule} uses field OP const, in or not in lists, and the default catch all, all inside Level M; "
                            f"decision {obs} matches.")
                write_result(system=system, dimension="B1", policy=pol, scenario=sid, expected=exp, observed=obs, grade=grade,
                             idiomatic=True, evidence_path=conf_path(system), glue=glue,
                             notes=note + " Cell grade is the minimum over the 8 scenarios: NOT, as pre registered.")
            elif system == "openfga":
                write_result(system=system, dimension="B1", policy=pol, scenario=sid, expected=exp, observed="not-expressible",
                             grade="WITH-WORK", idiomatic=False, evidence_path=conf_path(system), glue=OPENFGA_B1_GLUE,
                             notes=("The Phase 2 translator recorded the policy as not expressible: a Check answers one boolean for one "
                                    "relation, and this policy needs first match order over six rules mixing attributes and relations. "
                                    "OpenFGA 1.x conditions (CEL on tuples) and relation tuples make a path practical under the glue "
                                    "budget, so the cell is WITH-WORK with the glue costed, not executed; that matches the pre "
                                    "registered prediction and does not change the row verdict."))
            else:
                assert r["class"] == "MATCH", (system, sid, r["class"])
                write_result(system=system, dimension="B1", policy=pol, scenario=sid, expected=exp, observed=obs, grade="NATIVE",
                             idiomatic=(system != "cerbos"), evidence_path=conf_path(system), notes=B1_SYSTEM_NOTES[system])
    ev = evidence_dir("openlane", "docs")
    write_result(system="openlane", dimension="B1", policy="none", scenario="matrix-row", expected=None, observed="not_applicable",
                 grade="NOT", idiomatic=True, evidence_path=ev,
                 notes="Graded from documentation (results/openlane/evidence/docs/sources.txt): Openlane has no policy evaluation "
                       "language; policies are governance documents with approvals and history. Nothing to express the corpus in.")
    print("B1 written")


# ----------------------------------------------------------------------------- B3 relationships
CERBOS_B3_GLUE = {"description": "the caller resolves the document's parent chain and passes the set of principals who can view "
                                 "through it as a resource attribute list; a CEL condition tests membership. Cerbos evaluates the "
                                 "membership, the caller supplies the relationship data",
                  "components": ["caller side relationship resolver", "resource attribute list", "CEL membership condition"],
                  "loc": 40, "hours": 2}
B3_SYSTEM_NOTES = {
    "opa": "Relationship reachability is computed natively with the graph.reachable built in over data.graph compiled "
           "from the corpus tuples; the policy is one rule. 6/6 match.",
    "cedar": "The corpus tuples become the entity store's parent hierarchy and one policy per direct relation; Cedar's "
             "entity hierarchy resolves the transitive viewer. 6/6 match.",
    "openfga": "The native home of the question: a type definition with viewer and parent relations, the tuples written "
               "as is, one Check per scenario. 6/6 match.",
}


def run_b3() -> None:
    for system in SYSTEMS:
        rows = conformance(system)
        for (pol, sid), r in sorted(rows.items()):
            if pol != B3_POLICY:
                continue
            exp = r["expected"]["outcome"]
            obs = r["observed"]["observed"] if isinstance(r["observed"], dict) else str(r["observed"])
            if system == "prismpath":
                assert r["class"] == "UNEXPRESSIBLE"
                write_result(system=system, dimension="B3", policy=pol, scenario=sid, expected=exp, observed="not-expressible",
                             grade="NOT", idiomatic=True, evidence_path=conf_path(system),
                             notes=("PrismPath has no relationship graph and no data plane; the only way to answer the scenario is "
                                    "for the caller to derive the tuple and pass a boolean, at which point the caller made the decision. "
                                    "Recorded not expressible by the translator; pre registered NOT."))
            elif system == "cerbos":
                assert r["class"] == "UNEXPRESSIBLE"
                write_result(system=system, dimension="B3", policy=pol, scenario=sid, expected=exp, observed="not-expressible",
                             grade="WITH-WORK", idiomatic=False, evidence_path=conf_path(system), glue=CERBOS_B3_GLUE,
                             notes=("Cerbos has no relationship store, so the translator recorded the policy as not expressible. The "
                                    "difference from PrismPath's NOT: a CEL condition can test membership in a list the caller supplies, "
                                    "so the caller provides relationship data and Cerbos still evaluates the rule; the glue is costed, "
                                    "not built. Pre registered WITH-WORK."))
            else:
                assert r["class"] == "MATCH", (system, sid, r["class"])
                write_result(system=system, dimension="B3", policy=pol, scenario=sid, expected=exp, observed=obs, grade="NATIVE",
                             idiomatic=True, evidence_path=conf_path(system), notes=B3_SYSTEM_NOTES[system])
    ev = evidence_dir("openlane", "docs")
    write_result(system="openlane", dimension="B3", policy="none", scenario="matrix-row", expected=None, observed="not_applicable",
                 grade="NOT", idiomatic=True, evidence_path=ev,
                 notes="Graded from documentation: Openlane uses OpenFGA internally for its own objects and does not offer relationship "
                       "checks on a caller's objects; a system of record, not a relationship decision service.")
    print("B3 written")


# ----------------------------------------------------------------------------- B2 formal verification
B2_SOURCES = {
    "prismpath": ["formal/README.md on branch formal/lean-fq (13 theorems on Figueroa quantization, the spiral index, and the Zeckendorf wire; Lean 4.33.1, Mathlib v4.33.1, zero sorry, standard axioms only)",
                  "docs/research/supporting-evidence.md #111 (universal WCET envelope 3E + P: base case proven, induction open)",
                  "docs/research/supporting-evidence.md #109, #110 (cycle exact WCET formula, signed wcet_cycles)",
                  "prismpath/portable/conformance/ (frozen corpora certified on every target)"],
    "opa": ["https://www.openpolicyagent.org/docs/latest/policy-reference/ (Rego reference; no machine checked semantics or proofs are published)",
            "https://github.com/open-policy-agent/opa (Go implementation, tests and fuzzing, no proof artifacts)"],
    "cedar": ["https://github.com/cedar-policy/cedar-spec (cedar-lean: definitional authorizer, validator, and symbolic compiler in Lean 4.33.1; cedar-drt: differential random testing against the Rust implementation)",
              "https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md (verified properties: forbid overrides, explicit permit required, default deny, order and duplicate independence, sound policy slicing, sound type checking, sound level based entity slicing)",
              "https://github.com/cedar-policy/cedar-spec/tree/main/cedar-lean/Cedar/Thm"],
    "cerbos": ["https://docs.cerbos.dev/cerbos/latest/policies/compile (policy test framework; no formal verification documented)",
               "https://github.com/cerbos/cerbos"],
    "openfga": ["https://openfga.dev/docs/modeling/testing (model tests with the CLI; no formal verification documented)",
                "https://github.com/openfga/openfga"],
    "openlane": ["https://github.com/theopenlane/core (no decision engine to verify)"],
}
B2_ROWS = {
    "prismpath": ("NOT", "No machine checked proof of the decision engine. What exists, stated exactly: (1) a Lean 4 development on "
                         "branch formal/lean-fq proving that Figueroa quantization preserves decisions (I1), that the shipped reference "
                         "algorithm computes the proven partition, that spiral indexing is a bijection, and that the Zeckendorf wire "
                         "round trips and frames itself, 13 theorems, zero sorry, standard axioms only, bridged to the Python and Rust "
                         "code by 623 evaluated conformance checks rather than by a proof about the source; (2) the WCET envelope's "
                         "base case proven with the induction step open (#111) and the per policy bound calibrated cycle exact on the "
                         "RTL (#109); (3) conformance certification of the interpreter on every substrate. None of that is a proof of "
                         "the evaluator's semantics, so the pre registered NOT stands; the quantization proofs are a component proof and "
                         "are recorded, not counted."),
    "opa": ("NOT", "Rego has a written reference and an extensive test and fuzz corpus; no machine checked semantics or proofs "
                   "about the evaluator are published."),
    "cedar": ("NATIVE", "cedar-spec holds a definitional Lean model of the authorizer, validator, and a symbolic compiler with proven "
                        "properties (forbid overrides permit, allow only when explicitly permitted, default deny, evaluation order and "
                        "duplicate independence, sound policy slicing, sound type checking, sound level based slicing), tied to the "
                        "shipped Rust implementation by differential random testing. Lean toolchain v4.33.1, the same as PrismPath's "
                        "formal development. The pre registered NATIVE."),
    "cerbos": ("NOT", "A policy test framework and compile time checks; no formal verification documented."),
    "openfga": ("NOT", "Model tests through the CLI; no formal verification documented."),
    "openlane": ("NOT", "No decision engine, nothing to verify in this sense."),
}


def run_b2() -> None:
    for system, (grade, note) in B2_ROWS.items():
        ev = evidence_dir(system, "B2")
        (ev / "sources.txt").write_text("\n".join(B2_SOURCES[system]) + "\n")
        write_result(system=system, dimension="B2", policy="none", scenario="matrix-row", expected=None, observed="not_applicable",
                     grade=grade, idiomatic=True, evidence_path=ev, notes=note + f" Sources: {ev.relative_to(HERE.parent.parent)}/sources.txt.")
    print("B2 written")


# ----------------------------------------------------------------------------- B4 ecosystem
B4_SOURCES = {
    "prismpath": ["integrations/README.md (Zarf and UDS delivery of a signed policy, Vector codec both directions, C++ consumer, Wireshark dissector integrations/wireshark/facet.lua)",
                  "prismpath-ebpf/ (XDP and TC programs, loader, kernel certify), prismpath-hw/ (Zynq overlay, RP2350 and ESP32 firmware)",
                  "prismpath-telemetry-rs/ and prismpath-facet-bridge/ (Rust crates), prismpath/portable/ (C target)",
                  "adapters/compliance/ (osquery, Lynis, Prowler scanner adapters, OSCAL catalog import and export)",
                  "pyproject.toml (Python package prismpath 0.1.0, not published to a package index)"],
    "opa": ["https://www.openpolicyagent.org/ecosystem (over 60 listed integrations: Kubernetes admission control and Gatekeeper, Envoy, Terraform and conftest, Spring Security, SDKs for JavaScript, Java, C#, Go, Swift, Clojure, Rust, PHP, Zig)"],
    "cedar": ["https://github.com/cedar-policy (cedar Rust, cedar-java, cedar-go, cedar-wasm in the main repository, cedar-access-control-for-k8s for Kubernetes authorization and admission, cedar-local-agent, authorization-for-expressjs, vscode-cedar, cedar-for-agents)",
              "https://aws.amazon.com/verified-permissions/ (managed service built on Cedar)"],
    "cerbos": ["https://docs.cerbos.dev/cerbos/latest/api/ (REST and gRPC APIs; SDKs for Go, Java, JavaScript, .NET, Laravel, PHP, Python, Ruby, Rust; Kubernetes service, sidecar, and daemonset deployments; Helm chart; Cerbos Hub; query plan adapters for Prisma, Drizzle, Mongoose, Convex, LangChain, SQLAlchemy; authentication recipes)"],
    "openfga": ["https://openfga.dev/docs/getting-started/install-sdk (SDKs for Node.js, Go, .NET, Python, Java; CLI; Docker images)",
                "https://github.com/openfga/helm-charts (Kubernetes deployment)"],
    "openlane": ["https://docs.theopenlane.io/docs/platform/integrations/overview (identity providers Authentik, Azure Entra ID, Google Workspace, Keycloak, Okta; AWS, Google Cloud SCC, Microsoft Defender for Cloud, Cloudflare; GitHub App, Slack, Microsoft Teams; Google Drive, OneDrive; Tailscale; email)",
                 "https://docs.theopenlane.io/docs/api (GraphQL and REST API)"],
}
PRISMPATH_B4_GLUE = {"description": "a Kubernetes admission webhook or an Envoy ext_authz adapter that fronts the Python engine or the C "
                                    "target over HTTP; neither exists today, and there is no Terraform provider and no package index "
                                    "release. Estimated within the section 4 budget",
                     "components": ["HTTP shim over engine.run or the C target", "webhook or ext_authz deployment manifest"],
                     "loc": 200, "hours": 8}
B4_ROWS = {
    "prismpath": ("WITH-WORK", "Integration surface exists but is narrow and substrate shaped: signed policy delivery through Zarf and UDS, "
                               "a Vector codec, a Wireshark dissector, kernel programs, MCU and FPGA targets, Rust and C libraries, and "
                               "GRC scanner adapters. No Kubernetes admission path, no Envoy filter, no Terraform provider, no SDKs "
                               "beyond Python, Rust, and C, no package index publication. Pre registered WITH-WORK; the glue is costed."),
    "opa": ("NATIVE", "The broadest ecosystem in the field: Kubernetes admission (Gatekeeper), Envoy, Terraform and conftest, and SDKs "
                      "in nine languages listed on the project's ecosystem page. Pre registered NATIVE."),
    "cedar": ("NATIVE", "Against the pre registered WITH-WORK: Rust, Java, and Go implementations plus WebAssembly, Kubernetes "
                        "authorization and admission (cedar-access-control-for-k8s), a local agent, an Express.js integration, editor "
                        "support, and a managed service (Amazon Verified Permissions). Three of the four integration classes and three "
                        "implementations meet the NATIVE bar fixed above; the prediction was wrong and is reported as such."),
    "cerbos": ("NATIVE", "Nine SDKs, Kubernetes service, sidecar, and daemonset patterns, a Helm chart, query plan adapters for six "
                         "data layers, and Cerbos Hub. Pre registered NATIVE."),
    "openfga": ("NATIVE", "Five SDKs, a CLI, Docker images, Helm charts, and CNCF incubation. Pre registered NATIVE."),
    "openlane": ("NATIVE", "Sixteen documented integrations across identity providers, cloud posture sources, code and collaboration "
                           "tools, document stores, and network, with GraphQL and REST APIs. Pre registered NATIVE."),
}


def run_b4() -> None:
    for system, (grade, note) in B4_ROWS.items():
        ev = evidence_dir(system, "B4")
        (ev / "sources.txt").write_text("\n".join(B4_SOURCES[system]) + "\n")
        write_result(system=system, dimension="B4", policy="none", scenario="matrix-row", expected=None, observed="not_applicable",
                     grade=grade, idiomatic=True, evidence_path=ev, glue=PRISMPATH_B4_GLUE if grade == "WITH-WORK" else None,
                     notes=note + f" Sources: {ev.relative_to(HERE.parent.parent)}/sources.txt.")
    print("B4 written")


# ----------------------------------------------------------------------------- B5 maturity
# Repository figures read from the GitHub API on 2026-09-09 (gh api repos/<owner>/<repo>); contributor counts
# include anonymous contributors as GitHub reports them.
B5_FACTS = {
    "prismpath": {"first_commit": "2026-07-19", "commits": 381, "contributors": "one organization (Crystal Warden Labs)",
                  "release": "tag v0.1.0, not published to a package index", "foundation_or_operator": "none; adoption signals only"},
    "opa": {"created": "2015-12-28", "stars": 12217, "forks": 1672, "contributors": 610, "release": "v1.20.2 on 2026-09-03",
            "foundation_or_operator": "CNCF graduated, 2021-01-29 (announced 2021-02-04)"},
    "cedar": {"created": "2023-04-25", "stars": 1717, "forks": 171, "contributors": 63, "release": "v4.12.0 on 2026-07-28",
              "foundation_or_operator": "Amazon Verified Permissions (AWS) in production; CNCF .project automation present in the org"},
    "cerbos": {"created": "2021-03-21", "stars": 4578, "forks": 211, "contributors": 35, "release": "v0.55.0 on 2026-08-13 (pre 1.0 versioning)",
               "foundation_or_operator": "Cerbos Hub commercial operator"},
    "openfga": {"created": "2022-06-08", "stars": 5734, "forks": 487, "contributors": 117, "release": "v1.20.0 on 2026-09-08",
                "foundation_or_operator": "CNCF incubating since 2025-10-28 (sandbox 2022-09-14); Okta FGA operator"},
    "openlane": {"created": "2024-08-24", "stars": 302, "forks": 51, "contributors": 20, "release": "v2.4.9 on 2026-09-08",
                 "foundation_or_operator": "commercial operator theopenlane.io"},
}
B5_SOURCES = {
    "prismpath": ["git log (first commit 2026-07-19, 381 commits on main, one organization), git tag (v0.1.0)"],
    "opa": ["https://github.com/open-policy-agent/opa", "https://www.cncf.io/announcements/2021/02/04/cloud-native-computing-foundation-announces-open-policy-agent-graduation/"],
    "cedar": ["https://github.com/cedar-policy/cedar", "https://aws.amazon.com/verified-permissions/"],
    "cerbos": ["https://github.com/cerbos/cerbos", "https://www.cerbos.dev/"],
    "openfga": ["https://github.com/openfga/openfga", "https://www.cncf.io/blog/2025/11/11/openfga-becomes-a-cncf-incubating-project/", "https://openfga.dev/blog/incubation-announcement"],
    "openlane": ["https://github.com/theopenlane/core", "https://www.theopenlane.io/"],
}
OPENLANE_B5_GLUE = {"description": "an adopter pins a release, self hosts, and owns the upgrade path of a project two years old with a "
                                   "maintainer base of about twenty", "components": ["version pin", "self hosting", "upgrade ownership"],
                    "loc": 0, "hours": 4}
B5_ROWS = {
    "prismpath": ("NOT", "Under one year of public history from one organization, 381 commits since 2026-07-19, one tag, no package "
                         "index release, no foundation, no external production operator; demand side signals exist and are not adoption. "
                         "Pre registered NOT."),
    "opa": ("NATIVE", "Ten years of history, CNCF graduated in 2021, 610 contributors, monthly releases. Pre registered NATIVE."),
    "cedar": ("NATIVE", "Three years public, 63 contributors, a managed AWS service in production, regular releases. Pre registered NATIVE."),
    "cerbos": ("NATIVE", "Five years public, 35 contributors, a commercial operator, regular releases; the 0.x version line is noted. "
                         "Pre registered NATIVE."),
    "openfga": ("NATIVE", "Four years public, 117 contributors, CNCF incubating since October 2025, Okta FGA in production. Pre registered NATIVE."),
    "openlane": ("WITH-WORK", "Two years public, 20 contributors, a commercial operator, frequent releases; below the three year and thirty "
                              "contributor bar fixed above, adoptable with the recorded mitigation. Pre registered WITH-WORK."),
}


def run_b5() -> None:
    for system, (grade, note) in B5_ROWS.items():
        ev = evidence_dir(system, "B5")
        (ev / "sources.txt").write_text("\n".join(B5_SOURCES[system]) + "\n")
        (ev / "facts.json").write_text(json.dumps(B5_FACTS[system], indent=2) + "\n")
        write_result(system=system, dimension="B5", policy="none", scenario="matrix-row", expected=None, observed="not_applicable",
                     grade=grade, idiomatic=True, evidence_path=ev, glue=OPENLANE_B5_GLUE if grade == "WITH-WORK" else None,
                     notes=note + f" Figures: {ev.relative_to(HERE.parent.parent)}/facts.json (GitHub API, 2026-09-09).")
    print("B5 written")


def main(argv: List[str] | None = None) -> int:
    run_b1(); run_b2(); run_b3(); run_b4(); run_b5()
    return 0


if __name__ == "__main__":
    sys.exit(main())
