# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""OPA (Open Policy Agent, Rego v1) translator for the layer comparison contract.

Idiom:
- Ordered first-match rules are expressed using Rego's `else` chain keyword:
  `decision := {"outcome": ..., "rule": "r1"} if { ... } else := {"outcome": ..., "rule": "r2"} if { ... } ...`
- Unsatisfied conditions on missing input fields: in Rego, an expression accessing a missing
  input field is undefined, which causes rule body evaluation to fail (unsatisfied).
- Group B constructs (`role_at_least`, `eq_fields`, `intersects`, `related`) are natively supported:
  - `role_at_least`: rank map in `data.json` (`data.hierarchy`) compared with `>=`.
  - `eq_fields`: `input.a == input.b`.
  - `intersects`: set intersection count using `count({x | x := input.a[_]} & {x | x := input.b[_]}) > 0`.
  - `related`: transitive graph reachability via `graph.reachable` over `data.graph` in `data.json`.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismpath.comparisons.harness import TOOLCHAIN_BIN, Decision, Translation

SYSTEM = "opa"

CITATIONS = [
    "https://www.openpolicyagent.org/docs/latest/policy-language/#else-keyword",
    "https://www.openpolicyagent.org/docs/latest/policy-language/#undefined-values",
    "https://www.openpolicyagent.org/docs/latest/policy-language/#membership-in",
    "https://www.openpolicyagent.org/docs/latest/policy-language/#negation-not",
    "https://www.openpolicyagent.org/docs/latest/policy-language/#logical-or",
    "https://www.openpolicyagent.org/docs/latest/policy-language/#sets",
    "https://www.openpolicyagent.org/docs/latest/policy-language/#functions-built-in-graphreachable",
]


def _lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)
    raise ValueError(f"Unsupported literal: {v!r}")


def translate(policy: Dict[str, Any]) -> Translation:
    policy_id = policy["id"]
    pkg_name = f"comparison.{policy_id}"

    notes = [
        "Ordered first-match rules are encoded idiomatically using Rego's `else` chain (`decision := ... if { ... } else := ...`), with the final `else` without a body serving as the catch-all when present.",
        "Missing input fields in `cmp` or `in` make expressions undefined, causing rule body evaluation to fail (unsatisfied), which reproduces neutral semantics.",
    ]

    helper_rules: List[str] = []
    data_content: Dict[str, Any] = {}

    # Group B: role_at_least hierarchy mapping
    if "hierarchy" in policy:
        order = policy["hierarchy"]["order"]
        data_content["hierarchy"] = {role: i for i, role in enumerate(order)}
        notes.append("Role hierarchy is encoded natively via a rank map in data.json (`data.hierarchy`) compared with the `>=` operator.")

    # Group B: ReBAC graph compiling
    if "model" in policy:
        model = policy["model"]
        tuples = model.get("tuples", [])
        adj: Dict[str, set] = {}

        def add_edge(u: str, v: str):
            if u not in adj:
                adj[u] = set()
            if v not in adj:
                adj[v] = set()
            adj[u].add(v)

        for s, r, o in tuples:
            if r == "parent":
                # Parent tuple (s, parent, o) e.g. ["folder:f1", "parent", "doc:d1"]:
                # Viewers of parent folder can view child doc: folder:f1#viewer -> doc:d1#viewer
                add_edge(f"{s}#viewer", f"{o}#viewer")
            else:
                # Direct or userset tuple (s, r, o): e.g. ["user:alice", "member", "group:eng"] -> user:alice -> group:eng#member
                add_edge(s, f"{o}#{r}")

        data_content["graph"] = {k: sorted(list(v)) for k, v in sorted(adj.items())}
        notes.append(
            "Relationship reachability is computed natively using the `graph.reachable` built-in over `data.graph` compiled from model.tuples in data.json."
        )
        notes.append(
            "The model's three relation kinds become graph edges: direct and userset tuples (s, r, o) become edges s -> o#r; parent tuples (s, parent, o) become edges s#viewer -> o#viewer (parent viewer permits child viewer)."
        )
        notes.append(
            "Compilation of the relation model into a reachability graph is handwritten for this model shape."
        )

    def compile_cond(c: Any, rule_id: str, depth: int = 0) -> List[str]:
        if c is True:
            return []
        (op, arg), = c.items()

        if op == "cmp":
            f, rel_op, const = arg
            return [f"input.{f} {rel_op} {_lit(const)}"]

        if op == "in":
            f, consts = arg
            lits = ", ".join(_lit(v) for v in consts)
            return [f"input.{f} in {{{lits}}}"]

        if op == "not_in":
            f, consts = arg
            lits = ", ".join(_lit(v) for v in consts)
            if "Guarded not_in with input.field != null so missing fields yield unsatisfied rather than true." not in notes:
                notes.append("Guarded not_in with input.field != null so missing fields yield unsatisfied rather than true.")
            return [f"input.{f} != null", f"not input.{f} in {{{lits}}}"]

        if op == "missing":
            return [f'object.get(input, "{arg}", null) == null']

        if op == "present":
            return [f"input.{arg} != null"]

        if op == "all":
            lines: List[str] = []
            for sub in arg:
                lines.extend(compile_cond(sub, rule_id, depth + 1))
            return lines

        if op == "any":
            hname = f"cond_{rule_id}" if depth == 0 else f"cond_{rule_id}_{depth}"
            for sub in arg:
                sub_lines = compile_cond(sub, rule_id, depth + 1)
                body = "\n    ".join(sub_lines)
                helper_rules.append(f"{hname} if {{\n    {body}\n}}")
            return [hname]

        if op == "not":
            sub_lines = compile_cond(arg, rule_id, depth + 1)
            if len(sub_lines) == 1 and not sub_lines[0].startswith("not "):
                return [f"not {sub_lines[0]}"]
            else:
                hname = f"cond_{rule_id}_sub"
                body = "\n    ".join(sub_lines)
                helper_rules.append(f"{hname} if {{\n    {body}\n}}")
                return [f"not {hname}"]

        if op == "role_at_least":
            f, floor = arg
            return [f"data.hierarchy[input.{f}] >= data.hierarchy[{_lit(floor)}]"]

        if op == "eq_fields":
            f1, f2 = arg
            return [f"input.{f1} == input.{f2}"]

        if op == "intersects":
            l1, l2 = arg
            return [f"count({{x | x := input.{l1}[_]}} & {{x | x := input.{l2}[_]}}) > 0"]

        if op == "related":
            subj_var, rel_var, obj_var = arg
            return [
                "graph_set := {k: {x | x := v[_]} | some k, v in data.graph}",
                f'target := sprintf("%s#%s", [input.{obj_var}, input.{rel_var}])',
                f"target in graph.reachable(graph_set, {{input.{subj_var}}})",
            ]

        raise ValueError(f"Unknown condition: {c}")

    else_branches: List[str] = []
    for idx, r in enumerate(policy["rules"]):
        r_id = r["id"]
        r_if = r["if"]
        r_then = r["then"]
        prefix = "decision :=" if idx == 0 else "else :="

        if r_if is True:
            else_branches.append(f'{prefix} {{"outcome": "{r_then}", "rule": "{r_id}"}}')
        else:
            cond_lines = compile_cond(r_if, r_id)
            body_str = "\n    ".join(cond_lines)
            else_branches.append(f'{prefix} {{"outcome": "{r_then}", "rule": "{r_id}"}} if {{\n    {body_str}\n}}')

    rego_parts = [f"package {pkg_name}"]
    if helper_rules:
        rego_parts.append("\n".join(helper_rules))
    rego_parts.append("\n".join(else_branches))

    files = {"policy.rego": "\n\n".join(rego_parts) + "\n"}
    if data_content:
        files["data.json"] = json.dumps(data_content, indent=2) + "\n"

    return Translation(
        files=files,
        notes=notes,
        citations=CITATIONS,
        expressible=True,
        idiomatic=True,
        dropped_rules=[],
    )


class Runner:
    def __init__(self, policy: Dict[str, Any], gen_dir: Path):
        self.policy = policy
        self.policy_id = policy["id"]
        self.gen_dir = gen_dir

    def decide(self, inp: Dict[str, Any]) -> Decision:
        clean_inp = {k: v for k, v in inp.items() if v is not None}

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f_inp:
            json.dump(clean_inp, f_inp)
            tmp_path = Path(f_inp.name)

        try:
            cmd = [
                str(TOOLCHAIN_BIN / "opa"),
                "eval",
                "--format",
                "json",
                "--data",
                str(self.gen_dir / "policy.rego"),
            ]
            data_json = self.gen_dir / "data.json"
            if data_json.exists():
                cmd.extend(["--data", str(data_json)])
            cmd.extend(["--input", str(tmp_path), f"data.comparison.{self.policy_id}.decision"])

            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                return Decision("error", raw=res.stderr or res.stdout)

            raw = res.stdout
            out = json.loads(raw)
            results = out.get("result")
            if not results:
                return Decision("undefined", None, None, raw)

            val = results[0]["expressions"][0]["value"]
            return Decision(val["outcome"], val.get("rule"), None, raw)
        except Exception as e:
            return Decision("error", raw=str(e))
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def close(self) -> None:
        pass
