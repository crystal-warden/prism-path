# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""OpenFGA translator for the layer comparison.

OpenFGA answers one question: does `user` have `relation` on `object`, given an authorization model
and a set of relationship tuples. The corpus's relationship policy (`document_sharing_rebac`) IS
that question, so it translates directly: each type and relation of the corpus model becomes a
type definition, `direct` becomes a directly assignable relation, `userset` becomes a `group#member`
style assignable subject, and `parent` becomes `viewer from parent` (a tuple to userset). The
tuples are written verbatim. This is the documented OpenFGA idiom for groups and parent child
inheritance.

The four decision policies are NOT expressible here and are recorded that way rather than forced:
a Check returns one boolean for one relation. OpenFGA has conditions (CEL expressions on tuples)
that could gate an `allow` relation on request context, but a boolean cannot carry deny, abstain,
observe, and escalate_human as distinct results, and there is no ordered rule evaluation. An allow
only encoding through conditional tuples is a Group A combination test (Phase 5), not a translation.

The runner starts the pinned `openfga` binary with the in memory datastore on loopback, creates a
store, writes the model as the schema 1.1 JSON the HTTP API takes (generated directly, alongside a
DSL rendering for human review), writes the tuples, and issues one Check per scenario.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismpath.comparisons.harness import TOOLCHAIN_BIN, Decision, Translation

SYSTEM = "openfga"
HTTP_PORT, GRPC_PORT = 18090, 18091
CITATIONS = [
    "https://openfga.dev/docs/modeling/direct-access (directly related user types)",
    "https://openfga.dev/docs/modeling/user-groups (group#member as an assignable subject)",
    "https://openfga.dev/docs/modeling/parent-child (relation from parent: tuple to userset)",
    "https://openfga.dev/docs/modeling/conditions (conditions on tuples; why the decision policies are not expressible)",
    "https://openfga.dev/api/service (Check, WriteAuthorizationModel, Write)",
]


def _subject_types(model: Dict[str, Any], obj_type: str, relation: str) -> List[Dict[str, str]]:
    """Directly related user types for (type, relation): declared usersets plus the subject types
    the corpus tuples actually assign."""
    out: List[Dict[str, str]] = []
    seen = set()
    for rule in model["relations"][obj_type][relation]:
        if rule["kind"] == "userset":
            key = (rule["subject_type"], rule["subject_relation"])
            if key not in seen:
                seen.add(key)
                out.append({"type": rule["subject_type"], "relation": rule["subject_relation"]})
    for s, r, o in model["tuples"]:
        if r == relation and o.split(":", 1)[0] == obj_type and "#" not in s:
            key = (s.split(":", 1)[0], "")
            if key not in seen:
                seen.add(key)
                out.append({"type": key[0]})
    return out


def _model_json(model: Dict[str, Any]) -> Dict[str, Any]:
    type_defs = []
    for t in model["types"]:
        rels = model["relations"].get(t, {})
        relations, meta = {}, {}
        for rel, rules in rels.items():
            parts = []
            if any(r["kind"] in ("direct", "userset") for r in rules):
                parts.append({"this": {}})
            for r in rules:
                if r["kind"] == "parent":
                    parts.append({"tupleToUserset": {"tupleset": {"relation": r["via"]},
                                                     "computedUserset": {"relation": r["parent_relation"]}}})
            relations[rel] = parts[0] if len(parts) == 1 else {"union": {"child": parts}}
            meta[rel] = {"directly_related_user_types": _subject_types(model, t, rel)}
        td: Dict[str, Any] = {"type": t}
        if relations:
            td["relations"] = relations
            td["metadata"] = {"relations": meta}
        type_defs.append(td)
    return {"schema_version": "1.1", "type_definitions": type_defs}


def _model_dsl(model: Dict[str, Any]) -> str:
    lines = ["model", "  schema 1.1"]
    for t in model["types"]:
        lines.append(f"type {t}")
        rels = model["relations"].get(t, {})
        if rels:
            lines.append("  relations")
        for rel, rules in rels.items():
            direct = ", ".join(d["type"] + (f"#{d['relation']}" if d.get("relation") else "")
                               for d in _subject_types(model, t, rel))
            expr = [f"[{direct}]"] if direct else []
            expr += [f"{r['parent_relation']} from {r['via']}" for r in rules if r["kind"] == "parent"]
            lines.append(f"    define {rel}: " + " or ".join(expr))
    return "\n".join(lines) + "\n"


def translate(policy: Dict[str, Any]) -> Translation:
    tr = Translation(citations=list(CITATIONS))
    related = [r for r in policy["rules"] if r["if"] is not True and "related" in r["if"]]
    if not related:
        tr.expressible = False
        tr.notes.append("not expressible: a Check returns one boolean for one relation; the policy needs "
                        f"{len(policy['outcomes'])} distinct outcomes ({', '.join(policy['outcomes'])}) selected by "
                        "ordered first match rules. Conditions on tuples could gate a single allow relation on the "
                        "request context, which is the Phase 5 combination test, not a translation.")
        return tr
    model = policy["model"]
    tr.files["model.json"] = json.dumps(_model_json(model), indent=2) + "\n"
    tr.files["model.fga"] = _model_dsl(model)
    tr.files["tuples.json"] = json.dumps(
        [{"user": s, "relation": r, "object": o} for s, r, o in model["tuples"]], indent=2) + "\n"
    tr.notes.append("the corpus relation model maps one to one: direct -> assignable, userset -> group#member "
                    "subject, parent -> 'viewer from parent'; model.json is generated directly in the schema 1.1 "
                    "JSON the API takes and model.fga is the same model in the DSL for review")
    return tr


class Runner:
    def __init__(self, policy: Dict[str, Any], gen_dir: Path):
        self.policy = policy
        self.related_rule = next(r for r in policy["rules"] if r["if"] is not True and "related" in r["if"])
        self.default_rule = next((r for r in policy["rules"] if r["if"] is True), None)
        self.base = f"http://127.0.0.1:{HTTP_PORT}"
        self.log = tempfile.NamedTemporaryFile("w", prefix="openfga_", suffix=".log", delete=False)
        self.proc = subprocess.Popen(
            [str(TOOLCHAIN_BIN / "openfga"), "run", "--datastore-engine", "memory",
             "--http-addr", f"127.0.0.1:{HTTP_PORT}", "--grpc-addr", f"127.0.0.1:{GRPC_PORT}",
             "--playground-enabled=false", "--log-format", "json"],
            stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        self._wait_healthy()
        self.store = self._post("/stores", {"name": policy["id"]})["id"]
        model = json.loads((gen_dir / "model.json").read_text(encoding="utf-8"))
        self.model_id = self._post(f"/stores/{self.store}/authorization-models", model)["authorization_model_id"]
        tuples = json.loads((gen_dir / "tuples.json").read_text(encoding="utf-8"))
        self._post(f"/stores/{self.store}/write", {"writes": {"tuple_keys": tuples}})

    def _wait_healthy(self) -> None:
        for _ in range(80):
            try:
                with urllib.request.urlopen(f"{self.base}/healthz", timeout=1) as r:
                    if r.status == 200:
                        return
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(0.25)
        raise RuntimeError("openfga did not become healthy")

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(),
                                     headers={"content-type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())

    def decide(self, inp: Dict[str, Any]) -> Decision:
        uf, rf, of = self.related_rule["if"]["related"]
        body = {"authorization_model_id": self.model_id,
                "tuple_key": {"user": inp.get(uf), "relation": inp.get(rf), "object": inp.get(of)}}
        try:
            res = self._post(f"/stores/{self.store}/check", body)
        except urllib.error.HTTPError as e:
            return Decision("error", None, None, e.read().decode(errors="replace"))
        raw = json.dumps(res, sort_keys=True)
        if res.get("allowed") is True:
            return Decision(self.related_rule["then"], self.related_rule["id"], None, raw)
        if self.default_rule is not None:
            return Decision(self.default_rule["then"], self.default_rule["id"], None, raw)
        return Decision("no_match", None, None, raw)

    def close(self) -> None:
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
        self.log.close()
        try:
            os.unlink(self.log.name)
        except OSError:
            pass
