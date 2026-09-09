# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""corpus_check.py: the neutral reference evaluator and the self consistency gate for the
layer comparison corpus (prismpath/comparisons/corpus/).

Every scenario's written `expected` is recomputed here from the policy's own rules under the
neutral semantics in corpus/README.md (ordered rules, first match wins, comparisons over a
missing field are unsatisfied). A scenario that disagrees with its own policy fails. This is what
makes the corpus a reference rather than an opinion, and it is what every translator (Phase 2)
must reproduce.

The module also computes the pre registration freeze hash: sha256 over the frozen files
(PREREGISTRATION.md, results/SCHEMA.md, corpus/README.md, corpus/*.json). `--freeze` writes it
to PREREGISTRATION.lock; the test pins it, so any later edit to the protocol or the corpus is
visible as a failing test and must be recorded as an amendment, never silently.

Usage:
    python -m prismpath.comparisons.corpus_check            # validate, exit nonzero on any error
    python -m prismpath.comparisons.corpus_check --freeze   # validate, then write PREREGISTRATION.lock
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
CORPUS_DIR = HERE / "corpus"
LOCK_PATH = HERE / "PREREGISTRATION.lock"
FROZEN_FILES = ("PREREGISTRATION.md", "results/SCHEMA.md", "corpus/README.md")

DECISIONS = {"allow", "deny", "observe", "abstain", "escalate_human"}
NON_DECISIONS = {"no_match", "refuse_policy", "refuse_input", "error", "undefined", "not_expressible"}
SCENARIO_KINDS = {
    "clear_allow", "clear_deny", "insufficient", "escalation", "undeclared_missing",
    "stale_policy", "tampered_policy", "tampered_input", "ai_worker_loop", "expressiveness",
    "relationship",
}
LIFECYCLE_KINDS = {"stale_policy", "tampered_policy", "tampered_input"}
LIFECYCLE_REASONS = {"stale", "tampered", "unsigned"}
DIMENSIONS = {f"A{i}" for i in range(1, 9)} | {f"B{i}" for i in range(1, 6)}
CMP_OPS = {"==", "!=", "<", "<=", ">", ">="}
LEVEL_M_FORMS = {"cmp", "in", "not_in", "all", "any", "not", "missing", "present"}
EXTENSION_FORMS = {"role_at_least", "eq_fields", "intersects", "related"}


class CorpusError(Exception):
    pass


# ----------------------------------------------------------------------------------------------
# the neutral reference evaluator
# ----------------------------------------------------------------------------------------------

def _get(inp: Dict[str, Any], field: str) -> Any:
    return inp.get(field, None)


def _cmp(a: Any, op: str, b: Any) -> bool:
    if a is None:
        return False
    if isinstance(a, bool) != isinstance(b, bool):
        # a bool never compares equal to an int or string under the neutral semantics
        return op == "!="
    if type(a) is not type(b):
        return op == "!="
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    if isinstance(a, str) or isinstance(a, bool):
        return False  # ordering is defined on ints only
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


def _related(model: Dict[str, Any], user: str, relation: str, obj: str,
             seen: Optional[set] = None) -> bool:
    """Zanzibar style check over the policy's declared model and tuples."""
    seen = seen or set()
    key = (user, relation, obj)
    if key in seen:
        return False
    seen.add(key)
    obj_type = obj.split(":", 1)[0]
    rules = model["relations"].get(obj_type, {}).get(relation, [])
    tuples = [tuple(t) for t in model["tuples"]]
    for rule in rules:
        kind = rule["kind"]
        if kind == "direct":
            if (user, relation, obj) in tuples:
                return True
        elif kind == "userset":
            st, sr = rule["subject_type"], rule["subject_relation"]
            for s, r, o in tuples:
                if r == relation and o == obj and s.endswith("#" + sr) and s.startswith(st + ":"):
                    subject_obj = s.split("#", 1)[0]
                    if _related(model, user, sr, subject_obj, seen):
                        return True
        elif kind == "parent":
            via, prel = rule["via"], rule["parent_relation"]
            for s, r, o in tuples:
                if o == obj and r == via:          # (parent_object, via, child): subject first, like every tuple
                    if _related(model, user, prel, s, seen):
                        return True
        else:
            raise CorpusError(f"unknown relation rule kind {kind!r}")
    return False


def evaluate(cond: Any, inp: Dict[str, Any], policy: Dict[str, Any]) -> bool:
    if cond is True:
        return True
    if not isinstance(cond, dict) or len(cond) != 1:
        raise CorpusError(f"malformed condition {cond!r}")
    (form, arg), = cond.items()
    if form == "cmp":
        field, op, const = arg
        if op not in CMP_OPS:
            raise CorpusError(f"bad op {op!r}")
        return _cmp(_get(inp, field), op, const)
    if form == "in":
        field, consts = arg
        v = _get(inp, field)
        return v is not None and any(_cmp(v, "==", c) for c in consts)
    if form == "not_in":
        field, consts = arg
        v = _get(inp, field)
        return v is not None and not any(_cmp(v, "==", c) for c in consts)
    if form == "missing":
        return _get(inp, arg) is None
    if form == "present":
        return _get(inp, arg) is not None
    if form == "all":
        return all(evaluate(c, inp, policy) for c in arg)
    if form == "any":
        return any(evaluate(c, inp, policy) for c in arg)
    if form == "not":
        return not evaluate(arg, inp, policy)
    if form == "role_at_least":
        field, floor = arg
        h = policy["hierarchy"]
        if h["field"] != field:
            raise CorpusError("role_at_least on a field with no declared hierarchy")
        v = _get(inp, field)
        return v is not None and h["order"].index(v) >= h["order"].index(floor)
    if form == "eq_fields":
        a, b = arg
        va, vb = _get(inp, a), _get(inp, b)
        return va is not None and vb is not None and va == vb
    if form == "intersects":
        a, b = arg
        va, vb = _get(inp, a), _get(inp, b)
        return bool(va) and bool(vb) and bool(set(va) & set(vb))
    if form == "related":
        uf, rf, of = arg
        u, r, o = _get(inp, uf), _get(inp, rf), _get(inp, of)
        if None in (u, r, o):
            return False
        return _related(policy["model"], u, r, o)
    raise CorpusError(f"unknown condition form {form!r}")


def decide(policy: Dict[str, Any], inp: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """First match wins. Returns (outcome, rule_id); ('no_match', None) when nothing matches."""
    for rule in policy["rules"]:
        if evaluate(rule["if"], inp, policy):
            return rule["then"], rule["id"]
    return "no_match", None


# ----------------------------------------------------------------------------------------------
# structural checks
# ----------------------------------------------------------------------------------------------

def _forms_used(cond: Any, out: set) -> None:
    if cond is True:
        return
    (form, arg), = cond.items()
    out.add(form)
    if form in ("all", "any"):
        for c in arg:
            _forms_used(c, out)
    elif form == "not":
        _forms_used(arg, out)


def _check_level_m_claim(policy: Dict[str, Any], errors: List[str]) -> None:
    """A policy claiming Level M may use only the small forms, int/bool/string constants, and
    missing/present only on bool fields (where `not field` is the exact PrismPath spelling)."""
    pid = policy["id"]
    for rule in policy["rules"]:
        forms: set = set()
        _forms_used(rule["if"], forms)
        bad = forms - LEVEL_M_FORMS
        if bad:
            errors.append(f"{pid}/{rule['id']}: level_m_claim but uses {sorted(bad)}")
        # walk again for constants and missing/present targets
        def walk(c: Any) -> None:
            if c is True:
                return
            (form, arg), = c.items()
            if form == "cmp":
                field, _op, const = arg
                if not isinstance(const, (int, str, bool)) or isinstance(const, float):
                    errors.append(f"{pid}/{rule['id']}: non Level M constant {const!r}")
                if isinstance(const, int) and not isinstance(const, bool) and not -2**31 <= const < 2**31:
                    errors.append(f"{pid}/{rule['id']}: constant {const} outside i32")
            elif form in ("in", "not_in"):
                for const in arg[1]:
                    if not isinstance(const, (int, str, bool)) or isinstance(const, float):
                        errors.append(f"{pid}/{rule['id']}: non Level M list constant {const!r}")
            elif form in ("missing", "present"):
                ftype = policy["fields"].get(arg, {}).get("type")
                if ftype != "bool":
                    errors.append(f"{pid}/{rule['id']}: {form} on non bool field {arg!r} is not an exact Level M spelling")
            elif form in ("all", "any"):
                for sub in arg:
                    walk(sub)
            elif form == "not":
                walk(arg)
        walk(rule["if"])


def _check_scenario(policy: Dict[str, Any], sc: Dict[str, Any], errors: List[str]) -> None:
    pid, sid = policy["id"], sc.get("id", "?")
    tag = f"{pid}/{sid}"
    kind = sc.get("kind")
    if kind not in SCENARIO_KINDS or kind in LIFECYCLE_KINDS:
        errors.append(f"{tag}: bad scenario kind {kind!r}")
        return
    steps = sc["steps"] if kind == "ai_worker_loop" else [sc]
    if kind == "ai_worker_loop":
        rx = sc.get("receipt_expected")
        if not isinstance(rx, dict) or set(rx) != {"per_decision", "signed", "tamper_evident", "carries_cause"}:
            errors.append(f"{tag}: ai_worker_loop needs receipt_expected with the four sub properties")
    for i, step in enumerate(steps):
        stag = tag if kind != "ai_worker_loop" else f"{tag}[{i}]"
        inp = step.get("input")
        exp = step.get("expected")
        if not isinstance(inp, dict) or not isinstance(exp, dict):
            errors.append(f"{stag}: input and expected must be objects")
            continue
        for f in inp:
            if f not in policy["fields"]:
                errors.append(f"{stag}: input field {f!r} not declared")
        outcome, rule = decide(policy, {k: v for k, v in inp.items() if v is not None})
        if exp.get("outcome") != outcome or exp.get("rule") != rule:
            errors.append(f"{stag}: written expected ({exp.get('outcome')}, {exp.get('rule')}) "
                          f"disagrees with the neutral semantics ({outcome}, {rule})")
        if outcome != "no_match" and outcome not in policy["outcomes"]:
            errors.append(f"{stag}: rule outcome {outcome!r} not in policy outcomes")
        if kind == "undeclared_missing" and policy.get("catch_all") is False and outcome != "no_match":
            errors.append(f"{stag}: undeclared_missing on a no catch all policy must land on no_match")
        cause = exp.get("prismpath_cause", "absent")
        if cause == "absent" or not (cause is None or isinstance(cause, int)):
            errors.append(f"{stag}: prismpath_cause must be an int code or null")


def _check_lifecycle(policy: Dict[str, Any], lc: Dict[str, Any], errors: List[str]) -> None:
    tag = f"{policy['id']}/{lc.get('id', '?')}"
    if lc.get("kind") not in LIFECYCLE_KINDS:
        errors.append(f"{tag}: bad lifecycle kind {lc.get('kind')!r}")
    if not isinstance(lc.get("presented"), dict):
        errors.append(f"{tag}: lifecycle needs a presented object")
    exp = lc.get("expected", {})
    if exp.get("outcome") not in ("refuse_policy", "refuse_input"):
        errors.append(f"{tag}: lifecycle expected outcome must be refuse_policy or refuse_input")
    if exp.get("reason") not in LIFECYCLE_REASONS:
        errors.append(f"{tag}: lifecycle reason must be one of {sorted(LIFECYCLE_REASONS)}")
    if "prismpath_cause" not in exp:
        errors.append(f"{tag}: lifecycle expected needs prismpath_cause (int or null)")


def check_policy(policy: Dict[str, Any], path: Path) -> List[str]:
    errors: List[str] = []
    pid = policy.get("id")
    if pid != path.stem:
        errors.append(f"{path.name}: id {pid!r} must equal the file stem")
    for key in ("title", "dimensions", "level_m_claim", "fields", "outcomes", "catch_all", "rules", "scenarios"):
        if key not in policy:
            errors.append(f"{pid}: missing {key!r}")
    if errors:
        return errors
    bad_dims = set(policy["dimensions"]) - DIMENSIONS
    if bad_dims:
        errors.append(f"{pid}: unknown dimensions {sorted(bad_dims)}")
    if not set(policy["outcomes"]) <= DECISIONS:
        errors.append(f"{pid}: outcomes must be decisions, got {policy['outcomes']}")
    ids = [r["id"] for r in policy["rules"]]
    if len(ids) != len(set(ids)):
        errors.append(f"{pid}: duplicate rule ids")
    last_unconditional = policy["rules"][-1]["if"] is True
    if bool(policy["catch_all"]) != last_unconditional:
        errors.append(f"{pid}: catch_all={policy['catch_all']} but last rule unconditional={last_unconditional}")
    for r in policy["rules"]:
        if r["then"] not in policy["outcomes"]:
            errors.append(f"{pid}/{r['id']}: outcome {r['then']!r} not declared")
        try:
            evaluate(r["if"], {}, policy)
        except CorpusError as e:
            errors.append(f"{pid}/{r['id']}: {e}")
    if policy["level_m_claim"]:
        _check_level_m_claim(policy, errors)
    else:
        if "prismpath_expressibility" not in policy or "predicted_grade" not in policy["prismpath_expressibility"]:
            errors.append(f"{pid}: a non Level M policy must pre register prismpath_expressibility.predicted_grade")
    sids = [s.get("id") for s in policy["scenarios"]] + [l.get("id") for l in policy.get("lifecycle", [])]
    if len(sids) != len(set(sids)):
        errors.append(f"{pid}: duplicate scenario ids")
    for sc in policy["scenarios"]:
        _check_scenario(policy, sc, errors)
    for lc in policy.get("lifecycle", []):
        _check_lifecycle(policy, lc, errors)
    # coverage: every declared outcome is reached by at least one scenario step
    reached: set = set()
    for sc in policy["scenarios"]:
        steps = sc["steps"] if sc.get("kind") == "ai_worker_loop" else [sc]
        for st in steps:
            if isinstance(st.get("expected"), dict):
                reached.add(st["expected"].get("outcome"))
    unreached = set(policy["outcomes"]) - reached
    if unreached:
        errors.append(f"{pid}: declared outcomes never reached by a scenario: {sorted(unreached)}")
    # every rule fires at least once
    fired = set()
    for sc in policy["scenarios"]:
        steps = sc["steps"] if sc.get("kind") == "ai_worker_loop" else [sc]
        for st in steps:
            if isinstance(st.get("expected"), dict):
                fired.add(st["expected"].get("rule"))
    unfired = set(ids) - fired
    if unfired:
        errors.append(f"{pid}: rules never selected by any scenario: {sorted(unfired)}")
    return errors


def load_corpus(corpus_dir: Path = CORPUS_DIR) -> List[Tuple[Path, Dict[str, Any]]]:
    out = []
    for p in sorted(corpus_dir.glob("*.json")):
        with p.open("r", encoding="utf-8") as fh:
            out.append((p, json.load(fh)))
    return out


def check_corpus(corpus_dir: Path = CORPUS_DIR) -> List[str]:
    errors: List[str] = []
    policies = load_corpus(corpus_dir)
    if not policies:
        return [f"no policies under {corpus_dir}"]
    for path, pol in policies:
        errors.extend(check_policy(pol, path))
    covered = set()
    for _p, pol in policies:
        covered |= set(pol.get("dimensions", []))
    # every Group A dimension that is scenario graded must have a policy; B2/B4/B5 are matrix rows
    for d in sorted(DIMENSIONS - {"B2", "B4", "B5"}):
        if d not in covered:
            errors.append(f"dimension {d} has no policy in the corpus")
    return errors


# ----------------------------------------------------------------------------------------------
# the freeze
# ----------------------------------------------------------------------------------------------

def frozen_paths(root: Path = HERE) -> List[Path]:
    paths = [root / f for f in FROZEN_FILES]
    paths += sorted((root / "corpus").glob("*.json"))
    return paths


def freeze_hash(root: Path = HERE) -> str:
    h = hashlib.sha256()
    for p in frozen_paths(root):
        rel = p.relative_to(root).as_posix()
        h.update(rel.encode("utf-8") + b"\0")
        h.update(hashlib.sha256(p.read_bytes()).hexdigest().encode("ascii") + b"\n")
    return h.hexdigest()


def write_lock(root: Path = HERE) -> str:
    digest = freeze_hash(root)
    lines = ["# Pre registration freeze. Regenerate ONLY as a recorded amendment (PREREGISTRATION.md section 12).",
             f"freeze_sha256 {digest}"]
    for p in frozen_paths(root):
        lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}")
    (root / "PREREGISTRATION.lock").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return digest


def read_lock(root: Path = HERE) -> Optional[str]:
    lock = root / "PREREGISTRATION.lock"
    if not lock.exists():
        return None
    for line in lock.read_text(encoding="utf-8").splitlines():
        if line.startswith("freeze_sha256 "):
            return line.split()[1]
    return None


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    errors = check_corpus()
    policies = load_corpus()
    n_sc = sum(len(p["scenarios"]) for _, p in policies)
    n_steps = sum(len(s["steps"]) for _, p in policies for s in p["scenarios"] if s.get("kind") == "ai_worker_loop")
    n_lc = sum(len(p.get("lifecycle", [])) for _, p in policies)
    print(f"corpus_check: {len(policies)} policies, {n_sc} scenarios ({n_steps} loop steps), {n_lc} lifecycle entries")
    for e in errors:
        print(f"  ERROR {e}")
    if errors:
        return 1
    if "--freeze" in argv:
        print(f"freeze_sha256 {write_lock()}  -> {LOCK_PATH.name}")
    else:
        current, locked = freeze_hash(), read_lock()
        state = "MATCH" if locked == current else ("NO LOCK" if locked is None else "DRIFT")
        print(f"freeze_sha256 {current}  lock: {state}")
        if state == "DRIFT":
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
