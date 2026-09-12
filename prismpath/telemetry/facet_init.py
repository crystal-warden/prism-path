#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""facet-init: draft a Facet policy flow from the Vector config you already run.

Your Vector routes ARE your codebook. This tool reads a `vector.toml`, finds the `route` and
`filter` transforms, transcribes every condition that is expressible in Level M
(`field OP const` atoms under and/or/not, plus `includes([..], .field)` as `in`), and emits a DRAFT
flow whose edges are those conditions. A sample of real events (NDJSON) is used for two things only:
discovering field names/types to annotate the draft, and verifying the draft end to end through
the preflight tool. **No condition is ever learned from the data** — the codebook must derive from
authored policy (that is the point), so the tool drafts and the author signs.

What does not transcribe is reported verbatim with the reason (function calls, regex, VRL variables,
field vs field, null, chained comparisons, float thresholds) so the author can decide its fate.
Vector's `route` transform sends an event to EVERY matching output while a flow edge routes FIRST
match; the draft preserves the authored order and the banner says so, because making the conditions
mutually exclusive (or reordering deliberately) is a signing decision, not a tool decision.

Usage:
  facet_init.py SAMPLE.ndjson [--vector-toml vector.toml] [--out DRAFT.md] [--name NAME]
                [--limit N] [--no-check]

Without --vector-toml it emits a skeleton flow annotated with the discovered fields, for authors
starting from scratch. Exit 0 when a draft was written and (if checked) preflight found it ready.
"""
from __future__ import annotations

import argparse
import ast
import json
import keyword
import re
import subprocess
import sys

try:
    import tomllib                                       # Python 3.11+ stdlib
except ImportError:                                      # 3.10: optional tomli fallback
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]       # --vector-toml will refuse politely
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent

_PATH_RE = re.compile(r'(?<![\w)\]"\'])\.([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)')
_INCLUDES_RE = re.compile(r'includes\s*\(\s*(\[[^\[\]]*\])\s*,\s*([A-Za-z_]\w*)\s*\)')


# ----------------------------------------------------------------- field naming
class FieldMap:
    """Event path -> flow field token. The leaf name wins while unambiguous; a collision (or a
    keyword leaf) falls back to the full underscore-joined path. Identity mappings need no
    field_paths entry on the codec."""

    def __init__(self) -> None:
        self.by_path: Dict[str, str] = {}
        self.by_token: Dict[str, str] = {}

    def token(self, path: str) -> str:
        if path in self.by_path:
            return self.by_path[path]
        leaf = path.split(".")[-1]
        tok = leaf if not keyword.iskeyword(leaf) else path.replace(".", "_")
        if self.by_token.get(tok, path) != path:
            tok = path.replace(".", "_")
        self.by_path[path] = tok
        self.by_token[tok] = path
        return tok

    def non_identity(self) -> Dict[str, str]:
        return {token: path for path, token in self.by_path.items() if token != path}


# ----------------------------------------------------------------- VRL -> Level M
def _vrl_source(cond: Any) -> Optional[str]:
    if isinstance(cond, str):
        return cond
    if isinstance(cond, dict) and isinstance(cond.get("source"), str):
        return cond["source"]
    return None


def transcribe(cond: Any, fields: FieldMap) -> Tuple[Optional[str], Optional[str]]:
    """VRL condition -> (Level M condition text, None) or (None, reason it cannot transcribe)."""
    src = _vrl_source(cond)
    if src is None:
        return None, "condition is not a VRL string"
    text = _PATH_RE.sub(lambda match: fields.token(match.group(1)), src.strip())
    text = text.replace("&&", " and ").replace("||", " or ")
    text = re.sub(r"!(?!=)", " not ", text)
    text = re.sub(r"\btrue\b", "True", text)
    text = re.sub(r"\bfalse\b", "False", text)
    text = re.sub(r"\bnull\b", "None", text)
    text = _INCLUDES_RE.sub(lambda match: f"{match.group(2)} in {match.group(1)}", text)
    text = " ".join(text.split())
    try:
        tree = ast.parse(text, mode="eval").body
    except SyntaxError:
        return None, f"not parseable after rewrite: {src.strip()!r}"
    reason = _level_m_reason(tree, set(fields.by_token))
    if reason:
        return None, f"{reason}: {src.strip()!r}"
    return text, None


def _level_m_reason(node: ast.AST, tokens: set) -> Optional[str]:
    """None when the expression is a Level M condition over known field tokens; else why not."""
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            reason = _level_m_reason(value, tokens)
            if reason:
                return reason
        return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _level_m_reason(node.operand, tokens)
    if isinstance(node, ast.Name):
        return None if node.id in tokens else \
            f"unrecognized identifier {node.id!r} (VRL variable or function)"
    if isinstance(node, ast.Compare):
        if len(node.ops) != 1:
            return "chained comparison; split into two atoms joined with and"
        op = type(node.ops[0]).__name__
        if op not in ("Lt", "LtE", "Gt", "GtE", "Eq", "NotEq", "In", "NotIn"):
            return f"comparison operator {op} is not Level M"
        left, right = node.left, node.comparators[0]
        if op in ("In", "NotIn"):
            if isinstance(left, ast.Name) and left.id in tokens \
                    and isinstance(right, (ast.List, ast.Tuple)) \
                    and all(isinstance(element, ast.Constant) for element in right.elts):
                return None
            return "in wants field in [literal, ...]"
        for side in (left, right):
            if isinstance(side, ast.Name) and side.id not in tokens:
                return f"unrecognized identifier {side.id!r} (VRL variable or function)"
        if isinstance(left, ast.Name) and isinstance(right, ast.Name):
            return "field vs field does not transcribe"
        name, const = (left, right) if isinstance(left, ast.Name) else (right, left)
        if not (isinstance(name, ast.Name) and isinstance(const, ast.Constant)):
            return "atom is not field OP literal"
        if const.value is None:
            return "null comparison is not Level M"
        if isinstance(const.value, float):
            return "float threshold (the codec compares truncated integers; round it and review)"
        return None
    return f"{type(node).__name__} is not Level M (only field OP const under and/or/not)"


# ----------------------------------------------------------------- sample discovery
def _flatten(obj: Any, prefix: str = "") -> List[Tuple[str, Any]]:
    if isinstance(obj, dict):
        out: List[Tuple[str, Any]] = []
        for key, value in obj.items():
            out += _flatten(value, f"{prefix}{key}." if isinstance(value, dict) else f"{prefix}{key}")
        return out
    return [(prefix, obj)]


def discover(sample_path: str, limit: Optional[int]) -> Tuple[int, Dict[str, dict]]:
    """Per flattened path: types seen, presence count, numeric range, distinct strings (capped)."""
    fields: Dict[str, dict] = {}
    event_count = 0
    lines = sys.stdin if sample_path == "-" else open(sample_path, encoding="utf-8")
    try:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if limit is not None and event_count >= limit:
                break
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            event_count += 1
            for path, value in _flatten(event):
                info = fields.setdefault(path, {"count": 0, "types": Counter(),
                                                "lo": None, "hi": None, "distinct": set()})
                info["count"] += 1
                if value is None:
                    info["types"]["null"] += 1
                elif isinstance(value, bool):
                    info["types"]["bool"] += 1
                elif isinstance(value, (int, float)):
                    info["types"]["float" if isinstance(value, float) else "int"] += 1
                    info["lo"] = value if info["lo"] is None else min(info["lo"], value)
                    info["hi"] = value if info["hi"] is None else max(info["hi"], value)
                elif isinstance(value, str):
                    info["types"]["str"] += 1
                    if len(info["distinct"]) <= 12:
                        info["distinct"].add(value)
                else:
                    info["types"][type(value).__name__] += 1
    finally:
        if lines is not sys.stdin:
            lines.close()
    return event_count, fields


def _field_line(path: str, info: dict, event_count: int) -> str:
    types = "/".join(type_name for type_name, _c in info["types"].most_common())
    extra = ""
    if info["lo"] is not None:
        extra = f", range {info['lo']}..{info['hi']}"
    elif info["distinct"]:
        vals = sorted(info["distinct"])
        shown = ", ".join(repr(value) for value in vals[:6])
        extra = f", values {shown}" + (" ..." if len(vals) > 6 else "")
    return f"{path} ({types}, {info['count']}/{event_count} events{extra})"


# ----------------------------------------------------------------- vector.toml -> draft nodes
def _sanitize(name: str) -> str:
    return re.sub(r"\W", "_", name)


def build_nodes(config: dict, fields: FieldMap):
    """Transcribe route/filter transforms into flow nodes. Returns (nodes, skipped, notes):
    nodes = [(name, [(target, cond_text_or_None_for_else)])] in emit order, leaves included."""
    transforms = config.get("transforms", {})
    usable = {name: transform for name, transform in transforms.items()
              if isinstance(transform, dict) and transform.get("type") in ("route", "filter")}
    skipped: List[str] = []
    notes: List[str] = []
    for name, transform in transforms.items():
        if isinstance(transform, dict) and name not in usable:
            skipped.append(f"transform {name!r} (type {transform.get('type', '?')}) is not route/filter; "
                           f"the chain stops there")

    # who consumes each output? route outputs are "T.route"; a filter's pass side is plain "T"
    consumers: Dict[str, List[str]] = {}
    for name, transform in usable.items():
        for inp in transform.get("inputs", []):
            consumers.setdefault(inp, []).append(name)

    def follow(output: str, leaf: str) -> str:
        cs = [consumer for consumer in consumers.get(output, [])]
        if len(cs) == 1:
            return _sanitize(cs[0])
        if len(cs) > 1:
            notes.append(f"output {output!r} fans out to {cs}; a flow edge has one target, so the "
                         f"draft ends that path at leaf {leaf!r}")
        return leaf

    entry = [name for name, transform in usable.items()
             if not any(input_name in usable or input_name.split(".")[0] in usable
                        for input_name in transform.get("inputs", []))]
    if len(entry) > 1:
        notes.append(f"multiple entry transforms {entry}; drafting from {entry[0]!r} "
                     f"(the rest still emit as nodes; re-point `start:` to change)")

    nodes: List[Tuple[str, List[Tuple[str, Optional[str]]]]] = []
    leaves: List[str] = []
    order = entry + [transform_name for transform_name in usable if transform_name not in entry]
    for name in order:
        transform = usable[name]
        node = _sanitize(name)
        edges: List[Tuple[str, Optional[str]]] = []
        if transform["type"] == "route":
            for route, cond in transform.get("route", {}).items():
                text, why = transcribe(cond, fields)
                leaf = _sanitize(f"{name}_{route}")
                if text is None:
                    skipped.append(f"route {name}.{route}: {why} -> those events fall to "
                                   f"_unmatched in the draft; add the edge by hand")
                    continue
                edges.append((follow(f"{name}.{route}", leaf), text))
            edges.append((follow(f"{name}._unmatched", _sanitize(f"{name}_unmatched")), None))
        else:                                            # filter: keep side chains, drop side ends
            text, why = transcribe(transform.get("condition"), fields)
            keep = follow(name, _sanitize(f"{name}_pass"))
            if text is None:
                skipped.append(f"filter {name}: {why} -> drafted as a pass-through to {keep!r}; "
                               f"restore the condition by hand")
                edges.append((keep, "always"))
            else:
                edges.append((keep, text))
                edges.append((_sanitize(f"{name}_dropped"), None))
        nodes.append((node, edges))
        for tgt, _c in edges:
            if tgt not in {_sanitize(transform_name) for transform_name in usable} and tgt not in leaves:
                leaves.append(tgt)
    for leaf in leaves:
        nodes.append((leaf, []))
    return nodes, skipped, notes


# ----------------------------------------------------------------- emit
_BANNER = """\
DRAFT generated by facet-init{origin}. Review every edge, then sign: a Facet codebook derives
from authored policy, and this file is not policy until an author owns it. Every condition below
was transcribed from a route or filter transform you already wrote; none was learned from the
sample. Vector's route transform sends an event to EVERY matching output, while a flow edge
routes FIRST match: make the conditions mutually exclusive or order them deliberately before
signing.\
"""


def emit_flow(name: str, nodes, banner_extra: List[str], origin: str) -> str:
    out = ["---", f"name: {name}", f"start: {nodes[0][0]}", "---",
           _BANNER.format(origin=origin)]
    out += banner_extra + [""]
    for node, edges in nodes:
        out.append(f"## {node}")
        for target, cond in edges:
            out.append(f"-> {target}: when {cond}" if cond and cond != "always"
                       else (f"-> {target}: always" if cond else f"-> {target}: else"))
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="facet-init",
        description="Draft a Facet policy flow from an existing vector.toml plus a sample of "
                    "real events. The tool drafts, the author signs.")
    ap.add_argument("sample", help="sample events, NDJSON; '-' for stdin")
    ap.add_argument("--vector-toml", default=None, metavar="vector.toml",
                    help="transcribe this config's route/filter conditions into the draft")
    ap.add_argument("--out", default=None, metavar="DRAFT.md",
                    help="write the draft flow here (default: <sample>.flow.md or draft.flow.md)")
    ap.add_argument("--name", default=None, help="flow name (default: derived from --out)")
    ap.add_argument("--limit", type=int, default=None, metavar="N", help="scan at most N events")
    ap.add_argument("--no-check", action="store_true",
                    help="skip the preflight verification run on the finished draft")
    args = ap.parse_args()

    event_count, observed = discover(args.sample, args.limit)
    if event_count == 0:
        print("no events read from the sample; nothing to draft against")
        return 1

    out_path = Path(args.out) if args.out else Path(
        (args.sample if args.sample != "-" else "draft").rsplit(".", 1)[0] + ".flow.md")
    name = args.name or _sanitize(out_path.stem.replace(".flow", ""))
    fields = FieldMap()
    report: List[str] = [f"# facet-init: {event_count} events scanned"]

    if args.vector_toml:
        if tomllib is None:
            print("--vector-toml needs Python 3.11+ (stdlib tomllib) or `pip install tomli`")
            return 1
        config = tomllib.loads(Path(args.vector_toml).read_text())
        nodes, skipped, notes = build_nodes(config, fields)
        if not any(edges for _n, edges in nodes):
            print(f"no route/filter transforms found in {args.vector_toml}; "
                  f"rerun without --vector-toml for a skeleton draft")
            return 1
        origin = f" from {Path(args.vector_toml).name} plus {Path(args.sample).name}"
        banner_extra: List[str] = []
        if skipped:
            banner_extra.append(f"TODO: {len(skipped)} condition(s) did not transcribe; "
                                f"facet-init's report lists them verbatim.")
        report.append(f"\n## Transcribed into {out_path}")
        for node, edges in nodes:
            for target, cond in edges:
                if cond:
                    report.append(f"- `{node} -> {target}` when `{cond}`")
        if skipped:
            report.append("\n## Needs the author (did not transcribe)")
            report += [f"- {skipped_reason}" for skipped_reason in skipped]
        if notes:
            report.append("\n## Structure notes")
            report += [f"- {note}" for note in notes]
    else:
        origin = f" from {Path(args.sample).name} (no vector.toml: skeleton only)"
        banner_extra = ["", "Observed fields (annotations only; the author writes the conditions):"]
        for path in sorted(observed):
            banner_extra.append(f"  {_field_line(path, observed[path], event_count)}")
        nodes = [("classify", [("end", "always")]), ("end", [])]
        report.append("\n## Skeleton draft (no vector.toml given)")
        report.append("- one `classify -> end: always` edge keeps it parseable; replace it with "
                      "your `-> target: when field OP const` edges")

    # only fields on edges that actually emitted count; a path registered during a FAILED
    # transcription is the author's problem, not part of the draft codebook
    used_tokens = {token for _n, edges in nodes for _tgt, cond in edges if cond
                   for token in re.findall(r"[A-Za-z_]\w*", cond) if token in fields.by_token}
    used_paths = {fields.by_token[token] for token in used_tokens}
    unused = [path for path in sorted(observed) if path not in used_paths]
    if args.vector_toml and unused:
        report.append("\n## Observed in the sample, no authored condition (not transmitted)")
        report += [f"- {_field_line(path, observed[path], event_count)}" for path in unused]
    missing = [path for path in sorted(used_paths) if path not in observed]
    if missing:
        report.append("\n## In your conditions but never seen in the sample")
        report += [f"- `{path}` (wrong path, or the sample does not cover it)" for path in missing]

    out_path.write_text(emit_flow(name, nodes, banner_extra, origin))
    report.append(f"\nwrote {out_path}")

    maps = {token: path for token, path in fields.non_identity().items() if token in used_tokens}
    map_args = [argument for token, path in sorted(maps.items()) for argument in ("--map", f"{token}={path}")]
    if maps:
        report.append("\n## Codec field paths (nested events)")
        for token, path in sorted(maps.items()):
            report.append(f'- `encoding.field_paths.{token} = "{path}"` (preflight: `--map {token}={path}`)')

    check_cmd = [sys.executable, str(HERE / "preflight.py"), str(out_path), args.sample, *map_args]
    report.append(f"\nFull report: `"
                  f"{' '.join(Path(part).name if position < 2 else part for position, part in enumerate(check_cmd))}`")
    print("\n".join(report))

    if args.no_check or args.sample == "-" or not args.vector_toml:
        return 0
    print("\n## Preflight check on the draft")
    res = subprocess.run(check_cmd, capture_output=True, text=True)
    tail = res.stdout[res.stdout.find("## Verdict"):] if "## Verdict" in res.stdout else res.stdout
    print(tail.strip())
    return res.returncode


if __name__ == "__main__":
    raise SystemExit(main())
