# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""harness.py: the translator contract every system under `systems/<id>/` implements, plus the
shared corpus iteration the Phase 2 checker and the Phase 3 runners both use.

A system module exposes:

    SYSTEM: str                                   the system id (matches results/<system>/)
    def translate(policy: dict) -> Translation    neutral corpus policy -> native artifacts
    class Runner:
        def __init__(self, policy: dict, gen_dir: Path): ...   gen_dir holds translate()'s files
        def decide(self, inp: dict) -> Decision                 one scenario input -> one decision
        def close(self) -> None

`Translation.files` maps a relative filename to its text; the checker writes them under
`systems/<id>/generated/<policy_id>/` so the translated policy is a committed, reviewable artifact
(it is the evidence pointer result files cite). `expressible=False` means the system cannot host
this policy at all; `dropped_rules` names rules the translation had to leave out, so a scenario
that expects one of them is recorded as DROPPED (measured inexpressibility), not as a translator
defect. `Decision.observed` is in the neutral vocabulary (corpus/README.md), or one of the
non decision results `undefined`, `error`, `not_expressible`, `no_match`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
CORPUS_DIR = HERE / "corpus"
SYSTEMS_DIR = HERE / "systems"
TOOLCHAIN_BIN = HERE / ".toolchain" / "bin"


@dataclass
class Translation:
    files: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)        # where the idiom strained, in plain words
    citations: List[str] = field(default_factory=list)    # official doc URLs for the constructs used
    expressible: bool = True
    idiomatic: bool = True                                # False when the translator was unsure
    dropped_rules: List[str] = field(default_factory=list)


@dataclass
class Decision:
    observed: str                    # neutral vocabulary or a non decision result
    rule: Optional[str] = None       # the rule id the system reports, when it can report one
    cause: Optional[int] = None      # the cause code the system reports, when it has one
    raw: str = ""                    # verbatim system output for the evidence file


def load_policies(corpus_dir: Path = CORPUS_DIR) -> List[Dict[str, Any]]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(corpus_dir.glob("*.json"))]


def scenario_steps(policy: Dict[str, Any]) -> Iterator[Tuple[str, str, Dict[str, Any], Dict[str, Any]]]:
    """Yield (scenario_id, kind, input, expected) for every decision the corpus asks for, loop
    steps expanded as `<scenario>[i]`. Lifecycle entries are not decisions and are not yielded."""
    for sc in policy["scenarios"]:
        if sc["kind"] == "ai_worker_loop":
            for i, st in enumerate(sc["steps"]):
                yield f"{sc['id']}[{i}]", sc["kind"], st["input"], st["expected"]
        else:
            yield sc["id"], sc["kind"], sc["input"], sc["expected"]


def gen_dir_for(system: str, policy_id: str) -> Path:
    return SYSTEMS_DIR / system / "generated" / policy_id


def write_translation(system: str, policy: Dict[str, Any], tr: Translation) -> Path:
    out = gen_dir_for(system, policy["id"])
    out.mkdir(parents=True, exist_ok=True)
    for old in out.iterdir():
        if old.is_file() and old.name != "TRANSLATION.json":
            old.unlink()
    for name, text in tr.files.items():
        (out / name).write_text(text, encoding="utf-8")
    meta = {
        "system": system, "policy": policy["id"], "expressible": tr.expressible, "idiomatic": tr.idiomatic,
        "dropped_rules": tr.dropped_rules, "notes": tr.notes, "citations": tr.citations,
        "files": sorted(tr.files),
    }
    (out / "TRANSLATION.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out
