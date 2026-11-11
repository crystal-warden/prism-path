# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Generate the Rust cause registry from the Python one, so the two cannot drift.

    python prismpath/portable/gen_causes_rs.py          writes prismpath-rs/src/causes.rs,
                                                        conformance/causes.json and
                                                        formal/Core/Causes.lean
    python prismpath/portable/gen_causes_rs.py --check  exits 1 if either file is not what the
                                                        registry in prismpath/kernel/causes.py
                                                        produces now

`formal/Core/Causes.lean` holds every (code, name) pair for the verified core's Lean semantics, whose
theorem `Core.refusal_registered` proves that every refusal the core can produce carries one of them.

`prismpath-rs/src/causes.rs` holds every (code, name, class, description) row of
`prismpath.kernel.causes`, the stop to cause mapping, and the registry hash, all taken from the
Python module at generation time. `conformance/causes.json` freezes the same facts as a corpus the
Rust crate replays (`prismpath-rs/tests/test_causes.rs`) and the Python test regenerates
(`prismpath/tests/test_causes_rs.py`). Nothing in this file lists a cause by hand.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

from prismpath.kernel import causes  # noqa: E402

RUST_OUT = REPO / "prismpath-rs" / "src" / "causes.rs"
LEAN_OUT = REPO / "formal" / "Core" / "Causes.lean"
CORPUS_OUT = HERE / "conformance" / "causes.json"
CLASSES = ("authority", "envelope", "routing", "wire", "state")


def _constant(cause_name: str) -> str:
    """`route:stuck` -> ROUTE_STUCK, `replay-duplicate` -> REPLAY_DUPLICATE."""
    return re.sub(r"[^A-Za-z0-9]+", "_", cause_name).upper()


def _literal(text: str) -> str:
    assert text.isascii(), text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_rust() -> str:
    rows = causes._REGISTRY
    constants = [_constant(row[1]) for row in rows]
    assert len(set(constants)) == len(constants), "two cause names collapse to one Rust constant"
    for _code, _name, cause_class, _description in rows:
        assert cause_class in CLASSES, cause_class
    out = []
    out.append("// SPDX-License-Identifier: Apache-2.0")
    out.append("// Copyright 2026 Crystal Warden Supply Chain Labs LLC")
    out.append("//! The refusal and deviation cause registry (docs/design/spec-cause-codes.md).")
    out.append("//!")
    out.append("//! GENERATED from `prismpath/kernel/causes.py` by `prismpath/portable/gen_causes_rs.py`. Do not edit")
    out.append("//! by hand: `prismpath/tests/test_causes_rs.py` fails when this file is not what the generator")
    out.append("//! writes now, so the two registries cannot drift. The registry is append only; a code is never")
    out.append("//! renumbered or reused and a name never changes once shipped.")
    out.append("")
    out.append("/// The cause of a clean outcome (terminal, waiting): no refusal, parking or escalation.")
    out.append("pub const CAUSE_NONE: u8 = 0;")
    out.append("")
    out.append("/// `registry_sha256()` of the Python registry when this file was generated.")
    out.append(f"pub const REGISTRY_SHA256: &str = {_literal(causes.registry_sha256())};")
    out.append("")
    out.append("/// The cause class, the semantic axis of the registry.")
    out.append("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
    out.append("pub enum CauseClass {")
    for cause_class in CLASSES:
        out.append(f"    {cause_class.capitalize()},")
    out.append("}")
    out.append("")
    out.append("impl CauseClass {")
    out.append("    /// The class name as the registry spells it.")
    out.append("    pub fn as_str(self) -> &'static str {")
    out.append("        match self {")
    for cause_class in CLASSES:
        out.append(f"            CauseClass::{cause_class.capitalize()} => {_literal(cause_class)},")
    out.append("        }")
    out.append("    }")
    out.append("}")
    out.append("")
    out.append("/// One registry row.")
    out.append("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
    out.append("pub struct Cause {")
    out.append("    pub code: u8,")
    out.append("    pub name: &'static str,")
    out.append("    pub class: CauseClass,")
    out.append("    pub description: &'static str,")
    out.append("}")
    out.append("")
    for (cause_code, cause_name, _class, _description), constant in zip(rows, constants):
        out.append(f"/// `{cause_name}`")
        out.append(f"pub const {constant}: u8 = {cause_code};")
    out.append("")
    out.append("/// Every registered cause, in registry order.")
    out.append("pub const REGISTRY: &[Cause] = &[")
    for cause_code, cause_name, cause_class, description in rows:
        out.append(f"    Cause {{ code: {cause_code}, name: {_literal(cause_name)}, class: CauseClass::{cause_class.capitalize()}, "
                   f"description: {_literal(description)} }},")
    out.append("];")
    out.append("")
    out.append("/// The engine's stop vocabulary mapped onto the registry; `terminal` and `waiting` are clean and have no cause.")
    out.append("pub const ENGINE_STOP_TO_CAUSE: &[(&str, u8)] = &[")
    for stop, cause_code in causes.ENGINE_STOP_TO_CAUSE.items():
        out.append(f"    ({_literal(stop)}, {_constant(causes.name(cause_code))}),")
    out.append("];")
    out.append("")
    out.append("/// The registry row for a code.")
    out.append("pub fn entry(cause_code: u8) -> Option<&'static Cause> {")
    out.append("    REGISTRY.iter().find(|row| row.code == cause_code)")
    out.append("}")
    out.append("")
    out.append("/// The canonical name of a code, or `None` for 0 and an unregistered code.")
    out.append("pub fn name(cause_code: u8) -> Option<&'static str> {")
    out.append("    entry(cause_code).map(|row| row.name)")
    out.append("}")
    out.append("")
    out.append("/// The code of a canonical name, or `None` for a name that is not registered.")
    out.append("pub fn code(cause_name: &str) -> Option<u8> {")
    out.append("    REGISTRY.iter().find(|row| row.name == cause_name).map(|row| row.code)")
    out.append("}")
    out.append("")
    out.append("/// The class of a code, or `None` for 0 and an unregistered code.")
    out.append("pub fn cause_class(cause_code: u8) -> Option<CauseClass> {")
    out.append("    entry(cause_code).map(|row| row.class)")
    out.append("}")
    out.append("")
    out.append("/// The cause of an engine stop (`stuck`, `needs_human`, `max_steps`, `contract_violation`), or")
    out.append("/// `CAUSE_NONE` for a clean stop (`terminal`, `waiting`) and for anything else.")
    out.append("pub fn engine_stop_cause(stopped: &str) -> u8 {")
    out.append("    ENGINE_STOP_TO_CAUSE.iter().find(|(stop, _)| *stop == stopped).map_or(CAUSE_NONE, |(_, cause_code)| *cause_code)")
    out.append("}")
    out.append("")
    out.append("/// A stable hash over the (code, name, class) triples, computed here from the table the way")
    out.append("/// `causes.registry_sha256()` does in Python. Descriptions are not covered.")
    out.append("#[cfg(feature = \"durable\")]")
    out.append("pub fn registry_sha256() -> String {")
    out.append("    use sha2::{Digest, Sha256};")
    out.append("    let blob = REGISTRY")
    out.append("        .iter()")
    out.append("        .map(|row| format!(\"{}|{}|{}\", row.code, row.name, row.class.as_str()))")
    out.append("        .collect::<Vec<_>>()")
    out.append("        .join(\"\\n\");")
    out.append("    hex::encode(Sha256::digest(blob.as_bytes()))")
    out.append("}")
    out.append("")
    return "\n".join(out)


def build_lean() -> str:
    rows = causes._REGISTRY
    out = ["-- SPDX-License-Identifier: Apache-2.0",
           "-- Copyright 2026 Crystal Warden Supply Chain Labs LLC",
           "/-!",
           "# The cause registry, for the verified core",
           "",
           "GENERATED from `prismpath/kernel/causes.py` by `prismpath/portable/gen_causes_rs.py`. Do not edit by",
           "hand: `gen_causes_rs.py --check` and `prismpath/tests/test_causes_rs.py` fail when this file is not",
           "what the generator writes now. Every (code, name) pair of the registry, in registry order; the core's",
           "spelling of its refusals (`Core.Refusal.code`, `Core.Refusal.cause`) is proved to land in this list",
           "(`Core.refusal_registered`), so a refusal with no registered code cannot be written.",
           "-/",
           "",
           "namespace Core",
           "",
           f"/-- `registry_sha256()` of the Python registry when this file was generated. -/",
           f"def causeRegistrySha256 : String := \"{causes.registry_sha256()}\"",
           "",
           "/-- Every registered (code, canonical name), in registry order. -/",
           "def causeRegistry : List (Nat × String) := ["]
    for index, (cause_code, cause_name, _class, _description) in enumerate(rows):
        assert cause_name.isascii() and '"' not in cause_name and "\\" not in cause_name, cause_name
        out.append(f"  ({cause_code}, \"{cause_name}\")" + ("," if index + 1 < len(rows) else ""))
    out += ["]", "", "end Core", ""]
    return "\n".join(out)


def build_corpus() -> dict:
    return {
        "version": 1,
        "comment": "FROZEN. The cause registry of prismpath.kernel.causes: every row, its hash, the engine stop mapping and "
                   "the lookups a consumer must answer. prismpath-rs/src/causes.rs is generated from the same registry and "
                   "prismpath-rs/tests/test_causes.rs replays this file. Appending a row regenerates it.",
        "registry_sha256": causes.registry_sha256(),
        "registry": [{"code": cause_code, "name": cause_name, "class": cause_class, "description": description}
                     for cause_code, cause_name, cause_class, description in causes._REGISTRY],
        "engine_stop_to_cause": dict(causes.ENGINE_STOP_TO_CAUSE),
        "clean_stops": ["terminal", "waiting"],
        "by_code": [{"code": cause_code, "name": causes.name(cause_code), "class": causes.cause_class(cause_code)}
                    for cause_code in (0, 1, 36, 48, 51, 52, 56, 68, 69, 86, 87, 200, 255)],
        "by_name": [{"name": probe, "code": causes.code(probe), "class": causes.cause_class(probe)}
                    for probe in ("route:stuck", "replay-duplicate", "no-such-cause", "", "ROUTE:STUCK", "route:stuck ")],
    }


def corpus_text() -> str:
    return json.dumps(build_corpus(), indent=1, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    outputs = [(RUST_OUT, build_rust()), (CORPUS_OUT, corpus_text()), (LEAN_OUT, build_lean())]
    if args.check:
        stale = [str(path.relative_to(REPO)) for path, text in outputs if not path.exists() or path.read_text(encoding="utf-8") != text]
        for path in stale:
            print(f"{path}: not what the Python registry generates now")
        return 1 if stale else 0
    for path, text in outputs:
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
