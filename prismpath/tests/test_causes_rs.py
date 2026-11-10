# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The Rust cause registry (prismpath-rs/src/causes.rs) and the cause corpus (conformance/causes.json)
are generated from prismpath.kernel.causes by portable/gen_causes_rs.py, so the two registries cannot
drift. These tests fail when a committed file is not what the generator writes now, and the Rust crate
holds its table and hash to the same corpus (prismpath-rs/tests/test_causes.rs)."""
import importlib.util
import json
from pathlib import Path

from prismpath.kernel import causes

REPO = Path(__file__).resolve().parents[2]
PORTABLE = REPO / "prismpath" / "portable"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_causes_rs", PORTABLE / "gen_causes_rs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_rust_registry_is_what_the_generator_writes_now():
    generator = _generator()
    assert (REPO / "prismpath-rs" / "src" / "causes.rs").read_text(encoding="utf-8") == generator.build_rust(), (
        "prismpath-rs/src/causes.rs is stale; run prismpath/portable/gen_causes_rs.py and commit the result")


def test_the_cause_corpus_is_what_the_generator_writes_now():
    generator = _generator()
    committed = (PORTABLE / "conformance" / "causes.json").read_text(encoding="utf-8")
    assert committed == generator.corpus_text()


def test_the_corpus_hash_is_the_registry_hash():
    doc = json.loads((PORTABLE / "conformance" / "causes.json").read_text(encoding="utf-8"))
    assert doc["registry_sha256"] == causes.registry_sha256()


def test_the_corpus_lists_every_row_and_the_engine_stops():
    doc = json.loads((PORTABLE / "conformance" / "causes.json").read_text(encoding="utf-8"))
    assert [(row["code"], row["name"], row["class"]) for row in doc["registry"]] == [
        (code, name, cause_class) for code, name, cause_class, _d in causes._REGISTRY]
    assert doc["engine_stop_to_cause"] == causes.ENGINE_STOP_TO_CAUSE


def test_the_conformance_flows_carry_the_run_cause():
    flows = json.loads((PORTABLE / "conformance" / "flows.json").read_text(encoding="utf-8"))
    seen = {(case["expect"]["stopped"], case["expect"]["cause"]) for case in flows["cases"] if "error" not in case["expect"]}
    assert ("stuck", causes.NAMES["route:stuck"]) in seen
    assert ("max_steps", causes.NAMES["route:max-steps"]) in seen
    assert ("needs_human", causes.NAMES["route:needs-human"]) in seen
    assert ("terminal", causes.CAUSE_NONE) in seen and ("waiting", causes.CAUSE_NONE) in seen
    assert ("contract_violation", causes.NAMES["route:contract-violation"]) in seen
    locked = json.loads((PORTABLE / "conformance" / "locked_flows.json").read_text(encoding="utf-8"))
    assert ("needs_human", causes.NAMES["route:below-human-floor"]) in {
        (case["expect"]["stopped"], case["expect"]["cause"]) for case in locked["cases"]}


STRICT_DECODE_CAUSES = ("wire:no-terminator", "wire:dangling-codeword", "wire:symbol-overflow", "wire:codebook-mismatch")


def test_the_strict_decode_causes_are_registered_and_have_no_emitter():
    """Causes 48 to 51 are registered, and no decoder in either language names them: the reference and its
    documents say what they mean (docs/design/spec-cause-codes.md) but not where a decoder raises each one,
    so emitting them would be a behavior invented here. Whoever decides where they fire adds the emitter, the
    corpus cases and a change to this test in the same commit (the owner's decision is recorded in
    CHANGELOG.md)."""
    assert [causes.code(name) for name in STRICT_DECODE_CAUSES] == [48, 49, 50, 51]
    sources = [path for path in (REPO / "prismpath").rglob("*.py")
               if "tests" not in path.parts and path.name not in ("causes.py", "gen_causes_rs.py")]
    sources += [path for crate in ("prismpath-rs", "prismpath-telemetry-rs", "prismpath-hotswap-rs", "prismpath-preflight")
                for path in (REPO / crate / "src").rglob("*.rs") if path.name != "causes.rs"]
    assert len(sources) > 100
    for path in sources:
        text = path.read_text(encoding="utf-8")
        for name in STRICT_DECODE_CAUSES:
            assert name not in text, f"{path.relative_to(REPO)} names {name}, which has no emitter by decision"
