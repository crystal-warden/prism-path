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


def test_the_lean_registry_is_what_the_generator_writes_now():
    generator = _generator()
    assert (REPO / "formal" / "Core" / "Causes.lean").read_text(encoding="utf-8") == generator.build_lean(), (
        "formal/Core/Causes.lean is stale; run prismpath/portable/gen_causes_rs.py and commit the result")


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
# the strict decode causes a decoder emits beside its own refusal string, and the one still without an emitter
EMITTED = {"wire:no-terminator": 48, "wire:dangling-codeword": 49, "wire:codebook-mismatch": 51}
NO_EMITTER = {"wire:symbol-overflow": 50}


def _sources():
    sources = [path for path in (REPO / "prismpath").rglob("*.py")
               if "tests" not in path.parts and path.name not in ("causes.py", "gen_causes_rs.py")]
    sources += [path for crate in ("prismpath-rs", "prismpath-telemetry-rs", "prismpath-hotswap-rs", "prismpath-preflight")
                for path in (REPO / crate / "src").rglob("*.rs") if path.name != "causes.rs"]
    assert len(sources) > 100
    return sources


def test_the_strict_decode_causes_are_registered():
    assert [causes.code(name) for name in STRICT_DECODE_CAUSES] == [48, 49, 50, 51]
    assert set(EMITTED) | set(NO_EMITTER) == set(STRICT_DECODE_CAUSES)


def test_three_strict_decode_causes_have_an_emitter_in_each_language():
    """48, 49 and 51 ride beside a decoder's own refusal string (receipts, the concentrator, the reading
    decoder). Python names them from the registry, Rust by the generated constant."""
    python = "\n".join(path.read_text(encoding="utf-8") for path in _sources() if path.suffix == ".py")
    rust = "\n".join(path.read_text(encoding="utf-8") for path in _sources() if path.suffix == ".rs")
    constants = {"wire:no-terminator": "WIRE_NO_TERMINATOR", "wire:dangling-codeword": "WIRE_DANGLING_CODEWORD",
                 "wire:codebook-mismatch": "WIRE_CODEBOOK_MISMATCH"}
    for name in EMITTED:
        assert f'causes.NAMES["{name}"]' in python, f"no Python decoder emits {name}"
        assert f"causes::{constants[name]}" in rust, f"no Rust decoder emits {name}"


def test_symbol_overflow_still_has_no_emitter():
    """Cause 50 is a wire integer beyond the CELL range, which the kernel decode plane and the dissector
    check at u16 against a frame's own cells. No Python or Rust decoder here is handed a cell range: the
    receipt cause is a byte of the receipt, the concentrator's registry is a field count, and a reading
    integer beyond 64 bits is a width the Rust crate refuses and Python carries (DIVERGENCES.md), none of which
    is the cell range. Whoever gives a decoder a cell range adds the emitter, the corpus cases and a change to
    this test in the same commit."""
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        for name in NO_EMITTER:
            assert name not in text, f"{path.relative_to(REPO)} names {name}, which has no emitter by decision"
        assert "WIRE_SYMBOL_OVERFLOW" not in text, f"{path.relative_to(REPO)} emits cause 50, which has no emitter by decision"
