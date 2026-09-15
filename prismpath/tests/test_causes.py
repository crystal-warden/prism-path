# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The cause code registry referee: structural integrity, frozen values, and the binding to
reality — every refusal string the codebase actually emits must have a registry entry, parsed
from the emitting source itself where practical, so the registry cannot silently drift from
the code it describes."""
import re
from pathlib import Path

from prismpath.hotswap import policy_pack
from prismpath.kernel import causes

REPO = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------- structure
def test_codes_and_names_unique():
    codes = [code for code, *_ in causes._REGISTRY]
    names = [name for _c, name, *_ in causes._REGISTRY]
    assert len(codes) == len(set(codes))
    assert len(names) == len(set(names))
    assert causes.CAUSE_NONE not in codes          # 0 is reserved for "clean decision"


def test_codes_fit_one_byte():
    assert all(1 <= code <= 255 for code, *_ in causes._REGISTRY)


def test_classes_are_the_declared_set():
    assert {cause_class for _c, _n, cause_class, _d in causes._REGISTRY} == {
        "authority", "envelope", "routing", "wire", "state"}


def test_lookups_round_trip():
    for code, name, cause_class, _d in causes._REGISTRY:
        assert causes.code(name) == code
        assert causes.name(code) == name
        assert causes.cause_class(code) == cause_class == causes.cause_class(name)
    assert causes.name(0) is None and causes.code("no-such-cause") is None


# ---------------------------------------------------------------------------- frozen values
def test_registry_frozen():
    """Append-only means this hash changes ONLY when rows are appended. If this test fails
    without an append, a shipped (code, name, class) was altered — that is the defect."""
    assert causes.registry_sha256() == (
        "74f1b33c52f426159612c9f16e32e5f798939715fe212001b726b89ef1125ffe")


# ------------------------------------------------------------------- binding to the codebase
# A registry name is `class:detail`. A parameterized emitter appends a second `:<detail>` the
# registry does not carry, so the pattern deliberately stops at the second colon.
_CAUSE_NAME = r"([a-z]+:[a-z0-9-]+)"


def _verifier_source() -> str:
    """The pack verifier's own text, resolved through the module object: `prismpath/policy_pack.py`
    is now a deprecation shim, so path arithmetic from causes.py reads the wrong file and the
    binding assertions below pass over an empty string."""
    return Path(policy_pack.__file__).read_text()


def test_verify_pack_failure_strings_are_registered():
    """Every `return False, ["..."]` failure string in policy_pack's verifier maps to a
    registry name (the parameterized count-mismatch matches its base name)."""
    emitted = set(re.findall(r'return False, \[f?"' + _CAUSE_NAME, _verifier_source()))
    assert emitted, "the verifier source parsed to no refusal strings at all"
    for emitted_name in emitted:
        assert causes.code(emitted_name) is not None, f"verifier emits {emitted_name!r} unregistered"


def test_image_and_envelope_refusal_strings_are_registered():
    """The structural half of the verifier (read_ppt_header, validate_image, load_envelope,
    check_envelope) refuses with free strings shaped exactly like registry names. They are rows,
    so a refusal that reaches a receipt carries a cause code and not only prose."""
    src = _verifier_source()
    emitted = set(re.findall(r'reasons\.append\(f?"' + _CAUSE_NAME, src))
    emitted |= set(re.findall(r'raise ValueError\("' + _CAUSE_NAME + r'"\)', src))
    emitted |= set(re.findall(r'return None, \[f?"' + _CAUSE_NAME, src))
    assert len(emitted) >= 19, f"expected the whole structural set, parsed {sorted(emitted)}"
    for emitted_name in emitted:
        assert causes.code(emitted_name) is not None, f"verifier emits {emitted_name!r} unregistered"


def test_wire_cause_strings_are_registered():
    """The wire modules' emitted causes (prismpath/telemetry replay + concentrator, gated by
    their own referees) appear verbatim in the registry."""
    for wire_cause in ("replay-duplicate", "replay-stale",
              "concentrator-unknown-stream", "concentrator-truncated"):
        assert causes.code(wire_cause) is not None


def test_engine_stop_states_are_mapped():
    for stop, code in causes.ENGINE_STOP_TO_CAUSE.items():
        assert causes.name(code) is not None, f"engine stop {stop!r} maps to unknown code {code}"
    assert set(causes.ENGINE_STOP_TO_CAUSE) == {
        "stuck", "needs_human", "max_steps", "contract_violation"}
