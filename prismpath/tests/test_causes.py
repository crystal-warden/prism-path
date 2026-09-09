# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The cause code registry referee: structural integrity, frozen values, and the binding to
reality — every refusal string the codebase actually emits must have a registry entry, parsed
from the emitting source itself where practical, so the registry cannot silently drift from
the code it describes."""
import re
from pathlib import Path

from prismpath.kernel import causes

REPO = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------------------- structure
def test_codes_and_names_unique():
    codes = [c for c, *_ in causes._REGISTRY]
    names = [n for _c, n, *_ in causes._REGISTRY]
    assert len(codes) == len(set(codes))
    assert len(names) == len(set(names))
    assert causes.CAUSE_NONE not in codes          # 0 is reserved for "clean decision"


def test_codes_fit_one_byte():
    assert all(1 <= c <= 255 for c, *_ in causes._REGISTRY)


def test_classes_are_the_declared_set():
    assert {k for _c, _n, k, _d in causes._REGISTRY} == {
        "authority", "envelope", "routing", "wire", "state"}


def test_lookups_round_trip():
    for c, n, k, _d in causes._REGISTRY:
        assert causes.code(n) == c
        assert causes.name(c) == n
        assert causes.cause_class(c) == k == causes.cause_class(n)
    assert causes.name(0) is None and causes.code("no-such-cause") is None


# ---------------------------------------------------------------------------- frozen values
def test_registry_frozen():
    """Append-only means this hash changes ONLY when rows are appended. If this test fails
    without an append, a shipped (code, name, class) was altered — that is the defect."""
    assert causes.registry_sha256() == (
        "e7f89a603c6fa5f02246d7b8f574303b42dcdb1bae0b4c4abaf6aaea0843a109")


# ------------------------------------------------------------------- binding to the codebase
def test_verify_pack_failure_strings_are_registered():
    """Every `return False, ["..."]` failure string in policy_pack's verifier maps to a
    registry name (the parameterized count-mismatch matches its base name)."""
    src = (REPO / "prismpath" / "policy_pack.py").read_text()
    emitted = set(re.findall(r'return False, \[f?"([a-z0-9:-]+)', src))
    emitted.discard("")                                     # the generic str(e) return
    for s in emitted:
        base = s.rstrip(":")
        assert causes.code(base) is not None, f"verifier emits {s!r}, registry lacks {base!r}"


def test_wire_cause_strings_are_registered():
    """The wire modules' emitted causes (prismpath/telemetry replay + concentrator, gated by
    their own referees) appear verbatim in the registry."""
    for s in ("replay-duplicate", "replay-stale",
              "concentrator-unknown-stream", "concentrator-truncated"):
        assert causes.code(s) is not None


def test_engine_stop_states_are_mapped():
    for stop, c in causes.ENGINE_STOP_TO_CAUSE.items():
        assert causes.name(c) is not None, f"engine stop {stop!r} maps to unknown code {c}"
    assert set(causes.ENGINE_STOP_TO_CAUSE) == {
        "stuck", "needs_human", "max_steps", "contract_violation"}
