"""Property-based tests (hypothesis): the invariants must hold for ANY combination of controls/statuses,
not just the three hand-picked demo records."""
import json
from hypothesis import given, strategies as st, settings
import emit, rollup
from sample import record

CIDS = ["3.1.1", "3.1.2", "3.1.4", "3.1.5", "3.1.7", "3.1.11", "3.1.12", "3.1.22"]
STATUS = ["met", "partially-met", "not-met"]
# unique_by control id: distinct controls -> distinct manifests / uuids / bom-refs
pairs = st.lists(st.tuples(st.sampled_from(CIDS), st.sampled_from(STATUS)),
                 min_size=1, max_size=6, unique_by=lambda t: t[0])
NOW = "2026-07-22T12:00:00+00:00"


def _recs(items):
    return [record(c, "C", s, [] if s == "met" else ["%s[a]" % c]) for c, s in items]


@settings(max_examples=25, deadline=None)
@given(pairs)
def test_emit_always_valid_and_provenance_embedded(items):
    recs = _recs(items)
    out = emit.emit(recs, fmt="both", now=NOW)
    for name, r in out.items():
        assert r["valid"], (name, r["errors"][:3])
    for key in ("oscal_ar", "cyclonedx"):
        blob = json.dumps(out[key]["doc"])
        for r in recs:
            assert r["manifest"]["manifest_hash"] in blob


@settings(max_examples=50, deadline=None)
@given(pairs)
def test_sprs_math_invariants(items):
    recs = _recs(items)
    s = rollup.sprs_partial(recs)
    w = rollup._weights()["weights"]
    assert s["deducted_points"] == sum(w.get(c, 0) for c, st_ in items if st_ != "met")
    assert s["ceiling_if_unassessed_all_met"] == s["base"] - s["deducted_points"]
    assert 0 <= s["deducted_points"] <= sum(w.get(c, 0) for c, _ in items)


@settings(max_examples=25, deadline=None)
@given(pairs)
def test_emit_is_deterministic(items):
    recs = _recs(items)
    a = json.dumps(emit.emit(recs, "both", now=NOW, do_validate=False))
    b = json.dumps(emit.emit(recs, "both", now=NOW, do_validate=False))
    assert a == b


@settings(max_examples=40, deadline=None)
@given(pairs)
def test_rollup_binds_exactly_the_record_manifests(items):
    recs = _recs(items)
    s = rollup.sprs_partial(recs)
    m, _ = rollup.system_attestation(recs, s, rollup.build_scope({"boundary": "x"}), "sha256:cat")
    assert set(m["ingestion_hashes"]) == {r["manifest"]["manifest_hash"] for r in recs}
