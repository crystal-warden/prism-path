"""Live-gemma integration (opt-in: `pytest -m gemma`). Exercises the real adjudicator end-to-end
and asserts the emitted standards are schema-valid. Kept out of the default fast/deterministic run."""
import os
import pytest

pytestmark = pytest.mark.gemma

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.dirname(HERE)


def test_live_end_to_end_emits_valid_standards():
    import compliance_adapter as ca
    reqdir = os.path.join(ADAPTER, "requests")
    recs = []
    for f in sorted(os.listdir(reqdir)):
        req = ca.load_request(os.path.join(reqdir, f))
        c = ca.get_control(req["control_id"])
        det = ca.adjudicate(c, req)
        assert det is not None, f
        assert det["status"] in ("met", "partially-met", "not-met")
        recs.append(ca.result_record(c, req, det, ca.attest(c, req, det)))
    out = ca.emit_reports(recs, fmt="both")
    for name, r in out.items():
        assert r["valid"], (name, r["errors"][:3])


def test_rev3_adjudication_runs_end_to_end():
    """The adjudicator is catalog-agnostic: it runs against a Rev 3 control (22 objectives) too."""
    import compliance_adapter as ca
    ca.use_standard("nist_800171_r3")
    try:
        c = ca.get_control("3.1.1")                            # Rev 3 Account Management
        req = {"control_id": "3.1.1", "boundary": "CUI enclave", "evidence": [{"type": "config",
               "text": "Account management policy defines allowed/prohibited account types; accounts are "
                       "created, enabled, modified, and disabled via IAM with documented approvals; inactive "
                       "accounts auto-disable after 35 days; a monthly account review is evidenced in the SIEM."}]}
        det = ca.adjudicate(c, req)
        assert det is not None and det["status"] in ("met", "partially-met", "not-met")
    finally:
        ca.use_standard("nist_800171_r2")


@pytest.mark.parametrize("fname,expected", [
    ("req_3.1.11_met.json", "met"),
    ("req_3.1.5_notmet.json", "not-met"),
])
def test_unambiguous_bundles_land_on_expected_status(fname, expected):
    """The two clear-cut curated bundles should adjudicate deterministically (temperature 0)."""
    import compliance_adapter as ca
    req = ca.load_request(os.path.join(ADAPTER, "requests", fname))
    c = ca.get_control(req["control_id"])
    det = ca.adjudicate(c, req)
    assert det is not None and det["status"] == expected, (fname, det and det["status"])
