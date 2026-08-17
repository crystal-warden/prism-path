# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Risk-controlled calibration tests (Area 1) — derive τ with a finite-sample guarantee (LTT/RCPS,
not conformal prediction) from labeled decisions."""
import pytest

from prismpath import calibrate
from prismpath.router import LLMRouter


def _rec(margin, correct):
    return {"margin": margin, "chosen": "a", "label": "a" if correct else "b"}


def test_wilson_lower_bounds():
    assert calibrate._wilson_lower(0, 0) == 1.0
    assert 0.0 <= calibrate._wilson_lower(8, 10) <= 0.8      # lower bound below point estimate 0.8
    assert calibrate._wilson_lower(100, 100) > 0.95          # all-correct, large n -> tight


def test_calibrate_picks_smallest_tau_meeting_bound():
    # low-margin decisions are often wrong; high-margin ones are right. A threshold should exist
    # that keeps only the confident (correct) ones.
    recs = ([_rec(0.02, False)] * 10 + [_rec(0.03, False)] * 5 +
            [_rec(0.10, True)] * 40 + [_rec(0.20, True)] * 40)
    cal = calibrate.calibrate(recs, alpha=0.1, confidence=0.95)
    assert cal["tau"] is not None and cal["tau"] >= 0.10     # excludes the wrong low-margin cluster
    # at the chosen τ, the lower bound clears the target
    at = next(p for p in cal["curve"] if p["tau"] == cal["tau"])
    assert at["acc_lower"] >= 1 - cal["alpha"]
    # the guarantee's width is surfaced at the top level (point vs certified lower bound + effective N)
    assert cal["tau_acc_lower"] == at["acc_lower"] and cal["tau_n_kept"] == at["n_kept"]
    assert cal["tau_accuracy"] >= cal["tau_acc_lower"] and cal["warning"] is None


def test_calibrate_ignores_unlabeled_and_empty():
    assert calibrate.calibrate([{"margin": 0.1}], alpha=0.05)["n"] == 0   # no label -> ignored
    assert calibrate.calibrate([], alpha=0.05)["tau"] == 0.0             # empty -> vacuously τ=0


def test_risk_controlled_router_uses_calibrated_tau(tmp_path):
    # enough samples for the 0.95 Wilson bound to clear 1−α at the confident threshold
    recs = [_rec(0.02, False)] * 20 + [_rec(0.30, True)] * 200
    cal = calibrate.calibrate(recs, alpha=0.05)
    assert cal["tau"] == 0.30
    r = calibrate.RiskControlledHybridRouter(LLMRouter(lambda p: "1"), calibration=cal)
    assert r.margin == cal["tau"] and r.alpha == 0.05 and r.escalate_all is False

    # round-trips through a file too
    p = str(tmp_path / "cal.json")
    calibrate.save_calibration(p, cal)
    r2 = calibrate.RiskControlledHybridRouter(LLMRouter(lambda p: "1"), calibration=p)
    assert r2.margin == cal["tau"]


def test_conformal_alias_still_resolves():
    # back-compat: the old name maps to the renamed class
    assert calibrate.ConformalHybridRouter is calibrate.RiskControlledHybridRouter


def test_router_escalates_all_and_warns_loudly_when_no_tau():
    cal = {"tau": None, "alpha": 0.05, "n": 5, "curve": [{"tau": 0.0}, {"tau": 0.4}]}
    with pytest.warns(RuntimeWarning, match="escalate EVERY decision"):
        r = calibrate.RiskControlledHybridRouter(LLMRouter(lambda p: "1"), calibration=cal)
    assert r.margin > 0.4 and r.escalate_all is True         # threshold above any real margin -> escalate all


def test_calibrate_surfaces_no_tau_and_low_n_warnings():
    # no threshold can meet the bound (all wrong) -> escalate-all warning
    none_cal = calibrate.calibrate([_rec(0.1, False)] * 40, alpha=0.05)
    assert none_cal["tau"] is None and "ESCALATE EVERY" in none_cal["warning"]
    # a τ exists but on tiny N (< MIN_EFFECTIVE_N) -> provisional warning (α loose enough that a
    # small all-correct sample clears the Wilson bound)
    low_n = calibrate.calibrate([_rec(0.3, True)] * 10, alpha=0.3)
    assert low_n["tau"] is not None and low_n["n"] < calibrate.MIN_EFFECTIVE_N
    assert "provisional" in low_n["warning"]
