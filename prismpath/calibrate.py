"""calibrate.py — turn the escalation threshold δ into a *risk-controlled* τ with a guarantee (Area 1).

The margin (top-1 − top-2 similarity) is a confidence score; escalating to the LLM is abstention.
This is **risk-controlled selective classification**: given a calibration set of labeled routing
decisions, find the smallest threshold τ such that decisions the router does NOT escalate
(margin ≥ τ) are correct at rate ≥ 1−α — certified by a finite-sample (Wilson) *lower* bound, so
the guarantee holds beyond the calibration sample. δ becomes *derived*, not chosen.

This is **not conformal prediction** — there is no nonconformity-score quantile and no exchangeable
prediction-set construction. The method is a single-threshold instance of the Learn-Then-Test /
Risk-Controlling-Prediction-Sets family (Angelopoulos, Bates, et al.); the Wilson lower bound is the
finite-sample certificate. We use "risk-controlled selective escalation", not "conformal", by design.

Assumption (stated so it can be checked): the Wilson bound treats the calibration decisions as an
i.i.d.-ish sample of deployment routing. Mixing authored *test fixtures* (which are not deployment
traffic) with real routelogs weakens that — prefer deployment `prismpath label` records, or report the
two sources separately.

    recs = routelog.load_records("routes.jsonl")   # labeled by `prismpath label` or flow_test
    cal = calibrate(recs, alpha=0.05)               # -> {tau, n, tau_n_kept, tau_acc_lower, curve, ...}
    router = RiskControlledHybridRouter(LLMRouter(gen), calibration=cal)   # runtime = HybridRouter at τ
"""
from __future__ import annotations

import json
import math
import warnings
from typing import List, Optional

from prismpath.router import HybridRouter

_Z = {0.90: 1.6448536269514722, 0.95: 1.959963984540054, 0.99: 2.5758293035489004}


def _wilson_lower(k: int, n: int, confidence: float = 0.95) -> float:
    """High-probability lower bound on a binomial success rate (Wilson score interval). No scipy."""
    if n == 0:
        return 1.0
    z = _Z.get(confidence, 1.959963984540054)
    phat = k / n
    denom = 1 + z * z / n
    center = phat + z * z / (2 * n)
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return max(0.0, (center - half) / denom)


def _labeled(records: List[dict]):
    out = []
    for r in records:
        m, lab = r.get("margin"), r.get("label")
        if m is None or lab is None:
            continue
        out.append((float(m), r.get("chosen") == lab))
    return out


MIN_EFFECTIVE_N = 30   # below this the Wilson bound is wide enough that τ is barely trustworthy


def calibrate(records: List[dict], alpha: float = 0.05, confidence: float = 0.95) -> dict:
    """Return {tau, alpha, n, tau_n_kept, tau_acc_lower, curve, warning, ...}. `tau` is the smallest
    margin threshold whose non-escalated decisions are correct at rate ≥ 1−α under the Wilson lower
    bound; None if no threshold achieves it (⇒ the router escalates everything — surfaced in
    `warning`). `tau_acc_lower` is the certified lower bound at τ and `tau_n_kept` its effective N, so
    the *width* of the guarantee (point accuracy vs lower bound) is inspectable, not just the point."""
    labeled = _labeled(records)
    total = len(labeled)
    thresholds = [0.0] + sorted({m for m, _ in labeled})
    curve, tau, tau_row = [], None, None
    for t in thresholds:
        kept = [(m, c) for m, c in labeled if m >= t]
        n = len(kept)
        k = sum(1 for _, c in kept if c)
        acc = (k / n) if n else 1.0
        low = _wilson_lower(k, n, confidence)
        row = {"tau": round(t, 4), "n_kept": n,
               "accuracy": round(acc, 4), "acc_lower": round(low, 4),
               "escalation_rate": round(1 - n / total, 4) if total else 0.0}
        curve.append(row)
        if tau is None and low >= 1 - alpha:
            tau, tau_row = t, row
    warning = None
    if tau is None:
        warning = (f"no margin threshold reaches the ≥{1 - alpha:.0%} lower bound on n={total} "
                   f"labeled decisions — the router will ESCALATE EVERY decision (LLM-router "
                   f"economics). Collect more labels or relax alpha.")
    elif total < MIN_EFFECTIVE_N:
        warning = (f"only n={total} labeled decisions (< {MIN_EFFECTIVE_N}); the Wilson bound is "
                   f"wide and τ={tau} is weakly certified — treat as provisional.")
    return {"alpha": alpha, "confidence": confidence, "tau": tau, "n": total,
            "tau_n_kept": tau_row["n_kept"] if tau_row else 0,
            "tau_accuracy": tau_row["accuracy"] if tau_row else None,
            "tau_acc_lower": tau_row["acc_lower"] if tau_row else None,
            "warning": warning, "curve": curve}


def save_calibration(path, cal: dict) -> None:
    with open(path, "w") as f:
        json.dump(cal, f, indent=2)


def load_calibration(path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class RiskControlledHybridRouter(HybridRouter):
    """A HybridRouter whose escalation margin is the *risk-controlled* τ (from `calibrate`) rather
    than a hand-set δ — same runtime behavior, but the threshold carries a finite-sample guarantee
    (Learn-Then-Test / RCPS family; see the module docstring — this is NOT conformal prediction).
    Pass a calibration dict or a path. If τ is None (no threshold met the bound) it escalates EVERY
    decision — which reverts to LLM-router economics, so we `warn` loudly rather than fail silently."""
    def __init__(self, llm_router, calibration, alpha: Optional[float] = None,
                 min_score: float = 0.0, embed=None):
        cal = load_calibration(calibration) if isinstance(calibration, str) else calibration
        tau = cal.get("tau")
        self.escalate_all = tau is None
        if self.escalate_all:                            # nothing met the bound -> escalate all
            warnings.warn(
                "RiskControlledHybridRouter: calibration τ is None — no margin threshold met the "
                f"risk bound (n={cal.get('n')}); routing will escalate EVERY decision to the LLM "
                "(LLM-router cost/latency). Collect more labels or relax alpha.",
                RuntimeWarning, stacklevel=2)
            tau = max((p["tau"] for p in cal.get("curve", [])), default=1.0) + 1.0
        super().__init__(llm_router, margin=tau, min_score=min_score, embed=embed)
        self.alpha = alpha if alpha is not None else cal.get("alpha")
        self.calibration = cal


# Back-compat alias for the pre-rename name. Deprecated: the method is risk-controlled selective
# classification (LTT/RCPS), not conformal prediction. Prefer RiskControlledHybridRouter.
ConformalHybridRouter = RiskControlledHybridRouter
