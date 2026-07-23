#!/usr/bin/env python3
"""Deferral / Resumption port (CORE) — suspend a unit-of-work and resume it later.

Domain-neutral: human-in-the-loop review, missing-evidence discovery, or any handoff where automated
flow must PAUSE, route to a human or client, and RESUME without losing state or breaking attestation.
The core owns suspend/resume + state integrity; an ADAPTER decides WHERE work queues and HOW the actor
interacts (a review UI, a ticket, an evidence-request email). This module is the port interface + a
file-backed reference store. The resume of a *review* resolution pairs with
`ledger_airgap.override_manifest` so a human override is attested immutably; the resume of an
*evidence* resolution re-enters the flow with new inputs. No LLM, no domain vocabulary.
"""
import os, json, hashlib, datetime


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DeferralStore:
    """The port. A backend implements defer / pending / get / resume."""
    def defer(self, unit_id, reason, state, prior_output=None): raise NotImplementedError
    def pending(self): raise NotImplementedError
    def get(self, unit_id): raise NotImplementedError
    def resume(self, unit_id, resolution, actor): raise NotImplementedError


class FileDeferralStore(DeferralStore):
    """v1 reference adapter: one JSON per deferred unit under a directory."""
    def __init__(self, dir_):
        self.dir = dir_; os.makedirs(dir_, exist_ok=True)

    def _path(self, unit_id):
        return os.path.join(self.dir, hashlib.sha256(unit_id.encode()).hexdigest()[:16] + ".json")

    def defer(self, unit_id, reason, state, prior_output=None):
        rec = {"unit_id": unit_id, "reason": reason, "state": state, "prior_output": prior_output,
               "status": "pending", "deferred_at": _now(), "resolution": None, "actor": None, "resolved_at": None}
        json.dump(rec, open(self._path(unit_id), "w"), indent=1)
        return rec

    def get(self, unit_id):
        p = self._path(unit_id)
        return json.load(open(p)) if os.path.exists(p) else None

    def pending(self):
        out = []
        for f in sorted(os.listdir(self.dir)):
            if f.endswith(".json"):
                r = json.load(open(os.path.join(self.dir, f)))
                if r.get("status") == "pending":
                    out.append(r)
        return out

    def resume(self, unit_id, resolution, actor):
        rec = self.get(unit_id)
        if not rec:
            raise KeyError(f"no deferred unit {unit_id}")
        if rec["status"] != "pending":
            raise ValueError(f"unit {unit_id} already {rec['status']}")
        rec.update(status="resolved", resolution=resolution, actor=actor, resolved_at=_now())
        json.dump(rec, open(self._path(unit_id), "w"), indent=1)
        return rec


if __name__ == "__main__":
    import tempfile, shutil
    d = tempfile.mkdtemp(prefix="cw_defer_")
    s = FileDeferralStore(d)
    s.defer("wu:001", reason="human_review: compensating control claimed",
            state={"flow": "x", "node": "adjudicate"}, prior_output={"status": "not-met"})
    out = {"deferred_pending": len(s.pending()) == 1}
    rec = s.resume("wu:001", resolution={"status": "met", "note": "compensating control accepted"}, actor="reviewer:jsmith")
    out["resume_records_actor"] = rec["actor"] == "reviewer:jsmith" and rec["status"] == "resolved"
    out["prior_output_preserved"] = rec["prior_output"]["status"] == "not-met"
    out["no_longer_pending"] = len(s.pending()) == 0
    print(json.dumps(out, indent=1))
    shutil.rmtree(d, ignore_errors=True)
