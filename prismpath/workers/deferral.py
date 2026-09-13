# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Deferral / Resumption port (CORE) — suspend a unit-of-work and resume it later.

Domain-neutral: human-in-the-loop review, missing-evidence discovery, or any handoff where automated
flow must PAUSE, route to a human or client, and RESUME without losing state or breaking attestation.
The core owns suspend/resume + state integrity; an ADAPTER decides WHERE work queues and HOW the actor
interacts (a review UI, a ticket, an evidence-request email). This module is the port interface + a
file-backed reference store. The resume of a *review* resolution pairs with
`ledger_airgap.override_manifest` so a human override is attested immutably; the resume of an
*evidence* resolution re-enters the flow with new inputs. No LLM, no domain vocabulary.
"""

import datetime
import hashlib
import json
import os
from abc import ABC
from abc import abstractmethod


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DeferralStore(ABC):
    """The port. A backend implements defer / pending / get / resume."""

    @abstractmethod
    def defer(self, unit_id, reason, state, prior_output=None):
        """Suspend `unit_id`, keeping the state and any prior output, and return the record."""
        raise NotImplementedError

    @abstractmethod
    def pending(self):
        """The records of every unit still suspended."""
        raise NotImplementedError

    @abstractmethod
    def get(self, unit_id):
        """One unit's record, or None when the store has never seen it."""
        raise NotImplementedError

    @abstractmethod
    def resume(self, unit_id, resolution, actor):
        """Close a suspended unit with the resolution and the actor, and return the record."""
        raise NotImplementedError


class FileDeferralStore(DeferralStore):
    """v1 reference adapter: one JSON per deferred unit under a directory."""

    def __init__(self, directory):
        self.dir = directory
        os.makedirs(directory, exist_ok=True)

    def _path(self, unit_id):
        return os.path.join(self.dir, hashlib.sha256(unit_id.encode()).hexdigest()[:16] + ".json")

    def _write(self, record):
        with open(self._path(record["unit_id"]), "w") as handle:
            json.dump(record, handle, indent=1)

    def defer(self, unit_id, reason, state, prior_output=None):
        rec = {
            "unit_id": unit_id,
            "reason": reason,
            "state": state,
            "prior_output": prior_output,
            "status": "pending",
            "deferred_at": _now(),
            "resolution": None,
            "actor": None,
            "resolved_at": None,
        }
        self._write(rec)
        return rec

    def get(self, unit_id):
        deferral_path = self._path(unit_id)
        if not os.path.exists(deferral_path):
            return None
        with open(deferral_path) as handle:
            return json.load(handle)

    def pending(self):
        out = []
        for filename in sorted(os.listdir(self.dir)):
            if not filename.endswith(".json"):
                continue
            with open(os.path.join(self.dir, filename)) as handle:
                record = json.load(handle)
            if record.get("status") == "pending":
                out.append(record)
        return out

    def resume(self, unit_id, resolution, actor):
        rec = self.get(unit_id)
        if not rec:
            raise KeyError(f"no deferred unit {unit_id}")
        if rec["status"] != "pending":
            raise ValueError(f"unit {unit_id} already {rec['status']}")
        rec.update(status="resolved", resolution=resolution, actor=actor, resolved_at=_now())
        self._write(rec)
        return rec
