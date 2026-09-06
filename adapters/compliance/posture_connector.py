#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Posture ingest connector — layer 3, the bridge from a scanned machine posture to deterministic
assessment.

A "posture" is a normalized bundle of machine-readable configuration facts plus provenance, produced
by a scanner adapter (Prowler, Steampipe, osquery, Lynis, InSpec, ...) or a configuration export.
This connector turns a posture into per-control assessment requests and runs them through the
adapter's comparator adjudicator, so a whole machine's covered controls are graded deterministically,
from one scan, with no model in the loop.

Do not build scanners; ingest them. Each scanner adapter has one job: emit this posture schema. The
mapping from a scanner's finding ids to fact keys is the adapter's content; this connector is
source-agnostic.

Posture schema:
    {
      "boundary": "human description of the assessed system or host",
      "host": "hostname (optional)",
      "provenance": {"source": "...", "collector": "...", "collected_at": "ISO-8601"},
      "facts": { "<fact_key>": <value>, ... }
    }

Fail-closed throughout: a control is graded here only when every one of its objectives is decidable
from the posture's facts (see deterministic_checks). Controls the posture cannot fully decide are
reported as `deferred` (they need the LLM adjudicator or more facts), never assumed satisfied.
"""
import os
import json

import compliance_adapter as _ca
import deterministic_checks as _dc

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(HERE, "posture_samples")


def load_posture(path):
    return json.load(open(path))


def load_sample(name="example_host"):
    return load_posture(os.path.join(SAMPLE_DIR, name + ".json"))


def _resolve_get_control(get_control):
    return get_control or _ca.get_control


def machine_checkable_controls(get_control=None):
    """Every control the comparator adjudicator CAN decide (all objectives have a registered check),
    independent of any posture. This is the coverage scanner adapters should target with their facts."""
    gc = _resolve_get_control(get_control)
    out = []
    for cid in _ca._catalog()["controls"]:
        try:
            if _dc.machine_checkable(gc(cid)):
                out.append(cid)
        except KeyError:
            continue
    return sorted(out)


def assessable_controls(facts, get_control=None):
    """The controls this posture's facts fully decide (a deterministic determination is available)."""
    gc = _resolve_get_control(get_control)
    req = {"facts": facts or {}}
    return [cid for cid in machine_checkable_controls(get_control)
            if _dc.adjudicate_deterministic(gc(cid), req) is not None]


def required_facts(get_control=None):
    """The fact keys the machine-checkable controls read, grouped by control — what a scanner adapter
    must supply for full coverage. Derived from the check registry so it never drifts from the checks."""
    gc = _resolve_get_control(get_control)
    out = {}
    for cid in machine_checkable_controls(get_control):
        out[cid] = sorted({_dc.FACT_KEYS[o["id"]] for o in gc(cid)["objectives"]
                           if o["id"] in _dc.FACT_KEYS})
    return out


def assess(posture, out_dir=None, get_control=None):
    """Grade every control this posture can fully decide, deterministically. Returns per-control
    determinations, the controls deferred for want of facts, and a status tally. Writes finding/POA&M
    records to out_dir when given."""
    gc = _resolve_get_control(get_control)
    facts = posture.get("facts", {}) or {}
    boundary = posture.get("boundary") or posture.get("host") or "(unspecified)"
    provenance = posture.get("provenance", {})

    assessable = assessable_controls(facts, get_control)
    deferred = [c for c in machine_checkable_controls(get_control) if c not in assessable]

    results = []
    tally = {"met": 0, "partially-met": 0, "not-met": 0}
    for cid in assessable:
        control = gc(cid)
        req = {"control_id": cid, "boundary": boundary, "facts": facts, "provenance": provenance}
        det = _ca.adjudicate(control, req)          # deterministic: every objective decidable here
        tally[det["status"]] = tally.get(det["status"], 0) + 1
        results.append({"control_id": cid, "title": control["title"],
                        "status": det["status"], "method": det.get("method"),
                        "unmet_objective_ids": det.get("unmet_objective_ids", [])})
        if out_dir:
            _ca.write_result(control, req, det, out_dir)

    return {"boundary": boundary, "provenance": provenance, "assessed": len(results),
            "deferred": deferred, "tally": tally, "results": results}
