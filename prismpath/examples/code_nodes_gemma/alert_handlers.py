# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Code-node handlers for the mixed md + code-node demo (alert_router.md).

Importable by dotted path (a real module, no lambdas / __main__), so `prismpath.sandbox.SandboxRunner`
can load them into the bwrap subprocess. Each handler is a LEAF ACTION: it returns outcome fields and
decides nothing — the branching lives on the flow's edges.
"""
import re

CRITICAL = {"checkout", "payments", "auth", "api", "gateway"}


def parse(node, instruction, state):
    """Code node: pull `error_count` and `service` out of the raw alert text. Deterministic."""
    text = str(state.get("alert", ""))
    m = re.search(r"(\d+)\s*errors?", text, re.I)
    error_count = int(m.group(1)) if m else -1
    sm = re.search(r"service[=:\s]+([a-z0-9_-]+)", text, re.I)
    service = sm.group(1).lower() if sm else "unknown"
    return {"error_count": error_count, "service": service,
            "text": f"parsed service={service} error_count={error_count}"}


def decide(node, instruction, state):
    """Code node: the page/no-page call is DETERMINISTIC. It combines a code-derived field
    (`error_count` from `parse`) with a model-derived hint (`urgent`, from the Gemma `triage` node)
    under a fixed policy. Emits `page`; the flow's edges route on it."""
    outs = state.get("_outcomes", {})
    error_count = int(outs.get("parse", {}).get("error_count", -1))
    service = str(outs.get("parse", {}).get("service", "unknown"))
    urgent = bool(outs.get("triage", {}).get("urgent", False))
    critical = service in CRITICAL
    page = critical and (error_count >= 50 or urgent)
    severity = 1 if page else 2 if (critical or error_count >= 25 or urgent) else 3
    return {"severity": severity, "page": page,
            "text": f"severity={severity} page={page} "
                    f"(critical={critical}, error_count={error_count}, urgent={urgent})"}
