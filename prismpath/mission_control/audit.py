# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The console's append-only audit log: every control action, Merkle committed.

One log object for the process, opened from `SETTINGS.audit_path`. Reach it as `audit.LOG` rather
than binding the object into another module, so a test that swaps the log (or an embedder that points
it elsewhere) is seen by every caller.
"""
from prismpath.ledgers import audit_log

from .config import SETTINGS

ACTOR = "operator"                                            # single local operator; audit actor
LOG = audit_log.AuditLog(SETTINGS.audit_path)


def record(action, data):
    """Append one control action under the single local operator."""
    return LOG.append(ACTOR, action, data)
