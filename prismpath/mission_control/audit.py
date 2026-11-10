# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The console's append-only audit log: every control action, Merkle committed.

One log object for the process, opened from `SETTINGS.audit_path`. Reach it as `audit.LOG` rather
than binding the object into another module, so a test that swaps the log (or an embedder that points
it elsewhere) is seen by every caller. When PRISMPATH_INSTANCE_KEY names an instance key, every control
action is followed by a signed root statement beside the log, as the policy host does.
"""
from prismpath.ledgers import audit_log
from prismpath.ledgers import root_statement

from .config import SETTINGS

ACTOR = "operator"                                            # single local operator; audit actor
LOG = audit_log.AuditLog(SETTINGS.audit_path, instance_key=root_statement.key_from_env(), sign_appends=True)


def record(action, data):
    """Append one control action under the single local operator. The action's data is what the operator
    sent (a sprint's configuration, a path), so it is content PrismPath did not write: a value that is not
    JSON is recorded as its string, and a float is refused, as `canon.content_bytes` refuses it, with an
    AuditWriteError that names the integer or decimal string to send instead."""
    from prismpath import canon
    from prismpath.kernel import canon2
    try:
        data = canon2.loads(canon.content_bytes(data, default=str))
    except canon.CanonicalError as error:
        raise audit_log.AuditWriteError(f"audit data has no canonical JSON form: {error}") from error
    return LOG.append(ACTOR, action, data)
