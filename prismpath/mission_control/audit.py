# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The console's append-only audit log: every control action, Merkle committed, written before it acts.

One log object for the process, opened from `SETTINGS.audit_path`. Reach it as `audit.LOG` rather
than binding the object into another module, so a test that swaps the log (or an embedder that points
it elsewhere) is seen by every caller. When PRISMPATH_INSTANCE_KEY names an instance key, every event
is followed by a signed root statement beside the log, as the policy host does.

An action that changes something is two events. The intent (`record_intent`) is written before the
effect and names what was asked, with its inputs and content hashes; when it cannot be written the
effect does not happen. The result (`record_result`) is written after the effect, under the action's
name with `.result` appended, and names the intent by its index and leaf, so a result cannot be moved
onto another intent without breaking the tree. An intent with no result is an effect whose outcome the
console did not live to record. `audited` wraps an effect in both. An event with no effect of its own
(a refusal) is one event, written with `record`.

The actor is `console/<interface>/<session fingerprint>`: which of the three interfaces asked, and
which launch of the console, named by the fingerprint of its session token, never the token itself.
"""
import contextlib

from prismpath.ledgers import audit_log
from prismpath.ledgers import root_statement

from .config import SETTINGS

INTERFACES = ("authoring", "operating", "auditing")
RESULT_SUFFIX = ".result"
LOG = audit_log.AuditLog(SETTINGS.audit_path, instance_key=root_statement.key_from_env(), sign_appends=True)


class ResultUnrecorded(audit_log.AuditWriteError):
    """The effect ran after its intent was recorded, and its result could not be written. The log holds
    the intent with no result, which is what it says of an effect whose outcome is unknown."""


def actor_for(session, interface: str) -> str:
    """`console/<interface>/<fingerprint>` for a session (`session.Session`) and one of INTERFACES."""
    if interface not in INTERFACES:
        raise ValueError(f"unknown console interface {interface!r}; expected one of {', '.join(INTERFACES)}")
    if session is None:
        raise ValueError("an audit actor needs the console's session")
    return f"console/{interface}/{session.fingerprint}"


def actor(request, interface: str) -> str:
    """The actor for a request the session guard let through: the app's session, the route's interface."""
    return actor_for(getattr(request.app.state, "session", None), interface)


def _canonical(data):
    """The action's data is what the caller sent (a sprint's configuration, a path), so it is content
    PrismPath did not write: a value that is not JSON is recorded as its string, and a float is refused,
    as `canon.content_bytes` refuses it, with an AuditWriteError that names the integer or decimal
    string to send instead."""
    from prismpath import canon
    from prismpath.kernel import canon2
    try:
        return canon2.loads(canon.content_bytes(data, default=str))
    except canon.CanonicalError as error:
        raise audit_log.AuditWriteError(f"audit data has no canonical JSON form: {error}") from error


def record(action: str, data, actor: str) -> dict:
    """Append one event that is complete in itself, such as a refusal, which has no effect to follow."""
    return LOG.append(actor, action, _canonical(data))


def record_intent(action: str, data, actor: str) -> dict:
    """Append what is about to be done, before it is done. Raises AuditWriteError, and then the caller
    must not act."""
    return LOG.append(actor, action, _canonical(data))


def record_result(intent_event: dict, ok: bool, detail=None) -> dict:
    """Append the outcome of an intent, after the effect, under the intent's actor."""
    index = intent_event["idx"]
    leaf = LOG.leaves[index] if 0 <= index < len(LOG.leaves) else None
    data = {"intent": index, "intent_leaf": leaf, "ok": bool(ok), "outcome": "done" if ok else "failed",
            "detail": detail}
    return LOG.append(intent_event["actor"], intent_event["action"] + RESULT_SUFFIX, _canonical(data))


@contextlib.contextmanager
def audited(action: str, data, actor: str):
    """Record the intent, run the block, record the result. The block may set `outcome["detail"]` (and
    `outcome["ok"]`, for an effect that reports its own failure) for the result event. An exception from
    the block is recorded as a failed result, named by its type and message, and raised again."""
    intent = record_intent(action, data, actor)
    outcome = {"ok": True, "detail": None, "intent": intent}
    try:
        yield outcome
    except BaseException as error:
        detail = getattr(error, "detail", None) or str(error)
        _result_or_raise(intent, False, {"error": type(error).__name__, "message": str(detail)[:500]})
        raise
    _result_or_raise(intent, outcome["ok"], outcome["detail"])


def _result_or_raise(intent, ok, detail):
    try:
        record_result(intent, ok, detail)
    except audit_log.AuditWriteError as error:
        raise ResultUnrecorded(f"{intent['action']} ran, its result is not recorded: {error}") from error
