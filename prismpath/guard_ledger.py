"""guard_ledger.py — wire guard verdicts into the attested trail.

This is where the onion's two halves meet: the **security** half (`guard.py`) decides, the
**observability** half (`audit_log.py`, `ledger_airgap.py`) records what it decided and under which
policy. Neither re-implements the other — per `adapters/ADAPTER_GUIDE.md` invariant 4, attestation
reuses the core.

WHAT A RECORDED VERDICT BINDS
-----------------------------
Each entry carries the decision *and* `policy_hash`, which covers both the contributing policy
documents and the normalization tables. So the trail answers not merely "was this denied?" but
"**which rules and which folding** produced that answer" — the C1 compensation the OTS spec calls
*bind the logic, not just the output*. A later change to a rule or a fold changes the hash, and the
old entries remain attributable to the version that actually ran.

Allowed verdicts are recorded too, not only denials. A trail that only contains refusals cannot
distinguish "the guard ran and permitted this" from "the guard never ran", which is exactly the
question an audit asks.

ON THE PROMPT TEXT (OTS spec §6 C4)
-----------------------------------
A hash of short, guessable text can be brute-forced by whoever holds the hash — "how do I kill
myself" has a tiny candidate space. So a text digest is recorded **only when a secret is supplied**,
as an HMAC. With no secret, no digest is written at all: the default refuses to create the leak
rather than making it opt-out. With a secret, an auditor holding both the text and the secret can
confirm a specific input produced a specific verdict, while the trail alone reveals neither.

WHAT THIS IS NOT *(vocabulary, per the standing rule)*
------------------------------------------------------
This produces an **attested, auditable** trail. It is **not** tamper-evident against an adversary
with filesystem access, because the underlying log is append-only by convention rather than by
construction — the same limitation `audit_log.py` states about itself and `SPEC_ledger_opentimestamps.md`
§1 states about the un-anchored ledger. The word "cryptographic" does not belong in any description
of this until OTS anchoring ships and a stamp→upgrade→verify round-trip has passed.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Callable, Optional

from prismpath.audit_log import AuditLog
from prismpath.guard import Guard, Verdict
from prismpath.ledger_airgap import provenance_manifest

__all__ = ["verdict_recorder", "attest_verdicts", "VERDICT_ACTION"]

#: The action name every guard verdict is logged under, so the trail is filterable.
VERDICT_ACTION = "guard.verdict"


def _text_digest(text: str, secret: Optional[bytes]) -> Optional[str]:
    """HMAC of the text, or None when no secret is available.

    Deliberately returns None rather than falling back to a bare hash: a plain digest of a short
    prompt is recoverable by brute force, so the safe default is to record nothing about the text.
    """
    if secret is None or text is None:
        return None
    return hmac.new(secret, text.encode("utf-8"), hashlib.sha256).hexdigest()


def verdict_recorder(
    log: AuditLog,
    guard: Guard,
    *,
    secret: Optional[bytes] = None,
    actor: str = "guard",
    gate_id: Optional[str] = None,
) -> Callable[[Verdict], None]:
    """Build the `on_verdict` callback `guard.guarded_exchange` expects.

    Usage keeps the security half unaware of the observability half — the guard emits verdicts, this
    decides what is worth keeping:

        recorder = verdict_recorder(log, guard, secret=device_secret)
        guarded_exchange(guard, text, call_model, on_verdict=recorder)
    """
    policy_hash = guard.policy_hash

    def record(verdict: Verdict, text: Optional[str] = None) -> None:
        data = {
            "direction": verdict.direction,
            "allowed": verdict.allowed,
            # Binds WHICH rules and WHICH normalization produced this, not just the outcome.
            "policy_hash": policy_hash,
            "gate_id": gate_id,
        }
        if not verdict.allowed:
            data.update(
                rule=verdict.rule,
                policy=verdict.policy,
                citation=verdict.citation,
                precedence=verdict.precedence,
            )
        digest = _text_digest(text, secret) if text is not None else None
        if digest:
            data["text_hmac"] = digest
        log.append(actor, VERDICT_ACTION, data)

    return record


def attest_verdicts(log: AuditLog, guard: Guard, label: str, *, gate_id: Optional[str] = None) -> dict:
    """Produce a provenance manifest over the guard verdicts recorded so far.

    Reuses `ledger_airgap.provenance_manifest` rather than inventing a second manifest format, so a
    guard attestation is verifiable by the same tooling as every other attested decision in the
    system. The manifest binds `policy_hash`, so "which safety policy ran" travels with the record.

    The `root` is the audit log's own marker. In the open release that is a count rather than a
    Merkle root — stated plainly here because a caller might otherwise assume more from the field
    name than the log actually provides.
    """
    ingestion = [
        e["id"] for e in log.events if e.get("action") == VERDICT_ACTION
    ]
    return provenance_manifest(
        root_hex=log.current_root(),
        label=label,
        policy_hash=guard.policy_hash,
        gate_id=gate_id,
        ingestion_hashes=ingestion,
    )
