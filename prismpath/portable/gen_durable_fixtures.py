"""Freeze cross-language fixtures for the DURABLE layer (checkpoint/resume + attestation
manifests) so the Rust port is gated against what the Python reference actually produces —
measured, not asserted (the same contract as predicates.json / spiral_fusion.json).

    python prismpath/portable/gen_durable_fixtures.py   ->  conformance/durable.json

Frozen here:
  * canonical  — objects with their exact `json.dumps(sort_keys=True)` byte layouts (compact and
    spaced separators): the encoding manifest hashes and pack signatures are computed over.
  * manifests  — provenance + override manifests built from fixed inputs (created injected for
    determinism), with their content-address hashes; a tampered copy that must verify False.
  * salt       — HMAC-SHA256 leaf salting vectors.
  * checkpoints — scenarios run through the REAL run_durable/resume with scripted agents; the
    sidecar JSON is frozen with `flow_path`/`saved_at` dropped (host-specific), `flow_hash` kept
    (deterministic over the flow text).
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from prismpath import ledger_airgap as la          # noqa: E402
from prismpath.checkpoint import run_durable, resume, load_checkpoint  # noqa: E402

OUT = HERE / "conformance" / "durable.json"

# ------------------------------------------------------------------ canonical JSON cases
_CANONICAL_OBJS = [
    {"b": 1, "a": 2},
    {"z": None, "a": True, "m": False},
    {"nested": {"y": [1, 2, {"k": "v"}], "x": "s"}},
    {"text": 'quote " backslash \\ newline \n tab \t', "n": -5},
    {"unicode": "café — ☕ 𝄞", "ascii": "plain"},
    {"floats": [1.5, 2.0, -0.25], "int": 3},
    {"empty_list": [], "empty_obj": {}, "empty_str": ""},
]

# ------------------------------------------------------------------------ checkpoint flows
_FLOW_HUMAN = """---
name: fx_human
start: triage
---
## triage
Decide.
-> fix: when done
-> escalate: when broken
## fix
Repair it.
-> close: always
## escalate
Hand off.
-> close: always
## close
Done.
"""

_FLOW_EVENT = """---
name: fx_event
start: kickoff
---
## kickoff
Start the job.
-> await_result: always
## await_result
Wait for the callback.
-> publish: on event ready
-> giveup: on timeout
## publish
Ship it.
## giveup
Abandon.
"""

_FLOW_CRASH = """---
name: fx_crash
start: ingest
---
## ingest
Take the input.
-> work: always
## work
Do the thing.
-> done: when ok
## done
Finished.
"""


def _scripted(script):
    used = {}

    def agent(node, _instruction, _state):
        seq = script.get(node)
        if seq is None:
            return {"text": node}
        i = used.get(node, 0)
        used[node] = i + 1
        outcome = seq[min(i, len(seq) - 1)]
        if isinstance(outcome, dict) and "__raise__" in outcome:
            raise RuntimeError(outcome["__raise__"])
        return outcome

    return agent


def _norm(cp: dict) -> dict:
    cp = dict(cp)
    cp.pop("flow_path", None)
    cp.pop("saved_at", None)
    return cp


def _scenarios(tmp: Path) -> list:
    out = []

    # s1 — plain run to terminal
    f1 = tmp / "fx_terminal.md"; f1.write_text(_FLOW_CRASH)
    c1 = tmp / "fx_terminal.ckpt.json"
    s1_script = {"ingest": [{"text": "in"}], "work": [{"text": "ok done", "ok": True}]}
    r1 = run_durable(str(f1), _scripted(s1_script), str(c1))
    out.append({"name": "terminal", "flow": _FLOW_CRASH, "script": s1_script,
                "final": {"path": r1.path, "stopped": r1.stopped},
                "ckpt": _norm(load_checkpoint(str(c1)))})

    # s2 — needs_human suspension, then resume with choose
    f2 = tmp / "fx_human.md"; f2.write_text(_FLOW_HUMAN)
    c2 = tmp / "fx_human.ckpt.json"
    s2_script = {"triage": [{"needs_human": True, "reason": "ambiguous"}],
                 "fix": [{"text": "repaired"}]}
    r2 = run_durable(str(f2), _scripted(s2_script), str(c2))
    ck2 = _norm(load_checkpoint(str(c2)))
    r2b = resume(str(c2), _scripted(s2_script), choose="fix")
    out.append({"name": "needs_human_choose", "flow": _FLOW_HUMAN, "script": s2_script,
                "suspended": {"path": r2.path, "stopped": r2.stopped}, "ckpt": ck2,
                "resume": {"choose": "fix"},
                "final": {"path": r2b.path, "stopped": r2b.stopped},
                "ckpt_after": _norm(load_checkpoint(str(c2)))})

    # s3 — waiting suspension, then resume with the event
    f3 = tmp / "fx_event.md"; f3.write_text(_FLOW_EVENT)
    c3 = tmp / "fx_event.ckpt.json"
    s3_script = {"kickoff": [{"text": "started"}], "await_result": [{"wait": True}],
                 "publish": [{"text": "shipped"}]}
    r3 = run_durable(str(f3), _scripted(s3_script), str(c3))
    ck3 = _norm(load_checkpoint(str(c3)))
    r3b = resume(str(c3), _scripted(s3_script), event="ready")
    out.append({"name": "waiting_event", "flow": _FLOW_EVENT, "script": s3_script,
                "suspended": {"path": r3.path, "stopped": r3.stopped}, "ckpt": ck3,
                "resume": {"event": "ready"},
                "final": {"path": r3b.path, "stopped": r3b.stopped},
                "ckpt_after": _norm(load_checkpoint(str(c3)))})

    # s4 — crash mid-run (agent raises, no error edge), then resume idempotently
    f4 = tmp / "fx_crash.md"; f4.write_text(_FLOW_CRASH)
    c4 = tmp / "fx_crash.ckpt.json"
    crash_script = {"ingest": [{"text": "in"}], "work": [{"__raise__": "worker died"}]}
    try:
        run_durable(str(f4), _scripted(crash_script), str(c4))
        raise SystemExit("crash scenario did not crash")
    except RuntimeError:
        pass
    ck4 = _norm(load_checkpoint(str(c4)))
    fixed_script = {"ingest": [{"text": "in"}], "work": [{"text": "ok now", "ok": True}]}
    r4b = resume(str(c4), _scripted(fixed_script))
    out.append({"name": "crash_resume", "flow": _FLOW_CRASH, "script": crash_script,
                "ckpt": ck4, "resume": {"script": fixed_script},
                "final": {"path": r4b.path, "stopped": r4b.stopped},
                "ckpt_after": _norm(load_checkpoint(str(c4)))})

    return out


def main() -> int:
    root = "b" * 64
    prior = la.provenance_manifest(root, "demo", policy_hash="sha256:deadbeef",
                                   gate_id="wazuh_triage@v3",
                                   ingestion_hashes=["sha256:aa", "sha256:bb"],
                                   knowledge_base_hash="sha256:kb26e3")
    prior["created"] = "2026-08-12T00:00:00Z"          # re-pin created deterministically…
    body = json.dumps({k: prior[k] for k in prior if k != "manifest_hash"}, sort_keys=True).encode()
    import hashlib
    prior["manifest_hash"] = hashlib.sha256(body).hexdigest()   # …and re-address

    override = la.override_manifest(prior, "auditor:jsmith", "compensating control accepted",
                                    "c" * 64)
    override["created"] = "2026-08-12T00:00:01Z"
    body = json.dumps({k: override[k] for k in override if k != "manifest_hash"}, sort_keys=True).encode()
    override["manifest_hash"] = hashlib.sha256(body).hexdigest()

    tampered = dict(prior)
    tampered["root"] = "e" * 64                                  # bound field edited post-address

    assert la.verify_manifest(prior) and la.verify_manifest(override)
    assert not la.verify_manifest(tampered)

    with tempfile.TemporaryDirectory(prefix="cw_durable_fx_") as td:
        scenarios = _scenarios(Path(td))

    doc = {
        "version": 1,
        "note": "Cross-language durable-layer fixtures, generated by the Python reference. "
                "The Rust port must reproduce every entry (canonical bytes exactly; checkpoints "
                "semantically with flow_path/saved_at dropped).",
        "canonical": [{"obj": o,
                       "compact": json.dumps(o, sort_keys=True, separators=(",", ":")),
                       "spaced": json.dumps(o, sort_keys=True)} for o in _CANONICAL_OBJS],
        "manifests": {"provenance": prior, "override": override, "tampered": tampered},
        "salt": [{"leaf": hashlib.sha256(b"logon success user=admin").hexdigest(),
                  "secret": "enclave-secret",
                  "expected": la.salt_leaf(hashlib.sha256(b"logon success user=admin").hexdigest(),
                                           "enclave-secret")},
                 {"leaf": "0" * 64, "secret": "s2", "expected": la.salt_leaf("0" * 64, "s2")}],
        "checkpoints": scenarios,
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"wrote {OUT}  ({len(_CANONICAL_OBJS)} canonical, {len(scenarios)} checkpoint scenarios)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
