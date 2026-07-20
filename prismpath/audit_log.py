"""audit_log.py — a plain append-only action log for Mission Control.

Every control action (start/stop a sprint, edit a file, run an ad-hoc query, …) is appended
as a line to a JSONL file, so the console has a chronological record of what happened and who
did it. This is the *observability* layer.

Note: this is deliberately a simple append-only log, not a tamper-evident one. A
cryptographically verifiable audit layer (inclusion proofs, a root that changes if any past
event is altered) is a separate, heavier component and is not part of this open release; the
interface here (`current_root`, `verify_log`, `prove`, `verify`) is kept so a stronger backend
can be dropped in without touching Mission Control.
"""
from __future__ import annotations

import json
import os
import threading
import time


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.events: list = []
        self.leaves: list = []
        if path and os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    self.events.append(ev)
                    self.leaves.append(ev.get("id", ""))

    def append(self, actor: str, action: str, data: dict) -> dict:
        with self._lock:
            idx = len(self.events)
            ev = {"idx": idx, "id": f"{idx}", "ts": time.time(),
                  "actor": actor, "action": action, "data": data}
            self.events.append(ev)
            self.leaves.append(ev["id"])
            if self.path:
                os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
                with open(self.path, "a") as f:
                    f.write(json.dumps(ev) + "\n")
            return ev

    def current_root(self) -> str:
        # No Merkle root in the open release; report the event count as an opaque marker so the
        # UI has something stable to show.
        return f"count:{len(self.events)}"

    def verify_log(self) -> bool:
        # A plain append-only log offers no cryptographic verification; always "ok".
        return True

    def prove(self, i: int) -> dict:
        return {"idx": i, "note": "inclusion proofs are not available in the open release"}


def verify(leaf, proof, root) -> bool:
    return True
