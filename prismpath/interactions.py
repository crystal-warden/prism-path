"""The 'glass window' — an append-only JSONL log of every model interaction.

Written at the three tap points where a prompt+output crosses the model boundary:
  - served `chat()`            (run_sprint.py)   kind="served"
  - swarm  `dispatch()`        (hermes_swarm.py) kind="swarm"
  - cecli  `_cecli_run()`      (run_sprint.py)   kind="cecli"

The swarm_exporter renders this into a polished live view. Everything here is BEST-EFFORT and
thread-safe: a logging failure must never propagate into (and kill) an unattended sprint.

Output path resolution: $SWARM_INTERACTIONS, else $SPRINT_PROJ/interactions.jsonl,
else $SWARM_PROJ/interactions.jsonl, else ./interactions.jsonl.
"""
import json
import os
import threading
import time

_LOCK = threading.Lock()
_PHASE = "init"


def set_phase(p: str):
    """Coarse pipeline phase (architect/ideate/build/fix/review/...) stamped onto events."""
    global _PHASE
    if p:
        _PHASE = str(p)


def _path() -> str:
    p = os.environ.get("SWARM_INTERACTIONS")
    if p:
        return p
    proj = os.environ.get("SPRINT_PROJ") or os.environ.get("SWARM_PROJ")
    return os.path.join(proj, "interactions.jsonl") if proj else "interactions.jsonl"


def record(kind: str, role: str, prompt: str, output: str, phase: str = "", dur_ms: int = 0, **meta):
    """Append one interaction event as a JSON line. Never raises."""
    try:
        ev = {
            "ts": round(time.time(), 3),
            "kind": kind,
            "role": role or "",
            "phase": phase or _PHASE,
            "dur_ms": int(dur_ms),
            "prompt": prompt or "",
            "output": output or "",
            "prompt_len": len(prompt or ""),
            "output_len": len(output or ""),
        }
        ev.update(meta)
        line = json.dumps(ev, ensure_ascii=False)
        with _LOCK:
            with open(_path(), "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception:
        pass  # a glass-window write must never break a sprint
