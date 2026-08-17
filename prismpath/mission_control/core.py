# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control — the single-user engine.

The reference deployment's control plane, re-scoped to **proving + observability over flows** for one
local operator on loopback. This module is transport-agnostic: pure functions over a single followed
sprint's on-disk artifacts (`status.json` heartbeat, `interactions.jsonl` glass lens, checkpoints,
the audit log). The FastAPI routers in this package are thin adapters over these functions.

No multi-user identity, no chat, no model inference — PrismPath routes and proves; it does not serve
models. See docs/design/control-plane.md.
"""
import glob as _glob
import json
import os
import re
import subprocess
import threading
import time

from prismpath import audit_log
try:
    from prismpath.swarm_exporter import _fold                # reuse the prompt/output folder
except Exception:                                             # pragma: no cover
    from swarm_exporter import _fold


PKG_DIR = os.path.dirname(os.path.abspath(__file__))          # prismpath/mission_control/
PRISM_DIR = os.path.dirname(PKG_DIR)                          # prismpath/  (the old "HERE")
REPO_ROOT = os.path.dirname(PRISM_DIR)                        # repo root (run_sprint cwd)

PROJ = os.path.abspath(os.environ.get("MC_PROJ", "/tmp/demo"))
PORT = int(os.environ.get("MC_PORT", "9109"))
# SECURITY: loopback-only. MC can start/stop the swarm and edit flow files — never LAN-reachable.
HOST = os.environ.get("MC_HOST", "127.0.0.1")
AUDIT = audit_log.AuditLog(os.environ.get("MC_AUDIT", os.path.join(PRISM_DIR, "mission_audit.log")))
ACTOR = "operator"                                            # single local operator; audit actor

# Auto-discovery: MC follows whichever sprint is live, whoever started it (control tab / CLI / hand).
MC_SCAN = os.environ.get("MC_SCAN", "/tmp/*/status.json")     # glob(s), os.pathsep-separated
MC_REGISTRY = os.path.expanduser(os.environ.get("MC_REGISTRY", "~/.prismpath/sprints.json"))

# Resource caps for the single-user control plane. Flow files and checkpoints are small; refuse anything
# larger so a runaway read/write can't exhaust memory, and bound the file listing on a pathological tree.
MAX_FILE_BYTES = int(os.environ.get("MC_MAX_FILE_BYTES", str(4 * 1024 * 1024)))   # 4 MiB
MAX_TREE_ENTRIES = int(os.environ.get("MC_MAX_TREE_ENTRIES", "5000"))

# --- single-user state --------------------------------------------------------
# One operator, one followed-sprint state. `proc` is the sprint we launched (if any); `proj` is the
# directory we observe; `pinned` freezes auto-follow to a chosen sprint.
STATE = {"proc": None, "proj": PROJ, "cfg": {}, "pinned": False}
_PROC_LOCK = threading.Lock()        # guards launch (one sprint at a time)
_FILE_LOCK = threading.Lock()        # serializes flow-file writes


def _under(path, base):
    """True if `path` is `base` itself or nested inside it (the sandbox containment check)."""
    path, base = os.path.abspath(path), os.path.abspath(base)
    return path == base or path.startswith(base + os.sep)


def _safe(proj, rel):
    """Resolve `rel` against `proj`, refusing any path that escapes the project tree."""
    p = os.path.abspath(os.path.join(proj, rel))
    if not _under(p, proj):
        raise ValueError("path escapes project")
    return p


# ----------------------------------------------------------------- fs helpers
def file_tree(proj):
    out = []
    for dp, dns, fns in os.walk(proj):
        dns[:] = [d for d in dns if d not in (".git", "tools", "__pycache__", "last-good")]
        for fn in sorted(fns):
            if len(out) >= MAX_TREE_ENTRIES:
                return out                        # bound the listing on a pathological tree
            if fn.endswith((".js", ".mjs", ".html", ".css", ".json", ".md", ".txt", ".pdf")) and not fn.startswith("."):
                rel = os.path.relpath(os.path.join(dp, fn), proj)
                try:
                    stt = os.stat(os.path.join(dp, fn))
                    # float mtime (sub-second): a same-size rewrite within one wall-clock second must
                    # still change the signature, or the editor re-shows stale content.
                    out.append({"path": rel, "size": stt.st_size, "mtime": stt.st_mtime})
                except OSError:
                    pass
    return sorted(out, key=lambda f: f["path"])


def _registry_projs():
    try:
        with open(MC_REGISTRY, encoding="utf-8") as f:
            d = json.load(f)
        return list(d.keys()) if isinstance(d, dict) else list(d)
    except Exception:
        return []


def discover_sprints():
    """Every sprint on the box, found by its status.json heartbeat: scan globs + the registry (sprints
    self-announce on start) + the launch default. Freshest still-heartbeating one is 'active' — this is
    what lets MC follow a sprint started ANYWHERE without a restart."""
    projs = set()
    for pat in MC_SCAN.split(os.pathsep):
        for sp in _glob.glob(pat):
            projs.add(os.path.dirname(os.path.abspath(sp)))
    for p in _registry_projs():
        projs.add(os.path.abspath(os.path.expanduser(p)))
    projs.add(os.path.abspath(PROJ))
    now, out = time.time(), []
    for p in projs:
        sp = os.path.join(p, "status.json")
        try:
            age = now - os.path.getmtime(sp)
            d = json.load(open(sp, encoding="utf-8"))
        except Exception:
            continue
        out.append({"proj": p, "name": os.path.basename(p), "age": round(age, 1),
                    "running": age < 120 and not d.get("done"),
                    "iteration": d.get("iteration"), "valid": d.get("valid"), "done": d.get("done")})
    out.sort(key=lambda s: (not s["running"], s["age"]))      # running first, then freshest
    return out


def _sync_active(state):
    """Point state at the active sprint unless one is pinned. Called from the most-frequent poll so
    every view follows the live sprint within a tick."""
    if state.get("pinned"):
        return
    found = discover_sprints()
    if found:
        state["proj"] = found[0]["proj"]


def sprint_running(state):
    p = state["proc"]
    if p and p.poll() is None:
        return True
    # also detect an EXTERNALLY-launched run_sprint via its live status.json heartbeat
    sp = os.path.join(state["proj"], "status.json")
    try:
        st = json.load(open(sp))
        fresh = (time.time() - os.path.getmtime(sp)) < 120
        return bool(fresh and not st.get("done"))
    except Exception:
        return False


def start_sprint(cfg, state):
    """Launch a sprint. `cfg['unbuffered']` (default True) governs whether the child streams live
    (`python -u` / PYTHONUNBUFFERED) or batches — the buffered/unbuffered console toggle."""
    with _PROC_LOCK:
        if sprint_running(state):
            return {"ok": False, "error": "a sprint is already running"}
        proj = os.path.abspath(cfg.get("proj") or state["proj"])
        env = dict(os.environ)
        env.update({
            "SPRINT_PROJ": proj, "SPRINT_GATE": cfg.get("gate", "browser"),
            "SPRINT_ARCH": cfg.get("arch", ""),   # empty -> run_sprint resolves it (plugin contract / browser default)
            "SPRINT_AGENT": cfg.get("agent", "swarm"), "SPRINT_EXEC": cfg.get("exec", "cecli"),
            "SPRINT_RAG": "1" if cfg.get("rag", True) else "0",
            "SPRINT_LESSONS": "1" if cfg.get("lessons", True) else "0",
            "SPRINT_FRESH": "1" if cfg.get("fresh", False) else "0",
            "SPRINT_SECONDS": str(int(cfg.get("seconds", 0))),      # 0 = open-ended (converge or STOP)
            "SPRINT_MAX_ITERS": str(int(cfg.get("max_iters", 0))),  # 0 = no cap
        })
        if cfg.get("model"):
            env["LLM_MODEL"] = cfg["model"]
        if cfg.get("nudge_file"):
            env["SPRINT_NUDGE_FILE"] = cfg["nudge_file"]
        unbuffered = bool(cfg.get("unbuffered", True))
        if unbuffered:
            env["PYTHONUNBUFFERED"] = "1"
        else:
            env.pop("PYTHONUNBUFFERED", None)
        argv = ["python"] + (["-u"] if unbuffered else []) + ["prismpath/run_sprint.py"]
        for f in ("STOP", "PAUSE"):
            try:
                os.remove(os.path.join(proj, f))
            except OSError:
                pass
        log = open(os.path.join(proj, "mc_sprint.log"), "a")
        p = subprocess.Popen(argv, cwd=REPO_ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        cfg = dict(cfg, unbuffered=unbuffered)
        state.update({"proc": p, "proj": proj, "cfg": cfg, "pinned": True})   # follow the one we started
    AUDIT.append(ACTOR, "sprint.start", {"proj": proj, "cfg": cfg, "pid": p.pid, "unbuffered": unbuffered})
    return {"ok": True, "pid": p.pid, "proj": proj, "unbuffered": unbuffered}


def _touch(proj, name, action):
    open(os.path.join(proj, name), "w").close()
    AUDIT.append(ACTOR, action, {"proj": proj})
    return {"ok": True}


def status(state):
    _sync_active(state)                               # auto-follow the live sprint (unless pinned)
    st = {}
    sp = os.path.join(state["proj"], "status.json")
    if os.path.isfile(sp):
        try:
            st = json.load(open(sp))
        except Exception:
            st = {}
    return {"running": sprint_running(state),
            "paused": os.path.isfile(os.path.join(state["proj"], "PAUSE")),
            "proj": os.path.basename(state["proj"]), "dir": state["proj"],
            "pinned": state.get("pinned", False),
            "unbuffered": state["cfg"].get("unbuffered"),     # the run's buffering mode (None if external)
            "sprints": discover_sprints(), "cfg": state["cfg"],
            "iteration": st.get("iteration"), "valid": st.get("valid"),
            "files": len(st.get("files", []) or []), "elapsed_s": st.get("elapsed_s"),
            "help_open": st.get("help_open"), "last_error": (st.get("last_error") or "")[:300],
            "done": st.get("done"), "model": st.get("model"),
            "audit_root": AUDIT.current_root()[:16], "audit_n": len(AUDIT.events)}


# The build roles span two served models: engineering voices + cecli on gemma4 (:8888), two contrarian
# product voices on qwen25 (:8889). Surfacing WHICH model answered lets the lens show the dialogue.
QWEN_ROLES = {"product-manager", "engagement-manager"}


def _model_for(role):
    return "qwen25 (LLM)" if role in QWEN_ROLES else "gemma4 (LLM)"


def _route(e):
    """Derive (from, to, substage): who sent the message and who received it. Every call is a
    role/cecli -> a served LLM (or the doc index), situated in propose->accept->build->test."""
    kind, role, prompt = e.get("kind"), e.get("role", ""), e.get("prompt", "")
    if kind == "retriever":
        return "retriever", "doc index", "retrieve"

    if kind == "cecli":
        return f"cecli·{role}", "gemma4 (LLM)", role
    sub = role
    if "Vote for the SINGLE best" in prompt:
        sub = "vote"
    elif "propose THE single highest" in prompt or "\nACTION:" in prompt:
        sub = "propose"
    return role, _model_for(role), sub


def mc_interactions(state, limit=300):
    proj = state["proj"]
    path = os.path.join(proj, "interactions.jsonl")
    events = []
    if os.path.isfile(path):
        for ln in open(path, errors="ignore").read().splitlines()[-limit:]:
            try:
                e = json.loads(ln)
            except Exception:
                continue
            p, o = _fold(e.get("prompt", "")), _fold(e.get("output", ""), head=0, tail=2200)
            frm, to, sub = _route(e)
            events.append({"ts": e.get("ts"), "kind": e.get("kind", "?"), "role": e.get("role", ""),
                           "phase": e.get("phase", ""), "dur_ms": e.get("dur_ms", 0),
                           "from": frm, "to": to, "substage": sub, "rc": e.get("rc"),
                           "prompt_len": e.get("prompt_len", 0), "output_len": e.get("output_len", 0),
                           "prompt": p["preview"], "output": o["preview"]})
    return {"summary": status(state), "events": events}


def retrievals(state, limit=200):
    """Observe the Retrieval port: which RAG chunks a run pulled, per turn. Reads the recorded
    `phase="retrieve"` interactions; surfaces structured hits (`hits_meta`: source/path/score) when the
    producer emitted them, else the count. Empty/degraded cleanly when a run used no RAG."""
    proj = state["proj"]
    path = os.path.join(proj, "interactions.jsonl")
    out = []
    if os.path.isfile(path):
        for ln in open(path, errors="ignore").read().splitlines():
            try:
                e = json.loads(ln)
            except Exception:
                continue
            if e.get("kind") != "retriever" and e.get("phase") != "retrieve":
                continue
            out.append({"ts": e.get("ts"), "query": (e.get("prompt") or "")[:300],
                        "n": e.get("hits", len(e.get("hits_meta", []) or [])),
                        "hits": e.get("hits_meta", [])})
    return {"retrievals": out[-limit:]}


def balance_state(state):
    """The category-balance ledger + current weights — visualizes EVEN expansion across directions."""
    led = {}
    try:
        with open(os.path.join(state["proj"], "category_balance.json"), encoding="utf-8") as f:
            led = json.load(f)
    except Exception:
        led = {}
    cats = sorted(led)
    rows = [{"name": c, "count": int(led.get(c, 0)),
             "weight": 1.0}
            for c in cats]
    return {"total": sum(r["count"] for r in rows), "categories": rows}


_FAIL_VALIDATE = re.compile(r"TypeError|Unknown|duplicate|missing|Expected|Argument", re.I)


def flow_state(state):
    """Derive the loop stage + active pushback edge: propose->accept->build->test/validate->repeat,
    with back-edges when the gate kicks work back to build/fix."""
    proj = state["proj"]
    st = {}
    try:
        st = json.load(open(os.path.join(proj, "status.json")))
    except Exception:
        pass
    phase = ""
    ipath = os.path.join(proj, "interactions.jsonl")
    if os.path.isfile(ipath):
        lines = open(ipath, errors="ignore").read().splitlines()
        for ln in reversed(lines[-5:]):
            try:
                phase = json.loads(ln).get("phase", "")
                break
            except Exception:
                continue
    valid = bool(st.get("valid"))
    err = st.get("last_error") or ""
    fail_kind = None
    if not valid and err:
        fail_kind = "test" if "lune test failed" in err else ("validate" if _FAIL_VALIDATE.search(err) else "validate")
    stage = {"retrieve": "build", "build": "build",
             "fix": "fix", "review": "validate"}.get(phase, "propose")
    if valid:
        stage = "validate"
    recent = []
    lp = os.path.join(proj, "sprint.log")
    if os.path.isfile(lp):
        for ln in open(lp, errors="ignore").read().splitlines()[-40:]:
            m = re.search(r"\[(rag|cecli|fix|HELP \d+|reflect)\]\s*(.*)", ln)
            if m:
                recent.append(m.group(0).split("] ", 1)[-1][:90] if "] " in m.group(0) else m.group(0)[:90])
            elif re.search(r"\[it \d+ \|.*valid=", ln):
                recent.append(ln.split("] ", 1)[-1][:90])
    return {"stage": stage, "gate_valid": valid, "iteration": st.get("iteration"),
            "fail_kind": fail_kind, "reason": err[:160], "help_open": st.get("help_open"),
            "recent": recent[-10:]}


def serialize_flow_graph(state, flow_path=None):
    """The flow topology the command center renders: nodes + tier-classified edges, plus the live
    checkpoint (active node, transcript, state vars). `flow_path` is resolved and CONTAINED to the
    followed project (or the bundled flows dir); it never reads an arbitrary path."""
    from prismpath.parser import parse_file
    from prismpath import predicates
    proj = state["proj"]
    if not flow_path:
        sp = os.path.join(proj, "status.json")
        if os.path.isfile(sp):
            try:
                with open(sp, encoding="utf-8") as f:
                    st = json.load(f)
                flow_path = st.get("flow_path") or st.get("flow")
            except Exception:
                pass
        if not flow_path:
            candidates = _glob.glob(os.path.join(proj, "flows", "*.md")) + _glob.glob(os.path.join(proj, "*.md"))
            flow_path = candidates[0] if candidates else os.path.join(PRISM_DIR, "flows", "coding.md")
    resolved = os.path.abspath(flow_path)
    if not (_under(resolved, proj) or _under(resolved, PRISM_DIR)):
        return {"error": "flow path escapes project sandbox"}
    graph = parse_file(resolved)
    nodes_data = {}
    for name, n in graph.nodes.items():
        edges = []
        for target, cond in n.edges:
            if predicates.is_error(cond):
                tier = "error"
            elif predicates.is_event(cond):
                tier = "event"
            elif predicates.is_deterministic(cond):
                tier = "deterministic"
            else:
                tier = "semantic"
            edges.append({"target": target, "condition": cond, "tier": tier})
        nodes_data[name] = {"name": name, "instruction": n.instruction, "terminal": n.terminal,
                            "annotations": n.annotations, "edges": edges}
    active = {}
    ckpt = os.path.join(proj, "checkpoint.json")
    if os.path.isfile(ckpt):
        try:
            with open(ckpt, encoding="utf-8") as f:
                active = json.load(f)
        except Exception:
            pass
    try:
        flow_text = open(resolved, encoding="utf-8").read()      # so the console can prove it (text-in)
    except Exception:
        flow_text = ""
    flow_path = os.path.relpath(resolved, proj) if _under(resolved, proj) else os.path.basename(resolved)
    return {"name": graph.name, "start": graph.start, "nodes": nodes_data,
            "flow_text": flow_text, "flow_path": flow_path,
            "active_node": active.get("node"), "transcript": active.get("transcript", []),
            "state_variables": active.get("state", {})}
