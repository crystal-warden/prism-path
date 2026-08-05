"""Mission Control — one interface for the whole swarm.

Consolidates: CONTROL (start / stop / pause a sprint, iteration cap or open-ended-until-converge),
OBSERVE (the live glass lens of agent prompts+outputs + status), REVIEW (browse & lightly edit the
files the agents create — viewer/editor, not an IDE), CHAT (query the model in parallel, separate
from the swarm), and AUDIT (an append-only action log — every control action is recorded with its
actor, so the console has a chronological record of what happened).

Security is a pillar, not a bolt-on: every state-changing endpoint appends to the audit log BEFORE
acting, and the event count is surfaced in the UI. (A tamper-evident cryptographic audit backend
is a separate component, not part of this open release — see audit_log.py.)

  MC_PROJ=/tmp/demo python -u prismpath/mission_control.py      # binds 127.0.0.1:9109 (loopback)
"""
import base64
import json
import os
import re
import subprocess
import threading
import time
import urllib.request
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from prismpath import audit_log
try:
    from prismpath.swarm_exporter import _fold                # reuse the prompt/output folder
except Exception:
    from swarm_exporter import _fold
try:
    import dice                                            # council categories + balance weights
except Exception:
    dice = None
try:
    from prismpath import retriever as _retriever            # dense RAG over a per-project turbovec index
except Exception:
    try:
        import retriever as _retriever
    except Exception:
        _retriever = None                                 # RAG simply off if unavailable (never fatal)

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.abspath(os.environ.get("MC_PROJ", "/tmp/demo"))
PORT = int(os.environ.get("MC_PORT", "9109"))
# SECURITY: loopback-only by default. Mission Control can start/stop the swarm, edit files, and query
# the models — it must never be reachable from the LAN. Override MC_HOST only behind a trusted proxy.
HOST = os.environ.get("MC_HOST", "127.0.0.1")
LLM_BASE = os.environ.get("LLM_BASE", "http://127.0.0.1:8888/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "gemma4")
AUDIT = audit_log.AuditLog(os.environ.get("MC_AUDIT", os.path.join(HERE, "rag", "..", "mission_audit.log")))
DEFAULT_RAG = os.environ.get("MC_RAG_INDEX", "")  # no built-in index; set MC_RAG_INDEX or per-sprint rag_index
# Auto-discovery: MC follows whichever sprint is live, no matter who started it (Control tab / CLI / hand).
MC_SCAN = os.environ.get("MC_SCAN", "/tmp/*/status.json")          # glob(s), os.pathsep-separated
MC_REGISTRY = os.path.expanduser(os.environ.get("MC_REGISTRY", "~/.prismpath/sprints.json"))
MC_USERS = os.path.expanduser(os.environ.get("MC_USERS", "~/.prismpath/users.json"))

# --- per-identity state -------------------------------------------------------
# Mission Control is now multi-user: each identity gets its OWN followed-sprint state (proc/proj/cfg/
# pinned), keyed by email. The single local owner (no Tailscale header) resolves to a box-wide
# "operator" identity, so local behavior is unchanged. Guests are sandboxed to their own project tree.
_STATE = {}                          # email -> {"proc","proj","cfg","pinned"}
_STATE_LOCK = threading.Lock()       # guards the _STATE dict (get-or-create / mutation)
_FILE_LOCK = threading.Lock()        # serializes file writes/uploads across threads
_CHAT = {}                           # email -> [ {role, content}, ... ]  (per-user conversation)
_CHAT_LOCK = threading.Lock()        # guards _CHAT read-modify-write
_CHAT_MAX = int(os.environ.get("MC_CHAT_MAX_TURNS", "20"))   # keep last N user+assistant pairs
RAG_K = int(os.environ.get("MC_RAG_K", "4"))                 # chunks retrieved per chat turn
_REINDEX = {}                        # email -> {running, ts, docs, chunks, error}  (rebuild status)
_REINDEX_LOCK = threading.Lock()     # guards _REINDEX read-modify-write


def _under(path, base):
    """True if `path` is `base` itself or nested inside it (the sandbox containment check)."""
    path, base = os.path.abspath(path), os.path.abspath(base)
    return path == base or path.startswith(base + os.sep)


def _scoped(ident):
    """Operators see/act box-wide (owner); everyone else is confined to ident['project']."""
    return ident.get("role") != "operator"


def _load_users():
    """email -> {role, project, rag_index}. Reloaded on each call (tiny file; add a user, no restart)."""
    try:
        with open(MC_USERS, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _default_identity():
    """The local owner: no Tailscale proxy in front, so no identity header. Full box-wide operator."""
    return {"email": "operator", "role": "operator", "project": PROJ, "rag_index": DEFAULT_RAG}


def _state_for(ident):
    key = ident["email"]
    with _STATE_LOCK:
        s = _STATE.get(key)
        if s is None:
            s = {"proc": None, "proj": os.path.abspath(ident["project"]), "cfg": {}, "pinned": False}
            _STATE[key] = s
        return s


def _registry_projs():
    try:
        with open(MC_REGISTRY, encoding="utf-8") as f:
            d = json.load(f)
        return list(d.keys()) if isinstance(d, dict) else list(d)
    except Exception:
        return []


def discover_sprints(ident=None):
    """Every sprint on the box, found by its status.json heartbeat: scan globs + the registry (sprints
    self-announce on start) + the launch default. The freshest still-heartbeating one is 'active' — this
    is what lets MC follow a sprint started ANYWHERE without a restart.

    When `ident` is a *scoped* (non-operator) user, the result is filtered to sprints inside their
    project tree, so a guest's selector never reveals the owner's (or another guest's) sprints."""
    import glob as _glob
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
    if ident is not None and _scoped(ident):
        base = os.path.abspath(ident["project"])
        out = [s for s in out if _under(s["proj"], base)]
    return out


def _sync_active(state, ident):
    """Point this identity's state at the active sprint unless they pinned one. Called from the
    most-frequent poll so every tab follows the live sprint within a tick. Scoped users only ever
    auto-follow sprints inside their own tree (discover_sprints already filters)."""
    if state.get("pinned"):
        return
    found = discover_sprints(ident)
    if found:
        state["proj"] = found[0]["proj"]


# ----------------------------------------------------------------- fs helpers
def _safe(proj, rel):
    p = os.path.abspath(os.path.join(proj, rel))
    if not p.startswith(os.path.abspath(proj) + os.sep) and p != os.path.abspath(proj):
        raise ValueError("path escapes project")
    return p


def file_tree(proj):
    out = []
    for dp, dns, fns in os.walk(proj):
        dns[:] = [d for d in dns if d not in (".git", "tools", "__pycache__", "last-good")]
        for fn in sorted(fns):
            if fn.endswith((".js", ".mjs", ".html", ".css", ".json", ".md", ".txt", ".pdf")) and not fn.startswith("."):
                rel = os.path.relpath(os.path.join(dp, fn), proj)
                try:
                    stt = os.stat(os.path.join(dp, fn))
                    # float mtime (NOT int) — sub-second resolution: cecli can rewrite a same-size file
                    # twice within one wall-clock second; truncating to whole seconds collides the change
                    # signature and re-introduces stale editor content (the very bug this tab fixes).
                    out.append({"path": rel, "size": stt.st_size, "mtime": stt.st_mtime})
                except OSError:
                    pass
    return sorted(out, key=lambda f: f["path"])


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


def start_sprint(cfg, ident, state):
    if sprint_running(state):
        return {"ok": False, "error": "a sprint is already running"}
    proj = os.path.abspath(cfg.get("proj") or state["proj"])
    if _scoped(ident) and not _under(proj, ident["project"]):
        return {"ok": False, "error": "project is outside your sandbox"}
    env = dict(os.environ)
    env.update({
        "SPRINT_PROJ": proj, "SPRINT_GATE": cfg.get("gate", "browser"),
        "SPRINT_ARCH": cfg.get("arch", ""),   # empty -> run_sprint resolves it (gate plugin's contract, or browser default)
        "SPRINT_AGENT": cfg.get("agent", "swarm"), "SPRINT_EXEC": cfg.get("exec", "cecli"),
        "SPRINT_RAG": "1" if cfg.get("rag", True) else "0",
        "SPRINT_RAG_INDEX": ident.get("rag_index") or DEFAULT_RAG,   # ground the sprint on this user's index
        "SPRINT_LESSONS": "1" if cfg.get("lessons", True) else "0",
        "SPRINT_FRESH": "1" if cfg.get("fresh", False) else "0",
        "SPRINT_SECONDS": str(int(cfg.get("seconds", 0))),     # 0 = open-ended (converge or STOP)
        "SPRINT_MAX_ITERS": str(int(cfg.get("max_iters", 0))),  # 0 = no cap (honored by run_sprint)
        "LLM_MODEL": cfg.get("model", LLM_MODEL),
    })
    if cfg.get("nudge_file"):
        env["SPRINT_NUDGE_FILE"] = cfg["nudge_file"]
    for f in ("STOP", "PAUSE"):
        try:
            os.remove(os.path.join(proj, f))
        except OSError:
            pass
    log = open(os.path.join(proj, "mc_sprint.log"), "a")
    p = subprocess.Popen(["python", "-u", "prismpath/run_sprint.py"],
                         cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         env=env, stdout=log, stderr=subprocess.STDOUT)
    state.update({"proc": p, "proj": proj, "cfg": cfg, "pinned": True})   # follow the one we just started
    AUDIT.append(ident["email"], "sprint.start", {"proj": proj, "cfg": cfg, "pid": p.pid})
    return {"ok": True, "pid": p.pid, "proj": proj}


def _touch(proj, name, actor, action):
    open(os.path.join(proj, name), "w").close()
    AUDIT.append(actor, action, {"proj": proj})
    return {"ok": True}


# ----------------------------------------------------------------- chat proxy
# The Chat tab is a real grounded assistant, not a one-shot proxy: each user has a private multi-turn
# history (kept server-side, keyed by identity) and every turn is grounded on THEIR project's RAG index
# (e.g. a guest's unreal.tvim) — the retrieved chunks are injected as a system preamble and surfaced
# back to the UI as citations. Replies stream token-by-token (SSE) for responsiveness.

def _retrieve_context(ident, message):
    """Top-RAG_K chunks from this identity's index -> (context_block, citations). Never raises."""
    if _retriever is None:
        return "", []
    try:
        hits = _retriever.retrieve(message, k=RAG_K, index_path=ident.get("rag_index"))
    except Exception:
        hits = []
    if not hits:
        return "", []
    ctx = "\n\n".join(f"[{h['source']}/{h['path']}]\n{h['text']}" for h in hits)
    cits = [{"source": h.get("source", ""), "path": h.get("path", ""),
             "score": round(float(h.get("score", 0)), 3)} for h in hits]
    return ctx, cits


def _chat_messages(message, ident):
    """Assemble the OpenAI message list: RAG system preamble + this user's prior turns + new message."""
    ctx, citations = _retrieve_context(ident, message)
    msgs = []
    if ctx:
        msgs.append({"role": "system", "content":
                     "You are a helpful assistant. Ground your answer in the retrieved documentation "
                     "below when it is relevant, and cite sources by their [source/path] tag. If the "
                     "docs don't cover the question, answer from general knowledge and say so.\n\n"
                     "=== RETRIEVED DOCS ===\n" + ctx})
    with _CHAT_LOCK:
        msgs.extend(list(_CHAT.get(ident["email"], [])))
    msgs.append({"role": "user", "content": message})
    return msgs, citations


def _append_history(email, user_msg, assistant_msg):
    with _CHAT_LOCK:
        h = _CHAT.setdefault(email, [])
        h.append({"role": "user", "content": user_msg})
        h.append({"role": "assistant", "content": assistant_msg})
        extra = len(h) - _CHAT_MAX * 2
        if extra > 0:
            del h[:extra]


def _reset_history(email):
    with _CHAT_LOCK:
        _CHAT.pop(email, None)


def chat(message, ident):
    """Non-streaming fallback (used when the client requests stream=false)."""
    messages, citations = _chat_messages(message, ident)
    AUDIT.append(ident["email"], "chat.query", {"message": message[:500]})
    AUDIT.append(ident["email"], "chat.rag", {"index": ident.get("rag_index"), "k": RAG_K, "n_hits": len(citations)})
    body = json.dumps({"model": LLM_MODEL, "messages": messages,
                       "max_tokens": 1200, "temperature": 0.3, "stream": False,
                       "chat_template_kwargs": {"enable_thinking": False}}).encode()
    try:
        req = urllib.request.Request(LLM_BASE.rstrip("/") + "/chat/completions", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as r:
            d = json.loads(r.read())
        reply = (d["choices"][0].get("message") or {}).get("content", "") or ""
    except Exception as e:
        reply = f"(model error: {e})"
    _append_history(ident["email"], message, reply)
    AUDIT.append(ident["email"], "chat.reply", {"chars": len(reply)})
    return {"reply": reply, "citations": citations}


# ----------------------------------------------------------------- RAG re-index
# Makes "share docs -> Gemma knows them" self-serve: a user uploads files into their docs/ and rebuilds
# THEIR index from the dashboard. Runs in a daemon thread (embedding is slow) — the UI polls status.
def _index_path_for(ident):
    idx = ident.get("rag_index") or DEFAULT_RAG          # resolve_identity already absolutized this
    return idx if os.path.isabs(idx) else os.path.join(ident["project"], idx)


def _run_reindex(ident, state):
    # docs + index belong to the user's HOME project (ident['project']), NOT the sprint they're currently
    # viewing — an operator's state['proj'] drifts as it box-follows live sprints; the corpus must not.
    email, docs, index_path = ident["email"], os.path.join(ident["project"], "docs"), _index_path_for(ident)
    try:
        from cwplatform.contexts.ingestion.application.ingest_corpus import IngestCorpus
        from cwplatform.contexts.ingestion.domain.models import ChunkingPolicy
        from cwplatform.contexts.ingestion.adapters.fs_loader import FsLoader
        from cwplatform.contexts.ingestion.adapters.default_chunker import DefaultChunker
        from cwplatform.contexts.ingestion.adapters.bge_embedder import BgeEmbedder
        from cwplatform.contexts.ingestion.adapters.turbovec_index_writer import TurbovecIndexWriter
        from cwplatform.contexts.governance.adapters.stdout_audit import StdoutAuditSink
        from cwplatform.shared_kernel.tenancy import Tenant
        if not os.path.isdir(docs) or not any(os.scandir(docs)):
            raise RuntimeError(f"no docs under {docs} — upload some first")
        os.makedirs(os.path.dirname(os.path.abspath(index_path)), exist_ok=True)
        dev = os.environ.get("EMBED_DEVICE") or "cpu"     # cpu by default: don't fight vLLM for the GPU
        ingest = IngestCorpus(loader=FsLoader(), chunker=DefaultChunker(),
                              embedder=BgeEmbedder(device=dev), index=TurbovecIndexWriter(),
                              audit=StdoutAuditSink(), policy=ChunkingPolicy())
        report = ingest(Tenant(id="t_local", name="local"), root=docs, index_path=index_path)
        if _retriever is not None:                        # drop the stale cached index so chat reloads it
            try:
                _retriever._cache.pop(index_path, None)
            except Exception:
                pass
        with _REINDEX_LOCK:
            _REINDEX[email] = {"running": False, "ts": time.time(), "docs": report.docs,
                               "chunks": report.chunks, "error": ""}
        AUDIT.append(email, "rag.reindex", {"index": index_path, "docs": report.docs, "chunks": report.chunks})
    except Exception as e:
        with _REINDEX_LOCK:
            _REINDEX[email] = {"running": False, "ts": time.time(), "docs": 0, "chunks": 0, "error": str(e)[:300]}
        AUDIT.append(email, "rag.reindex.error", {"error": str(e)[:300]})


def start_reindex(ident, state):
    email = ident["email"]
    with _REINDEX_LOCK:
        if (_REINDEX.get(email) or {}).get("running"):
            return {"ok": False, "error": "a reindex is already running"}
        _REINDEX[email] = {"running": True, "ts": time.time(), "docs": 0, "chunks": 0, "error": ""}
    threading.Thread(target=_run_reindex, args=(ident, state), daemon=True).start()
    return {"ok": True, "running": True}


def status(ident, state):
    _sync_active(state, ident)                        # auto-follow the live sprint (unless pinned)
    st = {}
    sp = os.path.join(state["proj"], "status.json")
    if os.path.isfile(sp):
        try:
            st = json.load(open(sp))
        except Exception:
            st = {}
    with _REINDEX_LOCK:
        rstat = dict(_REINDEX.get(ident["email"], {}))
    return {"running": sprint_running(state), "paused": os.path.isfile(os.path.join(state["proj"], "PAUSE")),
            "user": ident["email"], "role": ident["role"], "reindex": rstat,
            "proj": os.path.basename(state["proj"]), "dir": state["proj"], "pinned": state.get("pinned", False),
            "sprints": discover_sprints(ident), "cfg": state["cfg"],
            "iteration": st.get("iteration"), "valid": st.get("valid"),
            "files": len(st.get("files", []) or []), "elapsed_s": st.get("elapsed_s"),
            "help_open": st.get("help_open"), "last_error": (st.get("last_error") or "")[:300],
            "done": st.get("done"), "model": st.get("model"),
            "audit_root": AUDIT.current_root()[:16], "audit_n": len(AUDIT.events)}


# The council is split across two served models: the engineering voices + cecli executor run on
# gemma4 (:8888); the two contrarian product voices run on qwen25 (:8889). Surfacing WHICH model
# answered lets the lens show the gemma4-vs-qwen25 dialogue, not one undifferentiated "LLM".
QWEN_ROLES = {"product-manager", "engagement-manager"}


def _model_for(role):
    return "qwen25 (LLM)" if role in QWEN_ROLES else "gemma4 (LLM)"


def _route(e):
    """Derive (from, to, substage) — who sent the message and who received it.
    There is no agent↔agent messaging: every call is a role/cecli → a served LLM (or the doc
    index), orchestrated by the loop. The substage situates it in propose→accept→build→test."""
    kind, role, prompt = e.get("kind"), e.get("role", ""), e.get("prompt", "")
    if kind == "retriever":
        return "retriever", "doc index", "retrieve"
    if kind == "dice":
        return "\U0001F3B2 council dice", "council", "roll"
    if kind == "cecli":
        return f"cecli·{role}", "gemma4 (LLM)", role           # cecli executor always runs on gemma4
    sub = role
    if "Vote for the SINGLE best" in prompt:
        sub = "vote"
    elif "propose THE single highest" in prompt or "\nACTION:" in prompt:
        sub = "propose"
    return role, _model_for(role), sub


def mc_interactions(ident, state, limit=300):
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
    return {"summary": status(ident, state), "events": events}


def balance_state(state):
    """The category-balance ledger + current weights — visualizes EVEN expansion across directions.
    count = times that category has been chosen; weight = its current vote/dice multiplier (over-built
    < 1.0, neglected > 1.0)."""
    led = {}
    try:
        with open(os.path.join(state["proj"], "category_balance.json"), encoding="utf-8") as f:
            led = json.load(f)
    except Exception:
        led = {}
    cats = dice.CATEGORIES if dice is not None else sorted(led)
    rows = [{"name": c, "count": int(led.get(c, 0)),
             "weight": round(dice.balance_weight(led, c), 2) if dice is not None else 1.0}
            for c in cats]
    return {"total": sum(r["count"] for r in rows), "categories": rows}


_FAIL_VALIDATE = re.compile(r"TypeError|Unknown|duplicate|missing|Expected|Argument", re.I)


def flow_state(state):
    """Derive the loop stage + active pushback edge for the visual: propose→accept→build→
    test/validate→repeat, with back-edges when the gate kicks work back to build/fix."""
    proj = state["proj"]
    st = {}
    try:
        st = json.load(open(os.path.join(proj, "status.json")))
    except Exception:
        pass
    # latest interaction phase
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
    stage = {"council": "accept", "retrieve": "build", "build": "build",
             "fix": "fix", "review": "validate"}.get(phase, "propose")
    if valid:
        stage = "validate"
    # recent transitions from sprint.log (cleaned)
    recent = []
    lp = os.path.join(proj, "sprint.log")
    if os.path.isfile(lp):
        for ln in open(lp, errors="ignore").read().splitlines()[-40:]:
            m = re.search(r"\[(council|rag|cecli|fix|HELP \d+|reflect)\]\s*(.*)", ln)
            if m:
                recent.append(m.group(0).split("] ", 1)[-1][:90] if "] " in m.group(0) else m.group(0)[:90])
            elif re.search(r"\[it \d+ \|.*valid=", ln):
                recent.append(ln.split("] ", 1)[-1][:90])
    return {"stage": stage, "gate_valid": valid, "iteration": st.get("iteration"),
            "fail_kind": fail_kind, "reason": err[:160], "help_open": st.get("help_open"),
            "recent": recent[-10:]}


# --- agy run observability ----------------------------------------------------
# agy launches routed through ~/.local/bin/agy-run register a record here (one .json + a live .log +
# a final .out per run); the "agy" tab reads this to turn opaque background dispatches into watchable
# runs. Operator-only (agy prompts/logs can be sensitive — never exposed to Tailscale guests).
AGY_RUNS_DIR = os.path.expanduser(os.environ.get("AGY_RUNS_DIR", "~/.agy/runs"))
_AGY_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-\d+$")


def _pid_alive(pid):
    try:
        return os.path.exists("/proc/%d" % int(pid))
    except Exception:
        return False


def agy_runs(limit=60):
    """Newest-first list of registered agy runs; a 'running' record whose process is gone -> 'stale'."""
    out = []
    try:
        metas = [f for f in os.listdir(AGY_RUNS_DIR) if f.endswith(".json")]
    except FileNotFoundError:
        return {"runs": [], "dir": AGY_RUNS_DIR}
    for fn in metas:
        try:
            d = json.load(open(os.path.join(AGY_RUNS_DIR, fn)))
        except Exception:
            continue
        if d.get("status") == "running" and not _pid_alive(d.get("pid", -1)):
            d["status"] = "stale"          # wrapper died without recording an exit (kill -9 / crash)
        try:
            d["log_size"] = os.path.getsize(d.get("log", ""))
        except Exception:
            d["log_size"] = 0
        out.append(d)
    out.sort(key=lambda r: r.get("start", 0), reverse=True)
    return {"runs": out[:limit], "dir": AGY_RUNS_DIR}


def agy_log(rid, which="log", offset=0):
    """Incremental byte-read of a run's live log (or final .out) from `offset` — for UI streaming."""
    if not _AGY_ID_RE.match(rid or ""):
        return {"error": "bad id"}
    fn = os.path.join(AGY_RUNS_DIR, rid + (".out" if which == "out" else ".log"))
    if os.path.dirname(os.path.abspath(fn)) != os.path.abspath(AGY_RUNS_DIR):
        return {"error": "bad path"}
    try:
        size = os.path.getsize(fn)
        offset = max(0, min(int(offset or 0), size))
        with open(fn, "rb") as f:
            f.seek(offset)
            raw = f.read()
        return {"id": rid, "which": which, "offset": offset, "next": offset + len(raw),
                "size": size, "content": raw.decode("utf-8", "ignore")}
    except FileNotFoundError:
        return {"id": rid, "which": which, "offset": 0, "next": 0, "size": 0, "content": ""}
    except Exception as e:
        return {"error": str(e)}


SPA = open(os.path.join(HERE, "mission_control.html"), encoding="utf-8").read() \
    if os.path.isfile(os.path.join(HERE, "mission_control.html")) else "<h1>mission_control.html missing</h1>"


class H(BaseHTTPRequestHandler):
    def _send(self, obj, ctype="application/json"):
        body = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def _sse(self, obj):
        """Write one Server-Sent-Events frame. Raises on a dead socket (caller stops the stream)."""
        self.wfile.write(b"data: " + json.dumps(obj).encode() + b"\n\n")
        self.wfile.flush()

    def _chat_stream(self, message, ident):
        """Stream a grounded chat reply as SSE. Self-contained error handling: this method NEVER lets
        an exception escape to do_POST (which would try to _send a second response onto a half-written
        socket). On client disconnect it stops quietly; on upstream error it emits an {error} frame."""
        messages, citations = _chat_messages(message, ident)
        AUDIT.append(ident["email"], "chat.query", {"message": message[:500]})
        AUDIT.append(ident["email"], "chat.rag", {"index": ident.get("rag_index"), "k": RAG_K, "n_hits": len(citations)})
        body = json.dumps({"model": LLM_MODEL, "messages": messages,
                           "max_tokens": 1200, "temperature": 0.3, "stream": True,
                           "chat_template_kwargs": {"enable_thinking": False}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "close")     # no Content-Length: socket close signals end-of-stream
        self.end_headers()
        parts = []
        try:
            req = urllib.request.Request(LLM_BASE.rstrip("/") + "/chat/completions", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=180) as r:
                for raw in r:                         # vLLM emits "data: {json}\n\n" SSE lines
                    line = raw.decode("utf-8", "ignore").strip()
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        delta = (json.loads(data)["choices"][0].get("delta") or {}).get("content") or ""
                    except Exception:
                        delta = ""
                    if delta:
                        parts.append(delta)
                        self._sse({"delta": delta})   # may raise BrokenPipe -> caught below
        except (BrokenPipeError, ConnectionResetError):
            return                                    # client went away mid-stream; nothing more to do
        except Exception as e:
            try:
                self._sse({"error": str(e)})
            except Exception:
                return
        full = "".join(parts)
        _append_history(ident["email"], message, full)
        AUDIT.append(ident["email"], "chat.reply", {"chars": len(full)})
        try:
            self._sse({"citations": citations, "done": True})
        except Exception:
            pass

    def resolve_identity(self):
        """Map the request to {email, role, project, rag_index}. Source of truth is the
        `Tailscale-User-Login` header injected by `tailscale serve`:
          • header absent      -> the local owner: full box-wide operator (local use unchanged);
          • header + mapped    -> that user's role/project/rag_index from ~/.prismpath/users.json;
          • header + UNMAPPED  -> None (caller returns 'unknown user' — fail CLOSED, never operator).
        """
        login = self.headers.get("Tailscale-User-Login")
        if not login:
            return _default_identity()
        u = _load_users().get(login)
        if not u:
            return None
        proj = os.path.abspath(os.path.expanduser(u.get("project", PROJ)))
        idx = u.get("rag_index") or DEFAULT_RAG
        if idx and not os.path.isabs(idx):
            idx = os.path.join(proj, idx)
        return {"email": login, "role": u.get("role", "guest"), "project": proj, "rag_index": idx}

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        # parse_qs URL-DECODES values (browser encodeURIComponent turns "/" into "%2F"); the old
        # naive regex left "%2F" literal, so every nested file path failed to open -> empty editor.
        q = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        try:
            if path in ("/", "/index.html"):
                self._send(SPA, "text/html; charset=utf-8")
                return
            ident = self.resolve_identity()
            if ident is None:
                self._send({"error": "unknown user"})
                return
            state = _state_for(ident)
            if path == "/api/status":
                self._send(status(ident, state))
            elif path == "/api/interactions":
                self._send(mc_interactions(ident, state))
            elif path == "/api/flow":
                self._send(flow_state(state))
            elif path == "/api/balance":
                self._send(balance_state(state))
            elif path == "/api/flow/graph":
                flow_path = q.get("path")
                if not flow_path:
                    sp = os.path.join(state["proj"], "status.json")
                    if os.path.isfile(sp):
                        try:
                            with open(sp, encoding="utf-8") as f:
                                st = json.load(f)
                            flow_path = st.get("flow_path") or st.get("flow")
                        except Exception:
                            pass
                    if not flow_path:
                        import glob
                        candidates = glob.glob(os.path.join(state["proj"], "flows", "*.md")) + \
                                     glob.glob(os.path.join(state["proj"], "*.md"))
                        if candidates:
                            flow_path = candidates[0]
                        else:
                            flow_path = os.path.join(HERE, "flows", "coding.md")
                
                resolved_path = os.path.abspath(flow_path)
                if not (_under(resolved_path, state["proj"]) or _under(resolved_path, HERE)):
                    self._send({"error": "flow path escapes project sandbox"})
                    return
                
                from prismpath.parser import parse_file
                from prismpath import predicates
                
                graph = parse_file(resolved_path)
                nodes_data = {}
                for name, n in graph.nodes.items():
                    edges_data = []
                    for target, cond in n.edges:
                        if predicates.is_error(cond):
                            tier = "error"
                        elif predicates.is_event(cond):
                            tier = "event"
                        elif predicates.is_deterministic(cond):
                            tier = "deterministic"
                        else:
                            tier = "semantic"
                        edges_data.append({
                            "target": target,
                            "condition": cond,
                            "tier": tier
                        })
                    nodes_data[name] = {
                        "name": name,
                        "instruction": n.instruction,
                        "terminal": n.terminal,
                        "annotations": n.annotations,
                        "edges": edges_data
                    }
                
                ckpt_path = os.path.join(state["proj"], "checkpoint.json")
                active_state = {}
                if os.path.isfile(ckpt_path):
                    try:
                        with open(ckpt_path, encoding="utf-8") as f:
                            active_state = json.load(f)
                    except Exception:
                        pass
                self._send({
                    "name": graph.name,
                    "start": graph.start,
                    "nodes": nodes_data,
                    "active_node": active_state.get("node"),
                    "transcript": active_state.get("transcript", []),
                    "state_variables": active_state.get("state", {})
                })
            elif path == "/api/files":

                self._send({"proj": os.path.basename(state["proj"]), "dir": state["proj"],
                            "files": file_tree(state["proj"])})
            elif path == "/api/file":
                fp = _safe(state["proj"], q.get("path", ""))
                fst = os.stat(fp)
                self._send({"path": q.get("path", ""), "content": open(fp, errors="ignore").read(),
                            "mtime": fst.st_mtime, "size": fst.st_size})
            elif path == "/api/agy/runs":
                self._send({"error": "forbidden"} if ident.get("role") != "operator" else agy_runs())
            elif path == "/api/agy/log":
                self._send({"error": "forbidden"} if ident.get("role") != "operator"
                           else agy_log(q.get("id", ""), q.get("which", "log"), q.get("offset", "0")))
            elif path == "/api/audit":
                evs = AUDIT.events[-100:]
                self._send({"root": AUDIT.current_root(), "n": len(AUDIT.events),
                            "verify": AUDIT.verify_log(), "events": evs})
            elif path == "/api/audit/proof":
                i = int(q.get("i", "0"))
                if 0 <= i < len(AUDIT.leaves):
                    pr = AUDIT.prove(i)
                    self._send({"i": i, "path_len": len(pr["path"]), "peaks": len(pr["peaks"]),
                                "leaf": AUDIT.leaves[i][:16], "root": AUDIT.current_root()[:16],
                                "verified": audit_log.verify(AUDIT.leaves[i], pr, AUDIT.current_root())})
                else:
                    self._send({"error": "bad index"})
            elif path == "/api/queue":                      # runs suspended for a human decision
                from prismpath import checkpoint as _ckpt
                self._send({"items": _ckpt.list_queue()})
            elif path == "/api/fanouts":                    # fan-out composition trees (read-only)
                from prismpath import composer as _composer
                self._send({"fanouts": _composer.fanout_tree()})
            elif path == "/api/fanout/ckpt":                # one raw checkpoint, queue-dir-confined
                from prismpath import checkpoint as _ckpt
                qroot = os.path.realpath(_ckpt.queue_dir())
                rp = os.path.realpath(q.get("path", ""))
                if not rp.startswith(qroot + os.sep) or not rp.endswith(".json"):
                    self._send({"error": "path escapes the queue dir"})
                    return
                with open(rp, encoding="utf-8") as f:
                    self._send({"path": q.get("path", ""), "checkpoint": json.load(f)})
            else:
                self._send({"error": "not found"})
        except Exception as e:
            self._send({"error": str(e)})

    def do_POST(self):
        try:
            b = self._body()
            ident = self.resolve_identity()
            if ident is None:
                self._send({"error": "unknown user"})
                return
            a = ident["email"]
            state = _state_for(ident)
            if self.path == "/api/sprint/start":
                self._send(start_sprint(b, ident, state))
            elif self.path == "/api/sprint/select":         # pin the dashboard to a chosen sprint dir
                proj = os.path.abspath(b.get("proj") or state["proj"])
                if _scoped(ident) and not _under(proj, ident["project"]):
                    self._send({"error": "project is outside your sandbox"})
                    return
                state["proj"] = proj
                state["pinned"] = True
                self._send({"ok": True, "proj": state["proj"], "pinned": True})
            elif self.path == "/api/sprint/auto":           # resume auto-following the live sprint
                state["pinned"] = False
                _sync_active(state, ident)
                self._send({"ok": True, "proj": state["proj"], "pinned": False})
            elif self.path == "/api/sprint/stop":
                self._send(_touch(state["proj"], "STOP", a, "sprint.stop"))
            elif self.path == "/api/sprint/pause":
                self._send(_touch(state["proj"], "PAUSE", a, "sprint.pause"))
            elif self.path == "/api/sprint/resume":
                try:
                    os.remove(os.path.join(state["proj"], "PAUSE"))
                except OSError:
                    pass
                AUDIT.append(a, "sprint.resume", {"proj": state["proj"]})
                self._send({"ok": True})
            elif self.path == "/api/file":
                p = _safe(state["proj"], b["path"])
                with _FILE_LOCK:
                    open(p, "w", encoding="utf-8").write(b["content"])
                AUDIT.append(a, "file.edit", {"path": b["path"], "bytes": len(b["content"])})
                self._send({"ok": True, "mtime": os.stat(p).st_mtime})
            elif self.path == "/api/upload":                # drop doc(s) into <project>/docs/ (grounds chat)
                raw = (b.get("name", "") or "").replace("\\", "/").lstrip("/")
                rel_in = os.path.normpath(raw)              # keep subfolders (folder uploads); collapse ../
                if os.path.splitext(os.path.basename(rel_in))[1].lower() not in (".md", ".txt", ".pdf"):
                    self._send({"error": "only .md, .txt, .pdf allowed"})
                    return
                try:
                    data = base64.b64decode(b.get("content_b64", ""), validate=True)
                except Exception:
                    self._send({"error": "bad base64 payload"})
                    return
                rel = os.path.join("docs", rel_in)
                p = _safe(ident["project"], rel)            # docs land in the user's HOME project (not the
                with _FILE_LOCK:                            # followed sprint); raises if rel_in escapes it
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "wb") as f:
                        f.write(data)
                AUDIT.append(a, "file.upload", {"path": rel, "bytes": len(data)})
                self._send({"ok": True, "path": rel, "bytes": len(data)})
            elif self.path == "/api/reindex":               # rebuild THIS user's index from their docs/
                self._send(start_reindex(ident, state))
            elif self.path == "/api/chat":
                if b.get("stream", True):
                    self._chat_stream(b.get("message", ""), ident)   # writes its own SSE response
                else:
                    self._send(chat(b.get("message", ""), ident))
            elif self.path == "/api/chat/reset":
                _reset_history(a)
                AUDIT.append(a, "chat.reset", {})
                self._send({"ok": True})
            elif self.path == "/api/queue/decide":          # human picks an edge for a suspended run
                from prismpath import checkpoint as _ckpt
                cid = b.get("id", "")
                try:
                    # ids may be relpaths into a fan-out's *.children/ subdir; resolve_queue_item
                    # confines the path to the queue dir (the traversal guard the old basename gave).
                    cpath = _ckpt.resolve_queue_item(cid)
                    _ckpt.record_decision(cpath, b.get("choose", ""), decided_by=a)
                    AUDIT.append(a, "queue.decide", {"id": cid, "choose": b.get("choose")})
                    self._send({"ok": True})
                except Exception as e:
                    self._send({"error": str(e)})
            else:
                self._send({"error": "not found"})
        except Exception as e:
            self._send({"error": str(e)})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"mission control on {HOST}:{PORT}  proj={PROJ}  audit_root={AUDIT.current_root()[:16]}", flush=True)
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
