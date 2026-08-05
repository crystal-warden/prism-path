"""Agent orchestrator — plan -> approve -> execute backend for the chat UI.

FastAPI service (binds 0.0.0.0:8771, CORS open for the :8773 chat UI). A non-technical user types
a rough idea, gets an interactive PLAN from the served model (like planning mode), approves it,
then watches the builder+critic sprint (run_sprint.py) actually build it — progress over SSE.

Session state machine:  planning -> awaiting_approval -> executing -> done

API (this is the contract the chat-UI sprint codes against):
  POST /api/session                {prompt}      -> {session_id, phase, reply}
  POST /api/session/{id}/message   {text}        -> {phase, reply}
  POST /api/session/{id}/approve                 -> {phase:"executing"}
  GET  /api/session/{id}                          -> full session snapshot
  GET  /api/session/{id}/events                   -> SSE: message | phase | build_status | help | done
  GET  /api/session/{id}/artifact                 -> zip of the built project
  GET  /api/health

Run:  python -u prismpath/orchestrator.py
"""
import glob
import io
import json
import os
import subprocess
import time
import uuid
import zipfile

import requests
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
import asyncio

BASE = os.environ.get("LLM_BASE", "http://127.0.0.1:8888/v1")
MODEL = os.environ.get("LLM_MODEL", "gemma4")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.environ.get("ORCH_WORK", "/tmp/orchestrator")
TARGET = os.environ.get("ORCH_TARGET", "browser")          # browser | a gate-plugin name
ORCH_PLUGIN = None
if TARGET != "browser":
    from prismpath.plugins import load_gate
    ORCH_PLUGIN = load_gate(TARGET)
# architecture contract: browser is built-in (resolved relative to this file, CWD-independent);
# any other target's contract comes from its plugin
ARCH_FILE = (os.path.join(os.path.dirname(os.path.abspath(__file__)), "nudges", "APP_ARCHITECTURE.md")
             if TARGET == "browser" else getattr(ORCH_PLUGIN, "ARCH_PATH", ""))

PLAN_SENTINEL = "reply ok to build"
PLANNER_SYS = (
    "You are a friendly product planner who helps a NON-TECHNICAL person turn a rough idea into a "
    "small, concrete, buildable plan — a calm planning-mode conversation. Behaviour: ask at most "
    "1-3 clarifying questions, and only if truly needed; offer concrete suggestions when the user is "
    "unsure; then propose a SHORT structured plan: a one-line goal, 3-6 first-version features, and a "
    "small file/module layout with EXACT relative paths (no placeholders, no 'TBD'). Keep it tight — "
    "the least scope that delights (YAGNI). Be honest about how it gets checked: the agents build the "
    "code and automatically validate it, but a human does the final run to confirm it's good. "
    "When (and only when) you present a concrete plan ready to build, end your message with EXACTLY "
    "this line on its own:\nReply OK to build this, or tell me what to change.")
PLANNER_NOTE = getattr(ORCH_PLUGIN, "PLANNER_NOTE", "") if ORCH_PLUGIN else ""  # target-specific planner note

app = FastAPI(title="Agent orchestrator")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
SESS: dict = {}


class StartReq(BaseModel):
    prompt: str


class MsgReq(BaseModel):
    text: str


def _get(sid: str) -> dict:
    s = SESS.get(sid)
    if not s:
        raise HTTPException(404, "no such session")
    return s


def _llm(messages, max_new=2048, temp=0.5) -> str:
    sys = PLANNER_SYS + PLANNER_NOTE
    r = requests.post(BASE.rstrip("/") + "/chat/completions", json={
        "model": MODEL, "messages": [{"role": "system", "content": sys}] + messages,
        "max_tokens": max_new, "temperature": temp, "stream": False,
        "chat_template_kwargs": {"enable_thinking": False}}, timeout=600)
    r.raise_for_status()
    return (r.json()["choices"][0].get("message") or {}).get("content", "") or ""


def _planner_turn(s: dict) -> str:
    reply = _llm(s["messages"])
    s["messages"].append({"role": "assistant", "content": reply})
    if PLAN_SENTINEL in reply.lower():
        s["phase"] = "awaiting_approval"
        s["plan"] = reply
    elif s["phase"] != "executing":
        s["phase"] = "planning"
    return reply


@app.post("/api/session")
async def start(req: StartReq):
    sid = uuid.uuid4().hex[:8]
    s = {"id": sid, "phase": "planning", "messages": [{"role": "user", "content": req.prompt}],
         "plan": None, "proj": os.path.join(WORK, sid), "created": time.time(), "proc": None}
    SESS[sid] = s
    reply = await run_in_threadpool(_planner_turn, s)
    return {"session_id": sid, "phase": s["phase"], "reply": reply}


@app.post("/api/session/{sid}/message")
async def message(sid: str, req: MsgReq):
    s = _get(sid)
    s["messages"].append({"role": "user", "content": req.text})
    reply = await run_in_threadpool(_planner_turn, s)
    return {"phase": s["phase"], "reply": reply}


@app.post("/api/session/{sid}/approve")
def approve(sid: str):
    s = _get(sid)
    if s.get("proc") is not None:
        return {"phase": s["phase"]}
    os.makedirs(s["proj"], exist_ok=True)
    plan = s.get("plan") or s["messages"][-1]["content"]
    nudge = ("Build EXACTLY this approved plan — nothing more, nothing less (lazy-dev: least code that "
             "delivers it):\n\n" + plan)
    nf = os.path.join(s["proj"], "NUDGE.md")
    open(nf, "w", encoding="utf-8").write(nudge)
    env = dict(os.environ, SPRINT_PROJ=s["proj"], SPRINT_GATE=TARGET, SPRINT_ARCH=ARCH_FILE,
               SPRINT_NUDGE_FILE=nf, SPRINT_FRESH="0", LLM_BASE=BASE, LLM_MODEL=MODEL)
    out = open(os.path.join(s["proj"], "orch_run.out"), "w")
    s["proc"] = subprocess.Popen(["python", "-u", "prismpath/run_sprint.py"], cwd=REPO, env=env,
                                 stdout=out, stderr=subprocess.STDOUT)
    s["phase"] = "executing"
    return {"phase": "executing"}


@app.get("/api/session/{sid}")
def snapshot(sid: str):
    s = _get(sid)
    st = None
    stf = os.path.join(s["proj"], "status.json")
    if os.path.isfile(stf):
        try:
            st = json.load(open(stf))
        except Exception:
            st = None
    return {"id": sid, "phase": s["phase"], "messages": s["messages"], "plan": s.get("plan"),
            "build_status": st}


def _sse(obj) -> str:
    return "data: " + json.dumps(obj) + "\n\n"


@app.get("/api/session/{sid}/events")
async def events(sid: str):
    s = _get(sid)

    async def gen():
        sent, last_status, last_phase, help_seen = 0, None, None, 0
        while True:
            while sent < len(s["messages"]):
                m = s["messages"][sent]; sent += 1
                yield _sse({"type": "message", "role": m["role"], "content": m["content"]})
            if s["phase"] != last_phase:
                last_phase = s["phase"]
                yield _sse({"type": "phase", "phase": s["phase"]})
            helpf = os.path.join(s["proj"], "HELP.md")
            if os.path.isfile(helpf):
                opens = open(helpf, encoding="utf-8").read().count("- [ ]")   # unticked = awaiting supervisor
                if opens != help_seen:
                    help_seen = opens
                    yield _sse({"type": "help", "open": opens})
            stf = os.path.join(s["proj"], "status.json")
            if os.path.isfile(stf):
                try:
                    st = json.load(open(stf))
                except Exception:
                    st = None
                if st and st != last_status:
                    last_status = st
                    yield _sse({"type": "build_status", "status": st})
                    if st.get("done"):
                        yield _sse({"type": "done", "status": st})
                        break
            await asyncio.sleep(1.5)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/session/{sid}/artifact")
def artifact(sid: str):
    s = _get(sid)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in glob.glob(os.path.join(s["proj"], "**", "*"), recursive=True):
            if os.path.isfile(f) and "/node_modules/" not in f:
                z.write(f, os.path.relpath(f, s["proj"]))
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{sid}.zip"'})


@app.get("/api/health")
def health():
    return {"ok": True, "model": MODEL, "target": TARGET, "sessions": len(SESS)}


if __name__ == "__main__":
    os.makedirs(WORK, exist_ok=True)
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("ORCH_PORT", "8771")))
