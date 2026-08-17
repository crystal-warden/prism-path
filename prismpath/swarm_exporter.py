# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Observability for the prismpath Hermes swarm — Prometheus metrics + a polished live "glass lens".

Two surfaces, one stdlib http.server (no external deps), re-reading state on every request so it
tracks whatever sprint SWARM_PROJ points at:

  GET /metrics        Prometheus text  (numeric state: iteration, gate, files, help, role memory)
  GET /               the GLASS LENS — a polished, auto-refreshing view of the actual agent
                      interactions (every prompt sent + output received), human-readable, with
                      the repeated GOAL/ARCH/BLUEPRINT boilerplate folded away.
  GET /interactions   JSON feed backing the lens (status summary + recent interaction events).

Interaction events are written by prismpath/interactions.py at the three model tap points
(served chat, swarm dispatch, cecli) to  $SWARM_PROJ/interactions.jsonl.

Run:  SWARM_PROJ=/tmp/demo python -u prismpath/swarm_exporter.py   # binds 0.0.0.0:9108
"""
import glob
import html
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROJ = os.environ.get("SWARM_PROJ", "/tmp/demo")
ROLES_DIR = os.path.expanduser(os.environ.get("HERMES_ROLES_DIR", "~/.hermes-roles"))
PORT = int(os.environ.get("SWARM_EXPORTER_PORT", "9108"))
ROLES = ["architect", "coder", "test-author", "fixer", "critic"]
_PHASES = ["architect", "ideate", "build", "fix", "test-author", "review", "delete", "reflect"]
INTER_PATH = os.path.join(PROJ, "interactions.jsonl")
MAX_EVENTS = int(os.environ.get("SWARM_LENS_EVENTS", "300"))


def _esc(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")[:160]


def collect():
    out = []

    def g(name, val, labels=""):
        out.append(f'{name}{{{labels}}} {val}' if labels else f'{name} {val}')

    st = {}
    sp = os.path.join(PROJ, "status.json")
    if os.path.isfile(sp):
        try:
            st = json.load(open(sp))
        except Exception:
            st = {}
    g("swarm_iteration", st.get("iteration", 0) or 0)
    g("swarm_elapsed_seconds", st.get("elapsed_s", 0) or 0)
    g("swarm_valid", 1 if st.get("valid") else 0)
    g("swarm_done", 1 if st.get("done") else 0)
    g("swarm_files", len(st.get("files", []) or []))
    g("swarm_biggest_tokens", st.get("biggest_tok", 0) or 0)
    g("swarm_help_count_total", st.get("help_count", 0) or 0)

    log = ""
    lp = os.path.join(PROJ, "sprint.log")
    if os.path.isfile(lp):
        log = open(lp, errors="ignore").read()
    for kind in _PHASES:
        g("swarm_log_events", log.count(f"[{kind}]"), f'kind="{kind}"')
    phases = re.findall(r"\[(" + "|".join(_PHASES) + r")\]", log)
    phase = phases[-1] if phases else "init"
    decisions = re.findall(r"\[(?:review)\][^\n]*?([\w./\-]+\.(?:js|mjs|html|css))", log)
    target = decisions[-1] if decisions else ((st.get("files") or ["—"])[-1])
    g("swarm_current", 1,
      f'phase="{_esc(phase)}",target="{_esc(target)}",last_error="{_esc(st.get("last_error") or "none")}"')

    hp = os.path.join(PROJ, "HELP.md")
    htxt = open(hp, errors="ignore").read() if os.path.isfile(hp) else ""
    g("swarm_help_open", htxt.count("- [ ]"))
    g("swarm_help_resolved", htxt.count("- [x]"))

    now = time.time()
    for role in ROLES:
        home = os.path.join(ROLES_DIR, role)
        mem = os.path.join(home, "memories", "MEMORY.md")
        lessons = sum(1 for ln in open(mem, errors="ignore") if ln.strip().startswith("- ")) \
            if os.path.isfile(mem) else 0
        g("swarm_role_lessons", lessons, f'role="{role}"')
        db = os.path.join(home, "state.db")
        g("swarm_role_sessions_bytes", os.path.getsize(db) if os.path.isfile(db) else 0, f'role="{role}"')
        mtime = os.path.getmtime(db) if os.path.isfile(db) else (
            os.path.getmtime(home) if os.path.isdir(home) else now)
        g("swarm_role_idle_seconds", int(now - mtime), f'role="{role}"')

    g("swarm_up", 1)
    return "\n".join(out) + "\n"


# --------------------------------------------------------------- the glass lens
# Markers that begin the repeated boilerplate prefix in coder/fixer prompts; everything from the
# first hit to the real task tail is folded into a "[context]" chip so the human sees the signal.
_BOILER = re.compile(r"(PROJECT GOAL|APPROVED BLUEPRINT|architecture contract|"
                     r"You are building a single-page)", re.I)


def _fold(text, head=220, tail=1100):
    """Collapse a long, boilerplate-heavy prompt: keep a short head + the task-bearing tail."""
    text = text or ""
    n = len(text)
    if n <= head + tail + 40:
        return {"preview": text, "folded": 0, "full": text[:9000]}
    return {"preview": text[:head] + f"\n\n   …[{n - head - tail} chars of context folded]…\n\n" + text[-tail:],
            "folded": n - head - tail, "full": text[:9000]}


def read_interactions(limit=MAX_EVENTS):
    st = {}
    sp = os.path.join(PROJ, "status.json")
    if os.path.isfile(sp):
        try:
            st = json.load(open(sp))
        except Exception:
            st = {}
    events = []
    if os.path.isfile(INTER_PATH):
        try:
            lines = open(INTER_PATH, errors="ignore").read().splitlines()
        except Exception:
            lines = []
        for ln in lines[-limit:]:
            try:
                e = json.loads(ln)
            except Exception:
                continue
            p, o = _fold(e.get("prompt", "")), _fold(e.get("output", ""), head=0, tail=2200)
            events.append({
                "ts": e.get("ts"), "kind": e.get("kind", "?"), "role": e.get("role", ""),
                "phase": e.get("phase", ""), "dur_ms": e.get("dur_ms", 0),
                "prompt_len": e.get("prompt_len", len(e.get("prompt", ""))),
                "output_len": e.get("output_len", len(e.get("output", ""))),
                "rc": e.get("rc"), "focus": e.get("focus", ""),
                "prompt": p["preview"], "prompt_full": p["full"],
                "output": o["preview"], "output_full": o["full"],
            })
    summary = {
        "iteration": st.get("iteration", 0), "valid": bool(st.get("valid")),
        "files": len(st.get("files", []) or []), "elapsed_s": st.get("elapsed_s", 0),
        "help_open": st.get("help_open"), "last_error": (st.get("last_error") or "")[:300],
        "done": bool(st.get("done")), "model": st.get("model", ""),
        "proj": os.path.basename(PROJ), "count": len(events),
    }
    return {"summary": summary, "events": events}


GLASS_HTML = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Hermes Swarm · Glass Lens</title>
<style>
:root{--bg:#0b0f17;--panel:#121826cc;--panel2:#0f1420;--line:#1f2a3a;--ink:#e6edf6;--dim:#8da2bd;
--accent:#7cc7ff;--mono:'JetBrains Mono',ui-monospace,'SF Mono',Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#16203200,#0b0f17),var(--bg);
color:var(--ink);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{position:sticky;top:0;z-index:5;backdrop-filter:blur(10px);
background:linear-gradient(#0b0f17ee,#0b0f17b0);border-bottom:1px solid var(--line);padding:12px 18px}
.row{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
h1{font-size:15px;letter-spacing:.3px;margin:0;font-weight:650}
h1 .lens{color:var(--accent)}
.chip{font:12px/1 var(--mono);padding:5px 9px;border:1px solid var(--line);border-radius:999px;
background:var(--panel2);color:var(--dim);white-space:nowrap}
.chip b{color:var(--ink);font-weight:600}
.chip.ok{color:#5fd08a;border-color:#1f4030}.chip.bad{color:#ff8da0;border-color:#43212b}
.chip.warn{color:#e0b25f;border-color:#473a1e}
.spacer{flex:1}
.filters{margin-top:10px;gap:8px}
.tog{cursor:pointer;font:11px/1 var(--mono);padding:5px 10px;border-radius:7px;border:1px solid var(--line);
background:var(--panel2);color:var(--dim);user-select:none}
.tog.on{color:#0b0f17;font-weight:700}
#q{flex:1;min-width:160px;background:var(--panel2);border:1px solid var(--line);border-radius:7px;
color:var(--ink);padding:6px 10px;font:12px var(--mono);outline:none}
main{max-width:1080px;margin:0 auto;padding:16px 18px 80px}
.card{border:1px solid var(--line);border-left:3px solid var(--rc,#445);border-radius:11px;
margin:10px 0;background:var(--panel);overflow:hidden;box-shadow:0 1px 0 #ffffff08 inset}
.chead{display:flex;align-items:center;gap:10px;padding:9px 13px;cursor:pointer;flex-wrap:wrap}
.badge{font:10px/1 var(--mono);font-weight:700;letter-spacing:.4px;padding:4px 7px;border-radius:6px;
text-transform:uppercase;color:#0b0f17;background:var(--rc,#445)}
.role{font-weight:650;color:var(--ink)}
.meta{font:11px var(--mono);color:var(--dim)}
.t{font:11px var(--mono);color:#6f86a6}
.body{display:none;border-top:1px solid var(--line);padding:4px 13px 12px}
.card.open .body{display:block}
.seg{margin-top:9px}
.lbl{font:10px var(--mono);letter-spacing:.6px;color:var(--dim);text-transform:uppercase;margin:6px 0 3px}
pre{margin:0;white-space:pre-wrap;word-break:break-word;font:12px/1.55 var(--mono);
background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;max-height:340px;
overflow:auto;color:#cdd9ea}
pre.out{color:#bfe6cf}
.fold{color:#6f86a6;font-style:italic}
.empty{color:var(--dim);text-align:center;padding:60px 0;font:13px var(--mono)}
.pulse{width:8px;height:8px;border-radius:50%;background:#5fd08a;box-shadow:0 0 8px #5fd08a;animation:p 1.6s infinite}
@keyframes p{0%,100%{opacity:.35}50%{opacity:1}}
</style></head><body>
<header>
 <div class=row>
  <span class=pulse id=pulse></span>
  <h1>Hermes Swarm <span class=lens>· Glass Lens</span></h1>
  <span class=chip id=c-proj>proj —</span>
  <span class=chip id=c-it>it —</span>
  <span class=chip id=c-gate>gate —</span>
  <span class=chip id=c-files>files —</span>
  <span class=chip id=c-help>help —</span>
  <span class=spacer></span>
  <span class=chip id=c-count>0 turns</span>
 </div>
 <div class="row filters">
  <span class=tog data-k=served>served</span>
  <span class=tog data-k=swarm>swarm</span>
  <span class=tog data-k=cecli>cecli</span>
  <input id=q placeholder="filter by role / phase / text…">
 </div>
</header>
<main><div id=feed></div><div class=empty id=empty>waiting for interactions… (start a sprint)</div></main>
<script>
const RC={architect:'#8b9cff',coder:'#5fd08a','test-author':'#e0b25f',fixer:'#ff8da0',critic:'#5fc8e0',
 retriever:'#9bd9a0',build:'#b48bff',fix:'#ff9e7a','?':'#5a6b86'};
const hide=new Set();   // kinds toggled OFF
let openKeys=new Set(); // remember expanded cards across refresh
const esc=s=>(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function fmtTs(t){if(!t)return'';const d=new Date(t*1000);return d.toLocaleTimeString([], {hour12:false})+'.'+String(d.getMilliseconds()).padStart(3,'0').slice(0,2);}
function fmtDur(ms){if(!ms)return'';return ms<1000?ms+'ms':(ms/1000).toFixed(1)+'s';}
function key(e){return (e.ts||'')+'|'+e.kind+'|'+e.role+'|'+(e.prompt_len||0);}
document.querySelectorAll('.tog').forEach(t=>{t.classList.add('on');t.style.background=RC[t.dataset.k]||RC['?'];
 t.onclick=()=>{const k=t.dataset.k;if(hide.has(k)){hide.delete(k);t.classList.add('on');t.style.background=RC[k]||'#445';}
  else{hide.add(k);t.classList.remove('on');t.style.background='';}render();};});
document.getElementById('q').oninput=render;
let DATA={summary:{},events:[]};
function setChip(id,txt,cls){const el=document.getElementById(id);el.textContent=txt;el.className='chip'+(cls?' '+cls:'');}
function render(){
 const s=DATA.summary||{};
 setChip('c-proj','proj '+(s.proj||'—'));
 setChip('c-it','it '+(s.iteration??'—')+' · '+(s.elapsed_s||0)+'s');
 setChip('c-gate', s.valid?'gate GREEN':'gate RED', s.valid?'ok':'bad');
 setChip('c-files','files '+(s.files??'—'));
 setChip('c-help', s.help_open?('HELP #'+s.help_open):'no help', s.help_open?'warn':'');
 setChip('c-count',(DATA.events||[]).length+' turns');
 const q=document.getElementById('q').value.toLowerCase();
 const evs=(DATA.events||[]).filter(e=>!hide.has(e.kind)).filter(e=>!q ||
   (e.role+' '+e.phase+' '+e.kind+' '+e.prompt+' '+e.output).toLowerCase().includes(q));
 const feed=document.getElementById('feed');
 document.getElementById('empty').style.display=evs.length?'none':'block';
 feed.innerHTML=evs.slice().reverse().map(e=>{
  const k=key(e), open=openKeys.has(k)?' open':'', rc=RC[e.role]||RC[e.kind]||RC['?'];
  const rcline=(e.rc===0||e.rc)?` · rc=${e.rc}`:'';
  const foc=e.focus?` · ${esc(e.focus)}`:'';
  return `<div class="card${open}" data-k="${esc(k)}" style="--rc:${rc}">
   <div class=chead onclick="toggle(this)">
    <span class=badge>${esc(e.kind)}</span>
    <span class=role>${esc(e.role||'')}</span>
    <span class=meta>${esc(e.phase||'')}${rcline}${foc}</span>
    <span class=meta>↑${e.prompt_len||0} ↓${e.output_len||0} · ${fmtDur(e.dur_ms)}</span>
    <span style="flex:1"></span><span class=t>${fmtTs(e.ts)}</span>
   </div>
   <div class=body>
    <div class=seg><div class=lbl>prompt → model</div><pre>${esc(e.prompt)}</pre></div>
    <div class=seg><div class=lbl>← output</div><pre class=out>${esc(e.output)}</pre></div>
   </div></div>`;}).join('');
}
function toggle(head){const c=head.parentElement,k=c.dataset.k;
 c.classList.toggle('open');if(c.classList.contains('open'))openKeys.add(k);else openKeys.delete(k);}
async function tick(){try{const r=await fetch('/interactions');DATA=await r.json();render();
 document.getElementById('pulse').style.background='#5fd08a';}
 catch(e){document.getElementById('pulse').style.background='#ff8da0';}}
tick();setInterval(tick,2000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, ctype):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        try:
            if path.startswith("/metrics"):
                self._send(collect(), "text/plain; version=0.0.4")
            elif path.startswith("/interactions"):
                self._send(json.dumps(read_interactions()), "application/json")
            elif path in ("/", "/glass", "/index.html"):
                self._send(GLASS_HTML, "text/html; charset=utf-8")
            else:
                self._send("prismpath exporter -> / (glass lens) · /metrics · /interactions\n", "text/plain")
        except Exception as e:
            self._send(f"# exporter error: {e}\nswarm_up 0\n", "text/plain")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"swarm exporter on 0.0.0.0:{PORT} watching {PROJ}  (lens: http://127.0.0.1:{PORT}/)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
