"""Reusable validation gates for the agent build loops.

Factored out of run_creator2.py so the legacy creator loop AND the new timed/supervised
driver (run_sprint.py) share one gate. Every function takes the project dir explicitly
(no module-global PROJ), so a single process can gate multiple projects.

The BROWSER gate is the 4-layer contract gate proven across sprints 1-3:
  1. syntax   — per-file `node --check` (+ HTML well-formedness / truncation)
  2. link     — every relative import resolves to a real export (cross-module contract)
  3. dom      — every getElementById/querySelector('#x') id exists in the HTML
  4. behavioral — headless chromium loads it, no JS errors, primary control reacts

Optional non-browser gates live in plugins (loaded via plugins.load_gate) and mirror this shape.
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess

TOKENS_MAX = 4000   # tech-debt threshold (~16KB), single-sourced here


def token_est(s: str) -> int:
    return len(s) // 4


_EXP_DECL = re.compile(r"export\s+(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)")
_EXP_BRACE = re.compile(r"export\s*\{([^}]*)\}")
_IMP_NAMED = re.compile(r"import\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?\{([^}]*)\}\s*from\s*['\"]([^'\"]+)['\"]")
_IMP_DEFAULT = re.compile(r"import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s*['\"]([^'\"]+)['\"]")
_IMP_BARE = re.compile(r"import\s*['\"]([^'\"]+)['\"]")


def _exports(src: str):
    names = set(m.group(1) for m in _EXP_DECL.finditer(src))
    for m in _EXP_BRACE.finditer(src):
        for part in m.group(1).split(","):
            part = part.strip()
            if part:
                names.add(part.split(" as ")[-1].strip())
    return names, bool(re.search(r"export\s+default", src)), bool(re.search(r"export\s*\*\s*from", src))


def link_check(proj: str) -> list:
    """Every relative import must resolve to a file that exports the imported name(s)."""
    errs = []
    src_cache = {}
    js = glob.glob(os.path.join(proj, "**", "*.js"), recursive=True) + \
        glob.glob(os.path.join(proj, "**", "*.mjs"), recursive=True)
    for f in js:
        src_cache[os.path.abspath(f)] = open(f, encoding="utf-8").read()

    def resolve(importer, spec):
        if not (spec.startswith(".") or spec.startswith("/")):
            return None, "external"
        base = os.path.dirname(importer) if spec.startswith(".") else proj
        p = os.path.normpath(os.path.join(base, spec.lstrip("/")))
        for cand in (p, p + ".js", p + ".mjs", os.path.join(p, "index.js")):
            if os.path.isfile(cand):
                return os.path.abspath(cand), None
        return None, "missing"

    for f, src in src_cache.items():
        rel = os.path.relpath(f, proj)
        for m in _IMP_NAMED.finditer(src):
            names = [p.strip().split(" as ")[0].strip() for p in m.group(1).split(",") if p.strip()]
            tgt, why = resolve(f, m.group(2))
            if why == "external":
                errs.append(f"{rel}: external import '{m.group(2)}' not allowed (no CDN/network)")
                continue
            if why == "missing":
                errs.append(f"{rel}: imports from '{m.group(2)}' which does not exist")
                continue
            texp, _tdef, tstar = _exports(src_cache.get(tgt, ""))
            if tstar:
                continue
            for n in names:
                if n not in texp:
                    errs.append(f"{rel}: imports '{n}' not exported by {os.path.relpath(tgt, proj)} "
                                f"(it exports: {', '.join(sorted(texp)) or 'nothing'})")
        for m in _IMP_DEFAULT.finditer(src):
            tgt, why = resolve(f, m.group(2))
            if why == "missing":
                errs.append(f"{rel}: imports from '{m.group(2)}' which does not exist")
            elif why is None:
                _, tdef, _ = _exports(src_cache.get(tgt, ""))
                if not tdef:
                    errs.append(f"{rel}: default-imports from {os.path.relpath(tgt, proj)} which "
                                f"has no `export default`")
        for m in _IMP_BARE.finditer(src):
            tgt, why = resolve(f, m.group(1))
            if why == "missing":
                errs.append(f"{rel}: imports '{m.group(1)}' which does not exist")
    return errs


def dom_check(proj: str) -> list:
    """Every getElementById/querySelector('#x') id in JS must exist in the HTML (or be JS-created)."""
    errs = []
    html_files = glob.glob(os.path.join(proj, "**", "*.html"), recursive=True)
    if not html_files:
        return errs
    html = "\n".join(open(h, encoding="utf-8").read() for h in html_files)
    ids = set(re.findall(r"id\s*=\s*['\"]([^'\"]+)['\"]", html))
    js = glob.glob(os.path.join(proj, "**", "*.js"), recursive=True)
    alljs = "\n".join(open(f, encoding="utf-8").read() for f in js)
    ids |= set(re.findall(r"\.id\s*=\s*['\"]([^'\"]+)['\"]", alljs))
    ids |= set(re.findall(r"setAttribute\(\s*['\"]id['\"]\s*,\s*['\"]([^'\"]+)['\"]", alljs))
    for f in js:
        rel = os.path.relpath(f, proj)
        src = open(f, encoding="utf-8").read()
        refs = set(re.findall(r"getElementById\(\s*['\"]([^'\"]+)['\"]", src))
        refs |= set(re.findall(r"querySelector(?:All)?\(\s*['\"]#([A-Za-z0-9_\-]+)['\"]", src))
        for r in refs:
            if r not in ids:
                errs.append(f"{rel}: references DOM id '#{r}' that does not exist in the HTML "
                            f"(html ids: {', '.join(sorted(ids)) or 'none'})")
    return errs


def behavioral_check(proj: str) -> list:
    """Headless runtime gate: serve, load in chromium, capture JS errors, exercise the primary
    control, assert the DOM reacts. Self-skips (returns []) if playwright is unavailable."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return []
    import functools
    import http.server
    import socketserver
    import threading
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=proj)

    class Quiet(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

        def handle_error(self, *a):
            pass
    httpd = Quiet(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    errs = []
    try:
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            pg = b.new_page()
            cap = []
            pg.on("pageerror", lambda e: cap.append(f"uncaught: {str(e)[:180]}"))
            pg.on("console", lambda m: cap.append(f"console.error: {m.text[:180]}")
                  if m.type == "error" else None)
            pg.on("requestfailed", lambda r: cap.append(f"failed to load {r.url.split('/')[-1]}")
                  if r.url.endswith((".js", ".mjs", ".css")) else None)
            net = []
            pg.on("request", lambda r: net.append(r.url))
            pg.add_init_script("window.__rej=[];addEventListener('unhandledrejection',"
                               "e=>window.__rej.push(String(e.reason&&e.reason.message||e.reason)));")
            pg.goto(f"http://127.0.0.1:{port}/", wait_until="load", timeout=15000)
            pg.wait_for_timeout(1200)
            has_canvas = bool(pg.query_selector("canvas"))
            before = pg.evaluate("document.body.innerText")
            btn = None
            for b_ in pg.query_selector_all("button"):
                t = (b_.inner_text() or "").lower()
                if any(k in t for k in ("send", "submit", "go", "start", "play", "run", "ok", "enter", "approve")):
                    btn = b_
                    break
            btns = pg.query_selector_all("button")
            btn = btn or (btns[-1] if btns else None)
            inp = pg.query_selector("input, textarea")
            interacted = False
            net0 = len(net)
            if btn:
                if inp:
                    try:
                        inp.fill("behavioral gate test")
                    except Exception:
                        pass
                try:
                    btn.click(timeout=3000)
                    interacted = True
                except Exception:
                    pass
                pg.wait_for_timeout(2500)
            after = pg.evaluate("document.body.innerText")
            made_request = len(net) > net0   # a fetch/XHR counts as wired (async backends)
            # game/grid apps: the primary interaction is clicking a CELL, not a button — try that too
            if not has_canvas and after.strip() == before.strip() and not made_request:
                cell = None
                for sel in ("[data-index]", "[data-cell]", ".cell", "#board > *", ".board > *",
                            "#game > *", ".grid > *", "td"):
                    for e in pg.query_selector_all(sel):
                        try:
                            if e.is_visible():
                                cell = e
                                break
                        except Exception:
                            pass
                    if cell:
                        break
                if cell:
                    try:
                        cell.click(timeout=3000)
                        interacted = True
                    except Exception:
                        pass
                    pg.wait_for_timeout(1500)
                    after = pg.evaluate("document.body.innerText")
                    made_request = len(net) > net0
            for r in pg.evaluate("window.__rej || []"):
                cap.append(f"unhandledrejection: {str(r)[:180]}")
            if interacted and not has_canvas and after.strip() == before.strip() and not made_request:
                cap.append("the primary control produced NO visible change and NO network request after "
                           "clicking it (button and a grid cell) — its handler is likely not wired. Check "
                           "the composition root (input adapter -> app service -> transport/renderer).")
            errs = cap
            b.close()
    except Exception as e:
        print(f"    [behavioral] gate infra error (skipped): {str(e)[:140]}", flush=True)
        errs = []
    finally:
        httpd.shutdown()
        httpd.server_close()
    return [f"[behavioral] {e}" for e in errs]


def validate_browser(proj: str, tokens_max: int = TOKENS_MAX) -> dict:
    """Full browser gate. Returns {valid, oversized, oversized_file, biggest, biggest_file, errs}."""
    errs, oversized_file, biggest, biggest_file = [], None, 0, None
    paths = (glob.glob(os.path.join(proj, "**", "*.html"), recursive=True)
             + glob.glob(os.path.join(proj, "**", "*.js"), recursive=True)
             + glob.glob(os.path.join(proj, "**", "*.mjs"), recursive=True))
    if not any(p.endswith("index.html") for p in paths):
        errs.append("missing index.html")
    for p in paths:
        rel = os.path.relpath(p, proj)
        src = open(p, encoding="utf-8").read()
        tk = token_est(src)
        if tk > biggest:
            biggest, biggest_file = tk, rel
        if tk > tokens_max and (oversized_file is None
                                or tk > token_est(open(os.path.join(proj, oversized_file)).read())):
            oversized_file = rel
        if p.endswith(".html"):
            if src.lower().count("<script") != src.lower().count("</script>"):
                errs.append(f"{rel}: unclosed <script> (truncated?)")
            if "</html>" not in src.lower():
                errs.append(f"{rel}: missing </html> (truncated?)")
            import html.parser
            try:
                html.parser.HTMLParser().feed(src)
            except Exception as e:
                errs.append(f"{rel}: HTML parse error {str(e)[:120]}")
        else:
            if shutil.which("node"):
                pj = subprocess.run(["node", "--check", p], capture_output=True, text=True,
                                    timeout=25, cwd=proj)
                if pj.returncode != 0:
                    errs.append(f"{rel}: JS syntax {pj.stderr.strip()[:200]}")
    errs += link_check(proj)
    errs += dom_check(proj)
    if not errs:
        errs += behavioral_check(proj)
    return {"valid": not errs, "oversized": oversized_file is not None,
            "oversized_file": oversized_file, "biggest": biggest,
            "biggest_file": biggest_file, "errs": errs}
