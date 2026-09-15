# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
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


def token_est(source_text: str) -> int:
    return len(source_text) // 4


_EXP_DECL = re.compile(r"export\s+(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)")
_EXP_BRACE = re.compile(r"export\s*\{([^}]*)\}")
_IMP_NAMED = re.compile(r"import\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?\{([^}]*)\}\s*from\s*['\"]([^'\"]+)['\"]")
_IMP_DEFAULT = re.compile(r"import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s*['\"]([^'\"]+)['\"]")
_IMP_BARE = re.compile(r"import\s*['\"]([^'\"]+)['\"]")


def _exports(src: str):
    names = set(match.group(1) for match in _EXP_DECL.finditer(src))
    for match in _EXP_BRACE.finditer(src):
        for part in match.group(1).split(","):
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
    for js_path in js:
        src_cache[os.path.abspath(js_path)] = open(js_path, encoding="utf-8").read()

    def resolve(importer, spec):
        if not (spec.startswith(".") or spec.startswith("/")):
            return None, "external"
        base = os.path.dirname(importer) if spec.startswith(".") else proj
        resolved_path = os.path.normpath(os.path.join(base, spec.lstrip("/")))
        for cand in (resolved_path, resolved_path + ".js", resolved_path + ".mjs", os.path.join(resolved_path, "index.js")):
            if os.path.isfile(cand):
                return os.path.abspath(cand), None
        return None, "missing"

    for js_path, src in src_cache.items():
        rel = os.path.relpath(js_path, proj)
        for match in _IMP_NAMED.finditer(src):
            names = [raw_name.strip().split(" as ")[0].strip() for raw_name in match.group(1).split(",") if raw_name.strip()]
            tgt, why = resolve(js_path, match.group(2))
            if why == "external":
                errs.append(f"{rel}: external import '{match.group(2)}' not allowed (no CDN/network)")
                continue
            if why == "missing":
                errs.append(f"{rel}: imports from '{match.group(2)}' which does not exist")
                continue
            texp, _tdef, tstar = _exports(src_cache.get(tgt, ""))
            if tstar:
                continue
            for imported_name in names:
                if imported_name not in texp:
                    errs.append(f"{rel}: imports '{imported_name}' not exported by {os.path.relpath(tgt, proj)} "
                                f"(it exports: {', '.join(sorted(texp)) or 'nothing'})")
        for match in _IMP_DEFAULT.finditer(src):
            tgt, why = resolve(js_path, match.group(2))
            if why == "missing":
                errs.append(f"{rel}: imports from '{match.group(2)}' which does not exist")
            elif why is None:
                _, tdef, _ = _exports(src_cache.get(tgt, ""))
                if not tdef:
                    errs.append(f"{rel}: default-imports from {os.path.relpath(tgt, proj)} which "
                                f"has no `export default`")
        for match in _IMP_BARE.finditer(src):
            tgt, why = resolve(js_path, match.group(1))
            if why == "missing":
                errs.append(f"{rel}: imports '{match.group(1)}' which does not exist")
    return errs


def dom_check(proj: str) -> list:
    """Every getElementById/querySelector('#x') id in JS must exist in the HTML (or be JS-created)."""
    errs = []
    html_files = glob.glob(os.path.join(proj, "**", "*.html"), recursive=True)
    if not html_files:
        return errs
    html = "\n".join(open(html_path, encoding="utf-8").read() for html_path in html_files)
    ids = set(re.findall(r"id\s*=\s*['\"]([^'\"]+)['\"]", html))
    js = glob.glob(os.path.join(proj, "**", "*.js"), recursive=True)
    alljs = "\n".join(open(js_path, encoding="utf-8").read() for js_path in js)
    ids |= set(re.findall(r"\.id\s*=\s*['\"]([^'\"]+)['\"]", alljs))
    ids |= set(re.findall(r"setAttribute\(\s*['\"]id['\"]\s*,\s*['\"]([^'\"]+)['\"]", alljs))
    for js_path in js:
        rel = os.path.relpath(js_path, proj)
        src = open(js_path, encoding="utf-8").read()
        refs = set(re.findall(r"getElementById\(\s*['\"]([^'\"]+)['\"]", src))
        refs |= set(re.findall(r"querySelector(?:All)?\(\s*['\"]#([A-Za-z0-9_\-]+)['\"]", src))
        for dom_id in refs:
            if dom_id not in ids:
                errs.append(f"{rel}: references DOM id '#{dom_id}' that does not exist in the HTML "
                            f"(html ids: {', '.join(sorted(ids)) or 'none'})")
    return errs


LOAD_TIMEOUT_MS = 15000     # how long the page gets to fire `load`
SETTLE_MS = 1200            # after load, before the first reading of the DOM
CLICK_TIMEOUT_MS = 3000     # how long one control gets to become clickable
REACTION_WAIT_MS = 2500     # after the button click, before the second reading
CELL_REACTION_WAIT_MS = 1500    # after the grid cell click, before the third reading

# Words that mark the button an app means as its primary action, in the order a reader would guess.
PRIMARY_BUTTON_WORDS = ("send", "submit", "go", "start", "play", "run", "ok", "enter", "approve")

# Grid and board apps take their primary interaction on a cell rather than on a button.
CELL_SELECTORS = ("[data-index]", "[data-cell]", ".cell", "#board > *", ".board > *",
                  ".grid > *", "td")


def _serve(proj: str):
    """Serve proj over loopback on an ephemeral port. Returns (server, port)."""
    import functools
    import http.server
    import socketserver
    import threading
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=proj)

    class Quiet(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

        def handle_error(self, *ignored_args):
            # Deliberate silence: the gate judges the page, and a browser that abandons a request
            # mid flight (navigation, closing) is normal traffic, not a finding about the app.
            pass
    httpd = Quiet(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _primary_button(page):
    """The button the app means as its primary action, else the last button on the page."""
    buttons = page.query_selector_all("button")
    for candidate in buttons:
        button_text = (candidate.inner_text() or "").lower()
        if any(keyword in button_text for keyword in PRIMARY_BUTTON_WORDS):
            return candidate
    return buttons[-1] if buttons else None


def _first_visible_cell(page):
    """The first visible grid cell under any of the known board shapes, or None."""
    from playwright.sync_api import Error as PlaywrightError
    for selector in CELL_SELECTORS:
        for element in page.query_selector_all(selector):
            try:
                if element.is_visible():
                    return element
            except PlaywrightError:
                # Narrow skip: the element was re-rendered out from under the scan, so it is gone
                # rather than broken, and the next candidate is an equally good probe.
                continue
    return None


def _one_line(error) -> str:
    """Playwright errors carry a stack and a call log; a finding wants them on one short line."""
    return " ".join(str(error).split())[:180]


def _inspect_dom(page, requests: list) -> list:
    """Exercise the primary control and report when nothing in the DOM or the network moves."""
    from playwright.sync_api import Error as PlaywrightError
    findings = []
    has_canvas = bool(page.query_selector("canvas"))
    before = page.evaluate("document.body.innerText")
    button = _primary_button(page)
    field = page.query_selector("input, textarea")
    interacted = False
    requests_before = len(requests)
    if button:
        if field:
            try:
                field.fill("behavioral gate test")
            except PlaywrightError:
                # Narrow skip: a field that refuses typed text (readonly, hidden, a custom widget)
                # is not itself a defect, and the click below is the actual probe.
                pass
        try:
            button.click(timeout=CLICK_TIMEOUT_MS)
            interacted = True
        except PlaywrightError as error:
            findings.append(f"the primary control could not be clicked: {_one_line(error)}")
        page.wait_for_timeout(REACTION_WAIT_MS)
    after = page.evaluate("document.body.innerText")
    made_request = len(requests) > requests_before   # a fetch/XHR counts as wired (async backends)
    if not has_canvas and after.strip() == before.strip() and not made_request:
        cell = _first_visible_cell(page)
        if cell:
            try:
                cell.click(timeout=CLICK_TIMEOUT_MS)
                interacted = True
            except PlaywrightError as error:
                findings.append(f"a visible grid cell could not be clicked: {_one_line(error)}")
            page.wait_for_timeout(CELL_REACTION_WAIT_MS)
            after = page.evaluate("document.body.innerText")
            made_request = len(requests) > requests_before
    if interacted and not has_canvas and after.strip() == before.strip() and not made_request:
        findings.append("the primary control produced NO visible change and NO network request after "
                        "clicking it (button and a grid cell) — its handler is likely not wired. Check "
                        "the composition root (input adapter -> app service -> transport/renderer).")
    return findings


def _drive_browser(sync_playwright, port: int) -> list:
    """Load the served page in headless chromium and return everything that went wrong on it."""
    findings = []
    requests = []

    def on_console(message):
        if message.type == "error":
            findings.append(f"console.error: {message.text[:180]}")

    def on_request_failed(request):
        # Only the code and stylesheets the page is built from; a missing favicon is not a defect.
        if request.url.endswith((".js", ".mjs", ".css")):
            findings.append(f"failed to load {request.url.split('/')[-1]}")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.on("pageerror", lambda error: findings.append(f"uncaught: {str(error)[:180]}"))
        page.on("console", on_console)
        page.on("requestfailed", on_request_failed)
        page.on("request", lambda request: requests.append(request.url))
        page.add_init_script("window.__rej=[];addEventListener('unhandledrejection',"
                             "e=>window.__rej.push(String(e.reason&&e.reason.message||e.reason)));")
        page.goto(f"http://127.0.0.1:{port}/", wait_until="load", timeout=LOAD_TIMEOUT_MS)
        page.wait_for_timeout(SETTLE_MS)
        interaction = _inspect_dom(page, requests)
        for rejection in page.evaluate("window.__rej || []"):
            findings.append(f"unhandledrejection: {str(rejection)[:180]}")
        findings += interaction
        browser.close()
    return findings


def behavioral_check(proj: str) -> list:
    """Headless runtime gate: serve, load in chromium, capture JS errors, exercise the primary
    control, assert the DOM reacts. Self-skips (returns []) if playwright is unavailable."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        # Deliberate skip, not a failure: playwright is an optional dev dependency, so a checkout
        # without it still gets the syntax, link and dom layers of the browser gate. Anything the
        # harness raises once it HAS started is a failed gate, handled below.
        return []
    httpd, port = _serve(proj)
    try:
        errs = _drive_browser(sync_playwright, port)
    except Exception as error:
        print(f"    [behavioral] gate infra error (FAILED): {str(error)[:140]}", flush=True)
        errs = [f"gate infrastructure error: {str(error)[:140]}"]
    finally:
        httpd.shutdown()
        httpd.server_close()
    return [f"[behavioral] {problem}" for problem in errs]


def validate_browser(proj: str, tokens_max: int = TOKENS_MAX) -> dict:
    """Full browser gate. Returns {valid, oversized, oversized_file, biggest, biggest_file, errs}."""
    errs, oversized_file, biggest, biggest_file = [], None, 0, None
    paths = (glob.glob(os.path.join(proj, "**", "*.html"), recursive=True)
             + glob.glob(os.path.join(proj, "**", "*.js"), recursive=True)
             + glob.glob(os.path.join(proj, "**", "*.mjs"), recursive=True))
    if not any(path.endswith("index.html") for path in paths):
        errs.append("missing index.html")
    for path in paths:
        rel = os.path.relpath(path, proj)
        src = open(path, encoding="utf-8").read()
        tk = token_est(src)
        if tk > biggest:
            biggest, biggest_file = tk, rel
        if tk > tokens_max and (oversized_file is None
                                or tk > token_est(open(os.path.join(proj, oversized_file)).read())):
            oversized_file = rel
        if path.endswith(".html"):
            if src.lower().count("<script") != src.lower().count("</script>"):
                errs.append(f"{rel}: unclosed <script> (truncated?)")
            if "</html>" not in src.lower():
                errs.append(f"{rel}: missing </html> (truncated?)")
            import html.parser
            try:
                html.parser.HTMLParser().feed(src)
            except Exception as error:
                errs.append(f"{rel}: HTML parse error {str(error)[:120]}")
        else:
            if shutil.which("node"):
                pj = subprocess.run(["node", "--check", path], capture_output=True, text=True,
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
