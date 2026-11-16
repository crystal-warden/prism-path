# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The page's own verifier (U3) as the browser gets it.

The console serves the two portable modules the verifier imports, canon/2 and the RFC 6962 tree, and
nothing else from beside the kernel's corpora. `static/js/verify.mjs` names them by one relative
specifier that reaches the same file on disk (for node) and under the console's URL space (for the
browser). And in a real headless browser on loopback, the receipt card shows two verdicts that do not
lean on each other: a log whose receipt was edited is `console: invalid` and `page: invalid`, and a
console that lies about a receipt (the fixture below rewrites its answer in flight) still says
`console: signed-unpinned` while the page, from the bytes and the key pinned in the page, says
`page: invalid`. The browser check skips without Playwright and its Chromium, which CI does not install."""
import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")
from fastapi.testclient import TestClient  # noqa: E402

from prismpath.ledgers import audit_log, root_statement  # noqa: E402
from prismpath.mission_control import app as app_module  # noqa: E402
from prismpath.mission_control import core  # noqa: E402

PACKAGE = Path(__file__).resolve().parent.parent
REPO = PACKAGE.parent
JS = PACKAGE / "mission_control" / "static" / "js"
PORTABLE = PACKAGE / "portable"
SERVED = ("canon2.mjs", "merkle.mjs")


def _client():
    application = app_module.create_app()
    return TestClient(application, base_url=f"http://127.0.0.1:{core.SETTINGS.port}")


@pytest.mark.parametrize("name", SERVED)
def test_the_portable_modules_the_verifier_imports_are_served_as_javascript(name):
    response = _client().get(f"/portable/{name}")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/javascript")
    assert response.content == (PORTABLE / name).read_bytes()
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("name", ["prismpath.mjs", "run_vectors.mjs", "conformance/receipts.json", "..%2Fcanon.py",
                                  "gen_receipt_fixtures.py", "absent.mjs"])
def test_nothing_else_beside_the_corpora_is_served(name):
    assert _client().get(f"/portable/{name}").status_code == 404


def test_the_verifier_reaches_the_same_modules_on_disk_and_under_the_console():
    """A browser resolves `../../../portable/x` from /js/verify.mjs to /portable/x (a URL path cannot climb
    above its root), and node resolves it from static/js/ to prismpath/portable/x."""
    specifiers = re.findall(r'from "(\.\./[^"]*portable/[^"]+)"', (JS / "verify.mjs").read_text(encoding="utf-8"))
    assert sorted({spec.rsplit("/", 1)[1] for spec in specifiers}) == sorted(SERVED)
    for spec in specifiers:
        assert urllib.parse.urlparse(urllib.parse.urljoin("http://127.0.0.1:1/js/verify.mjs", spec)).path \
            == "/portable/" + spec.rsplit("/", 1)[1]
        assert (JS / spec).resolve() == (PORTABLE / spec.rsplit("/", 1)[1]).resolve()


# ------------------------------------------------------------------------------------ the headless check
def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _signed_log(path, key):
    log = audit_log.AuditLog(str(path), instance_key=key, sign_appends=True)
    for code, outcome in ((2, "refuse"), (0, "route"), (34, "escalate")):
        log.append("engine", "decision", {"outcome": outcome, "cause": code, "rule": "r1"})


def _edit_receipt(line: bytes) -> bytes:
    edited = line.replace(b'"outcome":"route"', b'"outcome":"refuse"')
    assert edited != line
    return edited


@pytest.fixture
def console(tmp_path):
    """A console on a free loopback port over an evidence root holding a signed log and a copy of it whose
    receipt 1 was edited after signing, with the instance public key."""
    pytest.importorskip("playwright.sync_api")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    made = root_statement.keygen(str(tmp_path / "keys"), "instance")
    _signed_log(evidence / "good.audit.jsonl", root_statement.InstanceKey.load(made["private"]))
    lines = (evidence / "good.audit.jsonl").read_bytes().split(b"\n")
    lines[1] = _edit_receipt(lines[1])
    (evidence / "edited.audit.jsonl").write_bytes(b"\n".join(lines))
    (evidence / "edited.audit.roots.jsonl").write_bytes((evidence / "good.audit.roots.jsonl").read_bytes())
    port = _free_port()
    state = tmp_path / "state"
    env = dict(os.environ, MC_PORT=str(port), MC_HOST="127.0.0.1", MC_EVIDENCE=str(evidence), MC_STATE_DIR=str(state),
               MC_AUDIT=str(state / "console_audit.log"), MC_PROJ=str(tmp_path), MC_SCAN=str(tmp_path / "status.json"),
               PYTHONPATH=str(REPO) + os.pathsep + os.environ.get("PYTHONPATH", ""), PYTHONDONTWRITEBYTECODE="1")
    server = subprocess.Popen([sys.executable, "-m", "prismpath.mission_control"], env=env, cwd=str(tmp_path),
                              stdout=open(tmp_path / "console.log", "w"), stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}/"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(url, timeout=2).read()
                break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("the console did not start: " + (tmp_path / "console.log").read_text())
        public = Path(made["public"]).read_bytes()
        yield {"url": url, "pin": {"label": "instance", "hex": public.hex(),
                                   "keyId": root_statement.key_id_of(public)}}
    finally:
        server.terminate()
        server.wait(timeout=10)


def _receipt_card(page, console, log_name, index):
    """Open the Trails screen, pick the log, open one receipt and wait for the page's own verdict."""
    page.goto(console["url"])
    page.evaluate("pin => sessionStorage.setItem('prismpath.pinned-keys', JSON.stringify([pin]))", console["pin"])
    page.click('[data-interface="auditing"].iface')
    page.click('[data-screen="trails"]')
    page.click(f'#tr-list [data-trail$="/{log_name}"]')
    page.fill("#rc-index", str(index))
    page.click("#rc-go")
    page.wait_for_function("() => /page: (?!checking)/.test(document.querySelector('#rc-out').textContent)", timeout=15000)
    chips = page.locator("#rc-out .verdict-line .chip").all_text_contents()
    return {chip.split(":", 1)[0]: chip for chip in chips}


def _launch(driver):
    """Playwright's own headless Chromium, else one an earlier Playwright left in its cache (it drives the
    same protocol), else a skip: nothing is downloaded here."""
    try:
        return driver.chromium.launch(headless=True)
    except Exception as missing:
        cache = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or Path.home() / ".cache" / "ms-playwright")
        for shell in sorted(cache.glob("chromium_headless_shell-*/chrome-linux/headless_shell"), reverse=True):
            try:
                return driver.chromium.launch(headless=True, executable_path=str(shell))
            except Exception:
                continue
        pytest.skip(f"no headless Chromium: {str(missing).splitlines()[0]}")


def test_a_headless_browser_gives_the_page_its_own_verdict(console):
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as driver:
        browser = _launch(driver)
        try:
            page = browser.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))

            good = _receipt_card(page, console, "good.audit.jsonl", 1)
            assert good["console"] == "console: signed-unpinned", good
            assert good["page"] == "page: signed", good

            edited = _receipt_card(page, console, "edited.audit.jsonl", 1)
            assert edited["console"] == "console: invalid", edited
            assert edited["page"].startswith("page: invalid ("), edited

            # A console that lies: its answer for the good log is rewritten in flight to carry the edited
            # receipt's bytes and event, while its verdict still says signed.
            def lie(route):
                answer = route.fetch()
                view = answer.json()
                line = _edit_receipt(base64.b64decode(view["raw"]["b64"]))
                view["raw"] = {"b64": base64.b64encode(line).decode(), "text": line.decode()}
                view["event"] = json.loads(line)
                route.fulfill(response=answer, body=json.dumps(view), headers={**answer.headers, "content-type": "application/json"})
            page.route("**/api/v1/evidence/receipt", lie)
            lied = _receipt_card(page, console, "good.audit.jsonl", 1)
            assert lied["console"] == "console: signed-unpinned", lied
            assert lied["page"].startswith("page: invalid ("), lied
            page.unroute("**/api/v1/evidence/receipt")

            # With no key pinned the page names that rather than trusting the key the statement carries.
            page.evaluate("() => sessionStorage.removeItem('prismpath.pinned-keys')")
            page.click("#rc-go")
            page.wait_for_function("() => /page: (?!checking)/.test(document.querySelector('#rc-out').textContent)")
            assert "page: unpinned" in page.locator("#rc-out .verdict-line").text_content()
            assert errors == []
        finally:
            browser.close()
