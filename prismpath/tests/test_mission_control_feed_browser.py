# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The collector feed's screens in a real browser: the console served on loopback, its feed client
reading a fake collector on a Unix socket, and headless Chromium opening the page the console served.

The live feed screen shows the decisions and the console's verdict over the collector's unsigned seals,
the cause monitor reads the live source, and the auditing card checks the kept session again. Every
request the page makes goes to the console's own loopback origin, and the page logs no error. The test
binds 127.0.0.1 only and skips when Playwright, its Chromium or uvicorn is not installed (CI's jobs install
none of them; it runs where a developer has them, with PRISMPATH_CHROMIUM naming a Chromium binary when
Playwright's own is not downloaded)."""
import os
import socket
import threading

import pytest

pytest.importorskip("fastapi")
uvicorn = pytest.importorskip("uvicorn")
sync_api = pytest.importorskip("playwright.sync_api")

from prismpath.ledgers import audit_log  # noqa: E402
from prismpath.mission_control import app as app_module  # noqa: E402
from prismpath.mission_control import core  # noqa: E402
from prismpath.tests.test_mission_control_feed import SESSION, FakeCollector, _wait, short_dir  # noqa: E402,F401


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def served(short_dir, tmp_path, monkeypatch):
    fake = FakeCollector([SESSION + [("pause", 60)]], path=os.path.join(short_dir, "f.sock"))
    root = tmp_path / "evidence"
    root.mkdir()
    project = tmp_path / "proj"
    project.mkdir()
    port = _free_port()
    monkeypatch.setattr(core.SETTINGS, "collector", fake.address)
    monkeypatch.setattr(core.SETTINGS, "collector_store", "")
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [str(root)])
    monkeypatch.setattr(core.SETTINGS, "port", port)
    monkeypatch.setattr(core.SETTINGS, "registry", str(tmp_path / "no-registry.json"))
    monkeypatch.setattr(core.SETTINGS, "scan", "")
    monkeypatch.setattr(core.audit, "LOG", audit_log.AuditLog(str(tmp_path / "console" / "mission_audit.log")))
    core.STATE.update({"proc": None, "proj": str(project), "cfg": {}, "pinned": True})
    application = app_module.create_app(read_only=False)
    server = uvicorn.Server(uvicorn.Config(application, host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    assert _wait(lambda: server.started, 20), "the console starts on loopback"
    try:
        yield f"http://127.0.0.1:{port}", root
    finally:
        server.should_exit = True
        thread.join(10)
        fake.close()


def test_the_feed_screens_in_a_headless_browser(served):
    origin, _root = served
    with sync_api.sync_playwright() as playwright:
        # PRISMPATH_CHROMIUM names a Chromium binary when the one this Playwright release expects is not
        # downloaded; nothing is downloaded by the test.
        executable = os.environ.get("PRISMPATH_CHROMIUM") or None
        try:
            browser = playwright.chromium.launch(headless=True, executable_path=executable)
        except Exception as error:
            pytest.skip(f"Chromium does not launch: {str(error).splitlines()[0]}")
        try:
            page = browser.new_page()
            errors, foreign = [], []
            page.on("console", lambda message: errors.append((message.text, message.location.get("url")))
                    if message.type == "error" else None)
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: None if request.url.startswith(origin + "/") else foreign.append(request.url))
            failed = []
            page.on("response", lambda response: failed.append(response.url) if response.status >= 400 else None)
            page.goto(origin + "/")
            page.click('[data-interface="operating"]')
            page.click('[data-screen="live"]')
            sync_api.expect(page.locator("#lv-out")).to_contain_text("console: intact", timeout=15000)
            live = page.inner_text("#lv-out")
            assert "collector seal, unsigned" in live and "route:no-matching-edge" in live
            assert "drop_policy" in live and "a policy is loaded" in live
            page.click('[data-screen="monitor"]')
            page.select_option("#cm-source", "live")
            page.fill("#cm-bucket", "60")
            page.click("#cm-go")
            sync_api.expect(page.locator("#cm-out")).to_contain_text("live feed", timeout=10000)
            assert "route:no-matching-edge" in page.inner_text("#cm-out")
            page.click('[data-interface="auditing"]')
            page.click('[data-screen="evidence"]')
            page.click("#fd-live")
            sync_api.expect(page.locator("#fd-out")).to_contain_text("console:", timeout=10000)
            kept = page.inner_text("#fd-out")
            assert "collector seal, unsigned" in kept and "segment" in kept
            assert "console: pending" in kept or "console: intact" in kept
            assert foreign == [], foreign
            assert failed == [], failed
            # The browser asks for /favicon.ico of its own accord and the console serves none.
            assert [error for error in errors if not str(error[1]).endswith("/favicon.ico")] == [], errors
        finally:
            browser.close()
