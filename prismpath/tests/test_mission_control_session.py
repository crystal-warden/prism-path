# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Mission Control's security floor: no request reaches a route unless it comes from the page the
console served, in the browser it served it to, over the host it was bound to.

Each test is one of the measurements the Mission Control plan made against the console (section 2.3)
or one of the WP0 guarantees. A form POST from another site, a request under a foreign `Host` (DNS
rebinding), a request without the session token, a project selected from anywhere on disk, a project
that moves under a request, and the `/tmp` defaults are all refused or gone. The server is driven
through fastapi.testclient only and never bound to an address."""
import json
import os
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from prismpath.ledgers import audit_log  # noqa: E402
from prismpath.mission_control import app as app_module  # noqa: E402
from prismpath.mission_control import config as mc_config  # noqa: E402
from prismpath.mission_control import core  # noqa: E402

try:
    from prismpath.mission_control import session
except ImportError:                       # main before WP0: the tests below fail on their assertions
    session = None

API_V1 = "/api/v1"
HEADER = "X-PrismPath-Session"
FLOW = "---\nname: f\nstart: a\n---\n## a\n-> b: when score > 5\n-> c: else\n## b\nDone.\n## c\nDone.\n"


def _token():
    live = getattr(app_module.app.state, "session", None)
    return live.token if live is not None else "no-session-on-this-build"


def _origin():
    return f"http://127.0.0.1:{core.SETTINGS.port}"


def _project(root, name, iteration, paused=False):
    project = root / name
    (project / "flows").mkdir(parents=True)
    (project / "flows" / f"{name}.md").write_text(FLOW, encoding="utf-8")
    (project / "status.json").write_text(json.dumps({"iteration": iteration, "valid": True}), encoding="utf-8")
    if paused:
        (project / "PAUSE").write_text("", encoding="utf-8")
    return project


@pytest.fixture
def proj(tmp_path):
    return _project(tmp_path / "sprints", "alpha", 1, paused=True)


@pytest.fixture
def raw(proj, tmp_path, monkeypatch):
    """A client on the bound origin that sends no session header of its own."""
    monkeypatch.setattr(core.SETTINGS, "scan", str(tmp_path / "sprints" / "*" / "status.json"))
    monkeypatch.setattr(core.SETTINGS, "registry", str(tmp_path / "no-registry.json"))
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [], raising=False)
    monkeypatch.setattr(core.audit, "LOG", audit_log.AuditLog(str(tmp_path / "audit.log")))
    core.STATE.update({"proc": None, "proj": str(proj), "cfg": {}, "pinned": True})
    return TestClient(app_module.app, base_url=_origin())


@pytest.fixture
def client(raw):
    raw.headers[HEADER] = _token()
    return raw


# ── 2.3 measured: a cross origin form POST reached the handler and dropped STOP ────────────────
def test_a_cross_origin_form_post_to_sprint_stop_is_refused_and_drops_no_marker(raw, proj):
    for headers in ({"Origin": "http://evil.example"},                         # what a browser sends
                    {"Origin": "http://evil.example", HEADER: _token()},       # even with the token
                    {"Origin": "null"}):
        response = raw.post(API_V1 + "/sprint/stop", data={"x": "1"},
                            headers={"Content-Type": "application/x-www-form-urlencoded", **headers})
        assert response.status_code == 403, (headers, response.text)
        assert set(response.json()["error"]) == {"code", "message"}
    assert not (proj / "STOP").exists()
    assert [event for event in core.audit.LOG.events if event.get("action") == "sprint.stop"] == []


def test_the_same_origin_with_the_token_still_stops(client, proj):
    response = client.post(API_V1 + "/sprint/stop", headers={"Origin": _origin()})
    assert response.status_code == 200, response.text
    assert (proj / "STOP").exists()


# ── 2.3 measured: a foreign Host was served (DNS rebinding) ────────────────────────────────────
def _operations(application):
    """(method, path) for every operation the app publishes. Read from the OpenAPI document, which is
    the same on every FastAPI release, where `app.routes` nests included routers on newer ones."""
    return {(method.upper(), path) for path, operations in application.openapi()["paths"].items()
            for method in operations}


def _every_route():
    operations = sorted(_operations(app_module.app))
    assert len(operations) > 30, "the route list is not the console's"
    yield from operations
    for path in ("/", "/index.html", "/js/main.mjs", "/style.css", "/openapi.json"):
        yield "GET", path


@pytest.mark.parametrize("host", ["evil.example", "evil.example:9109", "127.0.0.1", "127.0.0.1:1",
                                  "localhost.evil.example:9109", "127.0.0.1:9109.evil.example"])
def test_a_foreign_host_is_refused_on_every_route(client, host):
    assert session is not None, "no session guard: a foreign Host is served (and /events would stream)"
    for method, path in _every_route():
        response = client.request(method, path, headers={"Host": host})
        assert response.status_code == 403, (method, path, host, response.status_code)
        assert response.json()["error"]["code"] == 403


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]"])
def test_each_loopback_spelling_of_the_bound_port_is_served(client, host):
    response = client.get(API_V1 + "/status", headers={"Host": f"{host}:{core.SETTINGS.port}"})
    assert response.status_code == 200, response.text


# ── the session token ──────────────────────────────────────────────────────────────────────────
def test_an_api_request_without_the_session_header_is_refused_and_with_it_answers(raw):
    assert raw.get(API_V1 + "/status").status_code == 403
    assert raw.get(API_V1 + "/status", headers={HEADER: "wrong"}).status_code == 403
    assert raw.get(API_V1 + "/status", headers={HEADER: ""}).status_code == 403
    assert raw.post(API_V1 + "/prove/level-m", json={"flow": FLOW}).status_code == 403
    assert raw.get(API_V1 + "/status", headers={HEADER: _token()}).status_code == 200


def test_the_events_stream_needs_the_session_header(raw):
    assert session is not None, "no session guard: /events streams to anyone"
    assert raw.get(API_V1 + "/events").status_code == 403


def test_the_token_file_is_owner_only(tmp_path):
    assert session is not None, "no session module"
    live = session.Session.mint()
    state_dir = tmp_path / "state" / "prismpath"
    path = live.write_token_file(str(state_dir), 9109)
    assert Path(path).read_text(encoding="utf-8").strip() == live.token
    if os.name != "nt":
        assert os.stat(path).st_mode & 0o777 == 0o600
        assert os.stat(state_dir).st_mode & 0o077 == 0
    # a file left by an earlier launch with a wider mode is replaced, not reused
    os.chmod(path, 0o644)
    again = session.Session.mint()
    assert again.token != live.token
    path = again.write_token_file(str(state_dir), 9109)
    assert Path(path).read_text(encoding="utf-8").strip() == again.token
    if os.name != "nt":
        assert os.stat(path).st_mode & 0o777 == 0o600


def test_the_token_compare_is_exact(tmp_path):
    assert session is not None, "no session module"
    live = session.Session.mint()
    assert live.matches(live.token)
    assert not live.matches(live.token[:-1]) and not live.matches(None) and not live.matches("")
    assert live.fingerprint and live.token not in live.fingerprint


# ── the page carries the token, the response headers carry the policy ─────────────────────────
def test_index_html_holds_the_session_meta_tag(client):
    page = client.get("/")
    assert page.status_code == 200 and "Mission Control" in page.text
    assert f'<meta name="prismpath-session" content="{_token()}">' in page.text
    assert client.get("/index.html").text == page.text
    with open(os.path.join(core.SETTINGS.package_dir, "static", "index.html"), encoding="utf-8") as shipped:
        assert '<meta name="prismpath-session" content="">' in shipped.read()   # the token is never on disk


def test_the_csp_header_is_on_the_page_and_the_api(client):
    for path in ("/", "/js/main.mjs", API_V1 + "/status"):
        response = client.get(path)
        assert response.status_code == 200, path
        policy = response.headers.get("content-security-policy", "")
        assert policy.startswith("default-src 'self'; img-src 'self' data:; connect-src 'self'"), (path, policy)
        assert "frame-ancestors 'none'" in policy, path
        assert response.headers.get("x-content-type-options") == "nosniff", path
        assert response.headers.get("referrer-policy") == "no-referrer", path
    assert client.get(API_V1 + "/status").headers.get("cache-control") == "no-store"
    assert client.get("/").headers.get("cache-control") == "no-store"          # the page holds the token
    refused = client.get(API_V1 + "/status", headers={"Host": "evil.example"})
    assert refused.headers.get("content-security-policy", "").startswith("default-src 'self'")


def test_the_startup_lines_name_the_url_without_the_token(tmp_path):
    assert session is not None, "no session module"
    live = session.Session.mint()
    lines = session.startup_lines(core.SETTINGS, live, str(tmp_path / "token"), core.audit.LOG)
    text = "\n".join(lines)
    assert f"http://127.0.0.1:{core.SETTINGS.port}/" in text
    assert live.token not in text


# ── the bind host ──────────────────────────────────────────────────────────────────────────────
def test_a_non_loopback_bind_host_is_refused_unless_overridden():
    entry = session
    assert entry is not None and hasattr(entry, "check_bind_host"), "no bind host check"
    for host in ("127.0.0.1", "::1", "localhost", "127.0.0.2"):
        assert entry.check_bind_host(host, {}) is None
    for host in ("0.0.0.0", "::", "192.168.4.2", "example.com"):
        with pytest.raises(SystemExit):
            entry.check_bind_host(host, {})
        warning = entry.check_bind_host(host, {"MC_ALLOW_NON_LOOPBACK": "1"})
        assert warning and "warning" in warning.lower()


# ── the read only posture ─────────────────────────────────────────────────────────────────────
WRITE_ROUTES = {("POST", API_V1 + path) for path in (
    "/sprint/start", "/sprint/select", "/sprint/auto", "/sprint/stop", "/sprint/pause", "/sprint/resume",
    "/queue/decide", "/queue/event", "/file", "/quality/lock")}


def _routes(application):
    return _operations(application)


def test_the_read_only_posture_refuses_every_write_route(proj, tmp_path, monkeypatch):
    assert hasattr(app_module, "create_app"), "no posture: one app, every route mounted"
    full = app_module.create_app(read_only=False)
    assert WRITE_ROUTES <= _routes(full)
    read_only = app_module.create_app(read_only=True)
    assert not (WRITE_ROUTES & _routes(read_only))
    assert not any(path in read_only.openapi()["paths"] and method.lower() in read_only.openapi()["paths"][path]
                   for method, path in WRITE_ROUTES)
    monkeypatch.setattr(core.audit, "LOG", audit_log.AuditLog(str(tmp_path / "audit.log")))
    core.STATE.update({"proc": None, "proj": str(proj), "cfg": {}, "pinned": True})
    reader = TestClient(read_only, base_url=_origin(), headers={HEADER: read_only.state.session.token})
    for method, path in sorted(WRITE_ROUTES):
        response = reader.request(method, path, json={"proj": str(proj), "path": "flows/x.md", "content": "x",
                                                      "id": "x", "choose": "y", "flow_md": "flows/alpha.md",
                                                      "state_dir": "state"})
        assert response.status_code == 403, (path, response.status_code)
        assert "read-only" in response.json()["error"]["message"]
    assert not (proj / "STOP").exists() and not (proj / "flows" / "x.md").exists()
    assert core.audit.LOG.events == []
    assert reader.get(API_V1 + "/status").status_code == 200
    assert reader.post(API_V1 + "/prove/level-m", json={"flow": FLOW}).json()["level_m"] is True
    assert reader.get(API_V1 + "/file", params={"path": "flows/alpha.md"}).status_code == 200


def test_the_read_only_posture_is_read_from_the_environment():
    assert mc_config.Settings.from_environment({"MC_READ_ONLY": "1"}).read_only is True
    assert mc_config.Settings.from_environment({}).read_only is False


# ── project roots ──────────────────────────────────────────────────────────────────────────────
def test_sprint_select_outside_the_roots_is_refused(client, proj, tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    refused = client.post(API_V1 + "/sprint/select", json={"proj": str(elsewhere)})
    assert refused.status_code == 400, refused.text
    assert core.STATE["proj"] == str(proj)
    assert client.post(API_V1 + "/sprint/select", json={"proj": "/"}).status_code == 400
    # a write after a refused select still lands in the followed project, never under the path asked for
    assert client.post(API_V1 + "/file", json={"path": "note.md", "content": "x"}).status_code == 200
    assert not (elsewhere / "note.md").exists() and (proj / "note.md").exists()
    # a discovered sprint is selectable
    beta = _project(tmp_path / "sprints", "beta", 2)
    assert client.post(API_V1 + "/sprint/select", json={"proj": str(beta)}).status_code == 200
    assert core.STATE["proj"] == str(beta)
    # and so is a directory under an evidence root the launch named
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [str(tmp_path / "evidence")], raising=False)
    copy = tmp_path / "evidence" / "copy"
    copy.mkdir(parents=True)
    assert client.post(API_V1 + "/sprint/select", json={"proj": str(copy)}).status_code == 200


def test_a_project_holding_the_consoles_own_files_is_refused(client, tmp_path, monkeypatch):
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [str(tmp_path)], raising=False)
    monkeypatch.setattr(core.audit, "LOG", audit_log.AuditLog(str(tmp_path / "state" / "mission_audit.log")))
    response = client.post(API_V1 + "/sprint/select", json={"proj": str(tmp_path / "state")})
    assert response.status_code == 400, response.text


def test_sprint_start_outside_the_roots_is_refused(client, tmp_path, monkeypatch):
    from prismpath.mission_control import launch
    started = []
    monkeypatch.setattr(launch.subprocess, "Popen", lambda *a, **k: started.append(a))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    response = client.post(API_V1 + "/sprint/start", json={"proj": str(elsewhere)})
    assert response.status_code == 400, response.text
    assert started == [] and not (elsewhere / "mc_sprint.log").exists()


def test_the_settings_have_no_tmp_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    for name in ("MC_PROJ", "MC_SCAN", "MC_STATE_DIR", "MC_EVIDENCE"):
        monkeypatch.delenv(name, raising=False)
    settings = mc_config.Settings.from_environment()
    state_dir = os.path.join(str(tmp_path / "xdg"), "prismpath")
    assert settings.proj == os.path.join(state_dir, "project")          # was /tmp/demo
    assert settings.scan == ""                                          # was /tmp/*/status.json
    assert settings.audit_path == os.path.join(state_dir, "mission_audit.log")
    assert getattr(settings, "evidence_roots", None) == []
    roots = mc_config.Settings.from_environment({"MC_EVIDENCE": os.pathsep.join(["/srv/a", "", "/srv/b"])})
    assert roots.evidence_roots == [os.path.abspath("/srv/a"), os.path.abspath("/srv/b")]


# ── one captured project per request ──────────────────────────────────────────────────────────
def test_status_does_not_move_the_followed_project(client, proj, tmp_path):
    _project(tmp_path / "sprints", "fresher", 9)              # a newer live heartbeat than alpha
    earlier = time.time() - 30
    os.utime(proj / "status.json", (earlier, earlier))
    core.STATE.update({"proj": str(proj), "pinned": False})
    assert client.get(API_V1 + "/status").status_code == 200
    assert core.STATE["proj"] == str(proj)


def test_two_threads_selecting_and_reading_never_see_a_project_change_mid_request(client, proj, tmp_path,
                                                                                    monkeypatch):
    """alpha is paused at iteration 1, beta is running at iteration 2. One thread flips the console
    between them while the other reads /status; every answer must describe one project throughout."""
    from prismpath.mission_control import status as status_module
    beta = _project(tmp_path / "sprints", "beta", 2)
    real_running = status_module.sprint_running

    def slow_running(state):
        time.sleep(0.004)                                     # widen the window between the reads
        return real_running(state)

    monkeypatch.setattr(status_module, "sprint_running", slow_running)
    expected = {str(proj): (1, True), str(beta): (2, False)}
    stop, seen, failures = threading.Event(), [], []

    def flip():
        while not stop.is_set():
            for target in (proj, beta):
                client.post(API_V1 + "/sprint/select", json={"proj": str(target)})

    flipper = threading.Thread(target=flip)
    flipper.start()
    try:
        for _ in range(60):
            answer = client.get(API_V1 + "/status").json()
            seen.append(answer["dir"])
            if expected.get(answer["dir"]) != (answer["iteration"], answer["paused"]):
                failures.append(answer["dir"])
    finally:
        stop.set()
        flipper.join()
    assert len(set(seen)) == 2, "the flipper never moved the project"
    assert failures == [], f"{len(failures)} of {len(seen)} answers mixed two projects"
