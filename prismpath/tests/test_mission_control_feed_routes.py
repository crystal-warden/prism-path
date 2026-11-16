# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The collector feed's routes in the console: the live view and the live cause series (operating), a
kept session checked again (auditing), their posture, and the event stream's feed notice.

The server is driven through fastapi.testclient only and never bound to an address; the feed client
reads a fake collector on a Unix socket (test_mission_control_feed.FakeCollector)."""
import os

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from prismpath.mission_control import app as app_module  # noqa: E402
from prismpath.mission_control import core, feed, feed_client  # noqa: E402
from prismpath.mission_control.posture import capability  # noqa: E402
from prismpath.mission_control.session import TOKEN_HEADER  # noqa: E402
from prismpath.tests.test_mission_control_feed import (SESSION, FakeCollector, _records, _wait,  # noqa: E402,F401
                                                       short_dir)

API_V1 = "/api/v1"
FEED_ROUTES = {("GET", "/feed/live"), ("GET", "/feed/causes"), ("POST", "/evidence/feed")}


def _client(application):
    return TestClient(application, base_url=f"http://127.0.0.1:{core.SETTINGS.port}",
                      headers={TOKEN_HEADER: application.state.session.token})


@pytest.fixture
def roots(tmp_path, monkeypatch):
    root = tmp_path / "evidence"
    root.mkdir()
    monkeypatch.setattr(core.SETTINGS, "evidence_roots", [str(root)])
    monkeypatch.setattr(core.SETTINGS, "collector_store", "")
    return root


@pytest.fixture
def served(short_dir, roots, monkeypatch):
    """An app whose launch names a fake collector, run as the server runs it (the lifespan starts the
    client), after the collector has sent the whole recorded session."""
    fake = FakeCollector([SESSION], path=os.path.join(short_dir, "f.sock"))
    monkeypatch.setattr(core.SETTINGS, "collector", fake.address)
    application = app_module.create_app(read_only=False)
    with _client(application) as client:
        feed_state = application.state.feed
        assert feed_state is not None
        assert _wait(lambda: feed_state.check is not None and feed_state.check.segments
                     and feed_state.check.segments[0]["ended"] == "eof")
        yield client, application, roots
    assert application.state.feed._thread is None or not application.state.feed._thread.is_alive()
    fake.close()


def test_the_feed_routes_read_and_are_mounted_in_both_postures():
    routes = {(method, route.path) for router in app_module.ROUTERS for route in router.routes
              if hasattr(route, "methods") for method in route.methods}
    assert FEED_ROUTES <= {(method, path) for method, path in routes}
    for router in app_module.ROUTERS:
        for route in router.routes:
            if hasattr(route, "methods") and route.path in {path for _m, path in FEED_ROUTES}:
                assert capability(route) == "read", route.path
    paths = app_module.create_app(read_only=True).openapi()["paths"]
    assert {API_V1 + path for _m, path in FEED_ROUTES} <= set(paths)


def test_no_collector_named_means_no_client_and_the_live_view_says_so(roots, monkeypatch):
    monkeypatch.setattr(core.SETTINGS, "collector", "")
    application = app_module.create_app(read_only=False)
    assert application.state.feed is None
    with _client(application) as client:
        live = client.get(API_V1 + "/feed/live").json()
        assert live["connection"] == "off" and "MC_COLLECTOR" in live["reason"]
        series = client.get(API_V1 + "/feed/causes").json()
        assert series["source"] == "live" and series["buckets"] == [] and series["connection"] == "off"


def test_the_read_only_posture_connects_to_no_collector(short_dir, roots, monkeypatch):
    fake = FakeCollector([SESSION], path=os.path.join(short_dir, "f.sock"))
    monkeypatch.setattr(core.SETTINGS, "collector", fake.address)
    try:
        application = app_module.create_app(read_only=True)
        assert application.state.feed is None
        with _client(application) as client:
            live = client.get(API_V1 + "/feed/live").json()
            assert live["connection"] == "off" and "read-only" in live["reason"]
        assert fake.connections == 0
        assert not os.path.exists(roots / "collector-feed")
    finally:
        fake.close()


def test_a_non_loopback_endpoint_is_refused_at_launch(roots, monkeypatch):
    monkeypatch.setattr(core.SETTINGS, "collector", "tcp:192.0.2.10:9300")
    application = app_module.create_app(read_only=False)
    assert application.state.feed is None
    with _client(application) as client:
        assert "loopback" in client.get(API_V1 + "/feed/live").json()["reason"]


def test_the_live_view_shows_decisions_counters_and_the_chain(served):
    client, _application, _roots = served
    live = client.get(API_V1 + "/feed/live", params={"limit": 3}).json()
    assert live["connection"] in ("waiting", "connecting", "connected")
    assert [entry["index"] for entry in live["recent"]] == [20, 19, 18]
    decision = live["recent"][2]
    assert decision["kind"] == "decision" and decision["cause"]["label"] == "32 route:no-matching-edge"
    assert decision["outcome_name"] == "drop_policy" and decision["reading"]["cmd"]
    assert live["enforcer"]["counters"] == {"allow": "11", "drop": "7", "malformed": "2", "other": "0"}
    assert live["enforcer"]["loaded"] == 1 and live["feed"]["dropped"] == 0
    assert live["chain"]["status"] == "intact" and live["statement"] == "collector seal, unsigned"
    assert client.get(API_V1 + "/feed/live", params={"limit": 9999}).status_code == 422


def test_the_live_series_has_the_cause_monitors_shape(served):
    client, _application, _roots = served
    series = client.get(API_V1 + "/feed/causes", params={"bucket_s": 3600}).json()
    assert set(series) >= {"bucket_s", "events", "untimed", "buckets", "causes", "verdict_of", "path"}
    assert series["events"] == 21 and series["clock"] == "arrival"
    assert all(set(bucket) == {"start", "by_cause", "by_action"} for bucket in series["buckets"])
    assert sum(bucket["by_cause"].get("32", 0) for bucket in series["buckets"]) == 4
    assert series["causes"]["32"]["class"] == "routing"
    assert client.get(API_V1 + "/feed/causes", params={"bucket_s": 0}).status_code == 400


def test_a_kept_session_is_checked_again_through_the_auditing_route(served, tmp_path):
    client, _application, roots = served
    session = _records(SESSION)[0]["session"]
    report = client.post(API_V1 + "/evidence/feed", json={"path": f"collector-feed/{session}"}).json()
    assert report["status"] == "intact" and report["verdict_of"] == "console"
    assert report["statement"] == "collector seal, unsigned" and report["signed"] is False
    assert report["files"][0]["segment"] == 0 and report["files"][0]["ended"] == "eof"
    listed = client.get(API_V1 + "/evidence/logs").json()["feeds"]
    assert [entry["session"] for entry in listed] == [session]
    outside = client.post(API_V1 + "/evidence/feed", json={"path": str(tmp_path)})
    assert outside.status_code == 403 and outside.json()["error"]["reason"] == "outside-roots"
    assert client.post(API_V1 + "/evidence/feed", json={"path": f"collector-feed/{session}", "segment": 9}).status_code == 400
    # a field the route does not name is refused, as every auditing body is
    assert client.post(API_V1 + "/evidence/feed", json={"path": "x", "key": "00"}).status_code == 422


def test_the_event_stream_names_a_feed_change(served):
    _client_, application, _roots = served
    from prismpath.mission_control import events
    import asyncio
    import json

    class _Request:
        app = application

        async def is_disconnected(self):
            return False

    async def first_feed_event():
        response = await events.events(_Request())
        async for chunk in response.body_iterator:
            text = chunk if isinstance(chunk, str) else chunk.decode()
            payload = json.loads(text[len("data: "):])
            if payload["type"] == "feed":
                return payload
    payload = asyncio.run(asyncio.wait_for(first_feed_event(), 10))
    assert payload["connection"] in ("connecting", "connected", "waiting")


def test_the_page_lists_the_feed_paths_as_reads():
    from prismpath.tests.test_mission_control_client import _table, _write_routes
    paths = _table("paths.mjs", "PATHS")
    assert {"feedLive": "/feed/live", "feedCauses": "/feed/causes", "evidenceFeed": "/evidence/feed"}.items() <= paths.items()
    assert not {f"{method} {path}" for method, path in FEED_ROUTES} & _write_routes()
    assert feed.VERDICT_OF == "console"
