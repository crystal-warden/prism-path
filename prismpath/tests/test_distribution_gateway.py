# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""A gateway home that follows a policy stream (spec-policy-distribution.md, section 3, the `gateway` target, and
section 13, grants): the PEP machine over `GatewayHomeAdapter`, with the reverse proxy reading its policy, its route
table and the trust store its grants are verified under from the committed release at every request. Each test names
the conformance case of section 20 it covers."""
import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath import canon  # noqa: E402
from prismpath.agent import commands  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import state_record  # noqa: E402
from prismpath.agent import dist_kind as agent_home  # noqa: E402
from prismpath.gateway.dist_kind import Following, GatewayHomeAdapter  # noqa: E402
from prismpath.distribution.verify import GR2, PepView, verify  # noqa: E402
from prismpath.gateway import cli as gcli, grants, proxy, reading as rd  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import EXPIRES, NOW, STREAM, seal  # noqa: E402
from prismpath.tests.test_gateway import Running, Upstream, receipts  # noqa: E402
from prismpath.tests.test_gateway_grants import older_grant  # noqa: E402

H = canon.sha256_hex
HDR = rd.GRANT_HEADER
DEMO = gcli.DEMO_POLICY.read_bytes().rstrip(b"\n")
ROUTES = rd.Routes.load(gcli.DEMO_ROUTES).canonical()
# the same table with /admin/* read as orders, so a read of /admin/... needs no grant under the demo policy
OPEN = rd.Routes.from_doc({"routes": [{"match": "/admin/*", "class": "orders"},
                                      {"match": "/api/orders/*", "class": "orders"}]}).canonical()


def _read(point, signed):
    return state_record.read(signed, point.key.public_raw)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _write_key(directory: Path, role: str, name: str) -> None:
    """The test key `name` written as the home's `role` key pair: PEM private, raw public."""
    from cryptography.hazmat.primitives import serialization as ser
    private = _dist.GEN.test_key(name)
    (directory / f"{role}.key").write_bytes(private.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                                  ser.NoEncryption()))
    (directory / f"{role}.pub").write_bytes(_dist.GEN.public_raw(private))


@dataclass
class GatewayHome(_dist.Point):
    """A gateway PEP over a real gateway home: the adapter is `GatewayHomeAdapter` and the home holds its instance
    key and no authority key. A release is its `policy.core` and its `gateway.routes`."""
    kind: str = "gateway"
    artifact: str = "policy.core"
    routes: bytes = ROUTES
    authorities: list = field(default_factory=lambda: ["A", "B"])

    def adapter(self):
        return GatewayHomeAdapter(self.state_dir)

    def __post_init__(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        _write_key(self.state_dir, "instance", "I")
        super().__post_init__()

    def args(self, body: bytes, routes: bytes, widens: bool) -> dict:
        release = env.release_id(sorted([("gateway.routes", H(routes)), ("policy.core", H(body))]))
        active = self.pep.active.policy_sha256 if self.pep.active else ""
        return {"release": release, "policy_sha256": H(body), "replaces": active, "widens": widens}

    def stage_routes(self, body: bytes, seq: int, routes: bytes, widens: bool = False):
        """The `gateway.routes` envelope of the release of `body` and `routes` at `seq`, staged alone."""
        args = self.args(body, routes, widens)
        return _read(self, self.pep.stage(seal("gateway.routes", routes, seq=seq, targets=("gateway",), **args), routes))

    def release(self, body: bytes, seq: int, *, routes=None, froms=()):
        """Stage `body` and `routes` at `seq` with a widening statement of `froms`, then commit."""
        routes = routes or self.routes
        args = self.args(body, routes, True)
        statement = _dist.widening(froms)
        acks = [self.pep.stage(seal("trust.widening", statement, seq=seq, targets=("gateway",), **args), statement)]
        for name, data in (("gateway.routes", routes), ("policy.core", body)):
            acks.append(self.pep.stage(seal(name, data, seq=seq, targets=("gateway",), **args), data))
        acks.append(self.pep.commit(STREAM, seq, H(body)))
        return [_read(self, ack) for ack in acks]


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_home.onion_home, "clock", lambda: NOW)
    point = GatewayHome(tmp_path / "gateway")
    assert point.release(DEMO, 1)[-1].event == "committed"
    return point


@pytest.fixture
def owner(tmp_path):
    """Where the owner's authority key is: the test key A, which the gateway's anchor names."""
    directory = tmp_path / "owner"
    directory.mkdir()
    _write_key(directory, "authority", "A")
    return directory


def issue(owner, paths=("admin",), methods=("read",), ttl=600, now=NOW, policy=None, stream=STREAM):
    return grants.issue(owner, policy or H(DEMO), paths, methods, ttl, now=now, stream=stream)


# ------------------------------------------------------------------ the gateway row and its routes (W1)

def test_case_059_a_changed_route_table_is_larger_on_a_gateway_pep(gw):
    """case_059: W1, the gateway half (the agent half is in test_distribution_widening.py). Any change of the route
    table is larger, so a release that changes it without a widening statement is refused, and with one it commits.
    The same table again is not larger."""
    assert gw.stage_routes(DEMO, 2, OPEN).cause == "dist:widening-unsigned"
    assert gw.stage_routes(DEMO, 3, ROUTES).event == "staged"
    assert gw.release(DEMO, 4, routes=OPEN, froms=[H(DEMO)])[-1].event == "committed"
    assert gw.pep.active.bodies["gateway.routes"] == OPEN


def test_the_gateway_row_needs_its_route_table_and_reads_it_as_the_gateway_does(gw):
    """Section 3: a gateway release needs `policy.core` and `gateway.routes` (C2), and V11 holds a route table to
    `Routes.from_doc` and its canonical spelling."""
    args = gw.args(DEMO, ROUTES, True)
    statement = _dist.widening([])
    gw.pep.stage(seal("trust.widening", statement, seq=2, targets=("gateway",), **args), statement)
    gw.pep.stage(seal("policy.core", DEMO, seq=2, targets=("gateway",), **args), DEMO)
    assert _read(gw, gw.pep.commit(STREAM, 2, H(DEMO))).cause == "dist:incomplete"
    for bad in (canon2.dumps({"routes": [{"match": "/a//b", "class": "x"}]}), canon2.dumps({"routes": "all"}),
                canon2.dumps({"routes": [{"match": "/Admin/*", "class": "admin"}]}), b"{}"):
        assert gw.stage_routes(DEMO, 3, bad, widens=True).cause == "dist:bad-format", bad


# ------------------------------------------------------------------ grants (section 13)

def _reading(gw):
    return Following(gw.state_dir)


def test_case_081_a_grant_envelope_reads_valid_expired_then_invalid_four_ways(gw, owner, monkeypatch):
    """case_081: GR1, GR2, GR3. A grant the owner issued reads valid in scope and in time, expired after its
    lifetime, and invalid for another policy, out of scope, tampered, and once its envelope id is in the signed
    revocation list the PEP applied, which the gateway reads at its next decision."""
    follow = _reading(gw)
    value, doc = issue(owner)

    def read(header, path="admin", method="read"):
        return follow.current().grants.read([header], path, method)

    state, record = read(value)
    assert state == "valid" and record["grant_id"] == doc["grant_id"]
    monkeypatch.setattr(agent_home.onion_home, "clock", lambda: NOW + 600)
    assert read(value)[0] == "expired"
    monkeypatch.setattr(agent_home.onion_home, "clock", lambda: NOW)
    assert read(issue(owner, policy="ab" * 32)[0])[0] == "invalid"                     # another policy
    assert read(value, "orders")[0] == "invalid" and read(value, "admin", "write")[0] == "invalid"   # out of scope
    sealed, _body = (_unb64(part) for part in value.split("."))
    wider = grants.grant_body(["admin"], ["delete", "read", "write"])
    assert read(f"{_b64(sealed)}.{_b64(wider)}")[0] == "invalid"                       # tampered
    gw.revoke(1, envelopes=[doc["grant_id"]])
    assert read(value) == ("invalid", record)                                          # revoked by id


def test_case_100_the_grant_writer_seals_a_distribution_envelope(gw, owner):
    """case_100: L1, the grant half (the other older forms' writers are their pull requests'). `grants.issue` writes
    a `grant` envelope for the target `gateway` on the stream named, `seq` 1, under the policy named, with the body
    of section 13, and the gateway's verifier accepts it by the rules of GR2 alone."""
    value, doc = issue(owner, ttl=3600)
    sealed, body = (_unb64(part) for part in value.split("."))
    envelope_bytes, entries = env.unseal(sealed)
    envelope = env.read(envelope_bytes)
    assert (envelope.artifact, envelope.targets, envelope.stream, envelope.seq) == ("grant", ("gateway",), STREAM, 1)
    assert (envelope.policy_sha256, envelope.not_before, envelope.expires) == (H(DEMO), NOW, NOW + 3600)
    assert envelope.envelope_id == doc["grant_id"] and [kid for kid, _ in entries] == [_dist.key_id("A")]
    assert canon2.loads(body) == {"encoding": "canon/2", "format": "prismpath.dist-grant/1",
                                  "method_classes": ["read"], "path_classes": ["admin"]}
    trust = gw.pep.trust
    assert verify(sealed, body, trust=trust, pep=PepView("gateway", STREAM), now=NOW, rules=GR2).ok
    # a grant is not a release: offered to the PEP it is not one of its artifacts, and as a grant it skips V8
    assert not verify(sealed, body, trust=trust, pep=PepView("gateway", STREAM), now=NOW).ok
    assert _read(gw, gw.pep.stage(sealed, body)).cause == "dist:target-mismatch"
    assert verify(sealed, body, trust=trust, pep=PepView("gateway", "other/stream"), now=NOW,
                  rules=GR2).cause == "dist:target-mismatch"


def test_a_following_gateway_reads_no_older_grant_and_no_grant_for_another_stream(gw, owner, tmp_path):
    """L2: a gateway that has committed a release on its stream refuses the older `prismpath.grant/1` form, even
    signed by its authority, and GR2's V5 takes only a grant for its own stream."""
    follow = _reading(gw)
    older, _doc = older_grant(owner, H(DEMO), ["admin"], ["read"], 600, NOW)
    assert follow.current().grants.read([older], "admin", "read") == ("invalid", None)
    elsewhere, _doc = issue(owner, stream="gateway/other")
    assert follow.current().grants.read([elsewhere], "admin", "read")[0] == "invalid"
    unknown = tmp_path / "unknown"
    unknown.mkdir()
    _write_key(unknown, "authority", "Z")
    assert follow.current().grants.read([issue(unknown)[0]], "admin", "read") == ("invalid", None)


def test_a_grant_whose_lifetime_is_past_thirty_days_is_invalid(gw):
    """GR1: the lifetime is at most 30 days, whatever the envelope's own bound."""
    body = grants.grant_body(["admin"], ["read"])
    envelope_bytes = env.build("grant", body, stream=STREAM, seq=1, policy_sha256=H(DEMO),
                               release=env.release_id([("grant", H(body))]), targets=("gateway",),
                               not_before=NOW - 10, expires=NOW - 10 + grants.MAX_LIFETIME + 1)
    value = f"{_b64(env.seal(envelope_bytes, [_dist.GEN.test_key('A')]))}.{_b64(body)}"
    assert _reading(gw).current().grants.read([value], "admin", "read")[0] == "invalid"


# ------------------------------------------------------------------ the running gateway

def test_a_running_gateway_follows_a_revocation_a_route_change_and_an_expiry(gw, owner, monkeypatch):
    """Section 9, X3, R5, GR3: the gateway is built once and decides many requests. A grant revoked through the
    signed list, a new route table and the release's expiry each take effect at its next request, and every receipt
    names the route table it was read under."""
    up = Upstream()
    g = Running(up, gw.state_dir, routes=None)
    try:
        assert g.gateway.failure is None
        value, doc = issue(owner)
        assert g.request("GET", "/admin/users")[0] == 403
        assert g.request("GET", "/admin/users", headers={HDR: value})[0] == 200
        assert len(agent_home.take_readings(gw.state_dir)) == 2                     # for the PEP's heartbeat (H5)
        gw.revoke(1, envelopes=[doc["grant_id"]])
        assert g.request("GET", "/admin/users", headers={HDR: value})[0] == 403
        assert gw.release(DEMO, 2, routes=OPEN, froms=[H(DEMO)])[-1].event == "committed"
        assert g.request("GET", "/admin/users")[0] == 200
        monkeypatch.setattr(agent_home.onion_home, "clock", lambda: EXPIRES)                   # no file changed, only the time
        status, _headers, body = g.request("GET", "/api/orders/7")
        assert status == 403 and "no longer decides" in json.loads(body)["detail"]
    finally:
        g.close()
        up.close()
    lines = receipts(gw.state_dir)
    assert [line["routes_sha256"] for line in lines] == [H(ROUTES)] * 3 + [H(OPEN)]
    assert [line.get("grant", {}).get("grant_id") for line in lines] == [None, doc["grant_id"], doc["grant_id"], None]


def test_a_running_gateway_refuses_once_its_home_commits_another_policy(gw, monkeypatch):
    """One run is decided by one policy: after a commit of another policy the gateway refuses, saying so, until it
    is started again under the new one."""
    other = canon2.dumps(dict(canon2.loads(DEMO), rules=canon2.loads(DEMO)["rules"][1:]))
    up = Upstream()
    g = Running(up, gw.state_dir, routes=None)
    try:
        assert g.request("GET", "/api/orders/7")[0] == 200
        assert gw.release(other, 2)[-1].event == "committed"
        status, _headers, body = g.request("GET", "/api/orders/7")
        assert status == 403 and "another policy" in json.loads(body)["detail"]
    finally:
        g.close()
        up.close()


def test_a_home_that_follows_a_stream_takes_no_route_table_policy_or_revocation_from_the_command_line(gw, owner):
    """Section 3: the route table, the policy and the revocations of a following home are the stream's, so
    `--routes`, `init`, `grant` and `revoke` are refused there, while `rules` reads the committed release."""
    with pytest.raises(ValueError):
        proxy.Gateway("http://127.0.0.1:9", rd.Routes.from_doc(canon2.loads(ROUTES)), gw.state_dir)
    args = SimpleNamespace(upstream="http://127.0.0.1:9", listen="127.0.0.1:0", routes=str(gcli.DEMO_ROUTES),
                           home=str(gw.state_dir))
    with pytest.raises(SystemExit, match="--routes is refused"):
        gcli.serve(args)
    devnull = open(os.devnull, "w")
    with pytest.raises(commands.AgentError):
        gcli.init(gw.state_dir, None, out=devnull)
    with pytest.raises(commands.AgentError):
        gcli.grant(gw.state_dir, ["admin"], ["read"], 60, False, out=devnull)
    with pytest.raises(commands.AgentError):
        gcli.revoke(gw.state_dir, issue(owner)[1]["grant_id"], out=devnull)
    assert not (gw.state_dir / "authority.key").exists() and not (gw.state_dir / grants.REVOKED_FILE).exists()
    assert gcli.rules(gw.state_dir, True, out=devnull) == 0


def test_a_home_that_holds_its_authority_key_still_needs_its_route_table(tmp_path):
    home = tmp_path / "local"
    assert gcli.init(home, None, out=open(os.devnull, "w")) == 0
    with pytest.raises(ValueError):
        proxy.Gateway("http://127.0.0.1:9", None, home)
    with pytest.raises(SystemExit, match="--routes FILE"):
        gcli.serve(SimpleNamespace(upstream="http://127.0.0.1:9", listen="127.0.0.1:0", routes=None, home=str(home)))


def test_a_gateway_floor_allows_one_exact_route_and_method_and_is_silent_beside_it(tmp_path, monkeypatch):
    """case_187: AF1, AF9 on `gateway`, the `gateway` part: a floor that allows `read` on the class of one exact route allows a read of that path
    with basis `floor` whatever the release says, is silent for a write of it and for a path beside it, and a floor
    route that ends in `*` or a rule with no `method_class` test is `dist:floor-broad`."""
    from prismpath.distribution import floor
    monkeypatch.setattr(agent_home.onion_home, "clock", lambda: NOW)
    point = GatewayHome(tmp_path / "gateway", install_keys=["N1", "N2"], install_threshold=2)
    assert point.release(DEMO, 1)[-1].event == "committed"
    fields = canon2.loads(DEMO)["fields"]

    def core(*rules):
        return canon2.dumps({"fields": fields, "format": "prismpath.core/1", "rules": list(rules)})
    allow = {"target": "allow", "when": ["and", ["cmp", "path_class", "==", ["str", "ledger"]],
                                         ["cmp", "method_class", "==", ["str", "read"]]]}
    routes = rd.Routes.from_doc({"routes": [{"match": "/ledger/today", "class": "ledger"}]}).canonical()
    wide = rd.Routes.from_doc({"routes": [{"match": "/ledger/*", "class": "ledger"}]}).canonical()
    loose = {"target": "allow", "when": ["cmp", "path_class", "==", ["str", "ledger"]]}
    for seq, (policy, table) in enumerate(((core(allow), wide), (core(loose), routes)), 1):
        sent = point.send(point.install_set("install.floor", {"policy.core": policy, "gateway.routes": table}, seq,
                                            widens=True, check=False))
        assert floor.BROAD in [one.cause for one in sent]
    sent = point.send(point.install_set("install.floor", {"policy.core": core(allow), "gateway.routes": routes}, 3,
                                        widens=True))
    assert sent[-1].event == "install-widened"
    reading = {"http_reading_version": 1, "method_class": "read", "body_class": "none", "content_class": "none",
               "query": "none", "grant": "none"}

    def ask(path, method="read"):
        return point.pep.decide(lambda: "release", request={"path": path, "reading": {**reading, "method_class": method}})
    assert ask("/ledger/today")["basis"] == "floor"
    assert ask("/ledger/today", "write")["basis"] == "release"
    assert ask("/ledger/tomorrow")["basis"] == "release"


def test_case_203_a_gateway_route_table_is_held_inside_the_ceiling(tmp_path, monkeypatch):
    """case_203: CL1, CL2, the `gateway` part. A gateway PEP with a ceiling refuses a route table that gives one path
    another class than the ceiling's with `dist:above-ceiling`, and stages one that names fewer routes."""
    monkeypatch.setattr(agent_home.onion_home, "clock", lambda: NOW)
    point = GatewayHome(tmp_path / "gateway", install_keys=["N1", "N2"], install_threshold=2)
    assert point.release(DEMO, 1)[-1].event == "committed"
    ceiling = point.install_set("install.ceiling", {"policy.core": DEMO, "gateway.routes": ROUTES}, 1, widens=False)
    assert point.send(ceiling)[-1].event == "install-applied"
    assert point.stage_routes(DEMO, 2, OPEN, widens=True).cause == "dist:above-ceiling"
    fewer = rd.Routes.from_doc({"routes": [{"match": "/api/orders/*", "class": "orders"}]}).canonical()
    acks = point.release(DEMO, 3, routes=fewer, froms=[H(DEMO)])
    assert [one.event for one in acks] == ["staged", "staged", "staged", "committed"]
