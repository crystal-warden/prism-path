# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Grants at the gateway: a signed, scoped, time bounded and revocable authorization, read as the request's
`grant` field, decided by the policy and kept on the receipt's journal line."""
import base64
import json
import os

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.agent import commands  # noqa: E402
from prismpath.gateway import cli as gcli, grants, reading as rd  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402
from prismpath.tests.test_gateway import ROUTES, Running, Upstream, receipts  # noqa: E402

HDR = rd.GRANT_HEADER
NOW = 1_800_000_000


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "gwhome"
    assert gcli.init(h, None, out=open(os.devnull, "w")) == 0
    return h


def policy_sha(home):
    policy, _ = commands.load_checked(home)
    return commands._sha256_hex(policy.image)


def verifier(home, now=NOW):
    return grants.Verifier(commands._key_paths(home, "authority")[1].read_bytes(), policy_sha(home),
                           home / grants.REVOKED_FILE, clock=lambda: now)


def issue(home, paths=("admin",), methods=("read",), ttl=600, now=NOW, **kw):
    return grants.issue(home, kw.pop("sha", None) or policy_sha(home), paths, methods, ttl, now=now, **kw)


# -------------------------------------------------------------------------------------- the verifier
def test_a_grant_reads_valid_only_in_scope_and_in_time(home):
    value, doc = issue(home)
    v = verifier(home)
    state, record = v.read([value], "admin", "read")
    assert state == "valid" and record["grant_id"] == doc["grant_id"]
    assert v.read([value], "orders", "read")[0] == "invalid"               # another route class
    assert v.read([value], "admin", "write")[0] == "invalid"               # another method class
    assert verifier(home, NOW - 1).read([value], "admin", "read")[0] == "invalid"    # not yet in force
    assert verifier(home, NOW + 599).read([value], "admin", "read")[0] == "valid"
    assert verifier(home, NOW + 600).read([value], "admin", "read")[0] == "expired"
    assert v.read([], "admin", "read") == ("none", None)
    assert v.read([value, value], "admin", "read") == ("invalid", None)


def test_a_grant_from_another_key_or_policy_is_invalid(home, tmp_path):
    other = tmp_path / "other"
    assert gcli.init(other, None, out=open(os.devnull, "w")) == 0
    value, _ = issue(other)
    assert verifier(home).read([value], "admin", "read") == ("invalid", None)      # signed by another authority
    value, _ = issue(home, sha="0" * 64)
    assert verifier(home).read([value], "admin", "read")[0] == "invalid"           # issued under another policy


def _parts(value):
    head, _, tail = value.partition(".")
    pad = lambda t: base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
    return pad(head), pad(tail)


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def test_a_tampered_or_malformed_grant_is_invalid(home):
    value, doc = issue(home)
    body, sig = _parts(value)
    wider = dict(doc, method_classes=["delete", "read", "write"])
    forged = f"{_b64(canon2.dumps(wider))}.{_b64(sig)}"
    flipped = f"{_b64(body)}.{_b64(bytes([sig[0] ^ 1]) + sig[1:])}"
    v = verifier(home)
    for bad in (forged, flipped, value + "=", value.replace(".", ""), "x" * (grants.MAX_VALUE + 1), "a.b", ".",
                f"{_b64(json.dumps(doc).encode())}.{_b64(sig)}", value + ".x"):
        assert v.read([bad], "admin", "read")[0] == "invalid", bad


def test_a_revoked_grant_is_invalid_on_the_next_request(home):
    value, doc = issue(home)
    v = verifier(home)
    assert v.read([value], "admin", "read")[0] == "valid"
    assert gcli.revoke(home, doc["grant_id"], out=open(os.devnull, "w")) == 0
    assert v.read([value], "admin", "read")[0] == "invalid"
    assert grants.revoke(home, doc["grant_id"]) is False
    (home / grants.REVOKED_FILE).write_text("not an id\n")
    assert v.read([value], "admin", "read")[0] == "invalid"     # a list that cannot be read revokes everything
    (home / grants.REVOKED_FILE).unlink()
    assert v.read([value], "admin", "read")[0] == "valid"


@pytest.mark.parametrize("kw", [dict(paths=()), dict(methods=()), dict(methods=("fly",)), dict(paths=("unknown",)),
                                dict(paths=("Admin",)), dict(ttl=0), dict(ttl=grants.MAX_LIFETIME + 1)])
def test_issue_refuses_a_grant_that_would_not_be_well_formed(home, kw):
    with pytest.raises(grants.GrantError):
        issue(home, **kw)


# ------------------------------------------------------------------------------------ at the gateway
def test_the_gateway_lets_a_granted_request_through_and_receipts_the_grant(home):
    up = Upstream()
    g = Running(up, home)
    try:
        assert g.request("GET", "/admin/users")[0] == 403
        value, doc = issue(home, now=None)
        status, headers, _ = g.request("GET", "/admin/users", headers={HDR: value})
        assert status == 200 and HDR.title() not in up.seen[-1]["headers"]       # the grant is not forwarded
        assert g.request("DELETE", "/admin/users", headers={HDR: value})[0] == 403
        write, wdoc = issue(home, paths=("orders",), methods=("write",), now=None)
        assert g.request("POST", "/api/orders/", b"{}", {"Content-Type": "application/json", HDR: write})[0] == 200
        assert g.request("POST", "/api/orders/", b"{}", {"Content-Type": "application/json", HDR: value})[0] == 403
        assert gcli.revoke(home, doc["grant_id"], out=open(os.devnull, "w")) == 0
        assert g.request("GET", "/admin/users", headers={HDR: value})[0] == 403
    finally:
        g.close()
        up.close()
    lines = receipts(home)
    assert [line.get("grant", {}).get("grant_id") for line in lines] == [
        None, doc["grant_id"], doc["grant_id"], wdoc["grant_id"], doc["grant_id"], doc["grant_id"]]
    assert [line["receipt"]["verdict"]["kind"] if "verdict" in line["receipt"] else line["receipt"].get("decision")
            for line in lines][1] is not None


def test_the_grant_command_prints_a_header_value_the_gateway_accepts(home, capsys):
    assert gcli.grant(home, ["admin"], ["read"], 60, True) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["header"] == HDR and out["grant"]["path_classes"] == ["admin"]
    v = grants.Verifier(commands._key_paths(home, "authority")[1].read_bytes(), policy_sha(home))
    assert v.read([out["value"]], "admin", "read")[0] == "valid"
    with pytest.raises(commands.AgentError):
        gcli.grant(home, [], ["read"], 60, False)
    with pytest.raises(commands.AgentError):
        gcli.revoke(home, "nope")
