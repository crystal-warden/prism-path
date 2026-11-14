# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The tool server's re-decision, the receipt logger, and a loopback run of a few cases end to end."""
import os
import sys
from pathlib import Path

import pytest

from integrations.governed_harness.adversary import make_world
from integrations.governed_net import adversary_net, frame as fr, protocol as p
from integrations.governed_net.policy import NetPolicy
from integrations.governed_net.receipt_logger import EVENT, Event, ReceiptLogger
from integrations.governed_net.server import ToolServer

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "formal" / "diff"))
import core_diff  # noqa: E402


class Spy:
    def __init__(self):
        self.calls = []

    def __call__(self, call, workspace):
        self.calls.append(call)
        return {"ok": True, "output": "ran"}


@pytest.fixture
def server(tmp_path):
    world = make_world(tmp_path / "world")
    spy = Spy()
    srv = ToolServer(world["ws"], NetPolicy.load(), tmp_path / "run", tmp_path / "keys", execute=spy)
    srv.handles.listing(".")
    srv.handles.listing(".toolchain")
    return srv, spy, world


def send(srv, **kw):
    return srv.handle(p.encode(p.Request(**kw)))


def test_links_are_never_issued_a_handle(server):
    srv, _spy, _world = server
    names = {rel for _cls, rel in srv.handles.table.values()}
    assert "cfg" not in names and "link_out" not in names and "inner_link" not in names
    assert "notes.txt" in names and ".toolchain/VERSION" in names
    assert srv.handles.lookup(srv.handles.by_path[".toolchain/VERSION"])[0] == p.H_TC_FILE


def test_a_lie_about_the_class_never_runs(server):
    srv, spy, _world = server
    handle = srv.handles.by_path[".toolchain/VERSION"]
    reply = send(srv, cmd=p.WRITE, request_id=5, hclass=p.H_WS_FILE, handle=handle, data=b"2.0")
    assert reply.status == p.FINDING and spy.calls == []
    assert srv.findings[-1]["finding"] == "class-mismatch"
    assert srv.findings[-1]["server_decision"] == ["refuse", "agent:toolchain-write"]


def test_unissued_replayed_and_refused(server):
    srv, spy, _world = server
    assert send(srv, cmd=p.DELETE, request_id=1, hclass=1, handle=999999).status == p.FINDING
    handle = srv.handles.by_path["notes.txt"]
    assert send(srv, cmd=p.WRITE, request_id=2, hclass=1, handle=handle, data=b"x").status == p.OK
    assert send(srv, cmd=p.WRITE, request_id=2, hclass=1, handle=handle, data=b"x").status == p.FINDING
    assert send(srv, cmd=p.GIT_PUSH, request_id=3, arg0=1).status == p.FINDING
    assert srv.handle(b"\x00" * 40) is None
    assert [row["finding"] for row in srv.findings] == ["unissued-handle", "replayed-request-id",
                                                         "server-refuses-what-arrived", "malformed-arrived"]
    assert len(spy.calls) == 1


def test_receipt_written_before_execution(server):
    srv, _spy, _world = server
    seen = []

    def execute(call, workspace):
        seen.append((srv.run.run / "receipts.jsonl").read_bytes().count(b"\n"))
        return {"ok": True, "output": ""}
    srv.execute = execute
    send(srv, cmd=p.GIT_STATUS, request_id=9)
    assert seen == [1]


def test_logger_rebuilds_the_reading_and_checks_the_action(tmp_path):
    policy = NetPolicy.load()
    logger = ReceiptLogger(policy, tmp_path / "run", tmp_path / "keys")
    raw = EVENT.pack(77, 5, 1, 1, 107, fr.DROP_POLICY, 0, 1, p.WRITE, p.H_TC_FILE, 0, 3, 40000, 4, 0, 0, 0, 0)
    idx = logger.consume(Event.from_ring(raw))
    assert idx == 0 and logger.findings == []
    assert logger.status(77).status == p.REFUSED and logger.status(77).cause_code == 107
    # an event whose action disagrees with the image is recorded as a finding
    lie = EVENT.pack(78, 5, 1, 1, 107, fr.ALLOW, 0, 1, p.WRITE, p.H_TC_FILE, 0, 3, 40000, 4, 0, 0, 0, 0)
    logger.consume(Event.from_ring(lie))
    assert logger.findings[-1]["finding"] == "action-mismatch"
    logger.close()


@pytest.mark.skipif(not core_diff.ORACLE.exists() or not os.path.exists("/usr/bin/bwrap"),
                    reason="needs the Lean oracle and bubblewrap")
def test_loopback_end_to_end(tmp_path):
    ids = {"tool-1", "trav-1", "link-1", "push-1", "ok-3", "ok-8", "lie-class", "lie-bypass"}
    cases = [case for case in adversary_net.CASES if case.id in ids]
    summary = adversary_net.run_all("probe", tmp_path / "out", tmp_path / "keys", cases)
    assert summary["out_of_policy_executed"] == 0
    assert summary["executed_without_xdp_allow"] == 0
    assert summary["runs_verified"] == len(cases) == summary["replay_identical"]
    assert all(value == {"met_expected": sum(1 for c in cases if c.group == group)} or group == "benign"
               for group, value in summary["by_group"].items())
    assert summary["benign_ok"] == {"ok-3": True, "ok-8": True}


def test_source_outside_lan_is_a_finding(tmp_path):
    from integrations.governed_net import protocol as pp
    world = make_world(tmp_path / "w2")
    srv = ToolServer(world["ws"], NetPolicy.load(), tmp_path / "run2", tmp_path / "keys2", execute=Spy(),
                     lan_prefixes=["203.0.113.0/24"])
    srv.handles.listing(".")
    raw = pp.encode(pp.Request(cmd=pp.GIT_STATUS, request_id=7))
    # from the LAN: accepted and run
    assert srv.handle(raw, src=("203.0.113.40", 5000)).status == pp.OK
    # from the mesh VPN address: a finding, never run
    raw2 = pp.encode(pp.Request(cmd=pp.GIT_STATUS, request_id=8))
    assert srv.handle(raw2, src=("198.51.100.9", 5000)).status == pp.FINDING
    assert srv.findings[-1]["finding"] == "source-outside-lan"
    assert srv.by_client["198.51.100.9"]["out_of_prefix"] == 1


def test_same_request_id_from_two_clients_is_not_a_replay(tmp_path):
    from integrations.governed_net import protocol as pp
    world = make_world(tmp_path / "w3")
    srv = ToolServer(world["ws"], NetPolicy.load(), tmp_path / "run3", tmp_path / "keys3", execute=Spy(),
                     lan_prefixes=["127.0.0.0/8"])
    srv.handles.listing(".")
    raw = pp.encode(pp.Request(cmd=pp.GIT_STATUS, request_id=1234))
    assert srv.handle(raw, src=("127.0.0.1", 1)).status == pp.OK
    assert srv.handle(raw, src=("127.0.0.2", 1)).status == pp.OK      # same id, other client: fine
    assert srv.handle(raw, src=("127.0.0.1", 1)).status == pp.FINDING  # same id, same client: replay
    assert srv.findings[-1]["finding"] == "replayed-request-id"


@pytest.mark.skipif(not core_diff.ORACLE.exists() or not os.path.exists("/usr/bin/bwrap"),
                    reason="needs the Lean oracle and bubblewrap")
def test_two_client_loopback(tmp_path):
    from integrations.governed_net import adversary_net
    summary = adversary_net.two_client(tmp_path / "tc", tmp_path / "tck")
    assert summary["out_of_policy_executed"] == 0
    assert summary["executed_without_xdp_allow"] == 0
    assert summary["shared_id_replay_findings"] == 0
    assert summary["both_clients_have_receipts"]
    assert summary["runs_verified"] and summary["replay_identical"]
    assert set(summary["server_by_client"]) == set(summary["client_ips"])
    assert all(summary["server_by_client"][ip]["executed"] >= 1 for ip in summary["client_ips"])
