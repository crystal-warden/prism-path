# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The HTTP binding (spec-policy-distribution.md, section 8.2) over real sockets on loopback: host PEPs pull
from the reference controller's listener. Each test names the conformance case of section 20 it covers. The
last test is D2's done line, case 95 with three host PEPs over HTTP."""
import json
import socket
import threading
from contextlib import contextmanager

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import http as binding  # noqa: E402
from prismpath.distribution.controller import Controller  # noqa: E402
from prismpath.distribution.http import HttpTransport, PullClient  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import GEN, STREAM  # noqa: E402

OLD, NEW, NEWER = _dist.image(5), _dist.image(7), _dist.image(9)
H = canon.sha256_hex


class Between:
    """What a server in the middle hands out in place of the controller: everything the controller says, with
    `blob` and `answer` open to change, and every blob asked for counted."""

    def __init__(self, controller, blob=None, answer=None):
        self.inner, self._blob, self._answer = controller, blob, answer
        self.asked = []

    @contextmanager
    def locked(self):
        with self.inner.locked():
            yield self

    def answer(self, pep):
        answer = self.inner.answer(pep)
        return self._answer(answer) if self._answer else answer

    def blob(self, name):
        self.asked.append(name)
        data = self.inner.blob(name)
        return self._blob(name, data) if self._blob else data

    def receive(self, record):
        return self.inner.receive(record)

    def fleet(self):
        return self.inner.fleet()


@contextmanager
def listening(controller):
    server = binding.serve(controller, ("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, name="controller-server", daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", server
    finally:
        server.shutdown()
        server.server_close()


class Fleet:
    def __init__(self, tmp_path, names=("p1", "p2", "p3"), rule="each"):
        self.clock = _dist.Clock()
        self.dir = tmp_path / "controller"
        self.controller = Controller(str(self.dir), _dist.instance_key("C"), clock=self.clock)
        self.points = {name: _dist.HostPep(tmp_path / name, clock=self.clock, key=_dist.instance_key(name))
                       for name in names}
        self.first = next(iter(self.points.values()))
        self.controller.add_anchor(self.first.anchor(), dict(GEN.QUALIFICATION))
        self.ids = {name: self.controller.enroll(point.key.public_raw, "host", STREAM, "fleet", rule)
                    for name, point in self.points.items()}
        self.controller.save()

    def put(self, body, seq, *, widen=None, replaces=None, **args):
        """Store a release of `body` at `seq`, replacing the one put before it. The first, or one put with
        `widen`, goes with a widening statement that covers any PEP (W2, W3)."""
        previous = getattr(self, "previous", None)
        widen = self.first.policy_of(body) != previous if widen is None else widen      # W7: only a renewal does not
        replaces = (previous or "") if replaces is None else replaces
        pairs = _dist.release_with_statement(self.first, body, seq, widen=widen, replaces=replaces, **args)
        with self.controller.locked() as controller:
            for sealed, data in pairs:
                controller.put(sealed, data)
        self.previous = self.first.policy_of(body)
        return pairs[-1][0]

    def offer(self, seq, group="fleet"):
        with self.controller.locked() as controller:
            return controller.offer(group, STREAM, seq)

    def clients(self, base, **bases):
        return {name: PullClient(point.pep, HttpTransport(bases.get(name, base)))
                for name, point in self.points.items()}


def test_case_032_a_host_pep_stages_and_commits_with_the_controller_never_opening_a_connection(tmp_path, monkeypatch):
    """case_032: B3. Every connection is opened by the PEP's thread, none by the controller's."""
    fleet = Fleet(tmp_path, names=("p1",))
    fleet.put(OLD, 1)
    fleet.offer(1)
    opened = []
    real = socket.socket.connect

    def connect(self, address):
        opened.append(threading.current_thread().name)
        return real(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
    with listening(fleet.controller) as (base, _server):
        client = fleet.clients(base)["p1"]
        for _ in range(2):
            client.poll()
    assert fleet.points["p1"].pep.active.seq == 1
    assert opened and set(opened) == {threading.current_thread().name}


def test_case_033_a_blob_that_is_not_its_name_and_a_sealed_envelope_of_another_id_are_body_mismatch(tmp_path):
    """case_033: B4, V9. The release is never staged in either, beside the widening statement that came first."""
    fleet = Fleet(tmp_path, names=("p1",))
    release_id = env.envelope_id(env.unseal(fleet.put(OLD, 1))[0])
    other = fleet.first.seal(NEW, seq=2)
    fleet.offer(1)
    for name, change in (("body", lambda name, data: data[:-1] + bytes([data[-1] ^ 1]) if name == H(OLD) else data),
                         ("sealed", lambda name, data: other if name == release_id else data)):
        point = _dist.HostPep(tmp_path / f"q_{name}", clock=fleet.clock, key=_dist.instance_key("p1"))
        fleet.offer(1)                                  # the refusal before ended the last rollout
        between = Between(fleet.controller, blob=change)
        with listening(between) as (base, _server):
            PullClient(point.pep, HttpTransport(base)).poll()
        refused = [event["data"]["cause"] for event in point.pep.audit.events if event["action"] == "refused"]
        assert refused == ["dist:body-mismatch"] and "policy.ppt" not in point.pep.staged.held
        assert point.pep.active is None


def test_case_034_an_offer_for_an_envelope_the_controller_does_not_hold_is_a_failed_fetch(tmp_path):
    """case_034: B5. The offer is a hint: its fetch fails and nothing changes on the PEP."""
    fleet = Fleet(tmp_path, names=("p1",))
    missing = {"envelope_id": "ab" * 32, "stream": STREAM, "seq": 9, "artifact": "policy.ppt",
               "sealed_size": 400, "body_size": 40}
    between = Between(fleet.controller, answer=lambda answer: {**answer, "offers": [missing]})
    pep = fleet.points["p1"].pep
    before = (pep.state(), pep.floor, pep.staged, pep.trust)
    with listening(between) as (base, _server):
        client = fleet.clients(base)["p1"]
        client.poll()
    assert client.failures and client.failures[0][0] == "ab" * 32
    assert (pep.state(), pep.floor, pep.staged, pep.trust) == before
    assert not [event for event in pep.audit.events if event["action"] in ("refused", "staged")]


def test_case_030_a_forged_commit_and_a_forged_abort_run_only_what_the_authority_signed(tmp_path):
    """case_030: B1. Commit and abort are not signed. A commit no controller sent makes the signed staged release
    active, an abort no controller sent drops a staged one, and an offer of what the authority did not sign is
    refused, so nothing unsigned ever runs."""
    fleet = Fleet(tmp_path, names=("p1",))
    fleet.put(OLD, 1)
    pep = fleet.points["p1"].pep
    fleet.points["p1"].stage(OLD)
    forged = Between(fleet.controller, answer=lambda answer: {
        "epoch": answer["epoch"], "offers": [], "abort": [],
        "commit": [{"stream": STREAM, "seq": 1, "policy": H(OLD), "delay": 0}]})
    with listening(forged) as (base, _server):
        fleet.clients(base)["p1"].poll()
    assert pep.active.seq == 1
    pep.stage(fleet.first.seal(NEW, seq=2), NEW)
    forged = Between(fleet.controller, answer=lambda answer: {
        "epoch": answer["epoch"], "offers": [], "commit": [],
        "abort": [{"stream": STREAM, "seq": 2, "policy": H(NEW)}]})
    with listening(forged) as (base, _server):
        fleet.clients(base)["p1"].poll()
    assert pep.staged is None and pep.active.seq == 1
    raw = env.unseal(fleet.first.seal(NEWER, seq=3))[0]
    unsigned, unsigned_id = env.seal_entries(raw, []), env.envelope_id(raw)
    forged = Between(fleet.controller,
                     answer=lambda answer: {**answer, "offers": [{"envelope_id": unsigned_id}],
                                            "commit": [{"stream": STREAM, "seq": 3, "policy": H(NEWER)}]},
                     blob=lambda name, data: unsigned if name == unsigned_id else data)
    with listening(forged) as (base, _server):
        fleet.clients(base)["p1"].poll()
    assert pep.active.seq == 1 and pep.staged is None
    assert [event["data"]["cause"] for event in pep.audit.events if event["action"] == "refused"][-1] == "dist:bad-format"


def test_case_080_a_renewal_with_the_same_bodies_commits_with_no_body_fetched(tmp_path):
    """case_080: X5."""
    fleet = Fleet(tmp_path, names=("p1",))
    between = Between(fleet.controller)
    fleet.put(OLD, 1)
    fleet.offer(1)
    with listening(between) as (base, _server):
        client = fleet.clients(base)["p1"]
        for _ in range(2):
            client.poll()
        assert H(OLD) in between.asked
        between.asked.clear()
        fleet.put(OLD, 2, expires=_dist.EXPIRES + 86400)
        fleet.offer(2)
        for _ in range(2):
            client.poll()
    pep = fleet.points["p1"].pep
    assert pep.active.seq == 2 and pep.active.envelopes["policy.ppt"].expires == _dist.EXPIRES + 86400
    assert H(OLD) not in between.asked and len(between.asked) == 1                # the sealed envelope alone


def test_case_120_the_pull_client_never_reads_more_than_it_was_promised(tmp_path):
    """case_120: B9, the fetch half in Python. A body longer than its signed body_size, a sealed envelope of
    2,441 bytes and an offers answer of 65 kilobytes are each refused with nothing read past the bound, and the
    body of an envelope that fails its signature is never asked for."""
    fleet = Fleet(tmp_path, names=("p1",))
    sealed = fleet.put(OLD, 1)
    fleet.offer(1)
    envelope_id = env.envelope_id(env.unseal(sealed)[0])
    statement_id, info = next((one, info) for one, info in fleet.controller.stored.items()
                              if info["artifact"] == "trust.widening")
    statement = [statement_id, info["body_sha256"]]
    pep = fleet.points["p1"].pep

    def run(**change):
        fleet.offer(1)
        between = Between(fleet.controller, **change)
        with listening(between) as (base, _server):
            client = fleet.clients(base)["p1"]
            client.poll()
        return between, client

    between, client = run(blob=lambda name, data: data + b"\0" if name == H(OLD) else data)
    assert client.transport.blob_reads == len(sealed) + info["sealed_size"] + info["body_size"]
    assert between.asked == statement + [envelope_id, H(OLD)] and "policy.ppt" not in pep.staged.held
    between, client = run(blob=lambda name, data: data + b"\0" * (env.MAX_SEALED + 1 - len(data))
                          if name == envelope_id else data)
    assert client.transport.blob_reads == 0 and between.asked == [envelope_id] and "policy.ppt" not in pep.staged.held
    between, client = run(answer=lambda answer: {**answer, "pad": "x" * (65 * 1024)})
    assert client.transport.blob_reads == 0 and between.asked == [] and client.failures[0][0] == "offers"
    refused = [event["data"]["cause"] for event in pep.audit.events if event["action"] == "refused"]
    assert refused == ["dist:too-large", "dist:too-large"]

    entries = env.unseal(sealed)[1]
    forged = env.seal_entries(env.unseal(sealed)[0], [(entries[0][0], bytes(64))])
    other = _dist.HostPep(tmp_path / "q", clock=fleet.clock, key=_dist.instance_key("p1"))
    between = Between(fleet.controller, blob=lambda name, data: forged if name == envelope_id else data)
    with listening(between) as (base, _server):
        PullClient(other.pep, HttpTransport(base)).poll()
    assert between.asked == statement + [envelope_id] and "policy.ppt" not in other.pep.staged.held
    assert [event["data"]["cause"] for event in other.pep.audit.events if event["action"] == "refused"] == ["sig:invalid"]


def test_the_offers_answer_carries_an_etag_and_answers_304_or_waits_while_nothing_changed(tmp_path):
    """Section 7.5 b1: If-None-Match with the last ETag is 304 when nothing changed, and a long poll returns as
    soon as a state record changes the answer."""
    fleet = Fleet(tmp_path, names=("p1",))
    with listening(fleet.controller) as (base, server):
        transport = HttpTransport(base)
        pep_id = fleet.ids["p1"]
        assert transport.offers(pep_id)["offers"] == []
        assert transport.offers(pep_id) is None
        fleet.put(OLD, 1)
        fleet.offer(1)
        assert [offer["artifact"] for offer in transport.offers(pep_id)["offers"]] == ["trust.widening", "policy.ppt"]
        waited = []
        thread = threading.Thread(target=lambda: waited.append(transport.offers(pep_id, wait=10)))
        thread.start()
        client = PullClient(fleet.points["p1"].pep, HttpTransport(base))
        import time
        time.sleep(0.5)                                 # the long poll is waiting by now
        with fleet.controller.locked() as controller:   # a state record that changes nothing in the answer
            controller.receive(b"PPSR")
        server.notify()
        client.poll()                                   # stages, and its record changes the answer
        thread.join(15)
        assert waited and waited[0] is not None and waited[0]["commit"]


def test_case_095_three_host_peps_over_http_one_commits_one_refuses_a_downgrade_one_a_bad_signature(tmp_path):
    """case_095: F3, F4, F5, and D2's done line. One test pushes a pack to three host PEPs over real HTTP on
    loopback. One commits, one refuses a downgrade with dist:seq-replay, and one, whose path runs through a
    server in the middle that changes a signature byte, refuses with sig:invalid. The three audit logs and
    the controller's show all three outcomes."""
    fleet = Fleet(tmp_path)
    controller = fleet.controller
    with controller.locked():
        controller.enroll(fleet.points["p2"].key.public_raw, "host", STREAM, "canary", "each")
    fleet.put(NEWER, 3)
    fleet.offer(3, group="canary")

    def tamper(name, data):
        if name in controller.stored:
            data = bytearray(data)
            data[6 + 32] ^= 1
        return bytes(data)

    with listening(controller) as (base, _server), listening(Between(controller, blob=tamper)) as (middle, _m):
        clients = fleet.clients(base, p3=middle)
        for _ in range(2):
            clients["p2"].poll()
        assert fleet.points["p2"].pep.active.seq == 3
        with controller.locked():
            controller.enroll(fleet.points["p2"].key.public_raw, "host", STREAM, "fleet", "each")
        fleet.put(NEW, 2, widen=True, replaces="")      # a first install for p1 and p3
        fleet.offer(2)
        for _ in range(3):
            for client in clients.values():
                client.poll()
    with controller.locked() as view:
        rollout = view.rollouts[-1]
        assert rollout.state == "committed"
        assert rollout.members == {fleet.ids["p1"]: "committed", fleet.ids["p2"]: "refused",
                                   fleet.ids["p3"]: "refused"}
        findings = {name: dict(view.members[fleet.ids[name]].findings) for name in fleet.points}
        logged = [(event["action"], event["data"].get("pep"), event["data"].get("finding"))
                  for event in view.audit.events]
    assert fleet.points["p1"].pep.active.seq == 2
    assert fleet.points["p2"].pep.active.seq == 3 and fleet.points["p3"].pep.active is None
    assert set(findings["p1"]) == set() and set(findings["p2"]) == {"dist:seq-replay"}
    assert set(findings["p3"]) == {"sig:invalid"}
    outcomes = {name: [(event["action"], event["data"].get("cause")) for event in point.pep.audit.events
                       if event["action"] in ("committed", "refused")] for name, point in fleet.points.items()}
    assert outcomes["p1"] == [("committed", None)]
    assert outcomes["p2"] == [("committed", None)] + [("refused", "dist:seq-replay")] * 2   # statement, release
    assert outcomes["p3"] == [("refused", "sig:invalid")] * 2
    assert ("commit", fleet.ids["p1"], None) in logged
    assert ("finding", fleet.ids["p2"], "dist:seq-replay") in logged
    assert ("finding", fleet.ids["p3"], "sig:invalid") in logged
    with listening(controller) as (base, _server):
        transport = HttpTransport(base)
        status, data, _etag = transport._get("/dist/v1/fleet", 1 << 20)
    view = json.loads(data)
    assert {entry["labels"]["id"]: [error["code"] for error in entry["bundles"][STREAM]["errors"]]
            for entry in view["peps"]} == {fleet.ids["p1"]: [], fleet.ids["p2"]: ["dist:seq-replay"],
                                           fleet.ids["p3"]: ["sig:invalid"]}


def _pem(path, name):
    from prismpath.hotswap import policy_pack
    _priv, _pub, ser, _invalid = policy_pack._ed25519()
    path.write_bytes(GEN.test_key(name).private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    return str(path)


def test_the_command_line_seals_serves_provisions_pulls_and_rekeys_a_host_pep(tmp_path, capsys):
    """`prismpath dist` end to end at the PEP's and the controller's real clocks: the owner seals into the
    controller's inbox, the controller enrols the PEP and offers, the PEP is provisioned with the fingerprint
    and pulls over HTTP, and `rekey` rotates to a new key, releases under it, waits for the commit and only
    then revokes the old key, so the PEP never lapses. A rollback to the release under the revoked key is
    refused (RB2)."""
    import time as clock
    from prismpath import cli
    from prismpath.distribution import cli as dist_cli

    def run(*argv):
        args = cli.build_parser().parse_args(["dist", *argv])
        code = args.func(args)
        out = capsys.readouterr().out
        return code, (json.loads(out) if out.strip().startswith("{") else out)

    keys = {name: _pem(tmp_path / f"{name}.pem", name) for name in ("A", "B", "C", "D", "p1")}
    pub = tmp_path / "p1.pub"
    pub.write_bytes(GEN.public_raw(GEN.test_key("p1")))
    authority = tmp_path / "A.pub"
    authority.write_bytes(GEN.public_raw(GEN.test_key("A")))
    anchor = tmp_path / "anchor.json"
    assert run("anchor", "--pub", str(authority), "--target", "host", "--stream", STREAM,
               "--out", str(anchor))[0] == 0
    qualification = tmp_path / "qualification.json"
    qualification.write_text(json.dumps(GEN.QUALIFICATION))
    directory, state = tmp_path / "controller", tmp_path / "pep"
    now = int(clock.time())

    code, printed = run("pep", "provision", "--state", str(state), "--key", keys["p1"], "--anchor", str(anchor),
                        "--qualification", str(qualification))
    assert code == 0
    assert run("pep", "provision", "--state", str(state), "--key", keys["p1"],
               "--confirm", printed["fingerprint"])[1]["state"] == "no-policy"
    assert run("enroll", "--dir", str(directory), "--key", keys["C"], "--pub", str(pub), "--anchor", str(anchor),
               "--qualification", str(qualification), "--group", "g")[0] == 0
    (directory / "inbox").mkdir()
    body = tmp_path / "policy.ppt"
    body.write_bytes(OLD)
    sealed = directory / "inbox" / "r1.sealed"
    assert run("seal", "--artifact", "policy.ppt", "--body", str(body), "--stream", STREAM, "--seq", "1",
               "--target", "host", "--key", keys["A"], "--not-before", str(now - 60), "--expires", str(now + 86400),
               "--qualification", str(qualification), "--out", str(sealed))[0] == 0
    (directory / "inbox" / "r1.body").write_bytes(OLD)
    assert run("widen", "--sealed", str(sealed), "--key", keys["A"],              # W2, W3: a first install
               "--out", str(directory / "inbox" / "w1.sealed"))[0] == 0
    code, printed = run("offer", "--dir", str(directory), "--key", keys["C"], "--group", "g", "--stream", STREAM,
                        "--seq", "1")
    assert code == 0 and [one["artifact"] for one in printed["stored"]] == ["policy.ppt", "trust.widening"]
    assert printed["rollout"]["state"] == "offered"

    from prismpath.distribution.controller import Controller
    serving = dist_cli._Ingesting(Controller(str(directory), dist_cli._instance(keys["C"])))
    with listening(serving) as (base, _server):
        for _ in range(2):
            code, printed = run("pep", "poll", "--state", str(state), "--key", keys["p1"], "--url", base, "--once")
        assert printed["state"] == "active" and printed["active_seq"] == 1
        new_body = tmp_path / "policy2.ppt"
        new_body.write_bytes(NEW)
        result = {}
        rekey = threading.Thread(target=lambda: result.update(code=run(
            "rekey", "--dir", str(directory), "--key", keys["C"], "--old", keys["A"], "--new", keys["B"],
            "--body", str(new_body), "--qualification", str(qualification), "--group", "g", "--stream", STREAM,
            "--seq", "2", "--target", "host", "--not-before", str(now - 60), "--expires", str(now + 86400),
            "--timeout", "60")[0]))
        rekey.start()
        deadline = clock.monotonic() + 60
        while rekey.is_alive() and clock.monotonic() < deadline:
            run("pep", "poll", "--state", str(state), "--key", keys["p1"], "--url", base, "--once")
            clock.sleep(0.2)
        rekey.join(5)
        assert result.get("code") == 0
        code, printed = run("pep", "poll", "--state", str(state), "--key", keys["p1"], "--url", base, "--once")
    assert printed["state"] == "active" and printed["active_seq"] == 2 and printed["trust_seq"] == 2
    events = [json.loads(line) for line in (state / "dist" / "audit.log").read_text().splitlines() if line.strip()]
    assert "lapsed" not in [event["action"] for event in events]
    code, printed = run("pep", "rollback", "--state", str(state), "--key", keys["p1"])
    assert code == 1 and printed["cause"] == "sig:revoked-key" and printed["active_seq"] == 2
    code, printed = run("fleet", "--dir", str(directory), "--key", keys["C"])
    assert [rollout["state"] for rollout in printed["rollouts"]] == ["committed", "committed"]
    assert printed["trust_seq"] == 2 and printed["peps"][0]["findings"] == {}

    # case_292: W8. A rekey whose table allows more than the one it replaces is refused before the rotation is
    # stored, unless --widens says the owner means it
    wider = tmp_path / "policy3.ppt"
    wider.write_bytes(_dist.image(3))
    args = cli.build_parser().parse_args([
        "dist", "rekey", "--dir", str(directory), "--key", keys["C"], "--old", keys["B"], "--new", keys["D"],
        "--body", str(wider), "--qualification", str(qualification), "--group", "g", "--stream", STREAM,
        "--seq", "3", "--target", "host", "--not-before", str(now - 60), "--expires", str(now + 86400),
        "--timeout", "1"])
    assert args.func(args) == 1 and "refused: dist:widening-unsigned" in capsys.readouterr().err
    assert run("fleet", "--dir", str(directory), "--key", keys["C"])[1]["trust_seq"] == 2


def test_the_pull_client_tries_again_only_what_time_or_the_trust_chain_may_change(tmp_path):
    """An envelope refused with dist:not-yet-valid is fetched again on a later poll and staged once the PEP's
    clock reaches it. One refused for its signature is tried once and never fetched again."""
    fleet = Fleet(tmp_path, names=("p1",))
    later = _dist.NOT_BEFORE + 4000
    fleet.clock.now = later
    sealed = fleet.put(OLD, 1, not_before=later)
    fleet.offer(1)
    envelope_id = env.envelope_id(env.unseal(sealed)[0])
    fleet.clock.now = _dist.NOW
    between = Between(fleet.controller)
    pep = fleet.points["p1"].pep
    with listening(between) as (base, _server):
        client = fleet.clients(base)["p1"]
        client.poll()
        assert "policy.ppt" not in pep.staged.held and envelope_id not in client.done
        fleet.clock.now = later
        client.poll()
    assert pep.staged is not None and between.asked.count(envelope_id) == 2

    other = Fleet(tmp_path / "other", names=("p1",))
    other.put(OLD, 1)
    other.offer(1)
    spoiled = Between(other.controller, blob=lambda name, data: data[:38] + bytes([data[38] ^ 1]) + data[39:]
                      if name in other.controller.stored else data)
    with listening(spoiled) as (base, _server):
        client = other.clients(base)["p1"]
        for _ in range(3):
            client.poll()
    assert spoiled.asked.count(next(iter(other.controller.stored))) == 1
