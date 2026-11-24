# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The reconciling state (spec-policy-distribution.md, section 9.5, H14 and P5): the enforcement point on the
`host` target over a host adapter whose runtime steps the test makes fail, the `agent` home whose lapse ends its
sandboxed sessions, and the controller that reads the records. Each test names the conformance case of section 20
it covers. A restart is a fresh `Pep` over the same state directory, and a death is a `BaseException` no step
catches. This version builds no action floor and no fallback policy (section 21), so the withdrawal leaves the
runtime running nothing, and the cases and halves that need them stay pending."""
import subprocess
import sys
from dataclasses import dataclass, field, replace

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import state_record  # noqa: E402
from prismpath.distribution.adapters.host import HostAdapter  # noqa: E402
from prismpath.distribution.controller import Controller  # noqa: E402
from prismpath.distribution.pep import PepRefused  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import EXPIRES, STREAM  # noqa: E402

OLD, NEW, NEWER = _dist.image(5), _dist.image(7), _dist.image(9)
H = canon.sha256_hex
ZERO = bytes(16)


class Died(BaseException):
    """A death: the process is gone, and no step of the machine catches it."""


@dataclass
class Switches:
    """What the test does to the runtime: whether its install and its withdrawal fail, and how often each ran."""
    activate: bool = False
    withdraw: bool = False
    activations: int = 0
    withdrawals: int = 0
    die: bool = False

    def set(self, activate: bool, withdraw: bool) -> None:
        self.activate, self.withdraw = activate, withdraw

    def tries(self):
        return self.activations, self.withdrawals


class Flaky(HostAdapter):
    """The host adapter with a runtime that fails when the switches say so, before the host is touched."""

    def __init__(self, host, switches: Switches):
        super().__init__(host)
        self.switches = switches

    def activate(self, release) -> None:
        self.switches.activations += 1
        if self.switches.die:
            raise Died("the runtime step")
        if self.switches.activate:
            raise RuntimeError("the runtime did not take the release")
        super().activate(release)

    def deactivate(self, cause: str) -> None:
        self.switches.withdrawals += 1
        if self.switches.withdraw:
            raise RuntimeError("the runtime did not withdraw")
        super().deactivate(cause)


@dataclass
class FlakyHost(_dist.HostPep):
    switches: Switches = field(default_factory=Switches)

    def adapter(self):
        return Flaky(self.host(), self.switches)

    def records(self):
        return [state_record.read(signed, self.key.public_raw) for signed in self.pep.drain()]

    def read(self, signed):
        return state_record.read(signed, self.key.public_raw)

    def host_active(self):
        return self.pep.adapter.host.active().get("active")

    def actions(self, action):
        return sum(1 for event in self.pep.audit.events if event["action"] == action)

    def path(self, name):
        return self.state_dir / "dist" / name

    def covered(self, body, seq):
        """Stage `body` at `seq` with a widening statement whose `from` is empty, so a rollback to it is covered."""
        self.widen(body, seq, widens=True)
        self.stage(body, seq, widens=True)
        return self.pep.commit(STREAM, seq, H(body))


@pytest.fixture
def rig(tmp_path):
    return FlakyHost(tmp_path / "host")


def said(record):
    return record.event, record.state, record.active_seq


def running(entry):
    return (entry.running_policy, entry.running_seq) if entry.running_seq else None


def P(body):
    return state_record.prefix(H(body))


def test_case_240_a_failed_commit_withdraws_refuses_and_reports_committed_when_a_try_works(rig):
    """case_240: C6, C8, C9, C10, X3. A `host` PEP's commit whose runtime step fails withdraws the runtime, refuses
    the decision with dist:reconciling, stays reconciling through a tick whose try fails and is `active` with one
    `committed` record once a try works."""
    rig.commit(OLD)
    rig.stage(NEW, 2)
    rig.pep.drain()
    rig.switches.set(True, False)
    entered = rig.read(rig.pep.commit(STREAM, 2, H(NEW)))
    assert said(entered) == ("reconciling", "reconciling", 2) and entered.active_policy == P(NEW)
    entry = entered.reconciling
    assert (entry.owed, running(entry), entry.cause, entry.floor) == ("committed", None, None, ZERO)
    assert rig.host_active() is None                                     # withdrawn at once
    assert rig.pep.decide(lambda: "ran") == {"decision": None, "cause": "dist:reconciling", "mark": None}
    assert rig.pep.tick() is None and rig.pep.state() == "reconciling"
    beat = rig.read(rig.pep.record("beat"))
    assert beat.state == "reconciling" and beat.body == b"" and beat.reconciling is not None
    rig.switches.set(False, False)
    left = rig.read(rig.pep.tick())
    assert said(left) == ("committed", "active", 2) and left.extensions == b""
    assert [record.event for record in rig.records()] == ["reconciling", "beat", "committed"]
    assert rig.host_active() == H(NEW) and rig.pep.decide(lambda: "ran")["decision"] == "ran"
    assert (rig.actions("committed"), rig.actions("reconciling"), rig.actions("reconciled")) == (2, 1, 1)
    assert not rig.path("pending.json").exists()


def test_case_241_a_rollback_a_lapse_and_a_start_reconcile_and_report_what_they_owed(tmp_path):
    """case_241: C6, C7, C9. A rollback, a lapse at expiry and a start with no intent record, each with a runtime
    step that fails, are reconciling, then send `rolled-back`, `lapsed` with dist:expired and a `beat` with status
    active."""
    rig = FlakyHost(tmp_path / "rollback")
    rig.covered(OLD, 1)
    rig.commit(NEW, 2)
    rig.switches.set(True, False)
    entered = rig.read(rig.pep.rollback())
    assert said(entered) == ("reconciling", "reconciling", 1) and entered.reconciling.owed == "rolled-back"
    rig.switches.set(False, False)
    assert said(rig.read(rig.pep.tick())) == ("rolled-back", "active", 1) and rig.host_active() == H(OLD)

    rig = FlakyHost(tmp_path / "lapse")
    rig.commit(OLD)
    rig.clock.now = EXPIRES
    rig.switches.set(False, True)
    entered = rig.read(rig.pep.tick())
    assert said(entered) == ("reconciling", "reconciling", 0)
    entry = entered.reconciling
    assert (entry.owed, entry.cause, running(entry)) == ("lapsed", "dist:expired", (P(OLD), 1))
    assert rig.host_active() == H(OLD)                                   # the withdrawal is the step that failed
    rig.switches.set(False, False)
    left = rig.read(rig.pep.tick())
    assert (left.event, left.cause, left.state) == ("lapsed", "dist:expired", "no-policy") and rig.host_active() is None
    assert rig.actions("lapsed") == 1                                    # C12: written once

    rig = FlakyHost(tmp_path / "start")
    rig.commit(OLD)
    rig.pep.adapter.host.withdraw("dist:policy-lapsed")                  # the runtime lost what it ran
    rig.switches.set(True, True)
    rig.pep = rig.open()
    assert not rig.path("pending.json").exists()
    started = rig.records()
    assert [said(record) for record in started] == [("reconciling", "reconciling", 1)]
    assert (started[0].reconciling.owed, running(started[0].reconciling)) == ("beat", (P(OLD), 1))   # C7
    rig.switches.set(False, False)
    assert said(rig.read(rig.pep.tick())) == ("beat", "active", 1) and rig.host_active() == H(OLD)


def test_case_242_a_reconciling_pep_refuses_a_commit_a_delayed_commit_and_a_rollback(rig):
    """case_242: C8. A commit for the staged release, a commit with a delay that falls due and a rollback are each
    answered `refused` with dist:reconciling, nothing changes and the staged release stays staged."""
    monotonic = {"now": 0.0}
    rig.pep.monotonic = lambda: monotonic["now"]
    rig.covered(OLD, 1)
    rig.commit(NEW, 2)
    rig.stage(NEWER, 3)
    assert rig.read(rig.pep.commit(STREAM, 3, H(NEWER), delay_ms=500)).event == "beat"     # B8: due later
    rig.switches.set(True, False)
    assert rig.read(rig.pep.rollback()).event == "reconciling"
    rig.pep.drain()
    tries = rig.switches.tries()
    monotonic["now"] = 1.0
    rig.pep.record("beat")                                               # the delay falls due on the way in
    refused = [record for record in rig.records() if record.event == "refused"]
    committed = rig.read(rig.pep.commit(STREAM, 3, H(NEWER)))
    rolled = rig.read(rig.pep.rollback())
    for record in (refused[0], committed, rolled):
        assert (record.event, record.cause, record.state) == ("refused", "dist:reconciling", "reconciling")
        assert (record.active_seq, record.staged, record.staged_seq) == (1, True, 3)
    assert len(refused) == 1 and rig.pep.staged.seq == 3 and (rig.pep.active.seq, rig.pep.floor.seq) == (1, 2)
    assert rig.switches.tries() == tries                                  # no call but a tick tries the runtime


def test_case_243_a_reconciling_pep_stages_aborts_applies_trust_takes_an_anchor_and_a_statement(tmp_path):
    """case_243: C8, C9, G2, A1, R3. A reconciling PEP stages a new release with a stage ack that names it,
    replaces it with a higher one, aborts, applies a revocation, takes an anchor to confirm and takes the epoch id
    of a controller statement, and none of these tries the runtime."""
    rig = FlakyHost(tmp_path / "host", controller="C")
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=rig.clock)
    controller.add_anchor(rig.anchor(), dict(_dist.GEN.QUALIFICATION))
    rig.commit(OLD)
    rig.stage(NEW, 2)
    rig.switches.set(True, True)
    rig.pep.commit(STREAM, 2, H(NEW))
    tries = rig.switches.tries()
    staged = rig.read(rig.stage(NEWER, 3))
    release = _dist.env.release_id([("policy.ppt", H(NEWER))])
    assert (staged.event, staged.state, staged.staged_release) == ("staged", "reconciling", state_record.prefix(release))
    higher = rig.read(rig.stage(OLD, 4))
    assert (higher.event, higher.staged_seq) == ("staged", 4)
    assert rig.read(rig.pep.abort(STREAM, 4, H(OLD))).event == "aborted"
    applied = rig.read(rig.revoke(1, policies=[H(NEWER)]))
    assert (applied.event, applied.state, applied.trust_seq) == ("trust-applied", "reconciling", 1)
    rig.pep.provision(rig.anchor())
    assert rig.path("anchor.pending").exists()
    rig.pep.drain()
    assert rig.pep.take_statement(controller.statement(STREAM)) and rig.pep.drain() == []
    assert rig.read(rig.pep.record("beat")).epoch == controller.epoch_of(STREAM) == 1
    assert rig.switches.tries() == tries and rig.pep.state() == "reconciling"


def test_case_244_a_restarted_rollback_names_the_release_it_was_leaving(rig):
    """case_244: C7, H14. A rollback killed after its active record is restarted with a runtime that still fails:
    the entry names the release the rollback was leaving, read from the intent record, and the active fields the
    kept release."""
    rig.covered(OLD, 1)
    rig.commit(NEW, 2)
    rig.switches.die = True
    with pytest.raises(Died):
        rig.pep.rollback()
    rig.switches.die = False
    rig.switches.set(True, True)
    rig.pep = rig.open()
    last = rig.records()[-1]
    assert said(last) == ("reconciling", "reconciling", 1) and last.active_policy == P(OLD)
    assert (last.reconciling.owed, running(last.reconciling)) == ("rolled-back", (P(NEW), 2))
    assert rig.pep.running().seq == 2


def test_case_245_a_lapse_killed_before_its_active_record_is_lapsed_again_at_the_start(rig, monkeypatch):
    """case_245: C7. A lapse killed after its intent record and before its active record leaves the release active.
    The restart reports the lapse incomplete and its checks lapse the release again."""
    rig.commit(OLD)
    rig.clock.now = EXPIRES
    write = rig.pep.store.write

    def die(name, *rest):
        if name == "active.json":
            raise Died("the active record")
        return write(name, *rest)
    monkeypatch.setattr(rig.pep.store, "write", die)
    with pytest.raises(Died):
        rig.pep.tick()
    monkeypatch.undo()
    assert rig.path("pending.json").exists() and b"policy.ppt" in rig.path("active.json").read_bytes()
    rig.pep = rig.open()
    incomplete = [event for event in rig.pep.audit.events if event["action"] == "commit_incomplete"]
    assert [event["data"]["op"] for event in incomplete] == ["lapse"]
    assert [(record.event, record.cause) for record in rig.records()] == [("lapsed", "dist:expired")]
    assert rig.pep.state() == "no-policy" and rig.host_active() is None


def test_case_246_a_held_release_that_falls_while_withdrawn_is_never_installed(tmp_path):
    """case_246: C10, R5, X1, Q4, H14, the expiry and revocation runs. While a commit is reconciling with its
    runtime withdrawn, the held release expires, and in another run is revoked: it is never installed, the PEP is
    `no-policy` at once with one `lapsed` record of that cause and no `committed` record, and the floor stays the
    commit's. The ceiling and fallback runs are in test_distribution_install_controller.py."""
    for cause in ("dist:expired", "dist:revoked"):
        rig = FlakyHost(tmp_path / cause[5:])
        rig.commit(OLD)
        rig.stage(NEW, 2)
        rig.switches.set(True, False)
        rig.pep.commit(STREAM, 2, H(NEW))
        rig.pep.drain()
        activations = rig.switches.activations
        if cause == "dist:expired":
            rig.clock.now = EXPIRES
            rig.pep.record("beat")
        else:
            rig.revoke(1, policies=[H(NEW)])
        records = rig.records()
        lapsed = [record for record in records if record.event == "lapsed"]
        assert [(one.cause, one.state, one.active_seq) for one in lapsed] == [(cause, "no-policy", 0)], cause
        assert all(record.event != "committed" for record in records) and rig.switches.activations == activations
        assert (rig.pep.state(), rig.pep.floor.seq, rig.host_active()) == ("no-policy", 2, None)
        events = [event for event in rig.pep.audit.events if event["action"] == "lapsed"]
        assert len(events) == 1 and events[0]["data"]["ran"] is False


def test_case_247_a_running_release_that_will_not_withdraw_is_named_and_held_to_the_tests(rig):
    """case_247: C10, H14, X1. A commit whose runtime refuses to withdraw names the running release in every
    record, with dist:expired once it falls, each tick tries the withdrawal again, and the held release is still
    held to the tests."""
    rig.commit(OLD)
    rig.stage(NEW, 2, expires=EXPIRES + 86400)
    rig.switches.set(True, True)
    named = rig.read(rig.pep.commit(STREAM, 2, H(NEW))).reconciling
    assert (running(named), named.cause) == ((P(OLD), 1), None)
    withdrawals = rig.switches.withdrawals
    rig.clock.now = EXPIRES
    for tick in (1, 2, 3):
        assert rig.pep.tick() is None and rig.switches.withdrawals == withdrawals + tick
    beat = rig.read(rig.pep.record("beat"))
    assert (running(beat.reconciling), beat.reconciling.cause, beat.active_seq) == ((P(OLD), 1), "dist:expired", 2)
    rig.clock.now = EXPIRES + 86400
    both = rig.read(rig.pep.record("beat"))
    assert (both.reconciling.owed, both.reconciling.cause, both.active_seq) == ("lapsed", "dist:expired", 0)
    assert running(both.reconciling) == (P(OLD), 1)


def test_case_248_the_running_release_keeps_its_blobs_until_the_withdrawal_works(rig):
    """case_248: C11. A rollback whose runtime refuses to withdraw keeps every envelope and body of the release it
    was leaving through a stage of that release again, an abort and a higher release staged."""
    rig.covered(OLD, 1)
    rig.commit(NEW, 2)
    rig.switches.set(True, True)
    rig.pep.rollback()
    held = rig.pep.running().held["policy.ppt"]
    blobs = (held.sealed, held.body)
    rig.pep.stage(rig.pep.store.get(held.sealed), NEW)
    rig.pep.abort(STREAM, 2, H(NEW))
    rig.stage(NEWER, 3)
    rig.stage(OLD, 4)
    assert all(rig.pep.blob(name) is not None for name in blobs)
    rig.switches.set(False, False)
    rig.pep.tick()
    assert all(rig.pep.blob(name) is None for name in blobs)           # they go once the withdrawal works


@pytest.mark.parametrize("step", ("cleanup", "runtime"))
def test_case_249_a_commit_killed_around_its_record_is_reported_at_the_restart_and_audited_once(tmp_path,
                                                                                               monkeypatch, step):
    """case_249: C12, C4, H3. A commit killed after its state record is made and before its intent record goes is
    reported again at the restart with a higher counter, and one killed before its record is made once. Each run
    has one `committed` audit event."""
    rig = FlakyHost(tmp_path / step)
    rig.stage(OLD, 1)
    rig.pep.drain()
    if step == "cleanup":
        monkeypatch.setattr(rig.pep, "_cleanup", lambda: (_ for _ in ()).throw(Died("the clean up")))
    else:
        rig.switches.die = True
    with pytest.raises(Died):
        rig.pep.commit(STREAM, 1, H(OLD))
    monkeypatch.undo()
    rig.switches.die = False
    before = rig.records()
    rig.pep = rig.open()
    committed = [record for record in before + rig.records() if record.event == "committed"]
    assert len(committed) == (2 if step == "cleanup" else 1)
    assert all(later.counter > earlier.counter for earlier, later in zip(committed, committed[1:]))
    assert rig.actions("committed") == 1 and not rig.path("pending.json").exists() and rig.host_active() == H(OLD)


def test_case_250_a_locked_pep_whose_runtime_will_not_withdraw_carries_the_entry(rig):
    """case_250: C13, Q5, X3. A PEP whose floor cannot be read starts with a runtime that refuses to withdraw: it
    is `locked` with the entry and dist:floor-lost, each tick tries again, and once the runtime obeys it is
    `locked` with no entry."""
    rig.commit(OLD)
    rig.path("floor.json").write_bytes(b"{")
    rig.switches.set(False, True)
    rig.pep = rig.open(provision=False)
    started = rig.records()
    assert [said(record) for record in started] == [("reconciling", "locked", 0)]
    entry = started[0].reconciling
    assert (entry.owed, entry.cause, running(entry)) == ("beat", "dist:floor-lost", None)
    assert rig.pep.decide(lambda: "ran")["cause"] == "dist:floor-lost"
    withdrawals = rig.switches.withdrawals
    assert rig.pep.tick() is None and rig.switches.withdrawals == withdrawals + 1
    rig.switches.set(False, False)
    left = rig.read(rig.pep.tick())
    assert said(left) == ("beat", "locked", 0) and left.reconciling is None and rig.host_active() is None


def test_case_251_provisioning_withdraws_first_and_is_refused_over_a_stuck_runtime(rig):
    """case_251: P5, P3, H15. A reconciling PEP is not provisioned over a runtime that refuses to withdraw, and
    nothing changes. With one that obeys it is provisioned: `no-policy`, no intent record, no owed record sent and
    epoch 0."""
    rig.commit(OLD)
    rig.stage(NEW, 2)
    rig.switches.set(True, True)
    rig.pep.commit(STREAM, 2, H(NEW))
    rig.pep.drain()
    fingerprint = rig.pep.provision(rig.anchor())
    held = rig.path("active.json").read_bytes()
    with pytest.raises(PepRefused, match="P5"):
        rig.pep.confirm(fingerprint)
    assert rig.pep.state() == "reconciling" and rig.path("pending.json").exists() and rig.path("anchor.pending").exists()
    assert rig.path("active.json").read_bytes() == held and rig.pep.drain() == []
    rig.switches.set(True, False)
    provisioned = rig.read(rig.pep.confirm(fingerprint))
    assert (said(provisioned), provisioned.epoch, provisioned.reconciling) == (("provisioned", "no-policy", 0), 0, None)
    assert rig.pep.state() == "no-policy" and not rig.path("pending.json").exists() and rig.host_active() is None
    assert [record.event for record in rig.records()] == ["provisioned"]
    rig.switches.set(False, False)
    assert rig.pep.tick() is None and rig.pep.drain() == []              # the commit it owed is never sent


def test_case_274_a_renewal_whose_runtime_step_fails_stays_active(rig):
    """case_274: C10, X5. A renewal, whose bodies are byte for byte the active release's, whose runtime step fails
    stays `active` with the runtime running, sends `committed`, writes the failure to its audit log, tries again at
    the next tick and never withdraws."""
    rig.commit(OLD)
    rig.stage(OLD, 2, expires=EXPIRES + 86400)
    assert "trust.widening" not in rig.pep.staged.held                    # a renewal needs no statement
    rig.pep.drain()
    rig.switches.set(True, False)
    withdrawals = rig.switches.withdrawals
    committed = rig.read(rig.pep.commit(STREAM, 2, H(OLD)))
    assert said(committed) == ("committed", "active", 2) and committed.reconciling is None
    assert rig.actions("runtime_failed") == 1 and rig.host_active() == H(OLD)
    assert rig.pep.decide(lambda: "ran")["decision"] == "ran"
    activations = rig.switches.activations
    assert rig.pep.tick() is None and rig.switches.activations == activations + 1
    rig.switches.set(False, False)
    rig.pep.tick()
    rig.pep.tick()
    assert rig.switches.tries() == (activations + 2, withdrawals) and rig.pep.state() == "active"


def test_only_a_tick_and_a_start_try_the_runtime(rig):
    """C9: no decision, record, stage or abort tries the runtime. A tick makes one try, and a start that finds the
    state reports it again (C12)."""
    rig.commit(OLD)
    rig.stage(NEW, 2)
    rig.switches.set(True, True)
    rig.pep.commit(STREAM, 2, H(NEW))
    tries = rig.switches.tries()
    for _ in range(5):
        rig.pep.decide(lambda: None)
        rig.pep.record("beat")
    assert rig.switches.tries() == tries
    rig.pep.tick()
    assert rig.switches.tries() == (tries[0], tries[1] + 1)             # the withdrawal that failed, alone
    rig.pep = rig.open()
    assert rig.pep.state() == "reconciling" and rig.records()[-1].event == "reconciling"
    assert rig.actions("reconciling") == 2


# ------------------------------------------------------------------ the agent home, the mesh and the gateway

def test_case_267_an_agent_commit_never_reconciles_and_its_lapse_waits_for_every_session(tmp_path, monkeypatch):
    """case_267: C6, H14. An agent home commits a release while two sandboxed sessions of the older one run: it is
    not reconciling, no session is ended and the home's deciders read the new release at their next call. A mesh
    and a gateway PEP each commit and are not reconciling. The agent release then lapses with both sessions
    running, one of which ignores the terminate: the launcher's withdrawal ends the first, the PEP is reconciling
    with the lapsed release as the running release, and the next try kills the second and sends `lapsed`."""
    from prismpath.distribution.adapters import agent_home
    from prismpath.tests.test_distribution_agent_home import DEFAULT, STRICT, HomePep
    from prismpath.tests.test_distribution_gateway import DEMO, GatewayHome
    monkeypatch.setattr(agent_home, "clock", lambda: _dist.NOW)
    home = HomePep(tmp_path / "agent")
    assert home.release(STRICT, 1)[-1].event == "committed"
    sessions = [subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True),
                subprocess.Popen([sys.executable, "-c", "import signal, time; signal.signal(signal.SIGTERM, "
                                  "signal.SIG_IGN); print('ready', flush=True); time.sleep(60)"],
                                 start_new_session=True, stdout=subprocess.PIPE)]
    try:
        assert sessions[1].stdout.readline().strip() == b"ready"
        for proc in sessions:
            agent_home.register_session(home.state_dir, proc.pid, H(STRICT))
        committed = home.release(DEFAULT, 2)[-1]
        assert (committed.event, committed.state, committed.extensions) == ("committed", "active", b"")
        assert agent_home.committed(home.state_dir)["policy.core"] == DEFAULT        # the next call reads it
        assert all(proc.poll() is None for proc in sessions)                         # a commit ends no session
        home.pep.drain()
        home.clock.now = EXPIRES
        entered = state_record.read(home.pep.tick(), home.key.public_raw)
        assert (entered.event, entered.state) == ("reconciling", "reconciling")
        assert (entered.reconciling.owed, entered.reconciling.cause) == ("lapsed", "dist:expired")
        assert running(entered.reconciling) == (state_record.prefix(H(DEFAULT)), 2)
        assert sessions[0].wait(5) is not None and sessions[1].poll() is None
        assert home.pep.decide(lambda: "ran")["cause"] == "dist:reconciling"
        left = state_record.read(home.pep.tick(), home.key.public_raw)                # the next try kills it
        assert (left.event, left.cause, left.state) == ("lapsed", "dist:expired", "no-policy")
        assert sessions[1].wait(5) is not None and agent_home.sessions(home.state_dir) == []
    finally:
        for proc in sessions:
            if proc.poll() is None:
                proc.kill()
            proc.wait()

    mesh = _dist.MeshPep(tmp_path / "mesh")
    record = state_record.read(mesh.commit(OLD), mesh.key.public_raw)
    assert (record.event, record.state) == ("committed", "active")
    gateway = GatewayHome(tmp_path / "gateway")
    record = gateway.release(DEMO, 1)[-1]
    assert (record.event, record.state, gateway.pep.reconciling) == ("committed", "active", None)


# ------------------------------------------------------------------ H14 at the controller

class Fleet:
    """A controller and one flaky host PEP under one clock, with a controller key in its anchor."""

    def __init__(self, tmp_path):
        self.rig = FlakyHost(tmp_path / "host", controller="C")
        self.clock = self.rig.clock
        self.controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=self.clock)
        self.controller.add_anchor(self.rig.anchor(), dict(_dist.GEN.QUALIFICATION))
        self.pep_id = self.controller.enroll(self.rig.key.public_raw, "host", STREAM, "fleet")
        self.member = self.controller.members[self.pep_id]
        self.previous = ""

    def put(self, body, seq):
        for sealed, data in _dist.release_with_statement(self.rig, body, seq, widen=H(body) != self.previous,
                                                         replaces=self.previous):
            self.controller.put(sealed, data)
        self.previous = H(body)

    def send(self):
        """Every record the PEP made, after it took the controller's current statement, to the controller."""
        return [self.controller.receive(signed) for signed in self.rig.pep.drain()]

    def fresh(self):
        self.rig.pep.take_statement(self.controller.statement(STREAM))

    def stage_offered(self, rollout):
        for envelope_id in rollout.envelopes:
            info = self.controller.stored[envelope_id]
            self.rig.pep.stage(self.controller.sealed(envelope_id), self.controller.blob(info["body_sha256"]))


def test_case_252_a_record_with_a_wrong_reconciling_entry_is_state_invalid(tmp_path):
    """case_252: H14, H10. A record with status 3 and no type 4 entry, one with two, one with a type 4 entry under
    status 1, and one whose entry is 57 bytes are each `fleet:state-invalid`."""
    fleet = Fleet(tmp_path)
    fleet.fresh()
    good = state_record.read(fleet.rig.pep.record("beat"), fleet.rig.key.public_raw)
    entry = state_record.ReconcilingEntry(owed="committed").extension()
    short = bytes([4]) + (57).to_bytes(2, "little") + bytes(57)
    for state, extensions in (("reconciling", b""), ("reconciling", entry + entry), ("active", entry),
                              ("reconciling", short)):
        signed = state_record.build(replace(good, state=state, extensions=extensions, counter=good.counter + 1),
                                    fleet.rig.key)
        with pytest.raises(state_record.Refused):
            state_record.read(signed, fleet.rig.key.public_raw)
        assert fleet.controller.receive(signed) == "fleet:state-invalid"
    fine = state_record.build(replace(good, state="reconciling", extensions=entry, counter=good.counter + 2),
                              fleet.rig.key)
    assert state_record.read(fine, fleet.rig.key.public_raw).reconciling.owed == "committed"


def test_case_253_a_reconciling_record_never_moves_a_member_to_committed(tmp_path):
    """case_253: H14, F3. A controller in `committing` receives a reconciling record whose active fields name the
    new release and whose entry names the replaced one, a stage ack for a newer release in a reconciling record,
    then a `committed` record with status 1: the member is not committed and no policy mismatch is filed, the ack
    counts for the newer rollout, then `committed`. The entry naming a running release is filed dist:reconciling
    at once, as H14 item 2 says."""
    fleet = Fleet(tmp_path)
    fleet.put(OLD, 1)
    rollout = fleet.controller.offer("fleet", STREAM, 1)
    fleet.fresh()
    fleet.stage_offered(rollout)
    fleet.rig.pep.commit(STREAM, 1, H(OLD))
    fleet.send()
    fleet.controller.tick()
    assert rollout.state == "committed"
    fleet.put(NEW, 2)
    rollout = fleet.controller.offer("fleet", STREAM, 2)
    fleet.stage_offered(rollout)
    fleet.send()
    assert rollout.members[fleet.pep_id] == "committing"
    fleet.rig.switches.set(True, True)
    fleet.rig.pep.commit(STREAM, 2, H(NEW))
    findings = fleet.send()
    assert rollout.members[fleet.pep_id] == "committing" and "fleet:policy-mismatch" not in fleet.member.findings
    assert findings[-1] == "dist:reconciling" or "dist:reconciling" in fleet.member.findings
    fleet.put(NEWER, 3)
    newer = fleet.controller.offer("fleet", STREAM, 3)
    assert rollout.state == "aborted"
    fleet.stage_offered(newer)
    fleet.send()
    assert newer.members[fleet.pep_id] == "committing"                  # the acks of a reconciling PEP count
    fleet.rig.switches.set(False, False)
    fleet.rig.pep.tick()                                                 # the try works: committed, status 1
    fleet.rig.pep.commit(STREAM, 3, H(NEWER))
    fleet.send()
    assert newer.members[fleet.pep_id] == "committed" and "dist:reconciling" not in fleet.member.findings


def test_case_254_reconciling_is_filed_after_three_intervals_or_at_once(tmp_path):
    """case_254: H14, F4. Reconciling records that name no running release are filed dist:reconciling after the
    third interval. One whose entry names a running release, one whose floor field is not the held floor and a
    locked record with the entry are each filed at once, the running release and the floor are in the fleet view,
    and a record without the entry clears it."""
    fleet = Fleet(tmp_path)
    fleet.rig.commit(OLD)
    fleet.member.expected = (H(OLD), fleet.rig.pep.active.release, 1)
    fleet.rig.stage(NEW, 2)
    fleet.rig.switches.set(True, False)
    fleet.rig.pep.commit(STREAM, 2, H(NEW))
    fleet.member.expected = (H(NEW), fleet.rig.pep.active.release, 2)
    interval = fleet.controller.interval
    for step in range(3):
        fleet.fresh()
        fleet.rig.pep.record("beat")
        fleet.send()
        assert "dist:reconciling" not in fleet.member.findings, step
        fleet.clock.now += interval
    fleet.fresh()
    fleet.rig.pep.record("beat")
    fleet.send()
    assert "dist:reconciling" in fleet.member.findings
    fleet.rig.switches.set(False, False)
    fleet.rig.pep.tick()
    fleet.send()
    assert "dist:reconciling" not in fleet.member.findings
    view = fleet.controller.fleet()["peps"][0]
    assert view["running"] is None
    good = state_record.read(fleet.rig.pep.record("beat"), fleet.rig.key.public_raw)
    fleet.rig.pep.drain()
    counter = good.counter
    for state, entry in (("reconciling", state_record.ReconcilingEntry(owed="committed", running_policy=P(OLD),
                                                                        running_release=b"\x01" * 16, running_seq=1)),
                         ("reconciling", state_record.ReconcilingEntry(owed="committed", floor=b"\x02" * 16)),
                         ("locked", state_record.ReconcilingEntry(cause="dist:floor-lost"))):
        counter += 1
        signed = state_record.build(replace(good, state=state, extensions=entry.extension(), counter=counter),
                                    fleet.rig.key)
        fleet.controller.receive(signed)
        assert "dist:reconciling" in fleet.member.findings, state
        shown = fleet.controller.fleet()["peps"][0]["running"]
        assert (shown["seq"], shown["floor"]) == (entry.running_seq, entry.floor.hex())
        counter += 1
        fleet.controller.receive(state_record.build(replace(good, counter=counter), fleet.rig.key))
        assert "dist:reconciling" not in fleet.member.findings


def test_case_255_the_controller_takes_a_commit_from_the_fields_of_any_record(tmp_path):
    """case_255: H14, C12. Two `committed` records for one commit with rising counters: the second changes
    nothing. In another run no `committed` record comes, and a `beat` with status 1 and the new release moves the
    member to `committed`."""
    for lost in (False, True):
        fleet = Fleet(tmp_path / str(lost))
        fleet.put(OLD, 1)
        rollout = fleet.controller.offer("fleet", STREAM, 1)
        fleet.fresh()
        fleet.stage_offered(rollout)
        fleet.send()
        signed = fleet.rig.pep.commit(STREAM, 1, H(OLD))
        fleet.rig.pep.drain()
        if not lost:
            assert fleet.controller.receive(signed) is None and rollout.members[fleet.pep_id] == "committed"
            again = replace(state_record.read(signed, fleet.rig.key.public_raw), counter=fleet.member.counter + 1)
            before = (rollout.document(), dict(fleet.member.findings))
            assert fleet.controller.receive(state_record.build(again, fleet.rig.key)) is None
            assert (rollout.document(), dict(fleet.member.findings)) == before
        else:
            assert rollout.members[fleet.pep_id] == "committing"
            fleet.rig.pep.record("beat")
            fleet.send()
            assert rollout.members[fleet.pep_id] == "committed"
