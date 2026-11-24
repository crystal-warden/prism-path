# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The install statements, the fallback policy and the ceiling of policy distribution (spec-policy-distribution.md,
section 21.1, 21.3 and 21.4) in the Python machine, on `host`, `mesh` and `agent`. The `cfs` halves are in
integrations/cfs/tests/test_cfs_dist.py. Each test names the conformance case of section 20 it covers."""
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import frames, install, kinds, state_record  # noqa: E402
from prismpath.distribution.kinds import Refused  # noqa: E402
from prismpath.distribution.pep import PepRefused, read_committed_release  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import EXPIRES, GEN, NOT_BEFORE, NOW, STREAM, image, public, seal  # noqa: E402

H = canon.sha256_hex
KEYS = ["N1", "N2", "N3"]
FALLBACK, CEILING, TRUST = "install.fallback", "install.ceiling", "install.trust"


def _read(point, signed):
    return state_record.read(signed, point.key.public_raw)


def _host(tmp_path, name="host", **settings):
    settings.setdefault("install_keys", KEYS)
    settings.setdefault("install_threshold", 2)
    return _dist.HostPep(tmp_path / name, **settings)


def _mesh(tmp_path, name="mesh", **settings):
    settings.setdefault("install_keys", KEYS)
    settings.setdefault("install_threshold", 2)
    return _dist.MeshPep(tmp_path / name, **settings)


def _fallback(point, body, seq=1, **args):
    """The fallback set of `body` on a table kind, said to widen unless the caller says otherwise."""
    args.setdefault("widens", True)
    return point.install_set(FALLBACK, {point.artifact: body}, seq, **args)


def _held(point, kind):
    return point.pep.installed.held(kind)


def _raw_statement(point, changes, *, body=b"", signers=("N1", "N2")):
    """An install statement written as raw canon/2 bytes, so a member the writer refuses can be sent."""
    doc = {"artifact": FALLBACK, "body_sha256": H(body), "body_size": len(body), "encoding": "canon/2", "expires": 0,
           "format": env.FORMAT, "meta": {"as": "policy.ppt", **GEN.image_meta(image(9))}, "not_before": NOT_BEFORE,
           "policy_sha256": H(body), "release": env.install_release_id([("policy.ppt", H(body))]), "replaces": "",
           "seq": 1, "stream": STREAM, "targets": [point.kind], "widens": True}
    doc.update(changes)
    raw = canon.canon2_bytes(doc)
    return env.seal_entries(raw, sorted((_dist.key_id(name), GEN.test_key(name).sign(env.signed_message(raw)))
                                        for name in signers))


# ------------------------------------------------------------------ IS1, IS2, IS5: what an install statement is

def test_case_162_an_install_statement_is_checked_as_its_rules_say(tmp_path):
    """case_162: IS1, IS2, IS5. Signed only by an authority key, with `expires` set, naming two kinds, for another
    stream, with a body one byte short, a body that fails its artifact's check, no `as`, and `not_before` 301 seconds
    ahead of a PEP with a clock, each is refused with its cause and the PEP holds what it held."""
    point = _host(tmp_path)
    body = image(9)
    before = point.pep.installed.record

    def answer(sealed, data=body):
        record = _read(point, point.pep.stage(sealed, data))
        assert point.pep.installed.record == before and not point.pep.installed.staged
        return record.cause

    good = _fallback(point, body)[0][0]
    by_authority = point.install_set(FALLBACK, {"policy.ppt": body}, signers=["A"], widens=True)[0][0]
    assert answer(by_authority) == "dist:unknown-key"
    assert answer(_raw_statement(point, {"expires": NOT_BEFORE + 30 * 86400}, body=body)) == "dist:bad-format"
    assert answer(_raw_statement(point, {"targets": ["host", "mesh"]}, body=body)) == "dist:bad-format"
    other = point.install_set(FALLBACK, {"policy.ppt": body}, widens=True)
    other_stream = install.seal_set(FALLBACK, {"policy.ppt": body}, stream="other", seq=1, target="host",
                                    signers=[GEN.test_key("N1"), GEN.test_key("N2")], widens=True,
                                    metas={"policy.ppt": GEN.image_meta(body)}, not_before=NOT_BEFORE)
    assert answer(other_stream[0][0]) == "dist:target-mismatch"
    assert answer(other[0][0], body[:-1]) == "dist:body-mismatch"
    broken = b"PPT1" + b"\x00" * 40
    failing = point.install_set(FALLBACK, {"policy.ppt": broken}, metas={"policy.ppt": GEN.image_meta(body)},
                                widens=True)
    from prismpath.hotswap import policy_pack
    expected = install.kinds.causes.reason_name(policy_pack.validate_image(broken)[1][0])
    assert answer(failing[0][0], broken) == expected
    no_as = _raw_statement(point, {"meta": GEN.image_meta(body)}, body=body)
    assert answer(no_as) == "dist:bad-format"
    early = point.install_set(FALLBACK, {"policy.ppt": body}, widens=True, not_before=NOW + 301)
    assert answer(early[0][0]) == "dist:not-yet-valid"
    assert _read(point, point.pep.stage(good, body)).event == "install-widened"


def test_case_163_the_install_role_and_the_authority_role_are_strictly_apart(tmp_path):
    """case_163: IS2, K4, O4. An anchor that holds one key in both roles and one whose install key is the PEP's
    instance key are refused at provisioning. A release, a widening statement, a revocation and a rotation signed
    only by install keys are `dist:unknown-key`, and a rotation that adds an install key or a retired install key is
    `dist:rotation-invalid`."""
    fresh = _host(tmp_path, "fresh", install_keys=[])
    with pytest.raises((Refused, PepRefused)):
        fresh.pep.provision(_host(tmp_path, "template").anchor(keys=["A", "N2"]))
    with pytest.raises(PepRefused):
        fresh.pep.provision(_host(tmp_path, "template2").anchor(keys=["I"], threshold=1))
    point = _host(tmp_path)
    body = image(9)
    release = seal("policy.ppt", body, signer="N1", targets=("host",), widens=True)
    assert _read(point, point.pep.stage(release, body)).cause == "dist:unknown-key"
    statement = _dist.widening()
    widening = seal("trust.widening", statement, signer="N1", targets=("host",),
                    release=env.release_id([("policy.ppt", H(body))]), policy_sha256=H(body), widens=True)
    assert _read(point, point.pep.stage(widening, statement)).cause == "dist:unknown-key"
    assert _read(point, point.revoke(1, signer="N1")).cause == "dist:unknown-key"
    assert _read(point, point.rotate(1, "B", signers=("N1", "B"))).cause == "dist:unknown-key"
    assert _read(point, point.rotate(1, "N3")).cause == "dist:rotation-invalid"
    sealed, trust_body = point.install_trust(1, ["N1", "N2"], threshold=2)
    assert _read(point, point.pep.stage(sealed, trust_body)).event == "install-applied"
    assert _dist.key_id("N3") in point.pep.installed.record.retired
    assert _read(point, point.rotate(1, "N3")).cause == "dist:rotation-invalid"
    assert point.pep.trust.trust_seq == 0


def test_case_165_an_install_statement_counts_against_the_install_threshold(tmp_path):
    """case_165: IS2. With three install keys and an install threshold of 2, one good signature is
    `dist:unknown-key`, two are applied, and one good one beside one by a retired install key is
    `sig:revoked-key`."""
    point = _host(tmp_path)
    assert point.send(_fallback(point, image(9), signers=["N1"]))[-1].cause == "dist:unknown-key"
    assert point.send(_fallback(point, image(9), signers=["N1", "N2"]))[-1].event == "install-widened"
    sealed, body = point.install_trust(1, ["N1", "N2", "N4"], threshold=2, signers=["N1", "N2", "N4"])
    assert _read(point, point.pep.stage(sealed, body)).cause == "dist:install-widened"
    retired = _fallback(point, image(8), 2, signers=["N1", "N3"])
    assert _read(point, point.pep.stage(*retired[0])).cause == "sig:revoked-key"
    assert _held(point, FALLBACK).seq == 1


# ------------------------------------------------------------------ IS4, IS6: staging and applying a set

def _agent(tmp_path, name="agent", **settings):
    settings.setdefault("install_keys", KEYS)
    settings.setdefault("install_threshold", 2)
    return _dist.AgentPep(tmp_path / name, **settings)


def _policy(*rules):
    from prismpath.kernel.policy_source import compile_source
    return compile_source("---\nname: small\nstart: core_decision\nfield.tool: category\nfield.path_scope: category\n"
                          "---\n## core_decision\n"
                          '-> refuse agent:unclassifiable: when tool == "unknown" or path_scope == "unknown"\n'
                          '-> allow: when tool == "read_file" and path_scope == "workspace"\n'
                          + "".join(rule + "\n" for rule in rules))


NARROW = _policy()
WIDER = _policy('-> allow: when tool == "write_file" and path_scope == "workspace"')
WIDEST = _policy('-> allow: when tool == "write_file" and path_scope == "workspace"',
                 '-> allow: when tool == "list_dir" and path_scope == "workspace"')
HOSTS = canon.canon2_bytes(["api.example.com"])
MORE_HOSTS = canon.canon2_bytes(["api.example.com", "docs.example.com"])


def _zones(*names):
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.ZONES_FORMAT,
                               "protected": sorted(names)})


def _agent_set(point, kind, core, seq, hosts=HOSTS, zones=None, **args):
    bodies = {"policy.core": core, "egress.hosts": hosts}
    if zones is not None:
        bodies["agent.zones"] = zones
    args.setdefault("widens", kind == FALLBACK)
    return point.install_set(kind, bodies, seq, **args)


def test_case_168_a_set_is_staged_a_statement_at_a_time_and_applied_whole(tmp_path):
    """case_168: IS4, G1, G2. The fallback policy of an `agent` PEP arrives one statement at a time. The held one
    decides throughout, each statement is staged with event `staged` and survives a restart, and the set is applied
    when its last statement arrives. A set at a higher `seq` replaces the staged one, a lower one is then
    `dist:seq-replay`, and no reader ever sees a mix of two sets."""
    point = _agent(tmp_path)
    assert point.send(_agent_set(point, FALLBACK, NARROW, 1))[-1].event == "install-widened"
    held = _held(point, FALLBACK)

    def deciding():
        assert point.pep.fallback_decides() and point.pep.adapter.running.policy_sha256 == _held(point, FALLBACK).policy_sha256
        bodies = read_committed_release(str(point.state_dir), "agent", NOW).bodies
        assert (bodies["policy.core"], bodies["egress.hosts"]) in ((NARROW, HOSTS), (WIDER, MORE_HOSTS),
                                                                    (WIDEST, MORE_HOSTS))
        return bodies["policy.core"]

    second = _agent_set(point, FALLBACK, WIDER, 2, MORE_HOSTS)
    core = [pair for pair in second if pair[1] == WIDER][0]
    staged = point.send([core])[-1]
    assert (staged.event, staged.install.subject) == ("staged", "install.fallback") and deciding() == NARROW
    point.pep = point.open()                                                    # a restart before the last statement
    assert point.pep.installed.staged[FALLBACK].seq == 2 and _held(point, FALLBACK) == held and deciding() == NARROW
    hosts = [pair for pair in second if pair[1] == MORE_HOSTS][0]
    assert point.send([hosts])[-1].event == "install-widened" and deciding() == WIDER
    third, fourth = _agent_set(point, FALLBACK, NARROW, 3, MORE_HOSTS, widens=True), \
        _agent_set(point, FALLBACK, WIDEST, 4, MORE_HOSTS)
    assert point.send([third[1]])[-1].event == "staged" and deciding() == WIDER
    assert point.send([fourth[1]])[-1].event == "staged" and point.pep.installed.staged[FALLBACK].seq == 4
    assert point.send([third[0]])[-1].cause == "dist:seq-replay" and deciding() == WIDER
    assert point.send([fourth[0]])[-1].event == "install-widened" and deciding() == WIDEST


def _lock(point):
    (point.state_dir / "dist" / "floor.json").write_bytes(b"not a floor")
    point.pep = point.open(provision=False)
    assert point.pep.state() == "locked"


def test_case_171_a_locked_pep_still_takes_install_statements(tmp_path):
    """case_171: IS6, FB1. A `locked` PEP with an install threshold of 2 applies a fallback policy at a higher `seq`
    and stays `locked`, deciding under it."""
    point = _host(tmp_path)
    point.send(_fallback(point, image(9)))
    _lock(point)
    applied = point.send(_fallback(point, image(8), 2))[-1]
    assert (applied.event, applied.state) == ("install-widened", "locked")
    assert point.pep.state() == "locked" and _held(point, FALLBACK).seq == 2
    assert point.pep.decide(lambda: "runs")["basis"] == "fallback"
    assert point.pep.adapter.host.active()["active"] == H(image(8))


# ------------------------------------------------------------------ IS11: the install trust statement

def test_case_175_an_install_trust_statement_is_held_to_its_rules(tmp_path):
    """case_175: IS11, IS7. Two above the install trust sequence, without the signature of the key it adds, with fewer
    signatures than the install threshold, with five keys, with a threshold of 0, adding the PEP's instance key, a
    trusted authority key, a key id on the revocation list or a retired install key, and signed only by authority
    keys: each refused with its cause, and the trust store of section 5 unchanged."""
    point = _host(tmp_path, authorities=["A", "B"])
    point.revoke(1, keys=[_dist.key_id("R")])
    store = point.pep.trust
    sealed, body = point.install_trust(1, ["N1", "N2"], threshold=2)
    assert _read(point, point.pep.stage(sealed, body)).event == "install-applied"          # N3 retired

    def answer(sealed, body):
        record = _read(point, point.pep.stage(sealed, body))
        assert point.pep.trust.to_bytes() == store.to_bytes()
        return record.cause

    point.install_keys = ["N1", "N2"]
    assert answer(*point.install_trust(3, ["N1", "N2", "N4"], threshold=2)) == "dist:trust-replay"
    assert answer(*point.install_trust(2, ["N1", "N2", "N4"], threshold=2, signers=["N1", "N2"])) \
        == "dist:rotation-invalid"
    assert answer(*point.install_trust(2, ["N1", "N2", "N4"], threshold=2, signers=["N1", "N4"])) \
        == "dist:unknown-key"
    five = install.kinds.INSTALL_TRUST_FORMAT
    too_many = canon.canon2_bytes({"encoding": "canon/2", "format": five,
                                   "keys": sorted(public(name).hex() for name in ("N1", "N2", "N4", "N5", "N6")),
                                   "operators": [], "threshold": 2})
    assert answer(_trust_raw(point, 2, too_many, ["N1", "N2"]), too_many) == "dist:too-large"
    zero = canon.canon2_bytes({"encoding": "canon/2", "format": five,
                               "keys": sorted(public(name).hex() for name in ("N1", "N2")), "operators": [],
                               "threshold": 0})
    assert answer(_trust_raw(point, 2, zero, ["N1", "N2"]), zero) == "dist:bad-format"
    for added in ("I", "A", "R", "N3"):
        assert answer(*point.install_trust(2, ["N1", "N2", added], threshold=2)) == "dist:rotation-invalid", added
    assert answer(*point.install_trust(2, ["N1", "N2", "N4"], threshold=2, signers=["A", "B"])) == "dist:unknown-key"
    assert point.pep.installed.record.trust_seq == 1


def _trust_raw(point, seq, body, signers, widens=True):
    """An `install.trust` written as raw canon/2 bytes, for a body the writer refuses."""
    envelope_bytes = canon.canon2_bytes({
            "artifact": TRUST, "body_sha256": H(body), "body_size": len(body), "encoding": "canon/2", "expires": 0,
            "format": env.FORMAT, "meta": {}, "not_before": NOT_BEFORE, "policy_sha256": env.ZERO_HASH,
            "release": env.ZERO_HASH, "replaces": "", "seq": seq, "stream": STREAM, "targets": ["host"],
            "widens": widens})
    return env.seal(envelope_bytes, [GEN.test_key(name) for name in signers])


def test_case_176_a_statement_that_needs_five_signatures_is_made_in_two(tmp_path):
    """case_176: IS11. Four install keys at a threshold of 4 adding a fifth key would need five signatures, which a
    sealed envelope cannot hold, so the sealing tool refuses it. The engineer drops a key with the threshold at 3,
    then adds the new one, and the PEP applies both."""
    point = _host(tmp_path, install_keys=["N1", "N2", "N3", "N4"], install_threshold=4)
    record = point.pep.installed.record
    body = install.trust_body([public(name) for name in ("N1", "N2", "N3", "N5")], threshold=4)
    with pytest.raises(Refused) as refused:
        install.seal_trust(record, body, stream=STREAM, seq=1, targets=["host"],
                           signers=[GEN.test_key(name) for name in ("N1", "N2", "N3", "N4", "N5")],
                           not_before=NOT_BEFORE)
    assert refused.value.cause == "dist:too-large" and "5 signatures" in str(refused.value)
    first = install.trust_body([public(name) for name in ("N1", "N2", "N3")], threshold=3)
    sealed = install.seal_trust(record, first, stream=STREAM, seq=1, targets=["host"],
                                signers=[GEN.test_key(name) for name in ("N1", "N2", "N3", "N4")], not_before=NOT_BEFORE)
    assert _read(point, point.pep.stage(sealed, first)).event == "install-widened"           # a lower threshold
    record = point.pep.installed.record
    second = install.trust_body([public(name) for name in ("N1", "N2", "N3", "N5")], threshold=3)
    sealed = install.seal_trust(record, second, stream=STREAM, seq=2, targets=["host"],
                                signers=[GEN.test_key(name) for name in ("N1", "N2", "N3", "N5")], not_before=NOT_BEFORE)
    assert _read(point, point.pep.stage(sealed, second)).event == "install-widened"
    assert set(point.pep.installed.record.keys) == {_dist.key_id(name) for name in ("N1", "N2", "N3", "N5")}


# ------------------------------------------------------------------ FB1 to FB9: the fallback policy

def test_case_196_the_runtime_decides_under_the_fallback_set_and_without_one_refuses(tmp_path, monkeypatch):
    """case_196: FB1, X3. A `host` PEP with a fallback policy lapses and its runtime decides under the fallback
    `policy.ppt`; an `agent` home with one lapses and its hook, its egress proxy and its MCP proxy all read the
    fallback set. The same two with none lapse, the host withdraws its policy and every part of the home refuses."""
    from prismpath.agent import commands, egress_policy, mcp_proxy
    from prismpath.agent.profile import compile_profile
    from prismpath.distribution.adapters import agent_home
    from prismpath.tests.test_distribution_agent_home import ALLOW_HOSTS, DEFAULT, HomePep
    for with_fallback in (True, False):
        host = _host(tmp_path, f"host{with_fallback}")
        if with_fallback:
            host.send(_fallback(host, image(9)))
        host.commit(image(5))
        assert host.pep.adapter.host.active()["active"] == H(image(5))
        host.clock.now = EXPIRES
        lapsed = _read(host, host.pep.tick())
        if with_fallback:
            assert (lapsed.event, lapsed.fallback) == ("fallback", True)
            assert host.pep.adapter.host.active()["active"] == H(image(9))
        else:
            assert (lapsed.event, lapsed.fallback) == ("lapsed", False)
            assert host.pep.adapter.host.active().get("active") is None
        home = HomePep(tmp_path / f"home{with_fallback}", install_keys=KEYS, install_threshold=2)
        if with_fallback:
            home.send(home.install_set(FALLBACK, {"policy.core": DEFAULT, "egress.hosts": MORE_HOSTS}, 1, widens=True))
        assert home.release(ALLOW_HOSTS, 1)[-1].event == "committed"
        monkeypatch.setattr(agent_home, "clock", lambda: EXPIRES)
        home.clock.now = EXPIRES
        home.pep.tick()
        workspace = tmp_path / f"ws{with_fallback}"
        workspace.mkdir()
        (workspace / "f.txt").write_text("x")
        if not with_fallback:
            with pytest.raises(commands.AgentError):
                commands.load_checked(home.state_dir)
            with pytest.raises(commands.AgentError):
                commands.Committed(home.state_dir).current()
            governor = mcp_proxy.Governor(home.state_dir, tmp_path / "runs-none", "s1", workspace, str(workspace))
            assert governor.decide({"name": "read_file", "arguments": {"path": str(workspace / "f.txt")}}).kind == "refuse"
            monkeypatch.undo()
            continue
        policy, store = commands.load_checked(home.state_dir)                  # the hook's policy
        assert policy.image == DEFAULT and commands.hosts_of(home.state_dir) == ("api.example.com", "docs.example.com")
        gate = egress_policy.PolicyGate(policy, store, "egress-s", workspace, compile_profile(policy, "agent"),
                                        commands.hosts_of(home.state_dir), follow=commands.Committed(home.state_dir))
        assert commands.Committed(home.state_dir).current()[0].image == DEFAULT
        governor = mcp_proxy.Governor(home.state_dir, tmp_path / "runs", "s1", workspace, str(workspace))
        assert governor.decide({"name": "read_file", "arguments": {"path": str(workspace / "f.txt")}}).kind == "allow"
        assert gate("docs.example.com:443")[1] != "policy-lapsed"
        monkeypatch.undo()


def test_case_198_a_pep_that_goes_to_its_fallback_policy_sends_its_record_and_nothing_else(tmp_path):
    """case_198: FB4. On a medium where every frame it sends is recorded, a `mesh` PEP that goes to its fallback
    policy sends one state frame, its `fallback` record, and its runtime is handed the fallback table and nothing
    else, so no command leaves it that was not proposed to it."""
    point = _mesh(tmp_path)
    point.send(_fallback(point, image(9)))
    point.commit(image(5))
    calls = []
    adapter = point.pep.adapter
    for name in ("activate", "deactivate", "withdraw_to"):
        original = getattr(adapter, name)
        setattr(adapter, name, (lambda original, name: lambda *args: (calls.append(name), original(*args))[1])(
            original, name))
    point.pep.drain()
    point.clock.now = EXPIRES
    point.pep.tick()
    medium = [frames.encode(frames.State(0, record), limit=1024) for record in point.pep.drain()]
    assert len(medium) == 1 and _read(point, frames.decode(medium[0], limit=1024).record).event == "fallback"
    assert calls == ["withdraw_to", "activate"] and adapter.table == image(9)


def test_case_199_the_only_way_out_of_the_fallback_policy_is_a_release_that_passes_every_rule(tmp_path):
    """case_199: FB5, FB2. Under its fallback policy a PEP refuses a release with no widening statement and one whose
    statement names the fallback policy's hash, and commits one whose statement's `from` is empty, with bit 4 clear. A
    `locked` PEP under its fallback policy admits no release and decides under it until it is provisioned."""
    point = _host(tmp_path)
    point.send(_fallback(point, image(9)))
    assert _read(point, point.pep.record("beat")).fallback
    body = image(5)
    assert _read(point, point.pep.stage(point.seal(body, 1, widens=True), body)).cause == "dist:widening-unsigned"
    point.widen(body, 1, froms=[H(image(9))], widens=True)
    assert _read(point, point.pep.stage(point.seal(body, 1, widens=True), body)).cause == "dist:widening-unsigned"
    point.widen(body, 1, froms=[], widens=True)
    assert _read(point, point.pep.stage(point.seal(body, 1, widens=True), body)).event == "staged"
    committed = _read(point, point.pep.commit(STREAM, 1, H(body)))
    assert (committed.event, committed.fallback, committed.state) == ("committed", False, "active")
    locked = _host(tmp_path, "locked")
    locked.send(_fallback(locked, image(9)))
    _lock(locked)
    assert _read(locked, locked.pep.record("beat")).fallback
    assert _read(locked, locked.pep.stage(locked.seal(body, 1, widens=True), body)).cause == "dist:floor-lost"
    assert locked.pep.decide(lambda: "fallback")["basis"] == "fallback"
    locked.pep.confirm(locked.pep.provision(locked.anchor()))
    assert locked.pep.state() == "no-policy" and locked.pep.decide(lambda: "fallback")["basis"] == "fallback"
    assert _read(locked, locked.commit(body)).event == "committed"


def test_case_201_a_cut_off_pep_decides_under_its_release_then_under_its_fallback_policy(tmp_path):
    """case_201: FB7, X2. A cut off PEP decides under its release until it expires and then under its fallback
    policy for a whole year with no message."""
    point = _host(tmp_path)
    point.send(_fallback(point, image(9)))
    point.commit(image(5))
    point.clock.now = EXPIRES - 1
    assert "basis" not in point.pep.decide(lambda: "release")
    for now in (EXPIRES, EXPIRES + 86400, EXPIRES + 365 * 86400):
        point.clock.now = now
        point.pep.tick()
        assert point.pep.decide(lambda: "fallback")["basis"] == "fallback"
        assert point.pep.adapter.host.active()["active"] == H(image(9))


def test_case_202_a_new_fallback_policy_decides_at_once_or_waits_behind_the_release(tmp_path):
    """case_202: FB8, IS12. A PEP under its fallback policy decides under a narrower one and then a wider one at once,
    with bit 4 still set and the wider one reported `install-widened`; a PEP with an active release holds the wider
    one with the same event while its release keeps deciding."""
    point = _agent(tmp_path)
    point.send(_agent_set(point, FALLBACK, WIDER, 1, MORE_HOSTS))
    narrower = point.send(_agent_set(point, FALLBACK, NARROW, 2, HOSTS, widens=False))[-1]
    assert (narrower.event, narrower.fallback) == ("install-applied", True)
    assert point.pep.adapter.running.policy_sha256 == H(NARROW)
    wider = point.send(_agent_set(point, FALLBACK, WIDEST, 3, MORE_HOSTS))[-1]
    assert (wider.event, wider.cause, wider.fallback) == ("install-widened", "dist:install-widened", True)
    assert point.pep.adapter.running.policy_sha256 == H(WIDEST)
    other = _agent(tmp_path, "active")
    other.send(_agent_set(other, FALLBACK, NARROW, 1))
    other.commit(NARROW)
    held = other.send(_agent_set(other, FALLBACK, WIDEST, 2, MORE_HOSTS))[-1]
    assert (held.event, held.fallback, held.state) == ("install-widened", False, "active")
    assert other.pep.adapter.running.policy_sha256 == H(NARROW) and _held(other, FALLBACK).policy_sha256 == H(WIDEST)
    three = canon.canon2_bytes(["api.example.com", "docs.example.com", "x.example.com"])
    assert other.send(_agent_set(other, FALLBACK, WIDEST, 3, three, widens=False))[-1].cause \
        == "dist:widening-unsigned"


def test_case_222_zone_protection_never_drops_with_the_release(tmp_path):
    """case_222: FB9. An `agent` PEP whose release protects `keys` lapses. With a ceiling whose zones protect
    `ledger`, `ledger` is protected; with a ceiling that has none the release's `keys` stays protected; and a restart
    after the lapse changes nothing."""
    for ceiling_zones, protected in ((_zones("ledger"), {"ledger"}), (None, {"keys"})):
        point = _agent(tmp_path, f"agent{protected}")
        point.send(_agent_set(point, CEILING, WIDEST, 1, MORE_HOSTS, zones=ceiling_zones))
        point.send(_agent_set(point, FALLBACK, NARROW, 1, zones=ceiling_zones))
        zones = _zones("keys", "ledger") if ceiling_zones is not None else _zones("keys")
        release = env.release_id([("agent.zones", H(zones)), ("egress.hosts", H(HOSTS)), ("policy.core", H(NARROW))])
        point.stage(NARROW, 1, release=release)
        point.pep.stage(seal("agent.zones", zones, seq=1, targets=("agent",), release=release,
                             policy_sha256=H(NARROW), widens=True), zones)
        assert _read(point, point.pep.commit(STREAM, 1, H(NARROW))).event == "committed"
        point.clock.now = EXPIRES
        assert _read(point, point.pep.tick()).event == "fallback"
        for _restart in range(2):
            bodies = read_committed_release(str(point.state_dir), "agent", EXPIRES).bodies
            names = set(kinds.read_zones(bodies["agent.zones"])["protected"])
            assert protected <= names and (ceiling_zones is None) == ("ledger" not in names), names
            point.pep = point.open()


# ------------------------------------------------------------------ CL1 to CL3: the ceiling

def _list(point, seq, *tables, widens=False):
    """A ceiling list of `tables`, which replaces the held ceiling (IS12)."""
    held = point.pep.installed.record.sets[CEILING]
    return point.install_set(CEILING, {kinds.POLICY_LIST: install.ceiling_body(tables)}, seq, widens=widens,
                             replaces=held.policy_sha256 if held else "")


def test_case_204_a_staged_and_a_kept_release_meet_a_newer_ceiling_at_commit_and_rollback(tmp_path):
    """case_204: CL2, C3, RB2. A release inside the ceiling is staged, a narrower ceiling it is above is applied, and
    the release is still staged, then `dist:above-ceiling` at its commit and dropped. The same for a kept release at
    a rollback."""
    first, second, third = image(5), image(6), image(7)
    point = _host(tmp_path)
    assert point.send(_list(point, 1, first, second))[-1].event == "install-applied"
    point.commit(first)
    point.stage(second, 2)
    assert point.send(_list(point, 2, first))[-1].event == "install-applied"
    assert point.pep.staged is not None and point.pep.staged.seq == 2
    assert _read(point, point.pep.commit(STREAM, 2, H(second))).cause == "dist:above-ceiling"
    assert point.pep.staged is None
    kept = _host(tmp_path, "kept")
    kept.send(_list(kept, 1, first, second))
    kept.commit(second)
    kept.commit(first, 2)
    assert kept.send(_list(kept, 2, first, third, widens=True))[-1].event == "install-widened"
    assert kept.pep.previous is not None and kept.pep.previous.seq == 1
    assert _read(kept, kept.pep.rollback()).cause == "dist:above-ceiling"
    assert kept.pep.previous is None and kept.pep.active.seq == 2


def test_case_204_a_release_above_the_ceiling_is_refused_at_staging(tmp_path):
    """case_204: CL2. A release off the ceiling's list is `dist:above-ceiling` at V11, before it is staged."""
    point = _host(tmp_path)
    point.send(_list(point, 1, image(5)))
    assert _read(point, point.stage(image(6), 1)).cause == "dist:above-ceiling"
    assert "policy.ppt" not in point.pep.staged.held


def test_case_237_a_staged_set_is_held_to_the_ceiling_held_when_it_is_applied(tmp_path):
    """case_237: IS4, CL3. An `agent` PEP stages a fallback set whose release id covers an `agent.zones` that has not
    arrived, is given a ceiling the staged set is above, and the zones statement arrives: the ceiling is applied, then
    the set is dropped with `dist:above-ceiling` and the held fallback policy still decides."""
    point = _agent(tmp_path)
    point.send(_agent_set(point, FALLBACK, NARROW, 1))
    staged = _agent_set(point, FALLBACK, WIDEST, 2, MORE_HOSTS, zones=_zones("keys"))
    by_name = {envelope_as(sealed): (sealed, body) for sealed, body in staged}
    assert point.send([by_name["policy.core"], by_name["egress.hosts"]])[-1].event == "staged"
    assert point.send(_agent_set(point, CEILING, WIDER, 1, MORE_HOSTS))[-1].event == "install-applied"
    assert _read(point, point.pep.stage(*by_name["agent.zones"])).cause == "dist:above-ceiling"
    assert FALLBACK not in point.pep.installed.staged and _held(point, FALLBACK).seq == 1
    assert point.pep.adapter.running.policy_sha256 == H(NARROW)


def envelope_as(sealed):
    return env.read(env.unseal(sealed)[0]).meta["as"]


def test_case_217_a_set_is_whole_only_when_its_signed_release_id_is_computed_again(tmp_path):
    """case_217: IS4. An `agent` set whose signed release id covers an `agent.zones` is not applied until the zones
    statement arrives. A set whose release id covers none is applied without a stray `agent.zones` of another release
    id, which is `dist:incomplete`."""
    point = _agent(tmp_path)
    with_zones = {envelope_as(sealed): (sealed, body)
                  for sealed, body in _agent_set(point, FALLBACK, NARROW, 1, zones=_zones("keys"))}
    assert point.send([with_zones["policy.core"], with_zones["egress.hosts"]])[-1].event == "staged"
    assert _held(point, FALLBACK) is None
    assert point.send([with_zones["agent.zones"]])[-1].event == "install-widened"
    stray = {envelope_as(sealed): (sealed, body)
             for sealed, body in _agent_set(point, FALLBACK, WIDER, 2, MORE_HOSTS, zones=_zones("keys"))}
    plain = _agent_set(point, FALLBACK, WIDER, 2, MORE_HOSTS)
    assert point.send([plain[0]])[-1].event == "staged"
    assert point.send([stray["agent.zones"]])[-1].cause == "dist:incomplete"
    assert point.send([plain[1]])[-1].event == "install-widened"
    assert "agent.zones" not in _held(point, FALLBACK).bodies


def test_a_ceiling_the_active_release_is_above_lapses_it_to_the_fallback_policy(tmp_path):
    """CL3, IS12, FB3: a ceiling the active release is above is applied with `install-widened`, whatever its `widens`
    says, and the release lapses with `dist:above-ceiling` to the fallback policy, which must be inside the ceiling."""
    point = _host(tmp_path)
    point.send(_list(point, 1, image(5), image(9)))
    point.send(_fallback(point, image(9)))
    point.commit(image(5))
    point.pep.drain()
    applied = point.send(_list(point, 2, image(9)))[-1]
    sent = [_read(point, one) for one in point.pep.drain()]
    assert (applied.event, applied.cause) == ("install-widened", "dist:install-widened")
    assert [(one.event, one.cause) for one in sent][-2:] == [("install-widened", "dist:install-widened"),
                                                             ("fallback", "dist:above-ceiling")]
    assert point.pep.active is None and point.pep.decide(lambda: 1)["basis"] == "fallback"
    above = point.send(_list(point, 3, image(5)))[-1]
    assert above.cause == "dist:above-ceiling" and _held(point, CEILING).seq == 2


def test_the_fallback_policy_is_bounded_by_the_ceiling(tmp_path):
    """CL3: a fallback policy above the held ceiling is refused, on a list and on a kind that can decide."""
    point = _host(tmp_path)
    point.send(_list(point, 1, image(5)))
    assert point.send(_fallback(point, image(9)))[-1].cause == "dist:above-ceiling"
    agent = _agent(tmp_path)
    agent.send(_agent_set(agent, CEILING, WIDER, 1, HOSTS))
    assert "dist:above-ceiling" in [one.cause for one in agent.send(_agent_set(agent, FALLBACK, WIDEST, 1, HOSTS))]
    assert "dist:above-ceiling" in [one.cause for one in agent.send(_agent_set(agent, FALLBACK, NARROW, 2, MORE_HOSTS))]
    assert agent.send(_agent_set(agent, FALLBACK, NARROW, 3, HOSTS))[-1].event == "install-widened"


def test_an_agent_release_is_held_to_the_ceiling_s_policy_hosts_and_zones(tmp_path):
    """CL1, CL2: an `agent` release whose policy allows what the ceiling's refuses, with a host the ceiling's lacks,
    or dropping a name the ceiling's zones protect is `dist:above-ceiling`, and one inside it commits."""
    point = _agent(tmp_path)
    point.send(_agent_set(point, CEILING, WIDER, 1, HOSTS, zones=_zones("keys")))
    assert _read(point, point.stage(WIDEST, 1)).cause == "dist:above-ceiling"
    assert _read(point, point.stage(NARROW, 2, hosts=MORE_HOSTS)).cause == "dist:above-ceiling"
    point.stage(NARROW, 3)
    assert _read(point, point.pep.commit(STREAM, 3, H(NARROW))).cause == "dist:above-ceiling"   # no zones
    zones = _zones("keys", "other")
    release = env.release_id([("agent.zones", H(zones)), ("egress.hosts", H(HOSTS)), ("policy.core", H(NARROW))])
    point.stage(NARROW, 4, release=release)
    point.pep.stage(seal("agent.zones", zones, seq=4, targets=("agent",), release=release,
                         policy_sha256=H(NARROW), widens=True), zones)
    assert _read(point, point.pep.commit(STREAM, 4, H(NARROW))).event == "committed"


def test_a_gateway_route_table_is_inside_the_ceiling_when_every_path_keeps_its_class():
    """CL1: a route table that names fewer or narrower routes with the ceiling's classes is inside, one that gives a
    path another class or a path the ceiling leaves to `other` is not."""
    def table(*rows):
        return canon.canon2_bytes({"routes": [{"match": match, "class": name} for match, name in rows]})
    ceiling = table(("/admin/*", "admin"), ("/api/*", "api"))
    assert install.artifact_inside("gateway.routes", ceiling, table(("/api/v1", "api")))
    assert install.artifact_inside("gateway.routes", ceiling, table(("/api/v1/*", "api")))
    assert not install.artifact_inside("gateway.routes", ceiling, table(("/api/v1", "admin")))
    assert not install.artifact_inside("gateway.routes", ceiling, table(("/public", "api")))
    assert not install.artifact_inside("gateway.routes", table(("/api/v1", "api"), ("/api/*", "api")),
                                       table(("/api/*", "admin")))


def test_a_lost_ceiling_never_fails_open(tmp_path):
    """IS10: a PEP that starts with every copy of its ceiling unreadable keeps its release, reports
    `dist:install-lost`, and stages, commits and rolls back nothing until it holds a ceiling again."""
    point = _host(tmp_path)
    point.send(_list(point, 1, image(5), image(6)))
    point.commit(image(5))
    for directory in (point.state_dir / "dist" / "install" / "blobs", point.state_dir / "dist" / "install-copy" / "blobs"):
        for blob in directory.iterdir():
            blob.write_bytes(b"gone")
    point.pep = point.open()
    sent = [_read(point, one) for one in point.pep.drain()]
    assert ("refused", "dist:install-lost") in [(one.event, one.cause) for one in sent]
    assert sent[-1].install.subject == "install.ceiling" and point.pep.active is not None
    assert _read(point, point.stage(image(6), 2)).cause == "dist:install-lost"
    assert _read(point, point.pep.rollback() if point.pep.previous else point.pep.commit(STREAM, 2, H(image(6)))).cause \
        == "dist:install-lost"
    assert point.send(_fallback(point, image(5)))[-1].cause == "dist:install-lost"
    assert point.send(_list(point, 2, image(5), image(6)))[-1].event == "install-applied"
    assert _read(point, point.stage(image(6), 2)).event == "staged"


def test_case_226_a_host_with_one_file_system_loses_both_copies_of_its_install_record(tmp_path):
    """case_226: IS10. A `host` PEP whose two copies are on one file system loses both: it holds no set, reports
    `dist:install-lost`, keeps deciding under its release, and takes no install statement by message and no release
    until it is provisioned."""
    point = _host(tmp_path)
    point.send(_fallback(point, image(9)))
    point.commit(image(5))
    for path in (point.state_dir / "dist" / "install" / "record.json",
                 point.state_dir / "dist" / "install-copy" / "record.json"):
        path.write_bytes(b"gone")
    point.pep = point.open()
    assert [(one.event, one.cause) for one in map(lambda data: _read(point, data), point.pep.drain())][-1] \
        == ("refused", "dist:install-lost")
    assert point.pep.installed.fallback is None and "basis" not in point.pep.decide(lambda: "release")
    assert point.send(_fallback(point, image(8), 2))[-1].cause == "dist:install-lost"
    assert _read(point, point.stage(image(6), 2)).cause == "dist:install-lost"
    point.pep.confirm(point.pep.provision(point.anchor()))
    assert point.pep.installed.record is not None and not point.pep.installed.record_lost
    assert point.send(_fallback(point, image(8), 1))[-1].event == "install-widened"


def test_case_226_a_host_with_a_second_medium_keeps_its_sets(tmp_path):
    """IS10: with its second copy on another file system, a PEP that loses the first keeps its sets."""
    point = _host(tmp_path, install_copy=tmp_path / "second")
    point.send(_fallback(point, image(9)))
    (point.state_dir / "dist" / "install" / "record.json").write_bytes(b"gone")
    for blob in (point.state_dir / "dist" / "install" / "blobs").iterdir():
        blob.unlink()
    point.pep = point.open()
    assert _held(point, FALLBACK) is not None and not point.pep.installed.record_lost
    assert point.pep.decide(lambda: "fallback")["basis"] == "fallback"


# ------------------------------------------------------------------ P4: the anchor's install part

def test_case_230_the_anchor_brings_the_install_keys_to_the_install_record(tmp_path):
    """case_230: P4, CL4, K3, K4. A `/1` anchor that holds an `install` member and a `/2` anchor whose `domain` is
    not the hash of the domain the PEP was built with are refused at provisioning. A good `/2` anchor puts the install
    keys in the install record and none in the trust store, and a release signed by an install key is
    `dist:unknown-key`."""
    point = _host(tmp_path, install_keys=[])
    good = _host(tmp_path, "template")
    from prismpath.kernel import canon2
    second = canon2.loads(good.anchor())
    doc = canon.canon2_bytes({name: value for name, value in second.items() if name not in ("controller", "fresh")}
                             | {"format": "prismpath.dist-trust/1"})
    with pytest.raises((Refused, PepRefused)):
        point.pep.provision(doc)
    with pytest.raises(PepRefused):
        point.pep.provision(good.anchor(domain="00" * 32))
    point.pep.confirm(point.pep.provision(good.anchor()))
    record = point.pep.installed.record
    assert set(record.keys) == {_dist.key_id(name) for name in KEYS}
    assert not set(record.keys) & set(point.pep.trust.keys)
    body = image(5)
    assert _read(point, point.pep.stage(seal("policy.ppt", body, signer="N1", widens=True), body)).cause \
        == "dist:unknown-key"


def test_an_anchor_at_a_lower_install_trust_sequence_or_another_key_set_at_the_same_is_refused(tmp_path):
    """IS6: a provisioning whose install trust sequence is below the PEP's is refused, one at the same number brings
    the same key set, and one above it that shares no key starts the sequences again and drops the held sets."""
    point = _host(tmp_path, install_seq=3)
    point.send(_fallback(point, image(9), 4))
    with pytest.raises(PepRefused):
        point.pep.provision(point.anchor(seq=2))
    with pytest.raises(PepRefused):
        point.pep.confirm(point.pep.provision(point.anchor(keys=["N1", "N2", "N4"])))
    point.pep.confirm(point.pep.provision(point.anchor(seq=4, keys=["N1", "N2", "N4"])))
    assert _held(point, FALLBACK).seq == 4 and _dist.key_id("N3") in point.pep.installed.record.retired
    point.pep.confirm(point.pep.provision(point.anchor(seq=5, keys=["N5", "N6"])))
    assert _held(point, FALLBACK) is None and point.pep.installed.record.seqs[FALLBACK] == 0


def test_an_install_provisioning_changes_the_install_part_and_nothing_else(tmp_path):
    """IS13: on a PEP whose install threshold is 1 an install statement in a message is `dist:target-mismatch`, and
    an install provisioning applies it with its event while the trust store, the floor and the state stay."""
    point = _host(tmp_path, install_threshold=1)
    assert point.send(_fallback(point, image(9), signers=["N1"]))[-1].cause == "dist:target-mismatch"
    point.commit(image(5))
    trust, floor = point.pep.trust.to_bytes(), point.pep.floor
    records = [_read(point, one) for one in point.pep.provision_install(_fallback(point, image(9), signers=["N1"]))]
    assert records[-1].event == "install-widened" and point.pep.state() == "active"
    assert point.pep.trust.to_bytes() == trust and point.pep.floor == floor


def test_a_mesh_pep_compares_its_fallback_tables_byte_for_byte(tmp_path):
    """IS12: a `mesh` PEP takes `widens` false only when `replaces` is the held set's policy hash and the table is
    the held one, so only a renewal goes in on its signature."""
    point = _mesh(tmp_path)
    point.send(_fallback(point, image(9)))
    assert point.send(_fallback(point, image(8), 2, widens=False, replaces=H(image(9))))[-1].cause \
        == "dist:widening-unsigned"
    assert point.send(_fallback(point, image(9), 2, widens=False, replaces=""))[-1].cause == "dist:widening-unsigned"
    assert point.send(_fallback(point, image(9), 2, widens=False, replaces=H(image(9))))[-1].event == "install-applied"


def _older_pack(tmp_path, name: str) -> str:
    """A valid `ppt-pack/1` of a newer version than anything the host ran, signed by a key of its own."""
    from prismpath.hotswap import policy_pack as pp
    keys = pp.keygen(str(tmp_path / f"{name}-keys"))
    ppt = tmp_path / f"{name}.ppt"
    ppt.write_bytes(image(7))
    pp.build_pack(str(ppt), {"x": "int"}, 99, "dist-demo", keys["private"], keys["public"])
    return str(ppt), keys["public"]


def _swap_older(point, pack) -> dict:
    from prismpath.hotswap.policy_host import PolicyHost
    path, key = pack
    return PolicyHost(str(point.state_dir), [key], dict(GEN.QUALIFICATION), instance_key=point.key).swap(path)


def test_case_182_234_the_older_forms_stay_refused(tmp_path):
    """case_182: IS9, L2. A host PEP that holds an install statement and committed nothing refuses a `ppt-pack/1`,
    again after a second provisioning and after its install record is made unreadable. case_234: L2, P3. A host PEP
    that never held one refuses it on the stream it committed on, also after it is provisioned again, while one that
    was provisioned and committed nothing still takes it."""
    refused = {"ok": False, "reasons": ["dist:legacy-refused"]}
    point = _host(tmp_path)
    point.send(_fallback(point, image(9)))
    pack = _older_pack(tmp_path, "pack")
    assert point.pep.floor.seq == 0 and _swap_older(point, pack) == refused
    point.pep.confirm(point.pep.provision(point.anchor()))
    assert _swap_older(point, pack) == refused
    for path in point.pep.installed._paths():
        Path(path).write_bytes(b"not a record")
    point.pep = point.open()
    assert point.pep.installed.record_lost and _swap_older(point, pack) == refused

    plain = _dist.HostPep(tmp_path / "plain")
    plain.commit(image(5))
    assert _swap_older(plain, pack) == refused
    plain.pep.confirm(plain.pep.provision(plain.anchor()))
    assert plain.pep.floor.seq == 0 and _swap_older(plain, pack) == refused
    fresh = _dist.HostPep(tmp_path / "fresh")
    fresh.pep.confirm(fresh.pep.provision(fresh.anchor()))
    assert _swap_older(fresh, pack)["ok"]


def test_the_state_record_carries_the_install_entry_and_the_fallback_bit(tmp_path):
    """H10, FB2: a PEP that holds install keys sends the install entry in every record, its install id changing with
    every set it applies, and bit 4 while its fallback policy decides, with zeros for the active fields."""
    point = _host(tmp_path)
    first = _read(point, point.pep.record("beat"))
    assert first.install is not None and first.install.subject == "none" and not first.fallback
    applied = point.send(_fallback(point, image(9)))[-1]
    assert applied.install.install_id != first.install.install_id and applied.fallback
    assert applied.active_policy == b"\x00" * 16 and applied.active_seq == 0
    plain = _dist.HostPep(tmp_path / "plain")
    assert _read(plain, plain.pep.record("beat")).extensions == b""


def test_a_gateway_routes_by_its_fallback_set_when_its_release_lapses(tmp_path, monkeypatch):
    """FB1: a `gateway` home whose release lapses routes by its fallback set, as its long running gateway reads it,
    and one with none refuses."""
    from prismpath.agent import commands
    from prismpath.distribution.adapters import agent_home
    from prismpath.distribution.adapters.gateway import Following
    from prismpath.tests.test_distribution_gateway import DEMO, OPEN, ROUTES, GatewayHome
    monkeypatch.setattr(agent_home, "clock", lambda: NOW)
    for with_fallback in (True, False):
        point = GatewayHome(tmp_path / f"gateway{with_fallback}", install_keys=KEYS, install_threshold=2)
        if with_fallback:
            assert point.send(point.install_set(FALLBACK, {"policy.core": DEMO, "gateway.routes": OPEN}, 1,
                                                widens=True))[-1].event == "install-widened"
        assert point.release(DEMO, 1)[-1].event == "committed"
        following = Following(point.state_dir)
        assert following.current().routes.canonical() == ROUTES
        point.clock.now = EXPIRES
        monkeypatch.setattr(agent_home, "clock", lambda: EXPIRES)
        point.pep.tick()
        if with_fallback:
            assert following.current().routes.canonical() == OPEN
        else:
            with pytest.raises(commands.AgentError):
                following.current()
        monkeypatch.setattr(agent_home, "clock", lambda: NOW)


def test_the_engineer_s_tool_writes_the_anchor_s_install_part_sets_and_install_trust(tmp_path):
    """P4, IS11, IS12, CL1, CL2, K4: `prismpath dist anchor --install-pub` writes the install part a PEP takes,
    `dist install` seals a ceiling list and a fallback set the PEP applies, refuses a larger set sealed without
    `--widens` and a fallback above the ceiling, `dist seal --ceiling` refuses a release above it, and
    `dist install-trust` keeps the retired ids and refuses to add one back. A set sealed to follow the empty set names
    the empty string as `replaces`, since the empty set withdrew its kind (IS6)."""
    from prismpath import cli
    from prismpath.hotswap import policy_pack
    _priv, _pub, ser, _invalid = policy_pack._ed25519()
    keys = {}
    for name in ("A", "C", "N1", "N2", "N3"):
        keys[name] = tmp_path / f"{name}.pem"
        keys[name].write_bytes(GEN.test_key(name).private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                                 ser.NoEncryption()))
        (tmp_path / f"{name}.pub").write_bytes(public(name))

    def run(*argv):
        args = cli.build_parser().parse_args(["dist", *argv])
        return args.func(args)

    assert run("anchor", "--pub", str(tmp_path / "A.pub"), "--controller", str(tmp_path / "C.pub"), "--target", "mesh",
               "--stream", STREAM, "--install-pub", str(tmp_path / "N1.pub"), "--install-pub", str(tmp_path / "N2.pub"),
               "--install-threshold", "2", "--out", str(tmp_path / "anchor.json")) == 0
    point = _dist.MeshPep(tmp_path / "mesh", install_keys=[])
    point.pep.confirm(point.pep.provision((tmp_path / "anchor.json").read_bytes()))
    assert point.pep.installed.record.threshold == 2
    for seq, threshold in ((5, 5), (6, 6), (9, 9)):
        (tmp_path / f"t{threshold}.ppt").write_bytes(image(threshold))
    (tmp_path / "qualification.json").write_text(__import__("json").dumps(GEN.QUALIFICATION))
    common = ["--stream", STREAM, "--target", "mesh", "--key", str(keys["N1"]), "--key", str(keys["N2"]),
              "--not-before", str(NOT_BEFORE), "--qualification", str(tmp_path / "qualification.json")]
    assert run("install", "--kind", "ceiling", "--list", str(tmp_path / "t5.ppt"), "--list", str(tmp_path / "t9.ppt"),
               "--seq", "1", *common, "--out", str(tmp_path / "ceiling")) == 0
    ceiling = install_pairs(tmp_path / "ceiling")
    assert point.send(ceiling)[-1].event == "install-applied"
    assert run("install", "--kind", "fallback", "--set", f"policy.ppt={tmp_path / 't6.ppt'}", "--seq", "1",
               "--ceiling", str(tmp_path / "ceiling"), "--widens", *common, "--out", str(tmp_path / "above")) == 1
    assert run("install", "--kind", "fallback", "--set", f"policy.ppt={tmp_path / 't9.ppt'}", "--seq", "1",
               "--ceiling", str(tmp_path / "ceiling"), *common, "--out", str(tmp_path / "unsaid")) == 1
    assert run("install", "--kind", "fallback", "--set", f"policy.ppt={tmp_path / 't9.ppt'}", "--seq", "1",
               "--ceiling", str(tmp_path / "ceiling"), "--widens", *common, "--out", str(tmp_path / "fallback")) == 0
    assert point.send(install_pairs(tmp_path / "fallback"))[-1].event == "install-widened"
    assert run("install", "--kind", "fallback", "--set", f"policy.ppt={tmp_path / 't9.ppt'}", "--seq", "2",
               "--follows", str(tmp_path / "fallback"), *common, "--out", str(tmp_path / "renewal")) == 0
    assert point.send(install_pairs(tmp_path / "renewal"))[-1].event == "install-applied"
    assert run("install", "--kind", "ceiling", "--empty", "--seq", "2", "--follows", str(tmp_path / "ceiling"),
               "--widens", *common, "--out", str(tmp_path / "withdrawn")) == 0
    assert point.send(install_pairs(tmp_path / "withdrawn"))[-1].event == "install-widened"
    assert run("install", "--kind", "ceiling", "--list", str(tmp_path / "t9.ppt"), "--seq", "3", "--follows",
               str(tmp_path / "withdrawn"), *common, "--out", str(tmp_path / "again")) == 0
    assert point.send(install_pairs(tmp_path / "again"))[-1].event == "install-applied"   # IS6: it replaces nothing
    (tmp_path / "meta.json").write_text(__import__("json").dumps(GEN.image_meta(image(6))))
    assert run("seal", "--artifact", "policy.ppt", "--body", str(tmp_path / "t6.ppt"), "--stream", STREAM, "--seq", "1",
               "--target", "mesh", "--key", str(keys["A"]), "--meta", str(tmp_path / "meta.json"),
               "--ceiling", str(tmp_path / "ceiling"), "--out", str(tmp_path / "r.sealed")) == 1
    trust = ["--stream", STREAM, "--target", "mesh", "--seq", "1", "--retired", str(tmp_path / "retired"),
             "--current-pub", str(tmp_path / "N1.pub"), "--current-pub", str(tmp_path / "N2.pub"),
             "--current-threshold", "2", "--not-before", str(NOT_BEFORE)]
    assert run("install-trust", *trust, "--install-pub", str(tmp_path / "N1.pub"), "--threshold", "1",
               "--key", str(keys["N1"]), "--key", str(keys["N2"]), "--out", str(tmp_path / "drop.sealed")) == 0
    assert (tmp_path / "retired").read_text().split() == [_dist.key_id("N2")]
    assert run("install-trust", *trust[:-6], "--seq", "2", "--current-pub", str(tmp_path / "N1.pub"),
               "--current-threshold", "1", "--not-before", str(NOT_BEFORE), "--install-pub", str(tmp_path / "N1.pub"),
               "--install-pub", str(tmp_path / "N2.pub"), "--threshold", "1", "--key", str(keys["N1"]),
               "--key", str(keys["N2"]), "--out", str(tmp_path / "back.sealed")) == 1


def install_pairs(directory: Path):
    return [((directory / name).read_bytes(), (directory / (name[:-len(".sealed")] + ".body")).read_bytes())
            for name in sorted(path.name for path in directory.iterdir() if path.name.endswith(".sealed"))]
    assert run("install", "--kind", "ceiling", "--empty", "--seq", "2", "--follows", str(tmp_path / "ceiling"),
               "--widens", *common, "--out", str(tmp_path / "withdrawn")) == 0
    assert point.send(install_pairs(tmp_path / "withdrawn"))[-1].event == "install-widened"
    assert run("install", "--kind", "ceiling", "--list", str(tmp_path / "t9.ppt"), "--seq", "3", "--follows",
               str(tmp_path / "withdrawn"), *common, "--out", str(tmp_path / "again")) == 0
    assert point.send(install_pairs(tmp_path / "again"))[-1].event == "install-applied"   # IS6: it replaces nothing
