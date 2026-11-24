# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""An agent home that follows a policy stream (spec-policy-distribution.md, section 3, the `agent` target): the
PEP machine over `AgentHomeAdapter`, with the hook, the egress proxy and the zone point reading the committed
release through `commands.load_checked`. Each test names the conformance case of section 20 it covers."""
import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from prismpath import canon  # noqa: E402
from prismpath.agent import commands, zones  # noqa: E402
from prismpath.agent.policy import starter_path  # noqa: E402
from prismpath.agent.profile import compile_profile  # noqa: E402
from prismpath.distribution import state_record  # noqa: E402
from prismpath.distribution.adapters import agent_home  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import STREAM, seal  # noqa: E402

H = canon.sha256_hex
STRICT = starter_path("strict").read_bytes().rstrip(b"\n")
DEFAULT = starter_path("default").read_bytes().rstrip(b"\n")


def _read(point, signed):
    return state_record.read(signed, point.key.public_raw)


def _zones(*names) -> bytes:
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-zones/1",
                               "protected": sorted(names)})


@dataclass
class HomePep(_dist.AgentPep):
    """An agent PEP over a real agent home: the adapter is `AgentHomeAdapter`, the home holds its instance key."""

    def adapter(self):
        return agent_home.AgentHomeAdapter(self.state_dir)

    def __post_init__(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        from cryptography.hazmat.primitives import serialization as ser
        private = _dist.GEN.test_key("I")
        (self.state_dir / "instance.key").write_bytes(private.private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
        (self.state_dir / "instance.pub").write_bytes(_dist.GEN.public_raw(private))
        super().__post_init__()

    def release(self, body, seq, *, hosts=None, extra=(), widens=True, froms=(), withheld=()):
        """Stage `body` and `hosts` at `seq` with a widening statement of `froms`, and the `extra` (artifact, body)
        envelopes of the same release, leaving out the envelopes of `withheld` as a transport might, then
        commit."""
        hosts = hosts or self.hosts
        pairs = [("egress.hosts", hosts), ("policy.core", body), *extra]
        release = _dist.env.release_id(sorted((name, H(data)) for name, data in pairs))
        active = self.pep.active.policy_sha256 if self.pep.active else ""
        args = {"release": release, "policy_sha256": H(body), "replaces": active, "widens": widens}
        acks = []
        if widens:
            statement = _dist.widening(froms)
            acks.append(self.pep.stage(seal("trust.widening", statement, seq=seq, targets=("agent",), **args), statement))
        from prismpath.agent.profile import COMPILER_VERSION
        for name, data in pairs:
            if name in withheld:
                continue
            meta = {"compiler": COMPILER_VERSION} if name == "sandbox.profile" else {}
            acks.append(self.pep.stage(seal(name, data, seq=seq, targets=("agent",), meta=meta, **args), data))
        acks.append(self.pep.commit(STREAM, seq, H(body)))
        return [_read(self, ack) for ack in acks]


@pytest.fixture
def home(tmp_path):
    return HomePep(tmp_path / "home")


def test_a_home_that_follows_a_stream_decides_under_its_committed_release(home):
    """Section 3: the hook's policy is the committed `policy.core`, read with no authority key, and an authority key
    in the home is refused."""
    assert home.release(STRICT, 1)[-1].event == "committed"
    policy, _store = commands.load_checked(home.state_dir)
    assert policy.image == STRICT and commands.hosts_of(home.state_dir) == ("api.example.com",)
    (home.state_dir / "authority.key").write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
    with pytest.raises(commands.AgentError):
        commands.load_checked(home.state_dir)


def _connect_rule(target, dest):
    return {"target": target, "when": ["and", ["cmp", "tool", "==", ["str", "connect"]],
                                       ["cmp", "net_dest", "==", ["str", dest]],
                                       ["cmp", "command_class", "==", ["str", "none"]],
                                       ["cmp", "git_op", "==", ["str", "none"]],
                                       ["cmp", "path_scope", "==", ["str", "none"]]]}


def _with_rules(image, *rules):
    from prismpath.kernel import canon2
    doc = canon2.loads(image)
    doc["rules"] = list(rules) + doc["rules"]
    return canon2.dumps(doc)


ALLOW_HOSTS = _with_rules(DEFAULT, _connect_rule("allow", "allowed_host"))
NO_READS = _with_rules(ALLOW_HOSTS, {"target": "refuse_104", "when": ["cmp", "tool", "==", ["str", "read_file"]]})
# a larger policy, so the comparator's walk ends at the first reading it allows more, and the test stays quick


class _Echo:
    """A loopback TCP server standing in for every destination the egress proxy dials."""

    def __init__(self):
        import socket
        import threading
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(16)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                client, _ = self.server.accept()
            except OSError:
                return
            client.close()


def _connect_status(proxy, target):
    import socket
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(5)
    client.connect(proxy.socket_path)
    client.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    client.close()
    return int(data.split(b" ", 2)[1]), data


def test_a_commit_changes_the_hook_and_the_egress_proxy_together(tmp_path, monkeypatch):
    """Section 3, X3: one home holds one release. The egress proxy's gate is built as the launcher builds it and
    decides real CONNECTs while the hook decides tool calls. A commit that removes a host closes it at the gate's
    next connection, and a commit of another policy moves the hook's decision and the gate's at once: the gate's
    run was begun under the old policy, so it refuses rather than deciding under a policy its run does not name."""
    from prismpath.agent import egress, egress_policy
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)    # the hook is given HOME only, so both find one home
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(commands.sys, "platform", "linux")
    home_dir = commands.config_dir()
    point = HomePep(home_dir)
    both = canon.canon2_bytes(["docs.example.com", "other.example.com"])
    assert point.release(NO_READS, 1, hosts=both)[-1].event == "committed"
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.txt").write_text("x\n")
    hook_env = {"HOME": str(tmp_path), "CLAUDE_PROJECT_DIR": str(project)}
    answers = []

    def hook(session):
        data = {"session_id": session, "hook_event_name": "PreToolUse", "tool_name": "Read",
                "tool_input": {"file_path": str(project / "a.txt")}, "cwd": str(project)}
        answer = commands.hook(json.dumps(data).encode(), hook_env)
        answers.append(answer)
        return answer["hookSpecificOutput"]["permissionDecision"]

    policy, store = commands.load_checked(home_dir)
    profile = compile_profile(policy, "agent")
    gate = egress_policy.PolicyGate(policy, store, "egress-s", project, profile, commands.hosts_of(home_dir),
                                    home=home_dir, follow=commands.Committed(home_dir))
    echo = _Echo()
    sockets = tmp_path / "sock"
    sockets.mkdir()
    proxy = egress.EgressProxy(sockets / "e.sock", sockets / "e.log", gate=gate, resolver=lambda name: ["93.184.216.34"],
                               connect=lambda address, port, timeout: __import__("socket").create_connection(
                                   ("127.0.0.1", echo.port), timeout=timeout)).start()
    try:
        assert hook("s1") == "deny"
        assert [_connect_status(proxy, f"{host}:443")[0] for host in ("docs.example.com", "other.example.com")] == [200, 200]
        docs = canon.canon2_bytes(["docs.example.com"])
        assert point.release(NO_READS, 2, hosts=docs, widens=False)[-1].event == "committed"
        status, body = _connect_status(proxy, "other.example.com:443")
        assert status == 403 and b"refused-130" in body                 # the removed host, at the next connection
        assert _connect_status(proxy, "docs.example.com:443")[0] == 200 and hook("s2") == "deny"
        assert point.release(ALLOW_HOSTS, 3, hosts=docs)[-1].event == "committed"
        status, body = _connect_status(proxy, "docs.example.com:443")
        assert status == 403 and b"policy-changed" in body
        assert hook("s3") == "allow", answers[-1]
    finally:
        proxy.close()
        echo.server.close()


def test_every_load_checks_the_release_again(home, monkeypatch):
    """A release that expired, or whose only signing key was revoked, no longer loads, with no authority key."""
    home.release(STRICT, 1)
    monkeypatch.setattr(agent_home, "clock", lambda: _dist.EXPIRES)
    with pytest.raises(commands.AgentError):
        commands.load_checked(home.state_dir)
    other = HomePep(home.state_dir.parent / "other", authorities=["A", "B"])
    other.release(STRICT, 1)
    other.revoke(1, signer="B", keys=[_dist.key_id("A")])
    with pytest.raises(commands.AgentError):
        commands.load_checked(other.state_dir)


def test_case_049_an_agent_release_without_its_host_list_is_incomplete(home):
    """case_049: C2. `policy.core` staged without `egress.hosts` is not committed, and the active release stays."""
    home.release(STRICT, 1)
    release = _dist.env.release_id([("policy.core", H(DEFAULT))])
    args = {"release": release, "policy_sha256": H(DEFAULT), "replaces": H(STRICT), "widens": True}
    statement = _dist.widening([])
    home.pep.stage(seal("trust.widening", statement, seq=2, targets=("agent",), **args), statement)
    home.pep.stage(seal("policy.core", DEFAULT, seq=2, targets=("agent",), meta={}, **args), DEFAULT)
    assert _read(home, home.pep.commit(STREAM, 2, H(DEFAULT))).cause == "dist:incomplete"
    assert commands.load_checked(home.state_dir)[0].image == STRICT


def test_case_045_a_staged_sandbox_profile_that_is_not_the_compiled_one_is_derived_mismatch(home):
    """Case 45's profile half (its net.edge half is the XDP edge's): V11 at commit. A `sandbox.profile` must be the profile the staged `policy.core`
    compiles to, and the compiled one commits."""
    compiled = compile_profile(STRICT, "bash").canonical()
    other = canon.canon2_bytes({**json.loads(compiled), "max_processes": 512})
    records = home.release(STRICT, 1, extra=[("sandbox.profile", other)])
    assert records[-1].cause == "dist:derived-mismatch" and home.pep.active is None
    assert home.release(STRICT, 2, extra=[("sandbox.profile", compiled)])[-1].event == "committed"


def test_case_137_138_a_home_never_commits_a_release_with_its_zones_or_its_profile_withheld(home):
    """case_137, case_138: C2, E10 on a real agent home. A first install whose signed release names `agent.zones`
    and `sandbox.profile`, with either envelope withheld, is dist:incomplete and the hook loads nothing. After the
    whole release commits, an update that keeps the protected zones and adds a host, with its `agent.zones`
    withheld, is dist:incomplete too, and the hook, the egress hosts and the zone names stay the committed ones."""
    profile = compile_profile(STRICT, "bash").canonical()
    names = _zones("billing", "payroll")
    whole = [("agent.zones", names), ("sandbox.profile", profile)]
    for seq, withheld in ((1, ("agent.zones",)), (2, ("sandbox.profile",))):
        records = home.release(STRICT, seq, extra=whole, withheld=withheld)
        assert records[-1].cause == "dist:incomplete" and home.pep.active is None, withheld
        with pytest.raises(commands.AgentError):
            commands.load_checked(home.state_dir)
    assert home.release(STRICT, 3, extra=whole)[-1].event == "committed"
    more = canon.canon2_bytes(["api.example.com", "b.example.com"])
    records = home.release(STRICT, 4, hosts=more, extra=whole, withheld=("agent.zones",))
    assert records[-1].cause == "dist:incomplete" and home.pep.active.seq == 3
    policy, _store = commands.load_checked(home.state_dir)
    assert policy.image == STRICT and commands.hosts_of(home.state_dir) == ("api.example.com",)
    assert home.pep.active.bodies["agent.zones"] == names


def test_case_129_a_zone_file_that_protects_less_is_a_widening(home, tmp_path):
    """case_129: W1, W3, V11. Against an active release that protects `a` and `b`, a release whose `agent.zones`
    lacks `b`, and one with no `agent.zones` at all, each with no statement, are dist:widening-unsigned, and one
    that adds a name commits. The committed names are the zone point's, and the index is a control path."""
    home.release(STRICT, 1, extra=[("agent.zones", _zones("a", "b"))])
    fewer = home.release(STRICT, 2, widens=False, extra=[("agent.zones", _zones("a"))])
    assert [record.cause for record in fewer if record.event == "refused"][0] == "dist:widening-unsigned"
    none = home.release(STRICT, 3, widens=False)
    assert [record.cause for record in none if record.event == "refused"][0] == "dist:widening-unsigned"
    assert home.release(STRICT, 4, widens=False, extra=[("agent.zones", _zones("a", "b", "c"))])[-1].event == "committed"
    project = tmp_path / "project"
    project.mkdir()
    doc = zones.load(home.state_dir, STRICT, project)
    assert doc["protected"] == ["a", "b", "c"] and doc["project"] == str(project.resolve())
    assert zones.control_paths_of(doc) == (str(project.resolve() / ".contextcloud") + "/",)


def test_the_deciders_readings_reach_the_heartbeat(home):
    """H5 across the home's processes: a reading the egress or MCP proxy noted is in the PEP's next record."""
    home.release(STRICT, 1)
    from prismpath.agent.profile import domain_classes
    from prismpath.agent.policy import Policy
    names, constant, groups = domain_classes([Policy(STRICT).doc])
    reading = dict(zip(names, (group[0] for group in groups)), **constant)
    agent_home.note(home.state_dir, reading)
    record = _read(home, home.pep.record("beat"))
    from prismpath.distribution import heartbeat
    assert len(heartbeat.decode(STRICT, record.body)) == 1
    assert not (home.state_dir / "dist" / agent_home.SPOOL).exists()


def test_the_k2_scan_is_bounded_and_skips_the_runs(tmp_path):
    """K2: a private key of a trusted authority in the home refuses the start, and the scan does not walk the runs
    the home keeps."""
    from cryptography.hazmat.primitives import serialization as ser
    from prismpath.distribution.pep import PepRefused
    pem = _dist.GEN.test_key("A").private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    point = HomePep(tmp_path / "home")
    (point.state_dir / "runs").mkdir()
    (point.state_dir / "runs" / "authority.pem").write_bytes(pem)
    point.open()                                                  # a key among the runs is not looked at
    (point.state_dir / "copy.pem").write_bytes(pem)
    with pytest.raises(PepRefused):
        point.open()


def test_init_follow_provisions_a_home_with_no_authority_key(tmp_path, monkeypatch):
    """P2 through `prismpath agent init --follow`: the anchor is received and its fingerprint shown, then confirmed,
    and the home holds an instance key and no authority key."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(commands.sys, "platform", "linux")
    anchor = tmp_path / "anchor.json"
    anchor.write_bytes(_dist.trust_module.anchor_bytes([_dist.GEN.public_raw(_dist.GEN.test_key("A"))],
                                                       target="agent", stream=STREAM))
    project = tmp_path / "project"
    project.mkdir()
    out = []

    class Out:
        def write(self, text):
            out.append(text)

    assert commands.follow(project, STREAM, anchor, None, True, True, out=Out()) == 0
    fingerprint = json.loads("".join(out))["fingerprint"]
    out.clear()
    assert commands.follow(project, STREAM, None, fingerprint, True, True, out=Out()) == 0
    home = commands.config_dir()
    assert json.loads("".join(out))["state"] == "no-policy" and agent_home.is_distributed(home)
    assert (home / "instance.key").is_file() and not (home / "authority.key").exists()
    assert (project / ".claude" / "settings.json").is_file()


@pytest.mark.parametrize("part", ["floor.json", "counter.json", "setting.json"])
def test_a_locked_pep_s_hook_decides_nothing(home, part):
    """Q5: when the floor, the counter or the setting does not read the PEP is locked, and every load of the home
    refuses with dist:floor-lost."""
    home.release(STRICT, 1)
    (home.state_dir / "dist" / part).write_bytes(b"{")
    assert home.open().state() == "locked"
    with pytest.raises(commands.AgentError, match="dist:floor-lost"):
        commands.load_checked(home.state_dir)


@pytest.mark.parametrize("ground", ["envelope", "policy", "key", "floor", "retired", "expired"])
def test_a_reader_of_the_home_and_the_machine_judge_the_active_release_alike(tmp_path, ground, monkeypatch):
    """R5, X1, O3: one test of whether the active release still decides, asked by the machine at a restart and by
    every load of the home (`pep.standing`). A release active under a key only retired keeps deciding on both."""
    point = HomePep(tmp_path / ground, authorities=["A", "B"])
    point.release(STRICT, 3)
    envelope = point.pep.active.held["policy.core"].envelope_id
    if ground == "retired":
        point.rotate(1, add="C", retire="A", signers=("A", "C"))
    elif ground == "expired":
        point.clock.now = _dist.EXPIRES
        monkeypatch.setattr(agent_home, "clock", lambda: _dist.EXPIRES)
    else:
        lists = {"envelope": {"envelopes": [envelope]}, "policy": {"policies": [H(STRICT)]},
                 "key": {"keys": [_dist.key_id("A")]}, "floor": {"floors": {STREAM: 5}}}[ground]
        point.revoke(1, signer="B", **lists)
    decides = point.open().state() == "active"
    try:
        commands.load_checked(point.state_dir)
        loads = True
    except commands.AgentError:
        loads = False
    assert decides == loads == (ground == "retired")


def test_zones_answer_protected_and_none_in_a_home_that_follows_a_stream(tmp_path, monkeypatch):
    """Section 3 with the zone point of #118: a distributed home with a committed zone file, a trusted index and the
    program `zones set` recorded answers protected and none, not only unknown, and a zone setting that does not
    read makes the point say unknown, never an error out of the hook."""
    from prismpath.tests.test_zones import World
    point = HomePep(tmp_path / "home")
    point.release(STRICT, 1, extra=[("agent.zones", _zones("pkg.secure.check"))])
    world = World(tmp_path, monkeypatch, point.state_dir, STRICT)
    world.add("pkg/secure.py", "def check():\n    return 1\n", ["check"])
    world.add("pkg/mod.py", "def other():\n    return 2\n", ["other"])
    world.answer(pkg__secure__check="no", pkg__mod__other="no")
    zones.set_local(point.state_dir, world.project, world.index,
                    {"path": os.path.realpath(world.exe), "package": str(world.pkg)})
    env = {"CONTEXTCLOUD": str(world.exe), "PATH": os.environ.get("PATH", "")}
    hook_point = zones.information_point(point.state_dir, STRICT, world.project, env)
    assert isinstance(hook_point, zones.ContextCloudZones)
    assert hook_point.reach("pkg/secure.py", world.config()) == "protected"
    assert hook_point.reach("pkg/mod.py", world.config()) == "none"
    (point.state_dir / zones.LOCAL_SETTINGS).write_text("{not json")
    broken = zones.information_point(point.state_dir, STRICT, world.project, env)
    assert broken.reach("pkg/mod.py", world.config()) == "unknown"


def test_the_hook_s_decision_reaches_the_heartbeat(tmp_path, monkeypatch):
    """H5: the hook notes the reading it decided, as the proxies do, so the next state record carries it."""
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)    # the hook is given HOME only, so both find one home
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(commands.sys, "platform", "linux")
    home_dir = commands.config_dir()
    point = HomePep(home_dir)
    point.release(STRICT, 1)
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.txt").write_text("x\n")
    hook = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Read",
            "tool_input": {"file_path": str(project / "a.txt")}, "cwd": str(project)}
    answer = commands.hook(json.dumps(hook).encode(), {"HOME": str(tmp_path), "CLAUDE_PROJECT_DIR": str(project)})
    assert len(agent_home.take_readings(home_dir)) == 1, answer


def test_a_long_running_decider_follows_a_revocation_and_an_expiry(tmp_path, monkeypatch):
    """Section 9, X3, R5: the MCP proxy's Governor and the egress gate are built once and decide many calls. A
    revocation of the policy, and the release's expiry, stop both at their next decision, as a fresh load would."""
    from prismpath.agent import egress_policy, mcp_proxy
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "f.txt").write_text("x")
    params = {"name": "read_file", "arguments": {"path": str(workspace / "f.txt")}}

    def deciders(name):
        home = HomePep(tmp_path / name, authorities=["A", "B"])
        assert home.release(ALLOW_HOSTS, 1, hosts=canon.canon2_bytes(["docs.example.com"]))[-1].event == "committed"
        governor = mcp_proxy.Governor(home.state_dir, tmp_path / f"runs-{name}", "s1", workspace, str(workspace))
        policy, store = commands.load_checked(home.state_dir)
        gate = egress_policy.PolicyGate(policy, store, "egress-s", workspace, compile_profile(policy, "agent"),
                                        commands.hosts_of(home.state_dir), follow=commands.Committed(home.state_dir))
        assert governor.decide(params).kind == "allow" and gate("docs.example.com:443") == (True, "policy-allow")
        return home, governor, gate

    home, governor, gate = deciders("revoked")
    home.revoke(1, signer="B", policies=[H(ALLOW_HOSTS)])
    assert home.pep.state() == "no-policy"
    outcome = governor.decide(params)
    assert outcome.kind == "refuse" and "no release is active" in outcome.failure
    assert gate("docs.example.com:443") == (False, "policy-lapsed")
    _home, governor, gate = deciders("expired")
    monkeypatch.setattr(agent_home, "clock", lambda: _dist.EXPIRES)        # no file changed, only the time
    assert governor.decide(params).failure.startswith("the home's release no longer decides")
    assert gate("docs.example.com:443") == (False, "policy-lapsed")


@pytest.mark.parametrize("line, carried, bad", [(b"5\n", 2, 1), (b'["read_file"]\n', 2, 1), (b'"text"\n', 2, 1),
                                               (b"\xff\xfe\n", 2, 0), (b'{"tool":5}\n', 3, 0)])
def test_a_spool_line_that_is_not_a_reading_is_counted_and_never_stops_the_records(home, line, carried, bad):
    """H5: a reading another process of the home spooled is held to what `decide` holds a reading to. One the Facet
    codec cannot encode is skipped and counted, the readings beside it are carried, and the next record is made. A
    torn line never reads, and an object the codec encodes, as a reading no rule routes, is carried."""
    home.release(STRICT, 1)
    from prismpath.distribution import heartbeat
    from prismpath.tests.test_distribution_heartbeat import _readings
    good = _readings(STRICT, 2)
    from prismpath.kernel import canon2
    spool = home.state_dir / "dist" / agent_home.SPOOL
    spool.write_bytes(canon2.dumps(good[0]) + b"\n" + line + canon2.dumps(good[1]) + b"\n")
    before = home.pep.bad_readings
    record = _read(home, home.pep.record("beat"))
    assert len(heartbeat.decode(STRICT, record.body)) == carried and home.pep.bad_readings == before + bad
    assert _read(home, home.pep.record("beat")).event == "beat"


def test_a_commit_of_another_policy_drops_what_the_home_s_deciders_spooled_under_the_old_one(home):
    """H5: a reading spooled under the active policy and taken after a commit of another one is not reported under
    the new policy."""
    from prismpath.distribution import heartbeat
    from prismpath.kernel import canon2
    from prismpath.tests.test_distribution_heartbeat import _readings
    home.release(STRICT, 1)
    release = _dist.env.release_id([("egress.hosts", H(home.hosts)), ("policy.core", H(DEFAULT))])
    args = {"release": release, "policy_sha256": H(DEFAULT), "replaces": H(STRICT), "widens": True}
    statement = _dist.widening([])
    home.pep.stage(seal("trust.widening", statement, seq=2, targets=("agent",), **args), statement)
    for name, data in (("egress.hosts", home.hosts), ("policy.core", DEFAULT)):
        home.pep.stage(seal(name, data, seq=2, targets=("agent",), **args), data)
    (home.state_dir / "dist" / agent_home.SPOOL).write_bytes(
        b"".join(canon2.dumps(reading) + b"\n" for reading in _readings(STRICT, 3)))
    record = _read(home, home.pep.commit(STREAM, 2, H(DEFAULT)))
    assert record.event == "committed" and heartbeat.decode(DEFAULT, record.body) == []


# ------------------------------------------------------------------ a withdrawal signals only the session it registered

def _sleeper():
    import subprocess
    import sys
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)


def _entry(home_dir, pid, **fields):
    from prismpath.kernel import canon2
    directory = home_dir / "dist" / agent_home.SESSIONS
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{pid}.json").write_bytes(canon2.dumps({"pid": pid, "policy_sha256": H(STRICT), **fields}))


needs_proc = pytest.mark.skipif(not agent_home.can_identify(), reason="the platform has no /proc")


@needs_proc
@pytest.mark.parametrize("which", ["reused", "rebooted"])
def test_a_withdrawal_never_signals_a_pid_that_names_another_process_or_another_boot(home, which):
    """C6: an entry whose pid now names an unrelated process (its start time differs) or whose boot id is not this
    boot's is a session that ended. The process is never signalled and the entry is removed."""
    other = _sleeper()
    try:
        boot, start = agent_home.process_identity(other.pid)
        identity = {"reused": (boot, start + 1), "rebooted": ("0" * 8 + boot[8:], start)}[which]
        _entry(home.state_dir, other.pid, boot_id=identity[0], start_time=identity[1])
        agent_home.AgentHomeAdapter(home.state_dir).deactivate("dist:expired")
        assert agent_home.sessions(home.state_dir) == []
        assert other.poll() is None
    finally:
        other.kill()
        other.wait()


@needs_proc
def test_a_withdrawal_ends_the_live_session_it_registered(home):
    """C6: the launcher's entry holds the session's boot id and start time, and a withdrawal ends that session."""
    session = _sleeper()
    try:
        agent_home.register_session(home.state_dir, session.pid, H(STRICT))
        assert agent_home.session_identity(home.state_dir, session.pid) == agent_home.process_identity(session.pid)
        agent_home.AgentHomeAdapter(home.state_dir).deactivate("dist:expired")
        assert session.wait(5) is not None and agent_home.sessions(home.state_dir) == []
    finally:
        if session.poll() is None:
            session.kill()
        session.wait()


def test_without_proc_a_withdrawal_signals_nothing_and_reports_the_session(home, monkeypatch, tmp_path):
    """A platform without `/proc` cannot tell a session from a reused pid, so the withdrawal signals nothing and
    fails, keeping the entry."""
    monkeypatch.setattr(agent_home, "PROC", str(tmp_path / "no-proc"))
    sent = []
    monkeypatch.setattr(agent_home.os, "killpg", lambda *args: sent.append(args))
    monkeypatch.setattr(agent_home.os, "kill", lambda *args: sent.append(args))
    _entry(home.state_dir, 4242)
    with pytest.raises(agent_home.SessionsRunning):
        agent_home.AgentHomeAdapter(home.state_dir).deactivate("dist:expired")
    assert sent == [] and agent_home.sessions(home.state_dir) == [4242]
