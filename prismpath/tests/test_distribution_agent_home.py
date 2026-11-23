# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""An agent home that follows a policy stream (spec-policy-distribution.md, section 3, the `agent` target): the
PEP machine over `AgentHomeAdapter`, with the hook, the egress proxy and the zone point reading the committed
release through `commands.load_checked`. Each test names the conformance case of section 20 it covers."""
import json
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

    def release(self, body, seq, *, hosts=None, extra=(), widens=True, froms=()):
        """Stage `body` and `hosts` at `seq` with a widening statement of `froms`, and the `extra` (artifact, body)
        envelopes of the same release, then commit."""
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


def test_a_commit_changes_the_hook_and_the_egress_proxy_together(home):
    """Section 3: one home holds one release, so the hook's policy and the egress proxy's hosts move in one
    commit."""
    home.release(STRICT, 1)
    before = (commands.load_checked(home.state_dir)[0].image, commands.hosts_of(home.state_dir))
    more = canon.canon2_bytes(["api.example.com", "docs.example.com"])
    assert home.release(DEFAULT, 2, hosts=more, froms=[H(STRICT)])[-1].event == "committed"
    after = (commands.load_checked(home.state_dir)[0].image, commands.hosts_of(home.state_dir))
    assert before == (STRICT, ("api.example.com",)) and after == (DEFAULT, ("api.example.com", "docs.example.com"))


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
