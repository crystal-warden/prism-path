# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The XDP edge that follows a policy stream (spec-policy-distribution.md, section 3, the `xdp` target): the PEP
machine over `prismpath-ebpf/net_dist.py`'s `EdgeAdapter`, which compiles the edge table again from the staged
`policy.core` and `net.dests` at commit and loads what it commits through `net_swap.run_loader`, the loader call the
older signed pack gate ends in too. The loader is injected, so nothing here needs root or a NIC, and the loaded table
is run through the userspace evaluator `net_from_policy.build_evaluator` builds. Each test names the conformance case
of section 20 it covers."""
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("fcntl")

from prismpath.tests._repo import repo_file  # noqa: E402

_ebpf = repo_file("prismpath-ebpf", "net_dist.py").parent
repo_file("formal", "diff", "ebpf_batch.c")
for _extra in (repo_file("prismpath-hw"), _ebpf):
    if str(_extra) not in sys.path:
        sys.path.insert(0, str(_extra))

import net_cert  # noqa: E402
import net_dist  # noqa: E402
import net_from_policy as nf  # noqa: E402
from prismpath import canon  # noqa: E402
from prismpath.agent import commands  # noqa: E402
from prismpath.agent.profile import compile_profile  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import kinds, state_record, widening  # noqa: E402
from prismpath.distribution.pep import Pep, PepRefused  # noqa: E402
from prismpath.ledgers.audit_log import AuditLog  # noqa: E402
from prismpath.ledgers.root_statement import statements_path_for  # noqa: E402
from prismpath.tests import _dist  # noqa: E402
from prismpath.tests._dist import EXPIRES, NOT_BEFORE, STREAM, seal  # noqa: E402
from prismpath.tests.test_distribution_agent_home import (ALLOW_HOSTS, DEFAULT, HomePep, _connect_status,  # noqa: E402
                                                          _Echo)

H = canon.sha256_hex
TCP = 6
GOVERNED = ("192.168.4.20",)
MODEL, DOCS, SHARED = "160.79.104.10", "93.184.216.34", "160.79.104.11"
TABLE = {"format": nf.DEST_FORMAT, "model_api": {"api.anthropic.com": [MODEL]},
         "allowed_host": {"docs.example.com": [DOCS]}}
DESTS = nf.Destinations.from_object(TABLE).canonical()


def _dests(**allowed_host) -> bytes:
    return nf.Destinations.from_object({**TABLE, "allowed_host": {name.replace("_", "."): addresses
                                                                   for name, addresses in allowed_host.items()}}).canonical()


def _read(point, signed):
    return state_record.read(signed, point.key.public_raw)


class Loader:
    """Stands in for `./loader`: records each call, the table it was handed and the PEP's floor when it ran, and
    holds the loader to the hash it must be handed (`PPT_NET_VERIFIED_SHA256`)."""

    def __init__(self, rc: int = 0):
        self.calls, self.tables, self.floors, self.rc = [], [], [], rc

    def __call__(self, argv, capture_output=True, text=True, env=None):
        table = Path(argv[1]).read_bytes()
        assert env["PPT_NET_VERIFIED_SHA256"] == H(table)
        floor = Path(argv[1]).parent.parent / "dist" / "floor.json"
        self.floors.append(json.loads(floor.read_bytes())["seq"] if floor.exists() else None)
        self.calls.append(argv[2:])
        self.tables.append(table)
        return subprocess.CompletedProcess(argv, self.rc, "OK\n", "" if self.rc == 0 else "the kernel refused\n")


@dataclass
class EdgePep(_dist.Point):
    """An xdp PEP over `EdgeAdapter` on `lo` for the governed sources `sources`, with an injected loader. A release
    is its `policy.core`, its `net.dests` and its `net.edge`."""
    kind: str = "xdp"
    artifact: str = "policy.core"
    authorities: list = field(default_factory=lambda: ["A", "B"])
    loader: Loader = field(default_factory=Loader)
    sources: tuple = GOVERNED

    def adapter(self):
        return net_dist.EdgeAdapter(self.state_dir, "lo", sources=self.sources, run=self.loader,
                                    instance_key=self.key)

    def pairs(self, body: bytes, dests: bytes, edge=None, meta=None):
        compiled = net_dist.compiled_edge(body, dests, GOVERNED)
        return ([("net.dests", dests, {}), ("net.edge", compiled.ppt if edge is None else edge,
                                         meta or net_dist.edge_meta(compiled, "edge-env")), ("policy.core", body, {})])

    def args(self, body: bytes, pairs, widens: bool) -> dict:
        active = self.pep.active.policy_sha256 if self.pep.active else ""
        return {"release": env.release_id(sorted((name, H(data)) for name, data, _meta in pairs)),
                "policy_sha256": H(body), "replaces": active, "widens": widens}

    def release(self, body: bytes, seq: int, *, dests: bytes = DESTS, edge=None, meta=None, widens: bool = True,
                froms=()):
        """Stage the release of `body` and `dests` at `seq`, its `net.edge` the compiled one unless `edge` and `meta`
        say otherwise, with a widening statement of `froms` when it widens, then commit. The state records."""
        pairs = self.pairs(body, dests, edge, meta)
        args = self.args(body, pairs, widens)
        acks = []
        if widens:
            statement = _dist.widening(froms)
            acks.append(self.pep.stage(seal("trust.widening", statement, seq=seq, targets=("xdp",), **args), statement))
        for name, data, meta_of in pairs:
            acks.append(self.pep.stage(seal(name, data, seq=seq, targets=("xdp",), meta=meta_of, **args), data))
        acks.append(self.pep.commit(STREAM, seq, H(body)))
        return [_read(self, ack) for ack in acks]


@pytest.fixture
def edge(tmp_path):
    return EdgePep(tmp_path / "edge")


@pytest.fixture(scope="module")
def evaluator(tmp_path_factory):
    if not shutil.which("cc"):
        if os.environ.get("PRISMPATH_REQUIRE_CORE_ORACLE"):
            pytest.fail("PRISMPATH_REQUIRE_CORE_ORACLE is set and there is no C compiler (cc) for the evaluator")
        pytest.skip("no C compiler")
    return nf.build_evaluator(tmp_path_factory.mktemp("xdp_eval"))


def _syn(src: str, dst: str, port: int = 443) -> bytes:
    return net_cert.frame(src, dst, TCP, net_cert.tcp(40000, port, 0x02))


def _decide(evaluator, table: bytes, frames) -> list:
    return nf.decide_frames(evaluator, table, nf.NODE_NAMES, frames)


# ------------------------------------------------------------------ the xdp row and its edge table (V11, C2)

def test_case_045_a_staged_net_edge_that_is_not_the_compiled_table_is_derived_mismatch(edge):
    """case_045: V11 at commit, the net.edge half (the profile half is test_distribution_agent_home.py's). A
    `net.edge` must be the table compiled from the staged `policy.core` and `net.dests` for the edge's governed
    sources, and its `meta` must sign that table's flow and names. A table compiled from another policy, one compiled
    from another destination table, one whose flow hash is another's and one whose names hash is wrong are each
    `dist:derived-mismatch`, load nothing, and the compiled one commits and is loaded."""
    attached = list(edge.loader.calls)
    wider = nf.project(ALLOW_HOSTS, nf.Destinations.from_object(TABLE), list(GOVERNED))
    other = nf.project(DEFAULT, nf.Destinations.from_object({**TABLE, "model_api": {"api.anthropic.com": [
        MODEL, "160.79.104.12"]}}), list(GOVERNED))
    compiled = net_dist.compiled_edge(DEFAULT, DESTS, GOVERNED)
    meta = net_dist.edge_meta(compiled, "edge-env")
    for seq, (table, signed_meta) in enumerate([
            (wider.ppt, net_dist.edge_meta(wider, "edge-env")),
            (other.ppt, net_dist.edge_meta(other, "edge-env")),
            (compiled.ppt, {**meta, "flow_sha256": net_dist.edge_meta(wider, "e")["flow_sha256"]}),
            (compiled.ppt, {**meta, "names_sha256": H(b"edge\nallow\npass\nblock\n")})], start=1):
        assert edge.release(DEFAULT, seq, edge=table, meta=signed_meta)[-1].cause == "dist:derived-mismatch", seq
        assert edge.pep.active is None and edge.loader.calls == attached
    assert len({wider.ppt, compiled.ppt, other.ppt}) == 3
    assert edge.release(DEFAULT, 5)[-1].event == "committed"
    assert edge.loader.tables[-1] == compiled.ppt and edge.loader.calls[-1] == ["netupdate", "lo"]


def test_an_edge_set_up_for_other_sources_refuses_the_table_compiled_for_these(tmp_path):
    """The governed sources are part of what is compiled, so an edge and its signer must name the same ones: an edge
    governing another source compiles another table and refuses the release with `dist:derived-mismatch`."""
    elsewhere = EdgePep(tmp_path / "elsewhere", sources=("192.168.4.21",))
    assert elsewhere.release(DEFAULT, 1)[-1].cause == "dist:derived-mismatch"


def test_the_xdp_row_reads_its_artifacts_when_they_are_staged(edge):
    """Section 3, C2, V11 at staging: an xdp release needs all three artifacts, `net.dests` is a table the edge can
    use in its canonical spelling, and `net.edge` is an image the loader reads."""
    pairs = edge.pairs(DEFAULT, DESTS)
    args = edge.args(DEFAULT, pairs, True)
    statement = _dist.widening([])
    edge.pep.stage(seal("trust.widening", statement, seq=1, targets=("xdp",), **args), statement)
    for name, data, meta in pairs[1:]:
        assert _read(edge, edge.pep.stage(seal(name, data, seq=1, targets=("xdp",), meta=meta, **args), data)).event == "staged"
    assert _read(edge, edge.pep.commit(STREAM, 1, H(DEFAULT))).cause == "dist:incomplete"
    spaced = json.dumps(TABLE).encode()
    ipv6 = canon.canon2_bytes({**TABLE, "allowed_host": {"docs.example.com": ["2606:4700::1"]}})
    for bad, cause in ((spaced, "document:not-canonical"), (ipv6, "dist:bad-format"),
                       (canon.canon2_bytes({"format": "x"}), "dist:bad-format")):
        assert kinds.ARTIFACTS["net.dests"].check(None, bad, None) == cause, bad
    good = pairs[1][1]
    assert kinds.check_net_edge(None, good, None) is None
    assert kinds.check_net_edge(None, b"XXXX" + good[4:], None) is not None
    assert kinds.read_dests(DESTS) == nf.Destinations.from_object(TABLE)


def test_case_111_an_xdp_pep_refuses_to_start_with_hold(tmp_path):
    """case_111: X6, X10, the xdp half. An xdp PEP has no HOLD setting, so one given it refuses to start."""
    with pytest.raises(PepRefused, match="no HOLD setting"):
        Pep(str(tmp_path / "xdp"), net_dist.EdgeAdapter(tmp_path / "xdp", "lo", run=Loader()), _dist.instance_key(),
            _dist.Clock(), expiry_response="hold")


# ------------------------------------------------------------------ the destination table is ordered (W1)

def test_a_destination_table_is_larger_when_the_edge_it_compiles_to_would_allow_more():
    """9.4, W1: a table is larger when, under some set of classes the policy may pass, the edge allows an address the
    active table's does not. Another address is larger and one fewer is not. Dropping the refused name of an address
    an allowed name shares is larger though the address set shrinks, since the edge then allows that address."""
    shared = _dests(docs_example_com=[DOCS], shared_example_com=[SHARED])
    model_and_shared = nf.Destinations.from_object({**TABLE, "model_api": {"api.anthropic.com": [MODEL, SHARED]},
                                                    "allowed_host": {"docs.example.com": [DOCS],
                                                                     "shared.example.com": [SHARED]}}).canonical()
    model_alone = nf.Destinations.from_object({**TABLE, "model_api": {"api.anthropic.com": [MODEL, SHARED]},
                                               "allowed_host": {"docs.example.com": [DOCS]}}).canonical()
    assert widening.compare_artifact("net.dests", DESTS, shared) == widening.LARGER
    assert widening.compare_artifact("net.dests", shared, DESTS) == widening.NOT_LARGER
    assert widening.compare_artifact("net.dests", model_and_shared, model_alone) == widening.LARGER
    assert widening.compare_artifact("net.dests", DESTS, b"{}") == widening.CANNOT_DECIDE
    assert widening.compare_artifact("net.dests", DESTS, DESTS) == widening.NOT_LARGER


def test_an_edge_refuses_a_wider_destination_table_without_a_statement_and_takes_a_narrower_one(edge):
    """W1, W3 on an xdp PEP: a release whose table names another address and says it does not widen is
    `dist:widening-unsigned`, and one that names fewer commits on its signature alone."""
    wider = _dests(docs_example_com=[DOCS, "93.184.216.35"])
    assert edge.release(DEFAULT, 1, dests=wider)[-1].event == "committed"
    assert edge.release(DEFAULT, 2, widens=False)[-1].event == "committed"
    records = edge.release(DEFAULT, 3, dests=wider, widens=False)
    assert records[0].cause == "dist:widening-unsigned" and records[-1].event == "refused"
    assert edge.pep.active.bodies["net.dests"] == DESTS


# ------------------------------------------------------------------ the loader (C4, X3)

def test_the_edge_loads_once_per_table_with_the_floor_written_first_and_a_signed_log(edge, evaluator):
    """C4, X3: a PEP that holds no release loads the closed table, which drops every packet of a governed source and
    passes the others. A commit loads its table after the floor is written, a restart that finds the table loaded
    calls no loader, and an expiry loads the closed table again. Each load is one event in a log the PEP's instance
    key signs."""
    closed = net_dist.closed_table(GOVERNED)
    assert edge.loader.calls == [["netattach", "lo", str(edge.state_dir / "xdp" / "edge.names")]]
    assert edge.loader.tables == [closed]
    assert edge.release(DEFAULT, 1)[-1].event == "committed"
    assert edge.loader.calls[-1] == ["netupdate", "lo"] and edge.loader.floors[-1] == 1
    edge.pep = edge.open()
    assert len(edge.loader.calls) == 2
    frames = [_syn(GOVERNED[0], MODEL), _syn(GOVERNED[0], DOCS), _syn("192.168.4.21", DOCS)]
    assert _decide(evaluator, edge.loader.tables[-1], frames) == ["allow", "drop", "pass"]
    edge.clock.now = EXPIRES
    assert _read(edge, edge.pep.tick()).event == "lapsed"
    assert edge.loader.tables[-1] == closed
    assert _decide(evaluator, closed, frames) == ["drop", "drop", "pass"]
    log = edge.state_dir / "xdp" / "net_swaps.log"
    assert [event["action"] for event in AuditLog(str(log)).events] == ["refuse", "commit", "refuse"]
    commit = AuditLog(str(log)).events[1]["data"]
    assert (commit["policy_sha256"], commit["seq"], commit["verb"]) == (H(DEFAULT), 1, "netupdate")
    assert len(Path(statements_path_for(str(log))).read_text().splitlines()) == 3


def test_a_loader_that_fails_leaves_the_commit_to_be_finished_at_the_next_start(tmp_path):
    """C4 and C6: the floor and the active record are written before the loader runs, so a loader that refuses the
    table leaves the PEP reconciling (9.5), not raised out of the commit, and the next start with a working loader
    finishes it and loads the table."""
    point = EdgePep(tmp_path / "edge")
    point.loader.rc = 2
    before = len(point.loader.calls)                         # the start's own closed table, loaded with no policy
    point.release(DEFAULT, 1)
    assert point.loader.floors[before] == 1                  # the floor was on disk when the commit's load ran
    assert point.pep.state() == "reconciling"
    point.loader = Loader()
    point.pep = point.open()
    assert point.pep.state() == "active" and point.pep.active.seq == 1
    assert net_dist.compiled_edge(DEFAULT, DESTS, GOVERNED).ppt in point.loader.tables
    assert not (point.state_dir / "dist" / "pending.json").exists()


# ------------------------------------------------------------------ the writers (L1)

def _owner(directory: Path):
    """The test key A as the owner's authority key pair on disk: PEM private, raw public."""
    from cryptography.hazmat.primitives import serialization as ser
    directory.mkdir(parents=True, exist_ok=True)
    private = _dist.GEN.test_key("A")
    (directory / "authority.key").write_bytes(private.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                                    ser.NoEncryption()))
    (directory / "authority.pub").write_bytes(_dist.GEN.public_raw(private))
    return str(directory / "authority.key"), str(directory / "authority.pub")


def test_case_100_the_destination_table_and_edge_writers_seal_distribution_envelopes(edge, tmp_path):
    """case_100: L1, the destination table and edge half (the grant half is test_distribution_gateway.py's, and the
    other older forms' writers are PR 12's). `sign-dests` writes a `net.dests` envelope over the table's canonical
    bytes and no older manifest, `compile` reads it, and `sign` seals the edge's release, its `policy.core`,
    `net.dests` and `net.edge` under one release id with no `ppt-pack/1` manifest, which an xdp PEP commits as it
    is written."""
    priv, pub = _owner(tmp_path / "owner")
    table = tmp_path / "dests.json"
    table.write_text(json.dumps(TABLE, indent=1))
    signed = nf.sign_destinations(table, priv, pub, 1, expires=EXPIRES, not_before=NOT_BEFORE, stream=STREAM)
    assert not Path(str(table) + ".manifest.json").exists() and not Path(str(table) + ".manifest.sig").exists()
    envelope_bytes, entries = env.unseal(Path(str(table) + nf.SEALED).read_bytes())
    envelope = env.read(envelope_bytes)
    assert (envelope.artifact, envelope.targets, envelope.seq, envelope.body_sha256) == ("net.dests", ("xdp",), 1, H(DESTS))
    assert [kid for kid, _ in entries] == [_dist.key_id("A")] == [signed["key_id"]]
    loaded = nf.Destinations.load_signed(table, [pub])
    assert loaded.canonical() == DESTS
    image = tmp_path / "image.json"
    image.write_bytes(DEFAULT)
    out = tmp_path / "out"
    nf.write_edge(out, nf.project(DEFAULT, loaded, list(GOVERNED)), str(table))
    sealed = nf.sign(out, str(image), priv, pub, stream=STREAM, seq=1, qualification="edge-env", expires=EXPIRES,
                     not_before=NOT_BEFORE, widens=True)
    assert not (out / "edge.ppt.manifest.json").exists()
    release = out / nf.RELEASE_DIR
    statement = _dist.widening([])
    edge.pep.stage(seal("trust.widening", statement, seq=1, targets=("xdp",), release=sealed["release"],
                        policy_sha256=H(DEFAULT), widens=True), statement)
    for name in ("net.dests", "net.edge", "policy.core"):
        ack = edge.pep.stage((release / f"{name}.sealed").read_bytes(), (release / f"{name}.body").read_bytes())
        assert _read(edge, ack).event == "staged", name
    assert _read(edge, edge.pep.commit(STREAM, 1, H(DEFAULT))).event == "committed"
    assert edge.loader.tables[-1] == (out / "edge.ppt").read_bytes()
    assert edge.pep.active.envelopes["net.edge"].meta["qualification"] == "edge-env"


@pytest.mark.parametrize("tamper, reason", [("edit-address", "dests:tampered"), ("add-host", "dests:tampered"),
                                            ("other-key", "dests:sig-invalid"), ("revoked", "dests:revoked-key"),
                                            ("junk", "dests:bad-manifest"), ("not-a-table", "dests:invalid")])
def test_a_destination_table_its_envelope_does_not_sign_is_refused(tmp_path, tamper, reason):
    """L1: the reader of a `net.dests` envelope refuses a table it does not sign, one signed by a key not trusted
    or revoked, an envelope that does not read and a file that is no table, with the older form's reasons."""
    priv, pub = _owner(tmp_path / "owner")
    table = tmp_path / "dests.json"
    table.write_text(json.dumps(TABLE))
    nf.sign_destinations(table, priv, pub, expires=EXPIRES, not_before=NOT_BEFORE)
    keys, revoked, doc = [pub], frozenset(), json.loads(table.read_text())
    if tamper == "edit-address":
        doc["allowed_host"]["docs.example.com"] = ["93.184.216.99"]
    elif tamper == "add-host":
        doc["allowed_host"]["evil.example"] = ["6.6.6.6"]
    elif tamper == "other-key":
        _other_priv, other = _owner(tmp_path / "other")
        Path(other).write_bytes(_dist.GEN.public_raw(_dist.GEN.test_key("B")))
        keys = [other]
    elif tamper == "revoked":
        revoked = frozenset({_dist.key_id("A")})
    elif tamper == "junk":
        Path(str(table) + nf.SEALED).write_bytes(b"PPDE junk")
    else:
        doc = {"format": "x"}
    table.write_text(json.dumps(doc))
    assert nf.verify_destinations(table, keys, revoked)[:2] == ([reason], None)
    table.write_text(json.dumps(TABLE, indent=3) + "\n")                       # the envelope signs the table, not its spelling
    if tamper in ("edit-address", "add-host", "not-a-table"):
        assert nf.verify_destinations(table, keys, revoked)[0] == []


# ------------------------------------------------------------------ D7: one release, every enforcement point of the home

def test_one_release_changes_the_egress_proxy_and_the_xdp_table_and_both_report_it(tmp_path, evaluator):
    """D7 is done when one release changes the decision of the egress proxy and of the XDP table. The owner's change
    of policy, from the default to one that allows connects to allowed hosts, is sealed at one seq on one stream for
    the agent home and for the edge. The proxy of a run begun before refuses at its next connection, and the proxy of
    the next run passes the allowed host. The edge table the loader is handed, run through the userspace evaluator,
    drops a connect to the allowed host's address before and allows it after. Both PEPs report the new policy hash
    in their state records."""
    from prismpath.agent import egress, egress_policy
    hosts = canon.canon2_bytes(["docs.example.com"])
    home, xdp = HomePep(tmp_path / "home", hosts=hosts), EdgePep(tmp_path / "edge")
    assert home.release(DEFAULT, 1)[-1].event == "committed" and xdp.release(DEFAULT, 1)[-1].event == "committed"
    project = tmp_path / "project"
    project.mkdir()
    echo, sockets, proxies = _Echo(), tmp_path / "sock", []
    sockets.mkdir()

    def proxy(run: str):
        policy, store = commands.load_checked(home.state_dir)
        gate = egress_policy.PolicyGate(policy, store, run, project, compile_profile(policy, "agent"),
                                        commands.hosts_of(home.state_dir), home=home.state_dir,
                                        follow=commands.Committed(home.state_dir))
        started = egress.EgressProxy(sockets / f"{run}.sock", sockets / f"{run}.log", gate=gate,
                                     resolver=lambda name: [DOCS],
                                     connect=lambda address, port, timeout: __import__("socket").create_connection(
                                         ("127.0.0.1", echo.port), timeout=timeout)).start()
        proxies.append(started)
        return started

    frames = [_syn(GOVERNED[0], DOCS), _syn(GOVERNED[0], MODEL)]
    try:
        before = proxy("run-1")
        assert _connect_status(before, "docs.example.com:443")[0] == 403
        assert _decide(evaluator, xdp.loader.tables[-1], frames) == ["drop", "allow"]
        records = [home.release(ALLOW_HOSTS, 2)[-1], xdp.release(ALLOW_HOSTS, 2)[-1]]
        assert [record.event for record in records] == ["committed", "committed"]
        assert all(record.active_policy == state_record.prefix(H(ALLOW_HOSTS)) and record.active_seq == 2
                   for record in records)
        status, body = _connect_status(before, "docs.example.com:443")
        assert status == 403 and b"policy-changed" in body
        assert _connect_status(proxy("run-2"), "docs.example.com:443")[0] == 200
        assert _decide(evaluator, xdp.loader.tables[-1], frames) == ["allow", "allow"]
        for point in (home, xdp):
            assert _read(point, point.pep.record("beat")).active_policy == state_record.prefix(H(ALLOW_HOSTS))
    finally:
        for started in proxies:
            started.close()
        echo.server.close()
