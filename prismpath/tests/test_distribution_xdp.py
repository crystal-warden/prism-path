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
    holds the loader to the hash it must be handed (`PPT_NET_VERIFIED_SHA256`). `kernel` is the table the last load
    that worked left in the kernel, `fail_next` fails that many loads before `rc` holds again, and `netstats` reports
    `floor_count` passes of the `floor` node, which a load zeroes as the kernel's histogram is zeroed."""

    def __init__(self, rc: int = 0):
        self.calls, self.tables, self.floors, self.rc = [], [], [], rc
        self.kernel, self.fail_next, self.floor_count, self.stats = None, 0, 0, 0

    def __call__(self, argv, capture_output=True, text=True, env=None):
        if argv[2] == "netstats":
            self.stats += 1
            rows = f"  floor          {self.floor_count}\n" if self.floor_count else ""
            return subprocess.CompletedProcess(argv, 0, "\n[ppt_net histogram]\n" + rows + "  ----\n", "")
        table = Path(argv[1]).read_bytes()
        assert env["PPT_NET_VERIFIED_SHA256"] == H(table)
        floor = Path(argv[1]).parent.parent / "dist" / "floor.json"
        self.floors.append(json.loads(floor.read_bytes())["seq"] if floor.exists() else None)
        self.calls.append(argv[2:])
        self.tables.append(table)
        rc = 2 if self.fail_next else self.rc
        self.fail_next = max(self.fail_next - 1, 0)
        if rc == 0:
            self.kernel, self.floor_count = table, 0
        return subprocess.CompletedProcess(argv, rc, "OK\n", "" if rc == 0 else "the kernel refused\n")


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
    assert kinds.read("net.dests", DESTS) == nf.Destinations.from_object(TABLE)


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


# ------------------------------------------------------------------ section 21: the action floor and the fallback policy

FLOOR_A, FLOOR_B, OTHER_DOCS = "10.0.0.1", "10.0.0.2", "93.184.216.35"
INSTALL = {"install_keys": ["N1", "N2", "N3"], "install_threshold": 2}


def _floor_core(rule: str = '-> allow: when tool == "connect" and net_dest == "allowed_host"') -> bytes:
    """An xdp action floor's `policy.core`: one rule that tests the destination class `net_dest` (AF9)."""
    from prismpath.kernel.policy_source import compile_source
    fields = ("tool", "net_dest", "path_scope", "command_class", "git_op", "path_control", "zone_reach")
    head = "".join(f"field.{name}: {'bool' if name == 'path_control' else 'category'}\n" for name in fields)
    return compile_source("---\nname: floor\nstart: core_decision\n" + head + "---\n## core_decision\n" + rule + "\n")


FLOOR_CORE = _floor_core()
FLOOR_DESTS = nf.Destinations.from_object({"format": nf.DEST_FORMAT, "model_api": {},
                                           "allowed_host": {"a.floor.example.com": [FLOOR_A],
                                                            "b.floor.example.com": [FLOOR_B]}}).canonical()


def _set(point, install_kind: str, core: bytes, dests: bytes, seq: int = 1, *, edge=None, meta=None, **args):
    """The (sealed, body) pairs of an xdp install set: a `policy.core`, a `net.dests` and the `net.edge` they compile
    to, with the flow and names hashes its `meta` signs, unless `edge` and `meta` say otherwise (IS3)."""
    compiled = net_dist.compiled_edge(core, dests, GOVERNED)
    bodies = {"policy.core": core, "net.dests": dests, "net.edge": compiled.ppt if edge is None else edge}
    args.setdefault("widens", True)
    return point.install_set(install_kind, bodies, seq, metas={"net.edge": meta or net_dist.edge_meta(compiled, "edge-env")},
                             **args)


def _floored(evaluator, point, frames) -> list:
    return nf.decide_frames(evaluator, point.loader.kernel, nf.FLOOR_NODE_NAMES, frames)


def test_case_187_an_xdp_floor_passes_its_own_addresses_and_leaves_a_third_to_the_release(tmp_path, evaluator):
    """case_187: AF1, AF9, IS3, the `xdp` part (the `agent` part is in test_distribution_agent_home.py and the
    `gateway` part in test_distribution_gateway.py). An xdp PEP whose floor holds two addresses loads the floor with
    no release, to a `floor` node reached before the release, and then with a release that refuses both: a packet to
    one of them passes by the floor, and a packet to a third is left to the release, which drops it, or allows it when
    it is the release's. A floor that tests no destination class, or whose table holds a ninth entry, is
    `dist:floor-broad`."""
    from prismpath.distribution import floor as floors
    point = EdgePep(tmp_path / "edge", **INSTALL)
    assert point.send(_set(point, "install.floor", FLOOR_CORE, FLOOR_DESTS))[-1].event == "install-widened"
    frames = [_syn(GOVERNED[0], FLOOR_A), _syn(GOVERNED[0], DOCS), _syn(GOVERNED[0], MODEL),
              _syn(GOVERNED[0], FLOOR_B, 80), _syn("192.168.4.21", DOCS)]
    assert point.pep.active is None and point.loader.calls[-1] == ["netupdate", "lo"]
    assert _floored(evaluator, point, frames) == ["floor", "drop", "drop", "drop", "pass"]
    assert point.release(DEFAULT, 1)[-1].event == "committed"
    assert _floored(evaluator, point, frames) == ["floor", "drop", "allow", "drop", "pass"]
    assert _floored(evaluator, point, [_syn(GOVERNED[0], FLOOR_B)]) == ["floor"]
    assert net_dist.edge_table(point.pep.active.bodies, None, GOVERNED) == point.pep.active.bodies["net.edge"]
    broad = _floor_core('-> allow: when tool == "connect"')
    nine = nf.Destinations.from_object({"format": nf.DEST_FORMAT, "model_api": {}, "allowed_host": {
        f"h{index}.floor.example.com": [f"10.0.1.{index}"] for index in range(9)}}).canonical()
    assert floors.narrow("xdp", "policy.core", broad, {}, None) == floors.BROAD
    assert floors.narrow("xdp", "net.dests", nine, {}, None) == floors.BROAD
    assert floors.narrow("xdp", "policy.core", FLOOR_CORE, {}, None) is None
    with pytest.raises(kinds.Refused, match="not narrow"):
        _set(point, "install.floor", FLOOR_CORE, nine, 2)


def test_case_193_an_xdp_floor_pass_is_counted_as_a_floor_answer_with_no_would(tmp_path, evaluator):
    """case_193: AF7, RC1, the `xdp` part (the receipts of the other kinds are in test_distribution_floor.py and the
    `cfs` lines in test_distribution_c_cfs.py). The program passes a packet by its floor's edge table and writes no
    receipt, so the PEP records no `would`: the `floor` node's count in the kernel's histogram becomes the floor
    answers of the next state record and the override count stays at zero. A load zeroes the histogram, and what it
    held before is still counted."""
    point = EdgePep(tmp_path / "edge", **INSTALL)
    point.send(_set(point, "install.floor", FLOOR_CORE, FLOOR_DESTS))
    point.release(DEFAULT, 1)
    assert _floored(evaluator, point, [_syn(GOVERNED[0], FLOOR_A)] * 2) == ["floor", "floor"]
    point.loader.floor_count = 2                              # the kernel counted the two passes
    record = _read(point, point.pep.record("beat"))
    assert (record.install.answers, record.install.overrides) == (2, 0)
    assert _read(point, point.pep.record("beat")).install.answers == 2       # counted once
    point.loader.floor_count = 3
    assert point.release(ALLOW_HOSTS, 2)[-1].event == "committed"        # the load zeroes the histogram
    assert point.loader.floor_count == 0
    record = _read(point, point.pep.record("beat"))
    assert (record.install.answers, record.install.overrides) == (3, 0)
    assert not list((point.state_dir / "dist").rglob("*receipt*"))
    assert point.pep.installed.record.overrides == 0


def test_case_194_an_xdp_pep_refuses_a_floor_with_a_rate(tmp_path):
    """case_194: AF8, the `xdp` part (the `mesh` part is in test_distribution_floor.py and the `cfs` part in
    test_cfs_dist.py). The program has no durable write on the packet path and records no `would`, so an xdp floor
    takes no `rate`, and one sent with a rate is `dist:bad-format` and loads nothing."""
    point = EdgePep(tmp_path / "edge", **INSTALL)
    loads = len(point.loader.calls)
    sent = point.send(_set(point, "install.floor", FLOOR_CORE, FLOOR_DESTS, rate={"allows": 3, "window": 60}))
    assert sent[0].cause == "dist:bad-format" and point.pep.floor_set() is None
    assert len(point.loader.calls) == loads


def test_case_223_an_xdp_floor_whose_net_edge_lacks_names_sha256_is_bad_format(tmp_path):
    """case_223: IS1, IS5, the `xdp` part (the `host` and `mesh` parts are in test_distribution_install_controller.py
    and test_distribution_c.py). An xdp floor's `net.edge` statement signs the `meta` section 3 gives the artifact, so
    one without `names_sha256` is `dist:bad-format`, and the same set with it is applied."""
    from prismpath.tests.test_distribution_install_controller import _resealed
    point = EdgePep(tmp_path / "edge", **INSTALL)
    pairs = _set(point, "install.floor", FLOOR_CORE, FLOOR_DESTS)
    unnamed = [(_resealed(sealed, lambda meta: {key: value for key, value in meta.items() if key != "names_sha256"})
                if meta_as(sealed) == "net.edge" else sealed, body) for sealed, body in pairs]
    sent = point.send(unnamed)
    assert [record.cause for record in sent if record.event == "refused"] == ["dist:bad-format"]
    assert point.pep.floor_set() is None
    assert "install-widened" in [record.event for record in point.send(pairs)] and point.pep.floor_set() is not None


def meta_as(sealed: bytes) -> str:
    envelope_bytes, _entries = env.unseal(sealed)
    return json.loads(envelope_bytes.decode("utf-8"))["meta"]["as"]


def test_case_225_an_xdp_pep_refuses_an_operator_answer(tmp_path):
    """case_225: V5, OP1, the `xdp` third (the `host`, `mesh` and `cfs` parts are in test_cfs_dist.py and
    test_distribution_c_cfs.py). The xdp kind has no escalation, so a well signed `operator.answer` on its stream,
    with an install threshold of 2 and an operator key, is `dist:target-mismatch`."""
    point = EdgePep(tmp_path / "edge", operators=["O1"], **INSTALL)
    point.send(_set(point, "install.floor", FLOOR_CORE, FLOOR_DESTS))
    record = _read(point, point.pep.stage(*_dist.answer(point, "ab" * 32)))
    assert (record.event, record.cause) == ("refused", "dist:target-mismatch")


def test_case_273_an_xdp_swap_that_fails_withdraws_to_the_floor_and_the_fallback(tmp_path, evaluator):
    """case_273: C8, C10, C6. An xdp PEP with an action floor and a fallback policy has a loader swap that fails and a
    withdrawal that works: it loads the floor's and the fallback's edge tables, a packet the floor allows passes and
    one the fallback allows is allowed. Another xdp PEP's withdrawal fails too: the kernel keeps passing packets under
    the running release and its floor, every record names that release, and the controller files
    `dist:reconciling` at once."""
    from prismpath.distribution.controller import Controller
    newer = _dests(docs_example_org=[OTHER_DOCS])
    frames = [_syn(GOVERNED[0], FLOOR_A), _syn(GOVERNED[0], DOCS), _syn(GOVERNED[0], MODEL),
              _syn(GOVERNED[0], OTHER_DOCS)]
    point = EdgePep(tmp_path / "first", **INSTALL)
    point.release(DEFAULT, 1)
    point.send(_set(point, "install.floor", FLOOR_CORE, FLOOR_DESTS))
    assert point.send(_set(point, "install.fallback", ALLOW_HOSTS, DESTS))[-1].event == "install-widened"
    point.loader.fail_next = 1
    record = point.release(ALLOW_HOSTS, 2, dests=newer)[-1]
    assert (record.event, point.pep.state(), point.pep.reconciling["withdrawn"]) == ("reconciling", "reconciling", True)
    assert record.fallback and record.reconciling.running_seq == 0
    fallback = point.pep.installed.fallback.bodies
    assert point.loader.kernel == net_dist.edge_table(fallback, net_dist.floor_addresses(
        point.pep.floor_set().bodies, GOVERNED), GOVERNED)
    assert _floored(evaluator, point, frames) == ["floor", "allow", "allow", "drop"]

    stuck = EdgePep(tmp_path / "second", controller="C", **INSTALL)
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=stuck.clock)
    controller.add_anchor(stuck.anchor())
    pep_id = controller.enroll(stuck.key.public_raw, "xdp", STREAM, "fleet")
    stuck.release(DEFAULT, 1)
    stuck.send(_set(stuck, "install.floor", FLOOR_CORE, FLOOR_DESTS))
    running = stuck.loader.kernel
    stuck.loader.rc = 2
    record = stuck.release(ALLOW_HOSTS, 2, dests=newer)[-1]
    assert (record.event, stuck.pep.reconciling["withdrawn"]) == ("reconciling", False)
    assert stuck.loader.kernel == running
    assert _floored(evaluator, stuck, frames) == ["floor", "drop", "allow", "drop"]
    assert _read(stuck, stuck.pep.tick() or stuck.pep.record("beat")).state == "reconciling"
    stuck.pep.take_statement(controller.statement(STREAM))
    stuck.pep.record("beat")
    records = [_read(stuck, signed) for signed in stuck.pep.outbox]
    assert all(one.reconciling.running_policy == state_record.prefix(H(DEFAULT)) for one in records
               if one.state == "reconciling")
    for signed in stuck.pep.drain():
        controller.receive(signed)
    assert "dist:reconciling" in controller.members[pep_id].findings


def test_case_272_an_xdp_floor_whose_load_and_withdrawal_fail_is_named_by_the_floor_before(tmp_path, monkeypatch):
    """case_272: C10, H14, AF3. An xdp PEP with a release and an action floor applies a new floor whose load fails and
    whose withdrawal fails too. The kernel keeps the table it had, with the floor before, so every record names the
    set id of that floor as the floor the runtime holds and the controller files `dist:reconciling` at once. Then the
    withdrawal works and the load of the release still fails: the entry names the new floor and no running release.
    When the load works the PEP is active again and sends the `install-applied` record it owed."""
    from prismpath.distribution.controller import Controller
    point = EdgePep(tmp_path / "edge", controller="C", **INSTALL)
    controller = Controller(str(tmp_path / "controller"), _dist.instance_key("C"), clock=point.clock)
    controller.add_anchor(point.anchor())
    pep_id = controller.enroll(point.key.public_raw, "xdp", STREAM, "fleet")
    point.release(DEFAULT, 1)
    point.send(_set(point, "install.floor", FLOOR_CORE, FLOOR_DESTS))
    before, kernel = point.pep.floor_set().set_id, point.loader.kernel
    narrower = nf.Destinations.from_object({"format": nf.DEST_FORMAT, "model_api": {},
                                            "allowed_host": {"a.floor.example.com": [FLOOR_A]}}).canonical()
    point.loader.rc = 2
    record = point.send(_set(point, "install.floor", FLOOR_CORE, narrower, 2, widens=False))[-1]
    after = point.pep.floor_set().set_id
    assert (record.event, point.pep.reconciling["withdrawn"], after != before) == ("reconciling", False, True)
    assert point.loader.kernel == kernel
    point.pep.tick()
    point.pep.take_statement(controller.statement(STREAM))
    point.pep.record("beat")
    entries = [one.reconciling for one in (_read(point, signed) for signed in point.pep.outbox)
               if one.state == "reconciling"]
    assert len(entries) >= 2
    assert all((entry.floor, entry.running_policy, entry.running_seq)
               == (bytes.fromhex(before)[:16], state_record.prefix(H(DEFAULT)), 1) for entry in entries)
    for signed in point.pep.drain():
        controller.receive(signed)
    assert "dist:reconciling" in controller.members[pep_id].findings
    point.loader.rc = 0
    activate = point.pep.adapter.activate

    def refuses(release):
        raise net_dist.LoaderFailed("the kernel refused")
    monkeypatch.setattr(point.pep.adapter, "activate", refuses)
    assert point.pep.tick() is None and point.pep.reconciling["withdrawn"]
    entry = _read(point, point.pep.record("beat")).reconciling
    assert (entry.floor, entry.running_policy, entry.running_seq) == (bytes.fromhex(after)[:16], b"\x00" * 16, 0)
    assert point.loader.kernel == net_dist.edge_table(None, net_dist.floor_addresses(point.pep.floor_set().bodies,
                                                                                     GOVERNED), GOVERNED)
    monkeypatch.setattr(point.pep.adapter, "activate", activate)
    point.pep.tick()
    assert point.pep.state() == "active"
    assert [one.event for one in (_read(point, signed) for signed in point.pep.drain())][-1] == "install-applied"


def test_case_164_each_kind_takes_its_three_sets_in_its_own_form(tmp_path, monkeypatch):
    """case_164: IS1, IS3, IS5, CL1. A PEP of each of the six kinds is sent an action floor, a fallback policy and a
    ceiling in the form of its kind, a table for `host` and `mesh`, a `cfs.table` for `cfs` and a policy list as the
    ceiling of those three, a `policy.core` with its `egress.hosts`, its `gateway.routes` or its `net.dests` and
    `net.edge` for the others, and applies all three. Then an `agent` PEP is sent a fallback set with no
    `egress.hosts`, which is never whole, so it is not applied and the held set still decides, and a floor set that
    holds an `agent.zones`, an `xdp` PEP a floor whose `net.edge` is not compiled from its `policy.core` and
    `net.dests`, and a `gateway` PEP two statements at one `seq` with different release ids: `dist:bad-format`,
    `dist:derived-mismatch` and `dist:incomplete`, each with the held set unchanged."""
    from integrations.cfs.tests.test_cfs_dist import ALLOW_3, _body, _cfs_floor, _floor_point
    from prismpath.distribution import install
    from prismpath.agent import dist_kind as agent_home
    from prismpath.gateway import reading as rd
    from prismpath.kernel import canon2
    from prismpath.tests import test_distribution_floor as tf
    from prismpath.tests.test_distribution_gateway import DEMO, ROUTES, GatewayHome
    monkeypatch.setattr(agent_home.onion_home, "clock", lambda: _dist.NOW)
    FLOOR, FALLBACK, CEILING = "install.floor", "install.fallback", "install.ceiling"

    def events(point, pairs):
        return [record.event if record.event != "refused" else record.cause for record in point.send(pairs)]

    def listed(point, seq, *tables):
        return point.install_set(CEILING, {kinds.POLICY_LIST: install.ceiling_body(tables)}, seq)

    applied = {}
    for name in ("host", "mesh"):                                    # a table, and a policy list as the ceiling
        point = tf._table_point(tf.HostFloor if name == "host" else tf.MeshFloor, tmp_path, name)
        fallback = _dist.image(9)
        applied[name] = (events(point, tf._table_floor(point))[-1],
                         events(point, point.install_set(FALLBACK, {"policy.ppt": fallback}, 1, widens=True))[-1],
                         events(point, listed(point, 1, tf.GOOD_TABLE, fallback))[-1])
    app = _floor_point(tmp_path)
    applied["cfs"] = (events(app, _cfs_floor(app, ALLOW_3))[-1],
                      events(app, app.install_set(FALLBACK, {"cfs.table": _body(2)}, 1, widens=True))[-1],
                      events(app, listed(app, 1, ALLOW_3, _body(2)))[-1])
    agent = tf._agent(tmp_path)
    ceiling = tf.core(tf.LIST, '-> allow: when tool == "read_file" and path_scope == "workspace"')
    applied["agent"] = (events(agent, tf._set(agent, FLOOR, tf.NARROW))[-1],
                        events(agent, tf._set(agent, FALLBACK, tf.NARROW))[-1],
                        events(agent, tf._set(agent, CEILING, ceiling))[-1])
    gateway, ceiled = GatewayHome(tmp_path / "gateway", **INSTALL), GatewayHome(tmp_path / "ceiled", **INSTALL)
    fields = canon2.loads(DEMO)["fields"]
    floor_core = canon2.dumps({"fields": fields, "format": "prismpath.core/1", "rules": [
        {"target": "allow", "when": ["and", ["cmp", "path_class", "==", ["str", "orders"]],
                                     ["cmp", "method_class", "==", ["str", "read"]]]}]})
    today = rd.Routes.from_doc({"routes": [{"match": "/api/orders/today", "class": "orders"}]}).canonical()
    applied["gateway"] = (
        events(gateway, gateway.install_set(FLOOR, {"policy.core": floor_core, "gateway.routes": today}, 1,
                                            widens=True))[-1],
        events(gateway, gateway.install_set(FALLBACK, {"policy.core": DEMO, "gateway.routes": ROUTES}, 1,
                                            widens=True))[-1],
        # the policy comparator has no finite domain for the gateway's categories, so it decides only between equal
        # bodies, and a gateway ceiling holds only its own policy: that one goes to a second home (section 9.4)
        events(ceiled, ceiled.install_set(CEILING, {"policy.core": DEMO, "gateway.routes": ROUTES}, 1))[-1])
    edge = EdgePep(tmp_path / "edge", **INSTALL)
    two = _floor_core('-> allow: when tool == "connect" and net_dest == "allowed_host"\n'
                      '-> allow: when tool == "connect" and net_dest == "model_api"')
    wide = nf.Destinations.from_object({**TABLE, "allowed_host": {
        "docs.example.com": [DOCS], "a.floor.example.com": [FLOOR_A], "b.floor.example.com": [FLOOR_B]}}).canonical()
    applied["xdp"] = (events(edge, _set(edge, FLOOR, FLOOR_CORE, FLOOR_DESTS))[-1],
                      events(edge, _set(edge, FALLBACK, FLOOR_CORE, DESTS))[-1],
                      events(edge, _set(edge, CEILING, two, wide, widens=False))[-1])
    first = ("install-widened", "install-widened", "install-applied")
    assert applied == {name: first for name in ("host", "mesh", "cfs", "agent", "gateway", "xdp")}

    held = agent.pep.installed.record
    hostless = agent.install_set(FALLBACK, {"policy.core": tf.NARROW}, 2, widens=True)
    assert events(agent, hostless) == ["staged"] and agent.pep.installed.record.sets == held.sets
    assert agent.pep.fallback_decides() and agent.pep.installed.fallback.seq == 1           # the held set decides
    zoned = agent.install_set(FLOOR, {"policy.core": tf.NARROW, "egress.hosts": tf.HOSTS,
                                      "agent.zones": tf._zones("keys")}, 2, widens=True, check=False)
    assert "dist:bad-format" in [record.cause for record in agent.send(zoned)]
    assert agent.pep.installed.held(FLOOR).seq == 1
    other = net_dist.compiled_edge(two, wide, GOVERNED)
    sent = edge.send(_set(edge, FLOOR, FLOOR_CORE, FLOOR_DESTS, 2, edge=other.ppt,
                          meta=net_dist.edge_meta(other, "edge-env")))
    assert sent[-1].cause == "dist:derived-mismatch" and edge.pep.floor_set().seq == 1
    one = gateway.install_set(FLOOR, {"policy.core": floor_core, "gateway.routes": today}, 2, widens=True)
    another = gateway.install_set(FLOOR, {"policy.core": floor_core, "gateway.routes": ROUTES}, 2, widens=True,
                                  check=False)
    by_name = {meta_as(sealed): (sealed, body) for sealed, body in another}
    sent = gateway.send([one[1], by_name["gateway.routes"]])
    assert sent[-1].cause == "dist:incomplete" and gateway.pep.installed.held(FLOOR).seq == 1
