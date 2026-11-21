# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The network edge compiled from the signed agent policy (prismpath-ebpf/net_from_policy.py).

`project(image, destinations)` writes the table `ppt_net.bpf.c` loads, from the image's connect allow set and the owner's
destination table (host to addresses). These tests hold it to the Lean oracle. Per class: the classes the compile passes
are the classes the oracle allows a produced connect reading of, covered by the agent profile's proxy state. Per packet: a
corpus of frames (every table address, near misses, odd addresses, ports, protocols, fragments, a cut header, IP options,
non IPv4 frames, governed and ungoverned sources) is read into a reading by the front end (`net_cert.canonical_reading`,
written from the header layouts, independently of the C), run through the table by the in-kernel evaluator's own text
compiled natively (`formal/diff/ebpf_batch.c`; the verifier and the JIT are not covered, `ebpf_kernel` and `loader netcert`
cover those), and compared with the oracle's decisions on the connect readings the packet corresponds to. The table may
be stricter than the oracle and must never be looser. Every stricter case is classified by its reason.

Closed edge: a frame the program cannot classify (IPv6, 802.1Q and 802.1ad VLAN tags, other ethertypes, a cut off or
malformed IPv4 header) is dropped by an enforcing table, never passed, and the corpus holds each of them, among them an
IPv4 packet to an allowed address inside a VLAN tag. ARP is the one counted and passed. An observing table passes them.
The owner's destination table is signed, and the compile, the dry run and the first attach all refuse one that is not.

The signed table: the pack signature, the envelope, the version floor, the flow's hash in the manifest, the table
recompiled from the flow, and the loader's parser, all in the dry run that loads nothing.
"""
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from prismpath.tests._repo import repo_file

_ebpf = repo_file("prismpath-ebpf")
repo_file("formal", "diff", "ebpf_batch.c")
sys.path.insert(0, str(repo_file("prismpath-hw")))
sys.path.insert(0, str(_ebpf))
sys.path.insert(0, str(repo_file("formal", "diff")))

import net_cert  # noqa: E402
import net_compile  # noqa: E402
import net_from_policy as nf  # noqa: E402
from prismpath.agent import classifier  # noqa: E402
from prismpath.agent.egress_policy import PROXY_CLASSES  # noqa: E402
from prismpath.agent.policy import STARTERS, Policy, starter_path  # noqa: E402
from prismpath.agent.profile import compile_profile  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402
from prismpath.tests.test_egress_policy import IMAGES, _oracle_allows, oracle, with_rules  # noqa: E402,F401

TCP, UDP, ICMP, GRE = 6, 17, 1, 47
GOVERNED = ("192.168.4.20", "200.1.2.3")
DESTS = nf.Destinations.from_object({
    "format": nf.DEST_FORMAT,
    "model_api": {"api.anthropic.com": ["160.79.104.10", "160.79.104.11"],      # a name with several addresses
                  "platform.claude.com": ["160.79.104.10", "128.0.0.1"]},        # one shared, one on the 128 boundary
    "allowed_host": {"docs.example.com": ["93.184.216.34", "10.9.8.7"],
                     "shared.example.com": ["160.79.104.11", "223.255.255.254"]},  # 160.79.104.11 is also a model address
})
ALL_IMAGES = {**IMAGES}
# an image that allows every connect class: `other` and `unknown` are allowed by the policy and never passed by the edge
_ALLOW_ALL = {"target": "allow", "when": ["cmp", "tool", "==", ["str", "connect"]]}
ALL_IMAGES["allow_every_connect"] = canon2.dumps({**canon2.loads(starter_path("default").read_bytes().rstrip(b"\n")),
                                                  "rules": [_ALLOW_ALL] + canon2.loads(
                                                      starter_path("default").read_bytes().rstrip(b"\n"))["rules"]})


@pytest.fixture(scope="module")
def evaluator(tmp_path_factory):
    if not shutil.which("cc"):
        pytest.skip("no C compiler")
    return nf.build_evaluator(tmp_path_factory.mktemp("edge_eval"))


def _config(tmp_path):
    return classifier.Config.for_workspace(tmp_path, allowed_hosts=DESTS.allowed_hosts())


def _reading(host, port, config):
    return classifier.classify({"tool": "connect", "args": {"host": host, "port": port}}, config)


# ------------------------------------------------------------------------------- the destination table
def test_a_destination_table_is_validated_and_hashed_by_its_canonical_bytes():
    again = nf.Destinations.from_object(DESTS.to_object())
    assert again == DESTS and again.sha256() == DESTS.sha256()
    shuffled = nf.Destinations.from_object({"format": nf.DEST_FORMAT, "allowed_host": {"docs.example.com": ["10.9.8.7", "93.184.216.34", "10.9.8.7"],
                                                                                      "shared.example.com": ["223.255.255.254", "160.79.104.11"]},
                                            "model_api": dict(reversed(list(DESTS.to_object()["model_api"].items())))})
    assert shuffled.sha256() == DESTS.sha256()                              # order and repeats do not change the table
    assert DESTS.allowed_hosts() == ("docs.example.com", "shared.example.com")
    assert [h for h, _ in DESTS.named_at(int(__import__("ipaddress").IPv4Address("160.79.104.11")))] == \
        ["api.anthropic.com", "shared.example.com"]


@pytest.mark.parametrize("obj, why", [
    ({"format": "x"}, "format"),
    ({"format": nf.DEST_FORMAT, "model_api": {"evil.example": ["1.2.3.4"]}}, "model API host"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"api.anthropic.com": ["1.2.3.4"]}}, "model_api"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"Docs.Example.com": ["1.2.3.4"]}}, "lower case"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"1.2.3.4": ["1.2.3.4"]}}, "IP literal"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": []}}, "non empty"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": ["1.2.3"]}}, "dotted quad"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": ["01.2.3.4"]}}, "dotted quad"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": ["::1"]}}, "dotted quad"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": ["127.0.0.1"]}}, "edge will name"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": ["0.0.0.0"]}}, "edge will name"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": ["169.254.169.254"]}}, "edge will name"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": ["224.0.0.1"]}}, "edge will name"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": ["255.255.255.255"]}}, "edge will name"),
    ({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": [f"10.0.0.{n}" for n in range(1, 18)]}}, "past the 16"),
])
def test_a_destination_table_the_edge_cannot_use_is_refused(obj, why):
    with pytest.raises(nf.DestinationError, match=why):
        nf.Destinations.from_object(obj)


def test_resolve_takes_every_ipv4_address_and_refuses_a_host_with_none():
    got = nf.resolve(["a.example", "b.example"], lambda host: {"a.example": ["9.9.9.9", "1.1.1.1", "9.9.9.9", "2606::1"],
                                                               "b.example": ["8.8.8.8"]}[host])
    assert got == {"a.example": ["1.1.1.1", "9.9.9.9"], "b.example": ["8.8.8.8"]}
    with pytest.raises(nf.DestinationError, match="no IPv4"):
        nf.resolve(["c.example"], lambda host: ["2606::1"])


# ------------------------------------------------------------------------------------- the projection
def _passed(name):
    return nf.passed_classes(Policy(ALL_IMAGES[name]))


def test_the_starters_pass_model_api_only_and_a_policy_that_allows_a_host_passes_it():
    for starter in sorted(STARTERS):
        assert nf.passed_classes(Policy(starter_path(starter).read_bytes())) == ("model_api",)
    assert _passed("allow_host") == ("model_api", "allowed_host")
    assert _passed("allow_host_only") == ("allowed_host",)
    assert _passed("refuse_model") == ()
    assert _passed("allow_other") == ("model_api",)                       # `other` and `unknown` are never passed
    assert _passed("allow_every_connect") == ("model_api", "allowed_host")


@pytest.mark.parametrize("name", sorted(ALL_IMAGES))
def test_the_classes_the_compile_passes_are_the_oracles_allowed_classes_covered_by_the_profile(oracle, name, tmp_path):
    raw, config = ALL_IMAGES[name], _config(tmp_path)
    calls = {"model_api": ("api.anthropic.com", 443), "allowed_host": ("docs.example.com", 443),
             "other": ("other.example", 443), "unknown": ("other.example", 0)}
    readings = [_reading(*call, config) for call in calls.values()]
    assert [r["net_dest"] for r in readings] == list(calls)
    allowed = dict(zip(calls, _oracle_allows(raw, readings)))
    covered = PROXY_CLASSES[compile_profile(raw, "agent").net]
    assert nf.passed_classes(Policy(raw)) == tuple(c for c in nf.CLASSES if allowed[c] and c in covered)
    assert nf.connect_allows(Policy(raw)) == allowed                       # the reference and the oracle agree per class


def test_the_edge_is_the_same_bytes_every_time_and_the_drop_node_is_index_three():
    edge = nf.project(ALL_IMAGES["allow_host"], DESTS, GOVERNED)
    assert nf.project(ALL_IMAGES["allow_host"], DESTS, list(reversed(GOVERNED))).ppt == edge.ppt
    assert edge.names == ("edge", "allow", "pass", "drop") and nf.drop_mask_nodes(edge.names) == [3]
    for name in ALL_IMAGES:                                                # whatever the policy, the loader's mask index holds
        other = nf.project(ALL_IMAGES[name], DESTS, GOVERNED if name != "refuse_model" else ())
        assert other.names == edge.names
    assert edge.source_image_sha256 == nf.image_sha256(ALL_IMAGES["allow_host"]) == nf.image_sha256(Policy(ALL_IMAGES["allow_host"]))
    assert edge.destinations_sha256 == DESTS.sha256() and f"sha256 {edge.source_image_sha256}" in edge.flow


def test_addresses_at_or_above_128_are_named_by_their_bit_pattern_and_an_ordering_is_still_refused():
    assert nf.address_constant(int(__import__("ipaddress").IPv4Address("128.0.0.0"))) == -2 ** 31
    assert nf.address_constant(int(__import__("ipaddress").IPv4Address("127.255.255.255"))) == 2 ** 31 - 1
    edge = nf.project(ALL_IMAGES["allow_host"], DESTS)
    image = net_compile.compile_with_schema(parse(edge.flow), net_compile.SCHEMA)
    assert net_compile.address_refusals(image)                              # the guard for a hand written flow is unchanged
    assert not net_compile.address_refusals(image, bit_pattern_constants=True)
    ordering = "---\nname: o\nstart: s\n---\n## s\n-> a: when dst_ip > 5\n-> b: else\n## a\n## b\n"
    refused = net_compile.address_refusals(net_compile.compile_with_schema(parse(ordering), net_compile.SCHEMA),
                                           bit_pattern_constants=True)
    assert [name for name, _ in refused] == ["dst_ip"]


def test_an_address_shared_by_an_allowed_and_a_refused_name_is_dropped_and_reported():
    edge = nf.project(ALL_IMAGES["default"], DESTS, GOVERNED)              # model_api passes, allowed_host does not
    shared = edge.report["ambiguous_addresses_dropped"]
    assert [row["address"] for row in shared] == ["160.79.104.11"]
    assert {(n["host"], n["passed"]) for n in shared[0]["names"]} == {("api.anthropic.com", True), ("shared.example.com", False)}
    assert "160.79.104.11" not in edge.report["allowed_addresses"] and "160.79.104.10" in edge.report["allowed_addresses"]
    assert {r["host"] for r in edge.report["refused_by_policy"]} == {"docs.example.com", "shared.example.com"}
    both = nf.project(ALL_IMAGES["allow_host"], DESTS, GOVERNED)           # both classes pass, so the shared address does too
    assert both.report["ambiguous_addresses_dropped"] == [] and "160.79.104.11" in both.report["allowed_addresses"]


def test_an_image_that_allows_a_class_the_table_has_no_host_for_is_refused_loudly():
    only_model = nf.Destinations.from_object({"format": nf.DEST_FORMAT, "model_api": {"api.anthropic.com": ["160.79.104.10"]}})
    with pytest.raises(nf.ProjectionError, match="allowed_host"):
        nf.project(ALL_IMAGES["allow_host"], only_model)
    assert nf.project(ALL_IMAGES["default"], only_model).allowed == (int(__import__("ipaddress").IPv4Address("160.79.104.10")),)
    refuse_all = nf.project(ALL_IMAGES["refuse_model"], only_model)         # nothing passes: still a table, and it drops all
    assert refuse_all.allowed == () and "never" in refuse_all.flow


def test_an_image_without_the_connect_fields_cannot_be_projected():
    doc = canon2.loads(starter_path("default").read_bytes().rstrip(b"\n"))
    del doc["fields"]["net_dest"]
    doc["rules"] = [r for r in doc["rules"] if "net_dest" not in json.dumps(r["when"])]
    with pytest.raises(nf.ProjectionError, match="net_dest"):
        nf.project(canon2.dumps(doc), DESTS)


def test_too_many_addresses_are_refused_by_the_evaluators_limits_not_truncated():
    big = nf.Destinations.from_object({"format": nf.DEST_FORMAT, "model_api": {"api.anthropic.com": ["160.79.104.10"]},
                                       "allowed_host": {f"h{n}.example": [f"11.{n // 250}.{n % 250}.{(n * 7) % 250 + 1}"] for n in range(1300)}})
    with pytest.raises(nf.ProjectionError, match="evaluator cannot run"):
        nf.project(ALL_IMAGES["allow_host"], big)


# ------------------------------------------------------------------------------- the packet differential
ADDRESSES = ["160.79.104.10", "160.79.104.11", "128.0.0.1", "93.184.216.34", "10.9.8.7", "223.255.255.254",
             "160.79.104.12", "160.79.104.9", "128.0.0.0", "127.255.255.255", "93.184.216.35", "10.9.8.8", "8.8.8.8",
             "0.0.0.0", "255.255.255.255", "192.168.4.20"]
PORTS = [443, 442, 444, 80, 8443, 22, 1, 65535, 0]
SOURCES = ["192.168.4.20", "200.1.2.3", "192.168.4.21", "127.255.255.255", "128.0.0.0", "10.9.8.7"]


def _frames():
    """(label, frame) for the corpus. The L4 variants are net_cert's: plain, cut header, later fragment, first fragment,
    don't fragment, IP options; UDP, ICMP and GRE ignore ports; and four frames the program does not read at all."""
    out = []
    looks_like_tcp = net_cert.tcp(40000, 443, 0x02)
    for src in SOURCES:
        for dst in ADDRESSES:
            for port in PORTS:
                seg = net_cert.tcp(40000, port, 0x02)
                out += [
                    (f"tcp {src}>{dst}:{port}", net_cert.frame(src, dst, TCP, seg)),
                    (f"tcp ack {src}>{dst}:{port}", net_cert.frame(src, dst, TCP, net_cert.tcp(40000, port, 0x10))),
                    (f"tcp cut {src}>{dst}:{port}", net_cert.frame(src, dst, TCP, seg, cut=14 + 20 + 10)),
                    (f"tcp later fragment {src}>{dst}:{port}", net_cert.frame(src, dst, TCP, seg, frag_off=64)),
                    (f"tcp first fragment {src}>{dst}:{port}", net_cert.frame(src, dst, TCP, seg, frag_off=0x2000)),
                    (f"tcp df {src}>{dst}:{port}", net_cert.frame(src, dst, TCP, seg, frag_off=0x4000)),
                    (f"tcp options {src}>{dst}:{port}", net_cert.frame(src, dst, TCP, seg, options=b"\x01\x01\x01\x00")),
                    (f"udp {src}>{dst}:{port}", net_cert.frame(src, dst, UDP, net_cert.udp(40000, port))),
                ]
            out += [(f"icmp {src}>{dst}", net_cert.frame(src, dst, ICMP, b"\x08\x00" + b"\x00" * 6)),
                    (f"gre {src}>{dst}", net_cert.frame(src, dst, GRE, b"\x00" * 24)),
                    (f"udp later fragment payload like tcp 443 {src}>{dst}", net_cert.frame(src, dst, UDP, looks_like_tcp, frag_off=185))]
    out += _odd_frames()
    return out


def _ipv6_tcp(dst_port, src="fd00::14", dst="2606:4700::6810:84e5"):
    """An Ethernet + IPv6 + TCP frame, the connect an IPv6 host would make to an address the table cannot name."""
    import ipaddress
    seg = net_cert.tcp(40000, dst_port, 0x02)
    header = struct.pack("!IHBB", 0x60000000, len(seg), TCP, 64) + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
    return struct.pack("!6s6sH", b"\xff" * 6, b"\x02" * 6, 0x86DD) + header + seg


def _odd_frames():
    """Frames the front end cannot classify, each with the label the corpus and the tests use for its reason."""
    ipv4 = net_cert.frame("192.168.4.20", "160.79.104.10", TCP, net_cert.tcp(40000, 443, 0x02))   # an allowed connect
    eth = ipv4[:12]
    return [("ipv6 ethertype", eth + b"\x86\xdd" + b"\x60" + b"\x00" * 60), ("arp", eth + b"\x08\x06" + b"\x00" * 28),
            ("ipv6 tcp 443", _ipv6_tcp(443)), ("ipv6 tcp 80", _ipv6_tcp(80)), ("ipv6 mapped model address", _ipv6_tcp(443, dst="::ffff:160.79.104.10")),
            ("vlan tagged ipv4", eth + b"\x81\x00\x00\x01" + ipv4[12:]),
            ("vlan tagged ipv4 priority 7 vid 4094", eth + b"\x81\x00\xef\xfe" + ipv4[12:]),
            ("qinq tagged ipv4", eth + b"\x88\xa8\x00\x02\x81\x00\x00\x01" + ipv4[12:]),
            ("vlan tagged ipv6", eth + b"\x81\x00\x00\x01" + _ipv6_tcp(443)[12:]),
            ("lldp", eth + b"\x88\xcc" + b"\x00" * 30), ("mpls", eth + b"\x88\x47" + b"\x00" * 30),
            ("short frame", ipv4[:20]), ("ihl below 5", ipv4[:14] + b"\x44" + ipv4[15:]), ("cut ethernet header", ipv4[:10]),
            ("empty frame", b"")]


def _lean_table(raw, readings):
    return dict(zip([canon2.dumps(r) for r in readings], _oracle_allows(raw, readings)))


def run_differential(name, tmp_path, evaluator, sources):
    """Run the corpus through the edge compiled from image `name` and the destination table, against the oracle.
    Returns (outcomes, stricter, loose): a Counter of (expected, got), the stricter cases as {reason: [labels]}, and the
    cases where the table passed what the oracle refuses (it must be empty) or disagreed with the oracle's strict reading."""
    raw, config = ALL_IMAGES[name], _config(tmp_path)
    edge = nf.project(raw, DESTS, sources)
    covered = PROXY_CLASSES[compile_profile(raw, "agent").net]
    labelled = _frames()
    readings_of = [nf.front_end(frame) for _label, frame in labelled]
    needed = {}
    for reading in readings_of:
        if reading is None or "dst_port" not in reading:
            continue
        port, dst = reading["dst_port"], reading["dst_ip"]
        for host, _cls in DESTS.named_at(dst):
            needed[(host, port)] = _reading(host, port, config)
        needed[(nf.address_text(dst), port)] = _reading(nf.address_text(dst), port, config)
    lean = _lean_table(raw, list(needed.values()))
    allows = {key: lean[canon2.dumps(reading)] for key, reading in needed.items()}
    classes = {key: reading["net_dest"] for key, reading in needed.items()}
    got = nf.decide_frames(evaluator, edge.ppt, edge.names, [frame for _label, frame in labelled])
    outcomes, stricter, wrong = Counter(), {}, []
    governed = {int(__import__("ipaddress").IPv4Address(s)) for s in sources}
    for (label, _frame), reading, decided in zip(labelled, readings_of, got):
        if reading is None:                                                 # unclassifiable: closed, ARP the one pass
            expected = "pass" if nf.refusal(_frame) == "arp" else "drop"
        elif governed and reading["src_ip"] not in governed:
            expected = "pass"
        elif "dst_port" not in reading or reading["protocol"] != TCP:
            expected = "drop"
        else:
            port, dst = reading["dst_port"], reading["dst_ip"]
            names = [host for host, _cls in DESTS.named_at(dst)]
            strict = bool(names) and all(allows[(host, port)] and classes[(host, port)] in covered for host in names)
            expected = "allow" if strict else "drop"
        outcomes[(expected, decided)] += 1
        if decided != expected:
            wrong.append((label, expected, decided))
        if decided == "allow":                                              # the safety property, stated directly
            port, dst = reading["dst_port"], reading["dst_ip"]
            names = [host for host, _cls in DESTS.named_at(dst)]
            keys = [(host, port) for host in names] + [(nf.address_text(dst), port)]
            if not (all(allows[(host, port)] for host in names) and any(allows[key] for key in keys)):
                wrong.append((label, "oracle refuses", decided))
        if decided == "drop" and reading is not None and "dst_port" in reading and \
                not (governed and reading["src_ip"] not in governed):
            port, dst = reading["dst_port"], reading["dst_ip"]
            names = [host for host, _cls in DESTS.named_at(dst)]
            keys = [(host, port) for host in names] + [(nf.address_text(dst), port)]
            allowed_keys = [key for key in keys if allows[key]]
            if allowed_keys:                                                # the oracle allows a connect this packet could be
                if reading["protocol"] != TCP:
                    why = "not TCP: the oracle's connect is a TCP CONNECT, and the edge passes only TCP"
                elif all(classes[key] not in covered for key in allowed_keys):
                    why = "the allowed reading is `other` or `unknown`, which the proxy's profile never passes"
                else:
                    why = "another name at this address is refused by the oracle, so the edge drops the address"
                stricter.setdefault(why, []).append(label)
    return outcomes, stricter, wrong


@pytest.mark.parametrize("name", sorted(ALL_IMAGES))
@pytest.mark.parametrize("scoped", [True, False], ids=["scoped", "every-source"])
def test_the_compiled_table_agrees_with_the_oracle_over_the_packet_corpus_and_is_never_looser(oracle, evaluator, tmp_path, name, scoped):
    outcomes, stricter, wrong = run_differential(name, tmp_path, evaluator, GOVERNED if scoped else ())
    assert wrong == [], wrong[:10]
    assert sum(outcomes.values()) == len(_frames())
    assert not any(got == "nomatch" for _expected, got in outcomes)         # the final `else` always matches
    if _passed(name):
        assert outcomes[("allow", "allow")] > 0                             # the corpus does reach the allow node
    for why in stricter:
        assert why.startswith(("not TCP", "the allowed reading is", "another name at this address"))


def test_the_default_policy_passes_exactly_the_model_addresses_on_tcp_443_and_nothing_else(oracle, evaluator, tmp_path):
    edge = nf.project(ALL_IMAGES["default"], DESTS, GOVERNED)
    frames = [(f"{src}>{dst}:{port}/{proto}", net_cert.frame(src, dst, proto, (net_cert.tcp if proto == TCP else net_cert.udp)(40000, port, *([0x02] if proto == TCP else []))))
              for src in ("192.168.4.20", "192.168.4.21") for dst in ADDRESSES for port in (443, 80) for proto in (TCP, UDP)]
    got = dict(zip([label for label, _ in frames], nf.decide_frames(evaluator, edge.ppt, edge.names, [f for _l, f in frames])))
    allowed = {label for label, outcome in got.items() if outcome == "allow"}
    assert allowed == {f"192.168.4.20>{dst}:443/{TCP}" for dst in ("160.79.104.10", "128.0.0.1")}
    assert {label for label, outcome in got.items() if outcome == "pass"} == {label for label in got if label.startswith("192.168.4.21")}


def test_the_stricter_cases_are_listed_with_their_reasons(oracle, evaluator, tmp_path):
    _outcomes, stricter, wrong = run_differential("allow_host", tmp_path, evaluator, GOVERNED)
    assert wrong == [] and any(r.startswith("not TCP") for r in stricter)
    _outcomes, stricter, wrong = run_differential("allow_every_connect", tmp_path, evaluator, GOVERNED)
    assert wrong == [] and any(r.startswith("the allowed reading is") for r in stricter)   # `other` allowed, never passed
    _outcomes, stricter, _wrong = run_differential("allow_host_only", tmp_path, evaluator, GOVERNED)
    assert any(r.startswith("another name") for r in stricter)              # api and shared names disagree at 160.79.104.11


def test_a_frame_the_edge_cannot_classify_is_dropped_and_never_passed_except_arp(evaluator):
    edge = nf.project(ALL_IMAGES["default"], DESTS, GOVERNED)
    odd = _odd_frames()
    reasons = {label: nf.refusal(frame) for label, frame in odd}
    assert reasons["ipv6 tcp 443"] == "ipv6" and reasons["vlan tagged ipv4"] == "vlan" and reasons["qinq tagged ipv4"] == "vlan"
    assert reasons["vlan tagged ipv6"] == "vlan" and reasons["lldp"] == "ethertype" and reasons["arp"] == "arp"
    assert reasons["short frame"] == reasons["cut ethernet header"] == reasons["empty frame"] == "short"
    assert reasons["ihl below 5"] == "ip-header" and None not in reasons.values()
    got = dict(zip([label for label, _ in odd], nf.decide_frames(evaluator, edge.ppt, edge.names, [f for _l, f in odd])))
    assert {label for label, outcome in got.items() if outcome == "pass"} == {"arp"}
    assert {label for label, outcome in got.items() if outcome == "drop"} == set(got) - {"arp"}
    # the same frames from an ungoverned source are still dropped: the edge cannot read a source it cannot parse
    assert "vlan tagged ipv4" in got and got["vlan tagged ipv4"] == "drop"


def test_a_table_that_only_observes_passes_the_frames_it_cannot_classify(evaluator):
    edge = nf.project(ALL_IMAGES["default"], DESTS, GOVERNED)
    odd = [frame for _label, frame in _odd_frames()]
    assert nf.decide_frames(evaluator, edge.ppt, ("edge", "allow", "pass", "keep"), odd) == ["pass"] * len(odd)


def test_a_vlan_tagged_allowed_connect_is_dropped_while_the_untagged_one_is_allowed(evaluator):
    edge = nf.project(ALL_IMAGES["default"], DESTS, GOVERNED)
    plain = net_cert.frame("192.168.4.20", "160.79.104.10", TCP, net_cert.tcp(40000, 443, 0x02))
    tagged = plain[:12] + b"\x81\x00\x00\x2a" + plain[12:]
    assert nf.decide_frames(evaluator, edge.ppt, edge.names, [plain, tagged]) == ["allow", "drop"]


def test_the_program_counts_and_drops_what_it_cannot_classify_closed_only_when_the_table_enforces():
    source = (_ebpf / "ppt_net.bpf.c").read_text()
    assert "refused_map" in source and "closed ? XDP_DROP : XDP_PASS" in source and "cfg->drop_mask != 0" in source
    assert source.count("refuse(NET_REFUSED_") == 7                           # every early return of the front end goes through it
    assert "return XDP_PASS;" not in source.split("int ppt_net_prog")[1].split("struct ppt_regfile")[0]


def test_an_ipv6_destination_is_refused_not_truncated():
    for address in ("2606:4700::6810:84e5", "::ffff:160.79.104.10"):
        with pytest.raises(nf.DestinationError, match="dotted quad"):
            nf.Destinations.from_object({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": [address]}})


def test_a_table_the_loaders_parser_refuses_is_an_error_not_a_decision(evaluator):
    empty = nf.Edge(b"", nf.NODE_NAMES, "", "", "", (), (), {})
    with pytest.raises(nf.ProjectionError):
        nf.decide_frames(evaluator, empty.ppt, empty.names, [])


# ----------------------------------------------------------------------------------- the signed table
@pytest.fixture()
def signed(tmp_path):
    pytest.importorskip("cryptography")
    from prismpath.hotswap import policy_pack as pp
    edge = nf.project(ALL_IMAGES["default"], DESTS, GOVERNED)
    out = tmp_path / "edge"
    keys = pp.keygen(str(tmp_path / "keys"))
    dests = tmp_path / "dests.json"
    dests.write_text(json.dumps(DESTS.to_object()))
    nf.sign_destinations(dests, keys["private"], keys["public"], 1)
    nf.write_edge(out, edge, str(dests))
    manifest = nf.sign(out, keys["private"], keys["public"], "edge-env", 1, str(tmp_path / "env"))
    return {"out": out, "edge": edge, "keys": keys, "manifest": manifest, "env": str(tmp_path / "env" / "edge-env.envelope"),
            "state": str(tmp_path / "state"), "tmp": tmp_path, "pp": pp, "dests": dests}


def _verify(s, **kw):
    kw.setdefault("image", ALL_IMAGES["default"])
    kw.setdefault("destinations", DESTS)
    return nf.verify(s["out"], [s["keys"]["public"]], s["env"], s["state"], **kw)


def test_the_signed_table_carries_the_source_image_hash_and_the_dry_run_accepts_it(signed, evaluator):
    manifest = signed["manifest"]
    flow = (signed["out"] / "edge.flow.md").read_text()
    assert manifest["flow_sha256"] == signed["pp"].sha256_hex(flow.encode())      # the signature covers the flow
    assert manifest["image_sha256"] == signed["edge"].ppt_sha256
    assert nf.parse_flow_header(flow) == (nf.image_sha256(ALL_IMAGES["default"]), DESTS.sha256())
    assert set(manifest["fields"]) == set(nf.FLOW_FIELDS)
    result = _verify(signed, evaluator=evaluator)
    assert result["ok"], result
    assert result["dry_run"] and result["version"] == 1 and result["source_image_sha256"] == signed["edge"].source_image_sha256
    summary = json.loads((signed["out"] / "edge.json").read_text())
    assert summary["source_image_sha256"] == result["source_image_sha256"] and summary["ppt_sha256"] == result["ppt_sha256"]


def test_the_dry_run_loads_nothing_and_writes_no_version_floor(signed, evaluator):
    assert _verify(signed, evaluator=evaluator)["ok"]
    assert not (Path(signed["state"]) / "active_version").exists()
    rows = (Path(signed["state"]) / "net_swaps.log").read_text()
    assert "swap_dry_run" in rows and '"swap"' not in rows
    assert _verify(signed, evaluator=evaluator)["ok"]                            # and it can be run again: no floor moved


def test_the_loaders_own_checks_refuse_a_table_the_dry_run_is_given_altered(signed, evaluator):
    ppt = signed["out"] / "edge.ppt"
    good = ppt.read_bytes()
    for what, bad in (("magic", b"XXXX" + good[4:]), ("version", good[:4] + b"\x02\x00" + good[6:]), ("length", good[:-3])):
        ppt.write_bytes(bad)
        result = _verify(signed, evaluator=evaluator)
        assert not result["ok"], what
    ppt.write_bytes(good)
    assert _verify(signed, evaluator=evaluator)["ok"]


@pytest.mark.parametrize("tamper, reason", [
    ("table", "sig"), ("flow", "flow:sha256-not-signed"), ("names", "names:differ-from-flow"),
    ("image", "image:not-the-source"), ("dests", "destinations:not-the-source"),
    ("carried-dests", "dests:tampered")])
def test_the_dry_run_refuses_a_table_that_is_not_the_signed_projection_of_its_image(signed, evaluator, tamper, reason):
    out = signed["out"]
    image, dests = ALL_IMAGES["default"], DESTS
    if tamper == "table":
        ppt = bytearray((out / "edge.ppt").read_bytes())
        ppt[-1] ^= 1
        (out / "edge.ppt").write_bytes(bytes(ppt))
    elif tamper == "flow":
        (out / "edge.flow.md").write_text((out / "edge.flow.md").read_text().replace("Passes.", "Passes!"))
    elif tamper == "names":
        (out / "edge.names").write_text("edge\nallow\npass\nblock\n")
    elif tamper == "image":
        image = ALL_IMAGES["allow_host"]
    elif tamper == "carried-dests":
        carried = json.loads((out / nf.DEST_COPY).read_text())
        carried["allowed_host"]["docs.example.com"] = ["93.184.216.99"]
        (out / nf.DEST_COPY).write_text(json.dumps(carried))
    else:
        dests = nf.Destinations.from_object({**DESTS.to_object(), "allowed_host": {"docs.example.com": ["93.184.216.99"]}})
    result = _verify(signed, evaluator=evaluator, image=image, destinations=dests)
    assert not result["ok"]
    assert any(reason in r or (reason == "sig" and r.startswith(("image:", "sig", "manifest"))) for r in result["reasons"]), result["reasons"]


def test_an_unsigned_or_wrongly_signed_table_and_a_stale_version_are_refused(signed, evaluator, tmp_path):
    other = signed["pp"].keygen(str(tmp_path / "other"))
    wrong = nf.verify(signed["out"], [other["public"]], signed["env"], signed["state"], evaluator=evaluator)
    assert not wrong["ok"] and any("sig" in r for r in wrong["reasons"])
    no_envelope = nf.verify(signed["out"], [signed["keys"]["public"]], None, signed["state"], evaluator=evaluator)
    assert not no_envelope["ok"] and "envelope:missing" in no_envelope["reasons"]
    Path(signed["state"]).mkdir(exist_ok=True)
    (Path(signed["state"]) / "active_version").write_text("1")                    # a floor at 1: version 1 is not above it
    stale = _verify(signed, evaluator=evaluator)
    assert not stale["ok"] and any(r.startswith("version:not-monotonic") for r in stale["reasons"])


def test_the_command_line_compiles_signs_and_dry_runs_a_table(tmp_path, evaluator, capsys):
    pytest.importorskip("cryptography")
    from prismpath.hotswap import policy_pack as pp
    image, dests, out = tmp_path / "image.json", tmp_path / "dests.json", tmp_path / "out"
    image.write_bytes(ALL_IMAGES["default"])
    dests.write_text(json.dumps(DESTS.to_object()))
    keys = pp.keygen(str(tmp_path / "keys"))
    assert nf.main(["compile", str(image), str(dests), str(out), "--pub", keys["public"]]) == 2    # unsigned table: refused
    assert nf.main(["sign-dests", str(dests), "--priv", keys["private"], "--pub", keys["public"]]) == 0
    assert nf.main(["compile", str(image), str(dests), str(out), "--pub", keys["public"], "--source", "192.168.4.20"]) == 0
    assert nf.main(["sign", str(out), "--priv", keys["private"], "--pub", keys["public"], "--envelope-id", "e", "--version", "3",
                    "--envelope-dir", str(tmp_path / "env")]) == 0
    capsys.readouterr()
    assert nf.main(["verify", str(out), "--pub", keys["public"], "--envelope", str(tmp_path / "env" / "e.envelope"),
                    "--state", str(tmp_path / "state"), "--image", str(image), "--dests", str(dests)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] and result["version"] == 3 and result["dry_run"]
    assert nf.main(["compile", str(image), str(tmp_path / "bad.json"), str(out), "--pub", keys["public"]]) == 2


# ------------------------------------------------------------------- the owner signs the destination table
@pytest.fixture()
def owner(tmp_path):
    pytest.importorskip("cryptography")
    from prismpath.hotswap import policy_pack as pp
    keys = pp.keygen(str(tmp_path / "keys"))
    dests = tmp_path / "dests.json"
    dests.write_text(json.dumps(DESTS.to_object()))
    return {"keys": keys, "dests": dests, "pub": [keys["public"]], "tmp": tmp_path, "pp": pp}


def test_a_signed_destination_table_loads_and_carries_the_owners_key(owner):
    manifest = nf.sign_destinations(owner["dests"], owner["keys"]["private"], owner["keys"]["public"], 2)
    assert manifest["key_id"] == owner["keys"]["key_id"] and manifest["destinations_sha256"] == DESTS.sha256() and manifest["version"] == 2
    assert nf.Destinations.load_signed(owner["dests"], owner["pub"]) == DESTS
    assert nf.verify_destinations(owner["dests"], owner["pub"])[0] == []


def test_an_unsigned_destination_table_is_refused_by_the_compile(owner):
    with pytest.raises(nf.DestinationError, match="dests:unsigned"):
        nf.Destinations.load_signed(owner["dests"], owner["pub"])
    nf.sign_destinations(owner["dests"], owner["keys"]["private"], owner["keys"]["public"])
    Path(str(owner["dests"]) + ".manifest.sig").unlink()
    assert nf.verify_destinations(owner["dests"], owner["pub"])[0] == ["dests:unsigned"]


@pytest.mark.parametrize("tamper, reason", [
    ("edit-address", "dests:tampered"), ("add-host", "dests:tampered"), ("whitespace", "dests:tampered"),
    ("manifest-hash", "dests:sig-invalid"), ("signature", "dests:sig-invalid"), ("manifest-junk", "dests:bad-manifest"),
    ("other-key", "dests:sig-invalid"), ("revoked", "dests:revoked-key"), ("not-a-table", "dests:invalid")])
def test_a_tampered_or_wrongly_signed_destination_table_is_refused(owner, tamper, reason):
    path, pp = owner["dests"], owner["pp"]
    keys = owner["keys"]
    nf.sign_destinations(path, keys["private"], keys["public"])
    manifest_path, sig_path = Path(str(path) + ".manifest.json"), Path(str(path) + ".manifest.sig")
    revoked = frozenset()
    pub = owner["pub"]
    obj = json.loads(path.read_text())
    if tamper == "edit-address":
        obj["allowed_host"]["docs.example.com"] = ["93.184.216.99"]
        path.write_text(json.dumps(obj))
    elif tamper == "add-host":
        obj["allowed_host"]["evil.example"] = ["6.6.6.6"]
        path.write_text(json.dumps(obj))
    elif tamper == "whitespace":
        path.write_text(path.read_text() + "\n")                              # even a harmless edit is not what was signed
    elif tamper == "manifest-hash":
        manifest_path.write_bytes(manifest_path.read_bytes().replace(DESTS.sha256().encode(), b"0" * 64))
    elif tamper == "signature":
        sig = bytearray(sig_path.read_bytes()); sig[0] ^= 1
        sig_path.write_bytes(bytes(sig))
    elif tamper == "manifest-junk":
        manifest_path.write_text("not json")
    elif tamper == "other-key":
        pub = [pp.keygen(str(owner["tmp"] / "other"))["public"]]
    elif tamper == "revoked":
        revoked = frozenset([keys["key_id"]])
    else:                                                                       # signed, but not a table the edge can use
        path.write_text(json.dumps({"format": "x"}))
        manifest = json.loads(manifest_path.read_text())
        manifest["file_sha256"] = pp.sha256_hex(path.read_bytes())
        pp.write_signed_document(str(manifest_path), manifest)
        sig_path.write_bytes(pp._load_private(keys["private"]).sign(pp.signed_bytes(manifest)))
    got, table, _manifest = nf.verify_destinations(path, pub, revoked)
    assert got == [reason] and table is None
    with pytest.raises(nf.DestinationError, match=reason):
        nf.Destinations.load_signed(path, pub, revoked)


def test_a_table_the_edge_cannot_use_is_not_signed(owner):
    owner["dests"].write_text(json.dumps({"format": nf.DEST_FORMAT, "allowed_host": {"a.example": ["2606:4700::1"]}}))
    with pytest.raises(nf.DestinationError, match="dotted quad"):
        nf.sign_destinations(owner["dests"], owner["keys"]["private"], owner["keys"]["public"])
    other = owner["pp"].keygen(str(owner["tmp"] / "other"))
    owner["dests"].write_text(json.dumps(DESTS.to_object()))
    with pytest.raises(ValueError, match="private half"):
        nf.sign_destinations(owner["dests"], other["private"], owner["keys"]["public"])
    assert not Path(str(owner["dests"]) + ".manifest.json").exists()


# ----------------------------------------------------------------------------- the first attach is gated too
class _Loader:
    """Stands in for `./loader`: records the argv and the environment it was run with."""
    def __init__(self, rc=0):
        self.calls, self.envs, self.rc = [], [], rc

    def __call__(self, argv, capture_output=True, text=True, env=None):
        self.calls.append(argv)
        self.envs.append(env)
        return subprocess.CompletedProcess(argv, self.rc, "OK: attached\n", "")


def _attach(s, loader, **kw):
    return nf.attach(s["out"], "lo", [s["keys"]["public"]], s["env"], s["state"], loader="./loader", run=loader, **kw)


def test_the_first_attach_runs_every_gate_then_hands_the_loader_the_verified_hash_and_the_names(signed):
    loader = _Loader()
    result = _attach(signed, loader)
    assert result["ok"] and result["version"] == 1 and len(loader.calls) == 1
    out = signed["out"]
    assert loader.calls[0] == ["./loader", str(out / "edge.ppt"), "netattach", "lo", str(out / "edge.names")]
    assert loader.envs[0]["PPT_NET_VERIFIED_SHA256"] == signed["edge"].ppt_sha256
    assert (Path(signed["state"]) / "active_version").read_text() == "1"
    rows = (Path(signed["state"]) / "net_swaps.log").read_text()
    assert '"attach"' in rows
    again = _attach(signed, _Loader())                                           # the floor is at 1: the same version is a replay
    assert not again["ok"] and any(r.startswith("version:not-monotonic") for r in again["reasons"])


def test_a_dry_run_attach_stops_before_the_loader(signed):
    loader = _Loader()
    result = _attach(signed, loader, dry_run=True)
    assert result["ok"] and result["dry_run"] and loader.calls == []
    assert not (Path(signed["state"]) / "active_version").exists()


@pytest.mark.parametrize("tamper, reason", [
    ("dests-edit", "dests:tampered"), ("dests-unsigned", "dests:unsigned"), ("dests-missing", "dests:unsigned"),
    ("dests-resigned-by-another", "dests:sig-invalid"), ("dests-swapped-for-another-signed-table", "destinations:not-the-flows"),
    ("table", "image:sha256-mismatch"), ("flow", "flow:sha256-not-signed"), ("names", "names:differ-from-flow")])
def test_an_attach_the_gates_refuse_never_reaches_the_loader(signed, tmp_path, tamper, reason):
    out, pp = signed["out"], signed["pp"]
    dests = out / nf.DEST_COPY
    if tamper == "dests-edit":
        carried = json.loads(dests.read_text())
        carried["allowed_host"]["docs.example.com"] = ["93.184.216.99"]
        dests.write_text(json.dumps(carried))
    elif tamper == "dests-unsigned":
        Path(str(dests) + ".manifest.sig").unlink()
    elif tamper == "dests-missing":
        for name in (nf.DEST_COPY, nf.DEST_COPY + ".manifest.json", nf.DEST_COPY + ".manifest.sig"):
            (out / name).unlink()
    elif tamper == "dests-resigned-by-another":
        other = pp.keygen(str(tmp_path / "other"))
        nf.sign_destinations(dests, other["private"], other["public"])
    elif tamper == "dests-swapped-for-another-signed-table":
        other_table = tmp_path / "other.json"
        other_table.write_text(json.dumps({**DESTS.to_object(), "allowed_host": {"docs.example.com": ["93.184.216.99"]}}))
        nf.sign_destinations(other_table, signed["keys"]["private"], signed["keys"]["public"])
        for suffix in ("", ".manifest.json", ".manifest.sig"):
            shutil.copyfile(str(other_table) + suffix, str(dests) + suffix)
    elif tamper == "table":
        ppt = bytearray((out / "edge.ppt").read_bytes()); ppt[-1] ^= 1
        (out / "edge.ppt").write_bytes(bytes(ppt))
    elif tamper == "flow":
        (out / "edge.flow.md").write_text((out / "edge.flow.md").read_text().replace("Passes.", "Passes!"))
    else:
        (out / "edge.names").write_text("edge\nallow\npass\nblock\n")
    loader = _Loader()
    result = _attach(signed, loader)
    assert not result["ok"] and loader.calls == []
    assert reason in result["reasons"], result["reasons"]
    assert not (Path(signed["state"]) / "active_version").exists()


def test_a_swap_through_net_swap_checks_the_carried_destination_table_too(signed):
    check = nf.edge_check(signed["out"], [signed["keys"]["public"]])
    good = (signed["out"] / "edge.ppt").read_bytes()
    assert check(good) == []
    assert check(good + b"x") == ["edge:not-the-directorys-table"]
    Path(str(signed["out"] / nf.DEST_COPY) + ".manifest.sig").unlink()
    assert "dests:unsigned" in check(good)
    loader = _Loader()
    result = nf.net_swap.preload_swap(str(signed["out"] / "edge.ppt"), "lo", [signed["keys"]["public"]], signed["env"],
                                      signed["state"], run=loader, extra_checks=[check])
    assert not result["ok"] and loader.calls == [] and "dests:unsigned" in result["reasons"]


def test_net_swap_on_the_command_line_attaches_an_edge_only_with_its_signed_destination_table(signed, tmp_path, capsys):
    fake = tmp_path / "loader"
    fake.write_text("#!/bin/sh\necho \"$PPT_NET_VERIFIED_SHA256 $*\"\n")
    fake.chmod(0o755)
    args = [str(signed["out"] / "edge.ppt"), "lo", "--pub", signed["keys"]["public"], "--envelope", signed["env"],
            "--state", signed["state"], "--loader", str(fake), "--attach", "--edge", str(signed["out"]),
            "--names", str(signed["out"] / "edge.names")]
    Path(str(signed["out"] / nf.DEST_COPY) + ".manifest.sig").unlink()
    assert nf.net_swap.main(args) == 1 and "dests:unsigned" in capsys.readouterr().out
    assert not (Path(signed["state"]) / "active_version").exists()


# ----------------------------------------------------------------------- the loader refuses an unverified table
LOADER = _ebpf / "loader"


@pytest.mark.skipif(not LOADER.exists(), reason="loader not built (make -C prismpath-ebpf)")
def test_the_loaders_own_gate_refuses_a_table_that_is_not_the_one_the_host_verified(signed):
    table = str(signed["out"] / "edge.ppt")
    run = lambda env: subprocess.run([str(LOADER), table, "netverify"], capture_output=True, text=True, cwd=_ebpf,
                                     env={k: v for k, v in {**os.environ, **env}.items() if v is not None})
    clean = {"PPT_NET_VERIFIED_SHA256": None, "PPT_NET_ALLOW_UNVERIFIED": None}
    assert run(clean).returncode == 2 and "no verified table" in run(clean).stderr                  # a bare invocation
    wrong = run({**clean, "PPT_NET_VERIFIED_SHA256": "0" * 64})
    assert wrong.returncode == 2 and "is not the verified table" in wrong.stderr                    # some other table
    assert run({**clean, "PPT_NET_VERIFIED_SHA256": signed["edge"].ppt_sha256}).returncode == 0     # the one verified
    bypass = run({**clean, "PPT_NET_ALLOW_UNVERIFIED": "1"})
    assert bypass.returncode == 0 and "UNVERIFIED" in bypass.stderr                                 # the operator's explicit bypass
