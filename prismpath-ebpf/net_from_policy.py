#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Compile the network edge from the signed agent policy: one image, the hook, the sandbox, the proxy and the XDP table.

`project(image, destinations)` reads the connect half of a signed agent image and writes the table
`ppt_net.bpf.c` loads. It decides nothing itself. The reading domain of a connect is finite (the classifier gives a
connect `net_dest` of `model_api`, `allowed_host`, `other` or `unknown` and every other field its default), each
reading is decided through the reference (`Policy.decide`, which is `prismpath.kernel.core_reference`), and the table
passes only what the egress proxy would pass: a class the image allows and the compiled agent profile's `net` state
covers (`egress_policy.PROXY_CLASSES`). The differential in prismpath/tests/test_net_from_policy.py holds the table, run
through the userspace C evaluator, to the Lean oracle over every packet of a corpus.

What the XDP layer can see. It reads an Ethernet frame, and for IPv4 TCP and UDP the source and destination address, the
destination port, the protocol, the packet length, the TCP flags and the TTL (ppt_net.bpf.c). It cannot see a host
name. A connect reading holds a class, and the class comes from a name, so the edge needs a bridge: the DESTINATION
TABLE, the owner's list of the hosts of each class with the IPv4 addresses each is reached at (`Destinations`). The
table is a snapshot the owner resolves, and it is signed into the edge with the image.

  * A name that resolves to several addresses gets all of them in the table, up to 16 a host. They are allowed
    together, because a client may be handed any of them.
  * An address named by hosts of different decisions (a CDN address shared by an allowed host and a refused one) is
    DROPPED, and the compile report names it. The packet does not say which name the client asked for, so the edge
    allows an address only when every name the table gives it is allowed.
  * A name that changes address is not followed. The table is exact; a packet to an address it does not list is
    dropped until the owner resolves again and compiles and signs a new table (a signed version, monotonic, swapped
    atomically by net_swap.py). The edge fails closed on a moved name and never opens on its own.
  * Only port 443 is ever passed, the one port the classifier gives `model_api` and `allowed_host`, and only TCP.
    `other` and `unknown` are never passed even when the image allows them, as the proxy refuses them (`profile-net`).

Scope. The program passes a packet it does not govern. With `sources` given, only packets from those IPv4 addresses are
decided and every other source (the household) passes untouched; with none, every packet is decided. IPv6, ARP, a
VLAN tagged frame, a frame with a short IPv4 header and any non IPv4 ethertype PASS in the program and are not decided
here, so the owner keeps IPv6 off the governed segment or filters it elsewhere. A packet source is an address, not an
identity, so a host that sets another host's address is read as that host.

The table. Four nodes in a fixed order, `edge allow pass drop`, so the `drop` node is index 3 whichever policy compiled
it and the loader's drop mask (derived from the names file, carried across `netupdate`) never moves:

    edge: pass when src_ip is not a governed source; allow when TCP, port 443 and dst_ip in the allowed set; else drop

An address constant is the s32 bit pattern the front end puts in the register (`address_constant`), so an address at or
above 128.0.0.0 is a negative constant that net_compile would refuse in a hand written flow (`bit_pattern_constants`).
An ordering on an address is still refused. Only equality and membership are used on addresses.

The signed table. The compile writes the table, the names sidecar, the flow it was compiled from and a summary. The
flow names the SHA-256 of the source image and of the destination table and the governed sources, and `policy_pack`
signs the table with the flow's own SHA-256 (`flow_sha256`) and the flow's field dictionary in the manifest, so the
signature covers the image hash by way of the flow. `verify` is the dry run: the pack signature, the envelope and the
version floor through `net_swap.preload_swap(dry_run=True)`, then the flow against the manifest, the table recompiled
from the flow byte for byte, the names file against the flow, optionally the whole projection recompiled from the image
and destination table, and the loader's own parser (`ppt_image.c`, through `formal/diff/ebpf_batch.c`). It loads nothing.

    net_from_policy.py compile IMAGE DESTS OUT_DIR [--source IPV4 ...]
    net_from_policy.py sign OUT_DIR --priv KEY --pub KEY --envelope-id ID --version N
    net_from_policy.py verify OUT_DIR --pub KEY [--envelope BASE] [--state DIR] [--image IMAGE --dests DESTS]
    net_from_policy.py resolve HOST [HOST ...]       # the owner's one lookup, prints addresses (needs a network)
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
for extra in (REPO, REPO / "prismpath-hw", HERE):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import net_compile  # noqa: E402
import net_swap  # noqa: E402
from ebpf_table_limits import table_refusals  # noqa: E402
from prismpath.agent import classifier  # noqa: E402
from prismpath.agent.egress_policy import PROXY_CLASSES  # noqa: E402
from prismpath.agent.policy import Policy  # noqa: E402
from prismpath.agent.profile import ProfileError, compile_profile  # noqa: E402
from prismpath.hotswap import policy_pack as pp  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402
from prismpath.kernel.parser import parse  # noqa: E402

DEST_FORMAT = "prismpath.net_dests/1"
EDGE_PORT = classifier.MODEL_API_PORT
TCP = 6
MAX_ADDRESSES_PER_HOST = 16
NODE_NAMES = ("edge", "allow", "pass", "drop")
DROP_NODES = ("drop", "block")                    # the loader's drop mask names (loader.c config_set_drop_mask)
CLASSES = ("model_api", "allowed_host")
ABSENT, INT = 0, 2                                # TY_NONE, TY_INT of ppt_common.h
FLOW_FIELDS = {"src_ip": "int min=-2147483648 max=2147483647", "dst_ip": "int min=-2147483648 max=2147483647",
               "dst_port": "int min=0 max=65535", "protocol": "int min=0 max=255"}
SOURCE_LINE = re.compile(r"Source image sha256 ([0-9a-f]{64})\. Destinations sha256 ([0-9a-f]{64})\.")


class DestinationError(ValueError):
    """The destination table is not one the edge can use."""


class ProjectionError(Exception):
    """The image or the table cannot be projected onto an edge; the caller loads nothing."""


# ------------------------------------------------------------------------------------- addresses
def address_constant(address: int) -> int:
    """The value `ppt_net.bpf.c` holds for an address: its u32 bit pattern read as an s32."""
    return address - (1 << 32) if address >= (1 << 31) else address


def address_text(address: int) -> str:
    return str(ipaddress.IPv4Address(address))


def parse_address(text: str) -> int:
    """An IPv4 dotted quad as a u32. Refuses what no destination or source should be: the unspecified and
    `this network` range, loopback, link local (a cloud metadata address lives there), multicast and the reserved
    range that holds the broadcast address."""
    try:
        parsed = ipaddress.IPv4Address(text)
    except ValueError as error:
        raise DestinationError(f"{text!r} is not an IPv4 dotted quad: {error}") from None
    if parsed.packed[0] == 0 or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
        raise DestinationError(f"{text} is not an address the edge will name (this network, loopback, link local, "
                               f"multicast or reserved)")
    return int(parsed)


# ------------------------------------------------------------------------------ the destination table
@dataclass(frozen=True)
class Destinations:
    """The owner's hosts of each class and the IPv4 addresses each is reached at."""
    model_api: Dict[str, Tuple[int, ...]] = field(default_factory=dict)
    allowed_host: Dict[str, Tuple[int, ...]] = field(default_factory=dict)

    @classmethod
    def from_object(cls, obj) -> "Destinations":
        if not isinstance(obj, dict) or obj.get("format") != DEST_FORMAT or set(obj) - {"format", *CLASSES}:
            raise DestinationError(f"a destination table is an object of format {DEST_FORMAT} with `model_api` and "
                                   f"`allowed_host` maps of host to a list of addresses")
        tables: Dict[str, Dict[str, Tuple[int, ...]]] = {}
        for name in CLASSES:
            hosts = obj.get(name, {})
            if not isinstance(hosts, dict):
                raise DestinationError(f"`{name}` is not a map of host to addresses")
            tables[name] = {}
            for host, addresses in hosts.items():
                if not classifier.host_ok(host) or host.split(".")[-1][0].isdigit():
                    raise DestinationError(f"{host!r} is not a lower case host name the classifier reads (an IP literal "
                                           f"is not a name)")
                if name == "model_api" and host not in classifier.MODEL_API:
                    raise DestinationError(f"{host!r} is not a model API host of the classifier {classifier.MODEL_API}")
                if name == "allowed_host" and host in classifier.MODEL_API:
                    raise DestinationError(f"{host!r} is a model API host, so the classifier reads it as model_api")
                if not isinstance(addresses, list) or not addresses or not all(isinstance(a, str) for a in addresses):
                    raise DestinationError(f"{host!r} needs a non empty list of address strings")
                resolved = tuple(sorted({parse_address(a) for a in addresses}))
                if len(resolved) > MAX_ADDRESSES_PER_HOST:
                    raise DestinationError(f"{host!r} has {len(resolved)} addresses, past the {MAX_ADDRESSES_PER_HOST} "
                                           f"the edge takes for one name")
                tables[name][host] = resolved
        both = set(tables["model_api"]) & set(tables["allowed_host"])
        if both:
            raise DestinationError(f"{sorted(both)} listed under both classes")
        return cls(**tables)

    @classmethod
    def load(cls, path) -> "Destinations":
        try:
            return cls.from_object(json.loads(Path(path).read_text(encoding="utf-8")))
        except json.JSONDecodeError as error:
            raise DestinationError(f"{path} is not JSON: {error}") from None

    def to_object(self) -> dict:
        obj: dict = {"format": DEST_FORMAT}
        for name in CLASSES:
            obj[name] = {host: [address_text(a) for a in addresses] for host, addresses in sorted(getattr(self, name).items())}
        return obj

    def canonical(self) -> bytes:
        return canon2.dumps(self.to_object())

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()

    def allowed_hosts(self) -> Tuple[str, ...]:
        """The hosts the launcher must be given as `Config.allowed_hosts` so the classifier reads them `allowed_host`."""
        return tuple(sorted(self.allowed_host))

    def named_at(self, address: int) -> List[Tuple[str, str]]:
        """(host, class) of every name the table gives an address."""
        return [(host, name) for name in CLASSES for host, addresses in sorted(getattr(self, name).items())
                if address in addresses]

    def addresses(self) -> List[int]:
        return sorted({a for name in CLASSES for addresses in getattr(self, name).values() for a in addresses})


def resolve(hosts: Iterable[str], lookup: Callable[[str], Iterable[str]] = None) -> Dict[str, List[str]]:
    """The IPv4 addresses of each host, sorted and without duplicates. `lookup` defaults to the system resolver; the
    owner runs this once when writing the table, and a host that gives none is an error, never an empty entry."""
    def system(host: str) -> Iterable[str]:
        return [info[4][0] for info in socket.getaddrinfo(host, EDGE_PORT, socket.AF_INET, socket.SOCK_STREAM)]
    lookup = lookup or system
    found: Dict[str, List[str]] = {}
    for host in hosts:
        addresses = sorted({a for a in lookup(host) if ":" not in a}, key=lambda a: int(ipaddress.IPv4Address(a)))
        if not addresses:
            raise DestinationError(f"{host!r} resolved to no IPv4 address")
        found[host] = addresses
    return found


# ------------------------------------------------------------------------------------ the allow set
def image_sha256(image) -> str:
    """The SHA-256 of the signed image as the policy holds it (the canon/2 bytes, no trailing line feed), the hash a
    receipt and `prismpath agent verify` name."""
    return hashlib.sha256(image.image if isinstance(image, Policy) else Policy(image).image).hexdigest()


def connect_allows(policy: Policy) -> Dict[str, bool]:
    """Which `net_dest` classes the image allows a connect of, each produced connect reading decided through the
    reference. A decision other than `allow` is a refusal at the proxy (nobody is there to answer an escalation)."""
    for name in ("tool", "net_dest"):
        if name not in policy.doc["fields"]:
            raise ProjectionError(f"the image does not define {name!r}, so its connect allow set cannot be projected")
    config = classifier.Config.for_workspace(Path("/nonexistent-workspace"), allowed_hosts=("allowed.example",))
    calls = {"model_api": (classifier.MODEL_API[0], EDGE_PORT), "allowed_host": ("allowed.example", EDGE_PORT),
             "other": ("other.example", EDGE_PORT), "unknown": ("other.example", 0)}
    allows = {}
    for name, (host, port) in calls.items():
        reading = classifier.classify({"tool": "connect", "args": {"host": host, "port": port}}, config)
        assert reading["net_dest"] == name, (name, reading["net_dest"])
        allows[name] = policy.decide(policy.reading_bytes(reading)).kind == "allow"
    return allows


def passed_classes(policy: Policy) -> Tuple[str, ...]:
    """The classes the edge passes: allowed by the image and covered by the agent profile's proxy state, exactly the
    gate's test (`PolicyGate.__call__`)."""
    try:
        profile = compile_profile(policy, "agent")
    except ProfileError as error:
        raise ProjectionError(f"the image cannot be projected onto an agent profile: {error}") from None
    allows = connect_allows(policy)
    return tuple(name for name in CLASSES if allows[name] and name in PROXY_CLASSES[profile.net])


# ---------------------------------------------------------------------------------------- the edge
@dataclass(frozen=True)
class Edge:
    ppt: bytes
    names: Tuple[str, ...]
    flow: str
    source_image_sha256: str
    destinations_sha256: str
    sources: Tuple[int, ...]
    allowed: Tuple[int, ...]               # the addresses passed on TCP 443
    report: dict

    @property
    def ppt_sha256(self) -> str:
        return hashlib.sha256(self.ppt).hexdigest()

    def names_text(self) -> str:
        return "\n".join(self.names) + "\n"


def _flow(image_sha: str, dests_sha: str, sources: Sequence[int], allowed: Sequence[int]) -> str:
    def members(addresses):
        return ", ".join(str(address_constant(a)) for a in addresses)
    scope = f"src_ip not in [{members(sources)}]" if sources else "never"
    allow = f"protocol == {TCP} and dst_port == {EDGE_PORT} and dst_ip in [{members(allowed)}]" if allowed else "never"
    fields = "\n".join(f"field.{name}: {text}" for name, text in FLOW_FIELDS.items())
    governed = ", ".join(address_text(a) for a in sources) if sources else "every source"
    return f"""---
name: net_edge
start: edge
{fields}
---
## edge
The network edge compiled from one signed agent policy. Source image sha256 {image_sha}. Destinations sha256 {dests_sha}.
Governed: {governed}. Only TCP to port {EDGE_PORT} at an address of the destination table is passed, and every other
packet of a governed source is dropped.
-> pass: when {scope}
-> allow: when {allow}
-> drop: else
## allow
A governed source reaching an allowed destination. Passes.
## pass
A source the edge does not govern. Passes.
## drop
Everything else of a governed source. The loader maps this reserved node name to XDP_DROP.
"""


def compile_flow(flow: str) -> Tuple[bytes, Tuple[str, ...]]:
    """The table and node names of an edge flow, compiled against the canonical packet schema and checked against the
    evaluator's limits. The names are in index order, and the edge flow's order is fixed (`NODE_NAMES`)."""
    graph = parse(flow)
    image = net_compile.compile_with_schema(graph, net_compile.SCHEMA)
    names = tuple(name for name, _ in image.nodes)
    if names != NODE_NAMES:
        raise ProjectionError(f"the edge flow compiled to nodes {names}, not {NODE_NAMES}")
    for field_name, reason in net_compile.address_refusals(image, bit_pattern_constants=True):
        raise ProjectionError(f"the kernel front end cannot decide an atom on {field_name}: {reason}")
    off_schema = [name for name, slot in image.fields.items() if slot >= len(net_compile.SCHEMA)]
    if off_schema:
        raise ProjectionError(f"the edge reads fields outside the packet schema: {off_schema}")
    table = image.serialize()
    refusals = table_refusals(table)
    if refusals:
        raise ProjectionError("the evaluator cannot run the table: " + "; ".join(refusals))
    return table, names


def project(image, destinations: Destinations, sources: Sequence[str] = ()) -> Edge:
    """The edge of a signed agent image, a destination table and the governed sources. Raises ProjectionError when
    the image allows a class the table gives no host for (the edge would drop what the policy allows, silently),
    or the table is past what the evaluator holds."""
    policy = image if isinstance(image, Policy) else Policy(image)
    passed = passed_classes(policy)
    for name in passed:
        if not getattr(destinations, name):
            raise ProjectionError(f"the image allows {name} connections and the destination table lists no {name} host, "
                                  f"so the edge could not pass any")
    governed = tuple(sorted({parse_address(text) for text in sources}))
    allowed, ambiguous = [], []
    for address in destinations.addresses():
        named = destinations.named_at(address)
        verdicts = {cls in passed for _host, cls in named}
        if verdicts == {True}:
            allowed.append(address)
        elif verdicts == {True, False}:
            ambiguous.append({"address": address_text(address), "names": [{"host": h, "class": c, "passed": c in passed}
                                                                         for h, c in named]})
    image_sha, dests_sha = image_sha256(policy), destinations.sha256()
    flow = _flow(image_sha, dests_sha, governed, allowed)
    table, names = compile_flow(flow)
    report = {"classes_passed": list(passed), "allowed_addresses": [address_text(a) for a in allowed],
              "refused_by_policy": [{"host": h, "class": n} for n in CLASSES for h in sorted(getattr(destinations, n))
                                    if n not in passed],
              "ambiguous_addresses_dropped": ambiguous, "governed_sources": [address_text(a) for a in governed],
              "port": EDGE_PORT, "protocol": TCP}
    return Edge(table, names, flow, image_sha, dests_sha, governed, tuple(allowed), report)


def write_edge(out_dir, edge: Edge) -> Dict[str, str]:
    """Write `edge.ppt`, `edge.names`, `edge.flow.md` and `edge.json` (the summary). Nothing is signed here."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "edge.ppt").write_bytes(edge.ppt)
    (out / "edge.names").write_text(edge.names_text())
    (out / "edge.flow.md").write_text(edge.flow, encoding="utf-8")
    summary = {"format": "prismpath.net_edge/1", "ppt_sha256": edge.ppt_sha256, "source_image_sha256": edge.source_image_sha256,
               "destinations_sha256": edge.destinations_sha256, "report": edge.report}
    (out / "edge.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return {name: str(out / name) for name in ("edge.ppt", "edge.names", "edge.flow.md", "edge.json")}


def sign(out_dir, priv_path: str, pub_path: str, envelope_id: str, version: int, envelope_dir: Optional[str] = None) -> dict:
    """Sign `edge.ppt` with its flow (`policy_pack.build_pack`: manifest, `flow_sha256` and the field dictionary) and,
    when `envelope_dir` is given, the matching envelope. The owner's authority key signs both."""
    out = Path(out_dir)
    flow = (out / "edge.flow.md").read_text(encoding="utf-8")
    manifest = pp.build_pack(str(out / "edge.ppt"), {}, version, envelope_id, priv_path, pub_path, flow_text=flow)
    if envelope_dir:
        pp.build_envelope(envelope_id, pp.field_dictionary_of(flow), None, priv_path, pub_path, envelope_dir)
    return manifest


# -------------------------------------------------------------------------- the userspace C evaluator
def _sources() -> List[Path]:
    return [REPO / "formal" / "diff" / "ebpf_batch.c", HERE / "ppt_image.c", HERE / "ppt_eval_bpf.h",
            HERE / "ppt_common.h", HERE / "ppt_image.h"]


def build_evaluator(out_dir) -> Path:
    """`formal/diff/ebpf_batch.c` compiled against the in-kernel evaluator's own text and the loader's parser, named by
    a digest of its sources so a stale binary is never used. It is the userspace path: no verifier, no JIT, no kernel."""
    cc = shutil.which("cc")
    if not cc:
        raise RuntimeError("no C compiler (cc) to build the evaluator")
    digest = hashlib.sha256(b"".join(path.read_bytes() for path in _sources())).hexdigest()[:16]
    binary = Path(out_dir) / f"ebpf_batch-{digest}"
    if not binary.exists():
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        subprocess.run([cc, "-O2", "-std=gnu11", "-Wno-unknown-pragmas", "-I", str(HERE), "-o", str(binary),
                        str(REPO / "formal" / "diff" / "ebpf_batch.c"), str(HERE / "ppt_image.c")], check=True)
    return binary


def front_end(raw: bytes) -> Optional[Dict[str, int]]:
    """The reading `ppt_net.bpf.c` builds from a frame, or None where the program passes the frame undecided: not IPv4,
    a frame shorter than an Ethernet and a minimal IPv4 header, or an IPv4 header length below 20. The rest is
    `net_cert.canonical_reading`, written independently of the C from the header layouts."""
    import net_cert
    if len(raw) < 14 + 20 or struct.unpack_from("!H", raw, 12)[0] != 0x0800 or (raw[14] & 0x0F) * 4 < 20:
        return None
    return net_cert.canonical_reading(raw)


def registers(table: bytes, reading: Dict[str, int]) -> bytes:
    """A register file as ebpf_batch reads one: the start node, then (type, value) per schema slot. An address is its
    u32 bit pattern as an s32, a field the packet does not carry is absent."""
    start = struct.unpack_from("<H", table, 18)[0]
    out = struct.pack("<i", start)
    for name in net_compile.SCHEMA:
        if name in reading:
            value = reading[name]
            out += struct.pack("<ii", INT, address_constant(value) if name in net_compile.ADDRESS_FIELDS else value)
        else:
            out += struct.pack("<ii", ABSENT, 0)
    return out


def drop_mask_nodes(names: Sequence[str]) -> List[int]:
    """The node indices the loader's drop mask holds: a node named `drop` or `block`, within the first 64."""
    return [index for index, name in enumerate(names[:64]) if name in DROP_NODES]


def parser_accepts(binary: Path, table: bytes) -> None:
    """Raise ProjectionError unless the loader's own parser (`parse_image_buf`: magic, version, length, the map
    capacities and the evaluator's stack and program limits) admits the table. One all absent register file probes it."""
    probe = struct.pack("<i", 0) + struct.pack("<ii", ABSENT, 0) * len(net_compile.SCHEMA)
    data = b"case 0 1\n%d\n" % len(table) + table + b"\n" + b"%d\n" % len(probe) + probe + b"\n"
    done = subprocess.run([str(binary)], input=data, capture_output=True, check=True)
    if b"e limits" in done.stdout:
        raise ProjectionError(f"the loader's parser refused the table: {done.stderr.decode()[-300:]}")


def decide_frames(binary: Path, table: bytes, names: Sequence[str], frames: Sequence[bytes]) -> List[str]:
    """What `ppt_net_prog` does with each frame, by the evaluator's own text: `allow` (the allow node, XDP_PASS),
    `pass` (the pass node, XDP_PASS), `drop` (XDP_DROP), `unseen` (the program passes the frame before it reads a
    reading) or `nomatch` (the evaluator matched no edge, which the program passes). Raises when the loader's parser
    refuses the table."""
    parser_accepts(binary, table)
    cases, order = [], []
    for raw in frames:
        reading = front_end(raw)
        order.append(reading is not None)
        if reading is not None:
            cases.append(registers(table, reading))
    data = b"case 0 %d\n%d\n" % (len(cases), len(table)) + table + b"\n"
    data += b"".join(b"%d\n" % len(regs) + regs + b"\n" for regs in cases)
    done = subprocess.run([str(binary)], input=data, capture_output=True, check=True)
    line = done.stdout.decode().strip()
    rows = line.split(" ", 1)[1].split(";") if " " in line else []
    if len(rows) != len(cases) or any(row.startswith("e") for row in rows):
        raise ProjectionError(f"the loader's parser or the evaluator refused the table: {line} {done.stderr.decode()[-300:]}")
    masked = set(drop_mask_nodes(names))
    results, answers = [], iter(rows)
    for seen in order:
        if not seen:
            results.append("unseen")
            continue
        row = next(answers).split()
        if row[0] != "m":
            results.append("nomatch")
            continue
        target = int(row[2])
        results.append("drop" if target in masked else names[target])
    return results


# ------------------------------------------------------------------------------------ the dry run
def parse_flow_header(flow: str) -> Optional[Tuple[str, str]]:
    found = SOURCE_LINE.search(flow)
    return (found.group(1), found.group(2)) if found else None


def verify(out_dir, pubkeys: Sequence[str], envelope_base: Optional[str] = None, state_dir: Optional[str] = None,
           image: Optional[bytes] = None, destinations: Optional[Destinations] = None,
           evaluator: Optional[Path] = None, allow_unsigned: bool = False) -> dict:
    """Validate an edge directory without loading it: nothing here calls the loader or the kernel.

    1. the signed pack, the envelope and the version floor, by `net_swap.preload_swap(dry_run=True)`;
    2. the flow against the manifest's `flow_sha256`, the table recompiled from the flow (it must be byte for byte
       the signed table), the names file against the nodes, and the flow's source image hash against `image`;
    3. with `image` and `destinations`, the whole projection recompiled and compared;
    4. the loader's own parser (`ppt_image.c`) on the table, through the evaluator.
    Returns {"ok", "reasons", ...}; a reason is a short code."""
    out = Path(out_dir)
    ppt_path, reasons, info = out / "edge.ppt", [], {}
    try:
        table, flow = ppt_path.read_bytes(), (out / "edge.flow.md").read_text(encoding="utf-8")
        names_text = (out / "edge.names").read_text()
    except OSError as error:
        return {"ok": False, "reasons": [f"edge:unreadable:{error.errno}"]}
    if state_dir is None:
        import tempfile
        state_dir = tempfile.mkdtemp(prefix="net-edge-dry-run-")
    try:
        gate = net_swap.preload_swap(str(ppt_path), "dry-run", list(pubkeys), envelope_base, state_dir,
                                     allow_unsigned=allow_unsigned, dry_run=True)
    except RuntimeError as error:                       # no `cryptography`: loud absence
        return {"ok": False, "reasons": [f"signing:unavailable:{error}"]}
    if not gate["ok"]:
        reasons.extend(gate["reasons"])
    else:
        info.update({"version": gate.get("version"), "unsigned": gate.get("unsigned")})
    if not allow_unsigned:
        manifest = _manifest(ppt_path)
        if manifest is None or manifest.get("flow_sha256") != pp.sha256_hex(flow.encode("utf-8")):
            reasons.append("flow:sha256-not-signed")
    try:
        recompiled, names = compile_flow(flow)
    except Exception as error:                          # noqa: BLE001 - any failure to rebuild is a refusal
        reasons.append(f"flow:does-not-compile:{type(error).__name__}")
        recompiled, names = None, ()
    if recompiled is not None and recompiled != table:
        reasons.append("table:differs-from-flow")
    if names and names_text.split() != list(names):
        reasons.append("names:differ-from-flow")
    header = parse_flow_header(flow)
    if header is None:
        reasons.append("flow:no-source-hash")
    else:
        info["source_image_sha256"], info["destinations_sha256"] = header
        if image is not None and image_sha256(image) != header[0]:
            reasons.append("image:not-the-source")
        if destinations is not None and destinations.sha256() != header[1]:
            reasons.append("destinations:not-the-source")
    if image is not None and destinations is not None and not reasons:
        sources = [address_text(a) for a in _flow_sources(flow)]
        try:
            again = project(image, destinations, sources)
        except (ProjectionError, DestinationError) as error:
            reasons.append(f"projection:{type(error).__name__}")
        else:
            if again.ppt != table:
                reasons.append("table:not-the-projection-of-the-image")
    try:
        binary = evaluator or build_evaluator(Path(state_dir) / "build")
        parser_accepts(binary, table)
    except (ProjectionError, RuntimeError, subprocess.CalledProcessError) as error:
        reasons.append(f"loader-parser:{error}"[:200])
    info.update({"ok": not reasons, "reasons": reasons, "dry_run": True, "ppt_sha256": hashlib.sha256(table).hexdigest()})
    return info


def _manifest(ppt_path: Path) -> Optional[dict]:
    try:
        return canon2.loads(Path(str(ppt_path) + ".manifest.json").read_bytes().rstrip(b"\n"))
    except (OSError, ValueError):
        return None


def _flow_sources(flow: str) -> List[int]:
    found = re.search(r"-> pass: when src_ip not in \[([^\]]*)\]", flow)
    if not found:
        return []
    return sorted(int(value) % (1 << 32) for value in found.group(1).split(","))


# ------------------------------------------------------------------------------------------- the CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="verb", required=True)
    c = sub.add_parser("compile")
    c.add_argument("image")
    c.add_argument("dests")
    c.add_argument("out")
    c.add_argument("--source", action="append", default=[], help="a governed IPv4 source (repeat); none = every source")
    s = sub.add_parser("sign")
    s.add_argument("out")
    s.add_argument("--priv", required=True)
    s.add_argument("--pub", required=True)
    s.add_argument("--envelope-id", required=True)
    s.add_argument("--version", type=int, required=True)
    s.add_argument("--envelope-dir")
    v = sub.add_parser("verify")
    v.add_argument("out")
    v.add_argument("--pub", nargs="+", required=True)
    v.add_argument("--envelope")
    v.add_argument("--state")
    v.add_argument("--image")
    v.add_argument("--dests")
    r = sub.add_parser("resolve")
    r.add_argument("hosts", nargs="+")
    args = ap.parse_args(argv)
    try:
        if args.verb == "compile":
            edge = project(Path(args.image).read_bytes(), Destinations.load(args.dests), args.source)
            print(json.dumps({"written": write_edge(args.out, edge), "report": edge.report}, indent=1))
        elif args.verb == "sign":
            manifest = sign(args.out, args.priv, args.pub, args.envelope_id, args.version, args.envelope_dir)
            print(json.dumps({"image_sha256": manifest["image_sha256"], "flow_sha256": manifest["flow_sha256"],
                              "version": manifest["version"]}, indent=1))
        elif args.verb == "verify":
            image = Policy(Path(args.image).read_bytes()) if args.image else None
            dests = Destinations.load(args.dests) if args.dests else None
            result = verify(args.out, args.pub, args.envelope, args.state, image.image if image else None, dests)
            print(json.dumps(result, indent=1))
            return 0 if result["ok"] else 1
        else:
            print(json.dumps({"format": DEST_FORMAT, "resolved": resolve(args.hosts)}, indent=1))
    except (DestinationError, ProjectionError, ValueError, OSError) as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
