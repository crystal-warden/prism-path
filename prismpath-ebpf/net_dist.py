#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `xdp` target of policy distribution (docs/design/spec-policy-distribution.md, section 3): the host
preloader in front of the XDP loader, following a policy stream.

A release is its `policy.core`, its `net.dests` and its `net.edge`. The edge table is derived: it is the table
`net_from_policy.project` compiles from the policy's connect allow set and the destination table, for the
governed sources this edge is set up with. So the adapter's check at commit (V11, C2) compiles it again from the
staged `policy.core` and `net.dests` and holds the staged `net.edge` to it byte for byte, with the flow and names
hashes its envelope signs, and anything else is `dist:derived-mismatch`. The edge and the signer must name the
same governed sources, since they are part of what is compiled.

Whether a release allows more (W1) is the policy's comparison and the destination table's. A destination table
is larger than another when, for some set of classes the policy may pass, the edge it compiles to would allow an
address the other one does not (`compare_dests`). That holds the address set of section 9.4 to a subset, and
also catches the table that drops the one refused name of a shared address, which the edge then allows.

`activate` loads the committed table and `deactivate` loads the closed table, which drops every packet of a
governed source, so the edge never runs what the PEP refuses (X3). Both end in `net_swap.run_loader`, the one
loader call the older signed pack gate ends in too, with one audit event in a log signed by the PEP's instance
key. The machine has written its floor before either is called (C4). The adapter keeps which table the kernel
holds on which interface, so a restart that finds the table loaded calls no loader, the first load attaches the
program and every later one updates its maps. A loader that fails raises, so the commit is finished again when the
PEP next starts.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, FrozenSet, Iterable, Mapping, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
for extra in (REPO, HERE):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import net_from_policy as nf  # noqa: E402
import net_swap  # noqa: E402
from prismpath import canon  # noqa: E402
from prismpath.distribution import kinds, widening  # noqa: E402
from prismpath.distribution.adapters import CANNOT_DECIDE, LARGER, NOT_LARGER, Adapter  # noqa: E402
from prismpath.distribution.kinds import BAD_FORMAT, Refused  # noqa: E402

DERIVED_MISMATCH = "dist:derived-mismatch"
ZERO = "0" * 64
CLASS_SETS: Tuple[FrozenSet[str], ...] = (frozenset({"model_api"}), frozenset({"allowed_host"}),
                                          frozenset(nf.CLASSES))


class LoaderFailed(RuntimeError):
    """The loader did not take the table. The kernel still holds the table it held before."""


# ------------------------------------------------------------------ net.dests

def read_dests(body: bytes) -> "nf.Destinations":
    """`net.dests` (V11): a destination table the edge can use, in its canonical spelling, so one table is one body.
    `Refused` with `document:not-canonical` for canon/2 in another spelling and `dist:bad-format` otherwise."""
    doc = kinds.load_canonical(bytes(body), "net.dests")
    try:
        dests = nf.Destinations.from_object(doc)
    except nf.DestinationError as error:
        raise Refused(BAD_FORMAT, f"net.dests is not a table the edge can use ({error})") from None
    if dests.canonical() != bytes(body):
        raise Refused(BAD_FORMAT, "net.dests is not the table's canonical spelling")
    return dests


def allowed_under(dests: "nf.Destinations", classes: FrozenSet[str]) -> FrozenSet[int]:
    """The addresses an edge compiled from `dests` allows when the policy passes exactly `classes`: those every name
    the table gives them is of a class passed (`project`)."""
    return frozenset(address for address in dests.addresses()
                     if {cls for _host, cls in dests.named_at(address)} <= classes)


def compare_dests(active: bytes, staged: bytes) -> str:
    """W1 for `net.dests`: larger when, for some set of classes the policy may pass, the staged table lets the edge
    allow an address the active one does not. A table that does not read cannot be decided."""
    if bytes(active) == bytes(staged):
        return NOT_LARGER
    try:
        old, new = read_dests(active), read_dests(staged)
    except Refused:
        return CANNOT_DECIDE
    return NOT_LARGER if all(allowed_under(new, classes) <= allowed_under(old, classes)
                             for classes in CLASS_SETS) else LARGER


if "net.dests" not in widening.COMPARATORS:
    widening.register_comparator("net.dests", compare_dests)


# ------------------------------------------------------------------ net.edge

def compiled_edge(core: bytes, dests_body: bytes, sources: Sequence[str]) -> "nf.Edge":
    """The edge `net_from_policy.project` compiles from a `policy.core` body and a `net.dests` body for the governed
    `sources`. Raises `Refused`, `ProjectionError` or `DestinationError` when it does not compile."""
    return nf.project(bytes(core), read_dests(dests_body), list(sources))


def edge_meta(edge: "nf.Edge", qualification: str) -> dict:
    """The `meta` a `net.edge` envelope signs (section 3): the SHA-256 of the flow the table is compiled from and
    of its names file, and the qualification envelope id."""
    return {"flow_sha256": canon.sha256_hex(edge.flow.encode("utf-8")),
            "names_sha256": canon.sha256_hex(edge.names_text().encode("utf-8")), "qualification": qualification}


def derived_cause(staged: Mapping[str, Tuple[Any, bytes]], sources: Sequence[str]) -> Optional[str]:
    """V11 for a staged `net.edge` at commit: the table compiled again from the staged `policy.core` and `net.dests`
    must be its body, and the flow and names hashes its `meta` signs those of the compiled edge."""
    envelope, body = staged["net.edge"]
    try:
        edge = compiled_edge(staged["policy.core"][1], staged["net.dests"][1], sources)
    except (Refused, nf.ProjectionError, nf.DestinationError, ValueError):
        return DERIVED_MISMATCH
    meta = edge_meta(edge, envelope.meta.get("qualification", ""))
    if edge.ppt != bytes(body) or any(envelope.meta.get(name) != meta[name] for name in ("flow_sha256", "names_sha256")):
        return DERIVED_MISMATCH
    return None


def closed_table(sources: Sequence[str]) -> bytes:
    """The table a refusing edge loads: the edge flow with no allowed address, so every packet of a governed source
    is dropped and, with `sources` named, every other source passes as it always does."""
    governed = tuple(sorted({nf.parse_address(text) for text in sources}))
    return nf.compile_flow(nf._flow(ZERO, ZERO, governed, ()))[0]


# ------------------------------------------------------------------ the adapter

class EdgeAdapter(Adapter):
    """The adapter of one XDP edge on `iface`, its state under `<state_dir>/xdp/`. `sources` are the governed IPv4
    sources the edge is compiled for, none for every source. `loader` and `run` are the loader binary and how it is
    run, which a test injects. `instance_key` signs the edge's audit log."""
    kind = "xdp"

    def __init__(self, state_dir, iface: str, *, sources: Iterable[str] = (), loader: str = "./loader",
                 run: Callable = subprocess.run, instance_key=None):
        self.home = str(state_dir)
        self.iface = iface
        self.sources = tuple(sources)
        for text in self.sources:
            nf.parse_address(text)                     # a source the edge cannot name is refused before anything loads
        self.loader, self.run = loader, run
        self.dir = Path(state_dir) / "xdp"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.audit = net_swap.audit_log(str(self.dir), instance_key)
        self.running: Optional[str] = None

    def check(self, artifact: str, body: bytes, staged: Mapping[str, Tuple[Any, bytes]]) -> Optional[str]:
        if artifact == "net.edge":
            return derived_cause(staged, self.sources)
        return None

    def activate(self, release) -> None:
        self._load(release.bodies["net.edge"], "commit",
                   {"stream": release.stream, "seq": release.seq, "release": release.release,
                    "policy_sha256": release.policy_sha256})
        self.running = release.policy_sha256

    def deactivate(self, cause: str) -> None:
        self._load(closed_table(self.sources), "refuse", {"cause": cause})
        self.running = None

    def loaded(self) -> Optional[dict]:
        """What the kernel holds by this edge's last load: {iface, sha256}, or None before the first."""
        try:
            doc = json.loads((self.dir / "loaded.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return doc if isinstance(doc, dict) and set(doc) == {"iface", "sha256"} else None

    def _load(self, table: bytes, action: str, record: dict) -> None:
        sha256 = hashlib.sha256(table).hexdigest()
        held = self.loaded()
        if held == {"iface": self.iface, "sha256": sha256}:
            return                                     # a restart that finds the kernel already there
        verb = "netupdate" if held is not None and held["iface"] == self.iface else "netattach"
        names = self.dir / "edge.names"
        names.write_text("\n".join(nf.NODE_NAMES) + "\n")
        result = net_swap.run_loader(table, verb, self.iface, path=str(self.dir / "edge.ppt"), audit=self.audit,
                                     action=action, loader=self.loader, run=self.run, names_path=str(names),
                                     record=record)
        if not result["ok"]:
            raise LoaderFailed(f"the loader refused the {action} table: {result.get('loader_output', '')}")
        canon.atomic_write_bytes(str(self.dir / "loaded.json"),
                                 json.dumps({"iface": self.iface, "sha256": sha256}, sort_keys=True).encode())
