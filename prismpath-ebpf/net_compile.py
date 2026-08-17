#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Compile a network-triage flow to a PPT table with the CANONICAL packet-field schema pre-seeded, so
the compiled field indices line up with the fixed slots ppt_net.bpf.c fills from a real packet:

  0 src_ip  1 dst_ip  2 src_port  3 dst_port  4 protocol  5 pkt_len  6 tcp_flags  7 ttl

Emits <out.ppt> + a node-name sidecar (index order). Usage: net_compile.py <flow.md> <out.ppt> <out.names>
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "prismpath-hw"))
sys.path.insert(0, str(REPO))
import ppt_compile as pc                                  # noqa: E402
from prismpath.parser import parse_file                  # noqa: E402
from prismpath.analysis import _reachable                # noqa: E402
from prismpath import predicates                         # noqa: E402

SCHEMA = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "pkt_len", "tcp_flags", "ttl"]


def compile_with_schema(graph, schema, max_steps=25):
    """compile_flow, but with the field map pre-seeded to `schema` so indices are fixed by ABI."""
    img = pc.TableImage(max_steps)
    for i, name in enumerate(schema):
        img.fields[name] = i                              # pin canonical slots 0..N-1
    reach = _reachable(graph)
    names = [n for n in graph.nodes if n in reach]
    idx = {n: i for i, n in enumerate(names)}
    if graph.start not in idx:
        raise pc.SubsetError("bad-start", graph.start)
    for name in names:
        nedges = []
        for target, cond in graph.nodes[name].edges:
            if predicates.is_error(cond) or predicates.is_event(cond):
                continue
            if predicates.is_semantic(cond):
                raise pc.SubsetError("semantic-edge", cond)
            if target not in idx:
                raise pc.SubsetError("dangling-target", target)
            nedges.append((idx[target], cond, img.compile_condition(cond)))
        img.nodes.append((name, nedges))
    img.start = idx[graph.start]
    return img


def main():
    flow_md, out_ppt, out_names = (Path(a) for a in sys.argv[1:4])
    g = parse_file(str(flow_md))
    img = compile_with_schema(g, SCHEMA)
    names = [n for n, _ in img.nodes]
    out_ppt.write_bytes(img.serialize())
    out_names.write_text("\n".join(names) + "\n")
    # sanity: every referenced field must be within the canonical schema (else it silently reads NONE)
    used = sorted(img.fields.items(), key=lambda kv: kv[1])
    off_schema = [n for n, i in used if i >= len(SCHEMA)]
    print(f"flow={flow_md.name}  nodes={names}")
    print(f"fields (name->slot): {dict(used)}")
    if off_schema:
        print(f"  WARNING: fields not in the packet schema (will read NONE in-kernel): {off_schema}")
    print(f"start slot: {img.start} ({names[img.start]})")
    print(f"wrote {out_ppt} + {out_names}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
