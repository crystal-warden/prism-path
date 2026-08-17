# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""cocotb testbench — certify the RTL interpreter against the frozen conformance corpus.

THE gate (plan: days 3-4). Mirrors run_vectors.py exactly — same subset filter, same
expectations — but the evaluator is rtl/ppt_interp.sv under simulation. The DUT is built
ONCE; every image is loaded at runtime through the load port, because the whole claim is
one fixed circuit, any conformant flow as data.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import ppt_compile as pc                                    # noqa: E402
from prismpath.parser import parse                          # noqa: E402

CONF = Path(pc._REPO) / "portable" / "conformance"   # pc._REPO is the package dir

MAX_FIELDS, MAX_ATOMS, MAX_NODES, MAX_EDGES, MAX_PROG = 16, 64, 16, 48, 256


def fits(img: pc.TableImage) -> bool:
    n_edges = sum(len(e) for _, e in img.nodes)
    n_prog = sum(len(p) for _, es in img.nodes for _, _, p in es)
    return (len(img.fields) <= MAX_FIELDS and len(img.atoms) <= MAX_ATOMS
            and len(img.nodes) <= MAX_NODES and n_edges <= MAX_EDGES
            and n_prog <= MAX_PROG)


async def tick(dut):
    await RisingEdge(dut.clk)


async def load_word(dut, sel: int, addr: int, data: int):
    dut.load_en.value = 1
    dut.load_sel.value = sel
    dut.load_addr.value = addr
    dut.load_data.value = data & 0xFFFFFFFF
    await tick(dut)
    dut.load_en.value = 0


async def load_image(dut, img: pc.TableImage):
    visits_idx = img.fields.get("visits", 0xFFFF)
    await load_word(dut, 0, 0, visits_idx)
    for i, (f, op, ty, val) in enumerate(img.atoms):
        await load_word(dut, 1, i, (ty << 24) | (op << 16) | f)
        await load_word(dut, 2, i, val & 0xFFFFFFFF)
    edges_flat = []
    prog_flat = []
    for ni, (_name, nedges) in enumerate(img.nodes):
        await load_word(dut, 3, ni, (len(nedges) << 16) | len(edges_flat))
        for tgt, _cond, prog in nedges:
            await load_word(dut, 4, len(edges_flat), (len(prog_flat) << 16) | tgt)
            await load_word(dut, 5, len(edges_flat), len(prog))
            edges_flat.append(tgt)
            for w in prog:
                await load_word(dut, 6, len(prog_flat), w)
                prog_flat.append(w)


async def write_fields(dut, img: pc.TableImage, ctx: dict, intern: dict):
    for name, idx in sorted(img.fields.items(), key=lambda kv: kv[1]):
        ty, val = pc.encode_scalar(ctx.get(name), intern)
        dut.fld_we.value = 1
        dut.fld_idx.value = idx
        dut.fld_type.value = ty
        dut.fld_val.value = val & 0xFFFFFFFF
        await tick(dut)
    dut.fld_we.value = 0


async def evaluate(dut, node: int):
    dut.start.value = 1
    dut.node_idx.value = node
    await tick(dut)
    dut.start.value = 0
    for _ in range(4 * MAX_PROG + 8 * MAX_EDGES + 16):
        await tick(dut)
        if dut.done.value:
            if dut.match.value:
                return int(dut.match_edge.value), int(dut.target.value)
            return None
    raise TimeoutError("evaluate never pulsed done")


async def pulse_reset(dut):
    dut.rst.value = 1
    await tick(dut)
    await tick(dut)
    dut.rst.value = 0
    await tick(dut)


async def bump(dut, node: int):
    dut.bump_en.value = 1
    dut.bump_node.value = node
    await tick(dut)
    dut.bump_en.value = 0


def _init_inputs(dut):
    for name in ("load_en", "fld_we", "bump_en", "use_visits", "start"):
        getattr(dut, name).value = 0
    for name in ("load_sel", "load_addr", "load_data", "fld_idx", "fld_type",
                 "fld_val", "bump_node", "node_idx"):
        getattr(dut, name).value = 0


@cocotb.test()
async def conformance(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    _init_inputs(dut)
    await pulse_reset(dut)

    # ---------------------------------------------------------------- predicate vectors
    doc = json.loads((CONF / "predicates.json").read_text())
    passed = failed = excluded = oversize = 0
    failures = []
    img_cache: dict = {}
    loaded_cond = None
    for i, case in enumerate(doc["cases"]):
        cond, ctx, expect = case["cond"], case["ctx"], case["expect"]
        try:
            if cond not in img_cache:
                img_cache[cond] = pc.compile_predicate(cond)
            img = img_cache[cond]
            if not fits(img):
                oversize += 1
                continue
            intern = dict(img.intern)
            regs_ctx = {n: ctx.get(n) for n in img.fields}
            for v in regs_ctx.values():          # subset check, same as encode would do
                pc.encode_scalar(v, dict(intern))
        except pc.SubsetError:
            excluded += 1
            continue
        if loaded_cond != cond:
            await load_image(dut, img)
            loaded_cond = cond
        dut.use_visits.value = 0                 # eval mode: raw register file
        await write_fields(dut, img, ctx, dict(img.intern))
        got = (await evaluate(dut, 0)) is not None
        if got == expect:
            passed += 1
        else:
            failed += 1
            failures.append((i, cond, ctx, expect, got))

    dut._log.info(f"predicates: pass {passed} fail {failed} "
                  f"excluded {excluded} oversize {oversize}")
    for f in failures[:10]:
        dut._log.error(f"  ✗ {f}")
    assert failed == 0, f"{failed} predicate vectors diverged"
    assert oversize == 0, f"{oversize} images exceeded RTL parameters"
    pred_pass = passed

    # ---------------------------------------------------------------- engine vectors
    doc = json.loads((CONF / "flows.json").read_text())
    fpassed = ffailed = fexcluded = 0
    ffailures = []
    for case in doc["cases"]:
        exp = case["expect"]
        if ("start" in case or "state" in case
                or exp["stopped"] not in ("terminal", "stuck", "max_steps")
                or exp["pending_node"] is not None or exp["spawn"] is not None):
            fexcluded += 1
            continue
        graph = parse(case["flow"])
        try:
            img = pc.compile_flow(graph, case.get("maxSteps", 25))
            if not fits(img):
                raise pc.SubsetError("oversize")
            # validate script values are in-domain (mirrors encode_script)
            pc.encode_script(img, case["script"])
        except pc.SubsetError:
            fexcluded += 1
            continue

        await load_image(dut, img)
        loaded_cond = None
        await pulse_reset(dut)                   # fresh visits + field types per run
        dut.use_visits.value = 1
        names = [n for n, _ in img.nodes]
        node = img.start
        path = [names[node]]
        stopped = None
        visit_counts = [0] * len(img.nodes)
        intern = dict(img.intern)
        for _step in range(img.max_steps):
            nedges = img.nodes[node][1]
            if not nedges:
                stopped = "terminal"
                break
            await bump(dut, node)
            visit_counts[node] += 1
            seq = case["script"].get(names[node])
            if seq is None:
                outcome = {"text": names[node]}
            else:
                outcome = seq[min(visit_counts[node] - 1, len(seq) - 1)]
            fields = outcome if isinstance(outcome, dict) else {"text": str(outcome)}
            await write_fields(dut, img, fields, intern)
            res = await evaluate(dut, node)
            if res is None:
                stopped = "stuck"
                break
            _edge, tgt = res
            node = tgt
            path.append(names[node])
        else:
            stopped = "max_steps"

        if path == exp["path"] and stopped == exp["stopped"]:
            fpassed += 1
        else:
            ffailed += 1
            ffailures.append((case["name"], exp["path"], exp["stopped"], path, stopped))

    dut._log.info(f"flows: pass {fpassed} fail {ffailed} excluded {fexcluded}")
    for f in ffailures:
        dut._log.error(f"  ✗ {f}")
    assert ffailed == 0, f"{ffailed} engine vectors diverged"

    dut._log.info(f"RTL CONFORMANT: {pred_pass} predicate + {fpassed} engine vectors")


@cocotb.test()
async def sensor_log_replay(dut):
    """Replay the banked Day-2 sensor session through the simulated fabric: every sample of
    build/live_route_log.ndjson routed by the RTL must reproduce the decision the C target
    made live. Also records per-evaluate latency (the WCET evidence)."""
    log_path = HERE.parent / "build" / "live_route_log.ndjson"
    flow_md = (Path(pc._REPO) / "gallery" / "incident_severity"
               / "incident_severity.md")
    from prismpath.parser import parse_file
    img = pc.compile_flow(parse_file(str(flow_md)))
    names = [n for n, _ in img.nodes]

    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    _init_inputs(dut)
    await pulse_reset(dut)
    await load_image(dut, img)
    dut.use_visits.value = 0
    intern = dict(img.intern)

    n = mismatches = 0
    lat_min, lat_max = 10**9, 0
    for line in log_path.read_text().splitlines():
        rec = json.loads(line)
        expect = rec.pop("decision")
        await write_fields(dut, img, rec, intern)
        t0 = cocotb.utils.get_sim_time("ns")
        res = await evaluate(dut, img.start)
        cycles = int((cocotb.utils.get_sim_time("ns") - t0) / 10)
        lat_min, lat_max = min(lat_min, cycles), max(lat_max, cycles)
        got = names[res[1]] if res else "<stuck>"
        n += 1
        if got != expect:
            mismatches += 1
            if mismatches <= 5:
                dut._log.error(f"  sample {n}: RTL={got} live-C={expect} fields={rec}")
    dut._log.info(f"sensor replay: {n} samples, {mismatches} mismatches, "
                  f"evaluate latency {lat_min}-{lat_max} cycles")
    assert mismatches == 0
