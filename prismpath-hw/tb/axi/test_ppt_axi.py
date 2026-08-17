# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""cocotb test for the AXI-Lite wrapper — the PS-eye view of the interpreter.

Everything goes through real AXI4-Lite transactions, exactly as PYNQ MMIO will drive it:
sanity MAGIC read, image load, field writes, evaluate, result poll. The payload test
replays sensor samples from the banked Day-2 log and diffs decisions against the live run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

import ppt_compile as pc                                    # noqa: E402

R_LOAD_SEL_ADDR = 0x00
R_LOAD_DATA     = 0x04
R_FLD_IDX_TYPE  = 0x08
R_FLD_VAL       = 0x0C
R_BUMP          = 0x10
R_CTRL          = 0x14
R_STATUS        = 0x18
R_RESULT        = 0x1C
R_SOFT_RST      = 0x20
R_MAGIC         = 0x24


async def tick(dut):
    await RisingEdge(dut.s_axi_aclk)


async def axi_write(dut, addr: int, data: int):
    dut.s_axi_awaddr.value = addr
    dut.s_axi_awvalid.value = 1
    dut.s_axi_wdata.value = data & 0xFFFFFFFF
    dut.s_axi_wstrb.value = 0xF
    dut.s_axi_wvalid.value = 1
    dut.s_axi_bready.value = 1
    for _ in range(20):
        await tick(dut)
        if dut.s_axi_awready.value and dut.s_axi_wready.value:
            break
    else:
        raise TimeoutError("write handshake")
    dut.s_axi_awvalid.value = 0
    dut.s_axi_wvalid.value = 0
    for _ in range(20):
        if dut.s_axi_bvalid.value:
            break
        await tick(dut)
    await tick(dut)


async def axi_read(dut, addr: int) -> int:
    dut.s_axi_araddr.value = addr
    dut.s_axi_arvalid.value = 1
    dut.s_axi_rready.value = 1
    for _ in range(20):
        await tick(dut)
        if dut.s_axi_rvalid.value:
            break
    else:
        raise TimeoutError("read handshake")
    data = int(dut.s_axi_rdata.value)
    dut.s_axi_arvalid.value = 0
    await tick(dut)
    return data


async def load_image_axi(dut, img: pc.TableImage):
    async def load(sel, addr, data):
        await axi_write(dut, R_LOAD_SEL_ADDR, (sel << 16) | addr)
        await axi_write(dut, R_LOAD_DATA, data)
    await load(0, 0, img.fields.get("visits", 0xFFFF))
    for i, (f, op, ty, val) in enumerate(img.atoms):
        await load(1, i, (ty << 24) | (op << 16) | f)
        await load(2, i, val & 0xFFFFFFFF)
    n_edges = 0
    n_prog = 0
    for ni, (_name, nedges) in enumerate(img.nodes):
        await load(3, ni, (len(nedges) << 16) | n_edges)
        for tgt, _cond, prog in nedges:
            await load(4, n_edges, (n_prog << 16) | tgt)
            await load(5, n_edges, len(prog))
            n_edges += 1
            for w in prog:
                await load(6, n_prog, w)
                n_prog += 1


async def evaluate_axi(dut, img: pc.TableImage, node: int, ctx: dict, intern: dict):
    for name, idx in sorted(img.fields.items(), key=lambda kv: kv[1]):
        ty, val = pc.encode_scalar(ctx.get(name), intern)
        await axi_write(dut, R_FLD_IDX_TYPE, (ty << 16) | idx)
        await axi_write(dut, R_FLD_VAL, val & 0xFFFFFFFF)
    await axi_write(dut, R_CTRL, node)                     # use_visits=0
    for _ in range(200):
        status = await axi_read(dut, R_STATUS)
        if status & 0b010:                                 # done latch
            break
    else:
        raise TimeoutError("evaluate never done")
    if not (status & 0b100):                               # match bit
        await axi_read(dut, R_RESULT)                      # clear latch anyway
        return None
    result = await axi_read(dut, R_RESULT)                 # clears done latch
    return (result >> 16) & 0xFFFF, result & 0xFFFF


@cocotb.test()
async def axi_sensor_replay(dut):
    cocotb.start_soon(Clock(dut.s_axi_aclk, 10, "ns").start())
    for name in ("s_axi_awvalid", "s_axi_wvalid", "s_axi_bready",
                 "s_axi_arvalid", "s_axi_rready"):
        getattr(dut, name).value = 0
    dut.s_axi_aresetn.value = 0
    for _ in range(4):
        await tick(dut)
    dut.s_axi_aresetn.value = 1
    await tick(dut)

    magic = await axi_read(dut, R_MAGIC)
    assert magic == 0x50505431, f"MAGIC mismatch: {magic:#x}"

    from prismpath.parser import parse_file
    flow_md = (Path(pc._REPO) / "prismpath" / "gallery" / "incident_severity"
               / "incident_severity.md")
    img = pc.compile_flow(parse_file(str(flow_md)))
    names = [n for n, _ in img.nodes]
    await axi_write(dut, R_SOFT_RST, 1)
    await load_image_axi(dut, img)
    intern = dict(img.intern)

    log_path = HERE.parent.parent / "build" / "live_route_log.ndjson"
    lines = log_path.read_text().splitlines()
    step = max(1, len(lines) // 500)                       # ~500 spread samples
    n = mismatches = 0
    for line in lines[::step]:
        rec = json.loads(line)
        expect = rec.pop("decision")
        res = await evaluate_axi(dut, img, img.start, rec, intern)
        got = names[res[1]] if res else "<stuck>"
        n += 1
        if got != expect:
            mismatches += 1
            if mismatches <= 5:
                dut._log.error(f"  sample: AXI={got} live-C={expect} fields={rec}")
    dut._log.info(f"AXI sensor replay: {n} samples, {mismatches} mismatches")
    assert mismatches == 0
