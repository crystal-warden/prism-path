# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""ppt_axi_wmux: the shared write-channel mux in front of ppt_axi. cocotb plays two masters (PS on s_*,
loader on m_*) and the ppt_axi slave on o_*, and checks: a PS-only write passes through; a loader-only
write passes through; and when both fire together the loader wins first, then the PS completes - the
choice held stable for the whole transaction, no interleaving, no lost write."""
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

cap = []            # (addr, data) seen by the ppt_axi slave, in order


async def axi_slave(dut):
    dut.o_awready.value = 0
    dut.o_wready.value = 0
    dut.o_bvalid.value = 0
    dut.o_bresp.value = 0
    while True:
        await RisingEdge(dut.clk)
        if int(dut.o_awvalid.value) == 1 and int(dut.o_wvalid.value) == 1:
            dut.o_awready.value = 1
            dut.o_wready.value = 1
            addr = int(dut.o_awaddr.value)
            data = int(dut.o_wdata.value)
            await RisingEdge(dut.clk)
            dut.o_awready.value = 0
            dut.o_wready.value = 0
            cap.append((addr, data))
            dut.o_bvalid.value = 1
            while int(dut.o_bready.value) == 0:
                await RisingEdge(dut.clk)
            await RisingEdge(dut.clk)
            dut.o_bvalid.value = 0


async def master_write(dut, pre, addr, data):
    getattr(dut, pre + "_awaddr").value = addr
    getattr(dut, pre + "_awvalid").value = 1
    getattr(dut, pre + "_wdata").value = data
    getattr(dut, pre + "_wstrb").value = 0xF
    getattr(dut, pre + "_wvalid").value = 1
    while True:
        await RisingEdge(dut.clk)
        if int(getattr(dut, pre + "_awready").value) and int(getattr(dut, pre + "_wready").value):
            break
    getattr(dut, pre + "_awvalid").value = 0
    getattr(dut, pre + "_wvalid").value = 0
    getattr(dut, pre + "_bready").value = 1
    while True:
        await RisingEdge(dut.clk)
        if int(getattr(dut, pre + "_bvalid").value):
            break
    getattr(dut, pre + "_bready").value = 0


@cocotb.test()
async def wmux(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    for s in ("s_awaddr", "s_awvalid", "s_wdata", "s_wstrb", "s_wvalid", "s_bready",
              "m_awaddr", "m_awvalid", "m_wdata", "m_wstrb", "m_wvalid", "m_bready"):
        getattr(dut, s).value = 0
    dut.o_awready.value = 0
    dut.o_wready.value = 0
    dut.o_bvalid.value = 0
    dut.o_bresp.value = 0
    for _ in range(4):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)
    cocotb.start_soon(axi_slave(dut))

    # PS-only write reaches the slave
    cap.clear()
    await master_write(dut, "s", 0x04, 0xAA)
    for _ in range(4):
        await RisingEdge(dut.clk)
    assert cap == [(0x04, 0xAA)], f"PS-only -> {[(hex(a),d) for a,d in cap]}"

    # loader-only write reaches the slave
    cap.clear()
    await master_write(dut, "m", 0x00, 0xBB)
    for _ in range(4):
        await RisingEdge(dut.clk)
    assert cap == [(0x00, 0xBB)], f"loader-only -> {[(hex(a),d) for a,d in cap]}"

    # concurrent: loader wins first, PS completes after - both land, in that order, uncorrupted
    cap.clear()
    ps = cocotb.start_soon(master_write(dut, "s", 0x08, 0xCC))
    ld = cocotb.start_soon(master_write(dut, "m", 0x20, 0xDD))
    await ld
    await ps
    for _ in range(4):
        await RisingEdge(dut.clk)
    assert cap == [(0x20, 0xDD), (0x08, 0xCC)], f"concurrent order -> {[(hex(a),d) for a,d in cap]}"

    dut._log.info("AXI WMUX: PS and loader each reach ppt_axi; on collision the loader wins and the PS "
                  "completes after, selection held for the whole transaction - no interleave, no drop")
