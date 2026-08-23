# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""ppt_pack_loader: the fabric hot-swap engine replays a baked policy's load writes onto ppt_axi's AXI
slave, exactly as the PS would. cocotb plays the slave, captures every {reg,value} write, and asserts
the sequence matches each mock policy - proving the fabric can load a policy with no processor."""
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge


async def axi_write_slave(dut, captured):
    """Minimal AXI4-Lite write slave: accept aw+w together, capture, then a bvalid response."""
    dut.m_awready.value = 0
    dut.m_wready.value = 0
    dut.m_bvalid.value = 0
    dut.m_bresp.value = 0
    while True:
        await RisingEdge(dut.clk)
        if int(dut.m_awvalid.value) == 1 and int(dut.m_wvalid.value) == 1:
            dut.m_awready.value = 1
            dut.m_wready.value = 1
            addr = int(dut.m_awaddr.value)
            data = int(dut.m_wdata.value)
            await RisingEdge(dut.clk)                # master samples ready here, drops aw/w
            dut.m_awready.value = 0
            dut.m_wready.value = 0
            captured.append((addr, data))
            dut.m_bvalid.value = 1
            while int(dut.m_bready.value) == 0:
                await RisingEdge(dut.clk)
            await RisingEdge(dut.clk)
            dut.m_bvalid.value = 0


async def load(dut, pol):
    dut.load_pol.value = pol
    dut.load_go.value = 1
    await RisingEdge(dut.clk)
    dut.load_go.value = 0
    for _ in range(1000):
        await RisingEdge(dut.clk)
        if int(dut.done.value) == 1:
            return
    raise TimeoutError(f"load({pol}) never completed")


@cocotb.test()
async def loader(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    dut.load_go.value = 0
    dut.load_pol.value = 0
    dut.m_awready.value = 0
    dut.m_wready.value = 0
    dut.m_bvalid.value = 0
    dut.m_bresp.value = 0
    for _ in range(4):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    cap = []
    cocotb.start_soon(axi_write_slave(dut, cap))

    await load(dut, 0)
    exp0 = [(0x20, 1), (0x00, 0x00010002), (0x04, 200), (0x00, 0x00020003), (0x04, 500)]
    assert cap == exp0, f"policy 0: got {[(hex(a),d) for a,d in cap]} != expected"
    n0 = len(cap)
    cap.clear()

    await load(dut, 1)
    exp1 = [(0x20, 1), (0x00, 0x00070000), (0x04, 2)]
    assert cap == exp1, f"policy 1: got {[(hex(a),d) for a,d in cap]} != expected"
    n1 = len(cap)

    dut._log.info(f"PACK LOADER: policy 0 replayed {n0}/5 writes, policy 1 replayed {n1}/3 writes, "
                  f"all exact -> fabric loads a signed policy with no processor")
