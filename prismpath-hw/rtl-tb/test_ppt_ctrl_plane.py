# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""ppt_ctrl_plane: the whole fabric control plane end to end. cocotb plays ppt_axi's AXI slave and
presses buttons; it asserts that a button press flows through the signed control table into the loader
and lands as the exact register writes ppt_axi expects - and that the finale's control actions (color,
mute, decision) issue NO writes. This is the 'press a button, the fabric loads a signed policy, no
processor' proof: control-interpreter + pack loader composed."""
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

# decision-policy writes as they must appear on the AXI slave (from the loader's mock pack)
POL0 = [(0x20, 1), (0x00, 0x00010002), (0x04, 200), (0x00, 0x00020003), (0x04, 500)]
POL1 = [(0x20, 1), (0x00, 0x00070000), (0x04, 2)]

cap = []            # (addr, data) captured by the AXI slave


async def axi_write_slave(dut):
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
            await RisingEdge(dut.clk)
            dut.m_awready.value = 0
            dut.m_wready.value = 0
            cap.append((addr, data))
            dut.m_bvalid.value = 1
            while int(dut.m_bready.value) == 0:
                await RisingEdge(dut.clk)
            await RisingEdge(dut.clk)
            dut.m_bvalid.value = 0


async def press(dut, i, settle=80):
    cap.clear()
    dut.btn_press.value = (1 << i)
    await RisingEdge(dut.clk)
    dut.btn_press.value = 0
    for _ in range(settle):
        await RisingEdge(dut.clk)
        if int(dut.loading.value) == 0 and len(cap) > 0:
            for _ in range(6):
                await RisingEdge(dut.clk)
            break
    return list(cap)


@cocotb.test()
async def ctrl_plane(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    dut.sw.value = 0
    dut.btn_press.value = 0
    dut.m_awready.value = 0
    dut.m_wready.value = 0
    dut.m_bvalid.value = 0
    dut.m_bresp.value = 0
    for _ in range(4):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)
    cocotb.start_soon(axi_write_slave(dut))

    # Act 1: BTN0 hot-swaps to decision policy 0 -> those exact writes reach ppt_axi
    got = await press(dut, 0)
    assert got == POL0, f"BTN0 -> {[(hex(a),d) for a,d in got]} != policy 0"

    # Act 1: BTN1 hot-swaps to decision policy 1
    got = await press(dut, 1)
    assert got == POL1, f"BTN1 -> {[(hex(a),d) for a,d in got]} != policy 1"

    # BTN3 meta-swap into the finale: profile -> 1, and it installs the finale's decision policy (pack 1)
    got = await press(dut, 3)
    assert int(dut.profile.value) == 1, "meta-swap should enter the finale"
    assert got == POL1, f"meta-swap load -> {[(hex(a),d) for a,d in got]} != policy 1"

    # Finale BTN0 (cycle colors) must touch the AXI bus NOT AT ALL - it is pure fabric LED state
    got = await press(dut, 0, settle=40)
    assert got == [], f"finale color-cycle leaked AXI writes: {[(hex(a),d) for a,d in got]}"
    assert int(dut.color_idx.value) == 1, "finale BTN0 should have cycled the color"

    # Finale BTN1 mute: also no bus traffic
    got = await press(dut, 1, settle=40)
    assert got == [] and int(dut.mute.value) == 1, "finale mute should be local, no AXI writes"

    # BTN3 meta-swap exit: profile -> 0, reinstall Act 1's decision policy (pack 0)
    got = await press(dut, 3)
    assert int(dut.profile.value) == 0, "meta-swap exit should return to Act 1"
    assert got == POL0, f"meta-swap exit load -> {[(hex(a),d) for a,d in got]} != policy 0"

    dut._log.info("CTRL PLANE: button -> signed control table -> fabric loader -> exact ppt_axi writes, "
                  "no processor; finale color/mute stayed off the bus; meta-swap re-installed policies")
