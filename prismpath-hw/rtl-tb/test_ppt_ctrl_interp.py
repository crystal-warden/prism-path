# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""ppt_ctrl_interp: the control-interpreter. A signed control table maps (profile, button) -> action;
the profile (== signed ctrl_mode) selects which of two baked modes is live. This tb drives switches and
one-shot button presses and checks: Act 1 switches pick the source and BTN0-2 hot-swap decision
policies; BTN3 meta-swaps into the finale; finale BTN0 cycles colors, BTN1 mutes, BTN2 injects a
decision, BTN3 meta-swaps back - and BTN3's meta-swap changes what every other button means."""
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

loads = []          # load_pol captured on each load_go strobe
decins = [0]        # decision_in strobe count


async def monitor(dut):
    while True:
        await RisingEdge(dut.clk)
        if int(dut.load_go.value) == 1:
            loads.append(int(dut.load_pol.value))
        if int(dut.decision_in.value) == 1:
            decins[0] += 1


async def press(dut, i):
    dut.btn_press.value = (1 << i)
    await RisingEdge(dut.clk)          # 1-cycle one-shot, exactly like ctrl_in emits
    dut.btn_press.value = 0
    for _ in range(4):
        await RisingEdge(dut.clk)


async def set_sw(dut, v):
    dut.sw.value = v
    for _ in range(3):
        await RisingEdge(dut.clk)


@cocotb.test()
async def ctrl_interp(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    dut.sw.value = 0
    dut.btn_press.value = 0
    dut.ldr_busy.value = 0
    for _ in range(4):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)
    cocotb.start_soon(monitor(dut))

    assert int(dut.profile.value) == 0 and int(dut.mute.value) == 0 and int(dut.color_idx.value) == 0

    # --- Profile 0 (Act 1): switches pick the sensor source ---
    await set_sw(dut, 2)
    assert int(dut.src_sel.value) == 2, "Act1 switch should select source"

    # --- Profile 0: BTN0-2 hot-swap decision policies via the loader ---
    await press(dut, 0)
    await press(dut, 1)
    await press(dut, 2)
    assert loads == [0, 1, 2], f"Act1 hot-swaps -> {loads}, expected [0,1,2]"

    # --- loader-busy gating: a swap press while busy must NOT issue a load ---
    dut.ldr_busy.value = 1
    await press(dut, 0)
    assert loads == [0, 1, 2], f"swap while loader busy leaked a load: {loads}"
    dut.ldr_busy.value = 0

    # --- BTN3 meta-swap into the finale: loads pack 1, profile -> 1 ---
    await press(dut, 3)
    assert loads == [0, 1, 2, 1], f"meta-swap load -> {loads}"
    assert int(dut.profile.value) == 1, "meta-swap should enter finale (profile=1)"

    # --- Profile 1 (Finale): switches now pick the severity baseline ---
    await set_sw(dut, 3)
    assert int(dut.thresh_sel.value) == 3, "finale switch should select threshold"
    assert int(dut.src_sel.value) == 2, "source-select should freeze at its Act 1 value"

    # --- Finale BTN0 cycles LED colors (and issues no load) ---
    await press(dut, 0)
    assert int(dut.color_idx.value) == 1, "finale BTN0 should cycle color"
    await press(dut, 0)
    assert int(dut.color_idx.value) == 2, "finale BTN0 should keep cycling"
    assert loads == [0, 1, 2, 1], "finale BTN0 must not hot-swap"

    # --- Finale BTN1 mutes / unmutes ---
    await press(dut, 1)
    assert int(dut.mute.value) == 1, "finale BTN1 should mute"
    await press(dut, 1)
    assert int(dut.mute.value) == 0, "finale BTN1 should unmute"

    # --- Finale BTN2 injects a decision (strobe), still no swap ---
    d0 = decins[0]
    await press(dut, 2)
    assert decins[0] == d0 + 1, "finale BTN2 should strobe decision_in"
    assert loads == [0, 1, 2, 1], "finale BTN2 must not hot-swap"

    # --- BTN3 meta-swap exit: loads pack 0, profile -> 0 ---
    await press(dut, 3)
    assert loads == [0, 1, 2, 1, 0], f"meta-swap exit load -> {loads}"
    assert int(dut.profile.value) == 0, "meta-swap exit should return to Act 1"

    dut._log.info("CTRL INTERP: both signed profiles verified; BTN3 meta-swap re-pointed the control "
                  "table (same buttons, different meaning) and installed the mode's decision policy")
