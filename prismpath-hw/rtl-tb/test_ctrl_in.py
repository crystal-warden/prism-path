# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""ctrl_in: a bouncy button press must yield exactly one debounced strobe; switches sync through.
Makefile.ctrl overrides -GTHRESH=8 for fast simulation."""
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge


async def hold(dut, btn0, cycles):
    dut.btn_raw.value = btn0
    for _ in range(cycles):
        await RisingEdge(dut.clk)


@cocotb.test()
async def debounce(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    dut.btn_raw.value = 0
    dut.sw_raw.value = 0
    for _ in range(5):
        await RisingEdge(dut.clk)
    dut.rst.value = 0

    presses = 0

    async def mon():
        nonlocal presses
        while True:
            await RisingEdge(dut.clk)
            if int(dut.btn_press.value) & 0x1:
                presses += 1
    cocotb.start_soon(mon())

    # bounce shorter than THRESH=8: never settles -> no press
    for _ in range(4):
        await hold(dut, 1, 3)
        await hold(dut, 0, 3)
    # now a clean press: hold well past THRESH + sync latency
    await hold(dut, 1, 25)
    assert (int(dut.btn_level.value) & 0x1) == 1, "btn_level did not latch on a clean press"
    # release
    await hold(dut, 0, 25)
    assert (int(dut.btn_level.value) & 0x1) == 0, "btn_level did not clear on release"

    # switches sync through
    dut.sw_raw.value = 0b10
    for _ in range(5):
        await RisingEdge(dut.clk)
    assert int(dut.sw.value) == 0b10, f"sw {int(dut.sw.value):#b} != 0b10"

    assert presses == 1, f"expected exactly 1 debounced press, got {presses}"
    dut._log.info(f"CTRL_IN: bounce rejected, exactly {presses} clean press, switches synced")
