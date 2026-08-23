# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""ppt_field_ctrl: the finale datapath front-end. Verifies the control-plane outputs shape the field and
LED correctly - source select, mute-freeze, severity-baseline bias, decision-inject stepping, and LED
color-override - and that every finale-only effect is gated off in Act 1 so a meta-swap back restores
the plain live loop. The interpreter (not modeled here) still decides on eff_field; this only shapes it."""
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

GREEN = 0x02          # a decision color used for pass-through
RED6 = 0b001001       # palette red  {B,G,R}={001,001}
GRN6 = 0b010010       # palette green {010,010}


async def settle(dut, n=2):
    for _ in range(n):
        await RisingEdge(dut.clk)


def ef(dut):
    return int(dut.eff_field.value)


def led(dut):
    return int(dut.led_o.value)


@cocotb.test()
async def field_ctrl(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    for s in ("raw_pot", "raw_band", "profile", "src_sel", "thresh_sel",
              "mute", "color_idx", "decision_in", "dec_valid", "dec_color"):
        getattr(dut, s).value = 0
    await settle(dut, 3)
    dut.rst.value = 0
    dut.dec_valid.value = 1
    dut.dec_color.value = GREEN

    # ---------- Act 1 (profile 0) ----------
    dut.profile.value = 0
    dut.raw_pot.value = 1234
    dut.raw_band.value = 500
    dut.src_sel.value = 0
    await settle(dut)
    assert ef(dut) == 1234, f"Act1 pot source -> {ef(dut)}"
    assert led(dut) == GREEN, f"Act1 LED should be the decision color -> {led(dut)}"

    dut.src_sel.value = 1
    await settle(dut)
    assert ef(dut) == 500, f"Act1 walker source -> {ef(dut)}"

    # finale-only effects must be gated OFF in Act 1
    dut.thresh_sel.value = 3
    dut.color_idx.value = 1
    await settle(dut)
    assert ef(dut) == 500, f"Act1 must not bias the field -> {ef(dut)}"
    assert led(dut) == GREEN, f"Act1 must not override the LED -> {led(dut)}"
    dut.thresh_sel.value = 0
    dut.color_idx.value = 0

    # ---------- Finale (profile 1) ----------
    dut.profile.value = 1
    dut.src_sel.value = 0
    dut.raw_pot.value = 1000
    await settle(dut)
    assert ef(dut) == 1000, f"finale base field -> {ef(dut)}"

    # severity baseline: bias the field up
    dut.thresh_sel.value = 3
    await settle(dut)
    assert ef(dut) == 2600, f"finale severe bias 1000+1600 -> {ef(dut)}"
    dut.thresh_sel.value = 1
    await settle(dut)
    assert ef(dut) == 1600, f"finale caution bias 1000+600 -> {ef(dut)}"
    dut.thresh_sel.value = 0
    await settle(dut)
    assert ef(dut) == 1000, f"finale low bias -> {ef(dut)}"

    # clamp at 12-bit
    dut.raw_pot.value = 3000
    dut.thresh_sel.value = 3
    await settle(dut)
    assert ef(dut) == 0xFFF, f"finale field must clamp -> {ef(dut)}"
    dut.thresh_sel.value = 0
    dut.raw_pot.value = 1000

    # mute: freeze the field at its last live value
    await settle(dut)                       # frozen now tracks 1000
    dut.mute.value = 1
    dut.raw_pot.value = 200                  # sensor moves, but we're muted
    await settle(dut)
    assert ef(dut) == 1000, f"muted field should freeze -> {ef(dut)}"
    dut.mute.value = 0
    await settle(dut)
    assert ef(dut) == 200, f"unmute should follow the sensor -> {ef(dut)}"

    # LED color override cycles all colors; idx 0 = back to the live decision color
    dut.color_idx.value = 1
    await settle(dut)
    assert led(dut) == RED6, f"finale color override red -> {led(dut)}"
    dut.color_idx.value = 2
    await settle(dut)
    assert led(dut) == GRN6, f"finale color override green -> {led(dut)}"
    dut.color_idx.value = 0
    await settle(dut)
    assert led(dut) == GREEN, f"idx 0 -> live decision color -> {led(dut)}"

    # decision input (BTN2): press ARMS a governed decision at a fixed reference (DEC_REF=200);
    # while armed, the switch-selected severity picks the verdict (sweep SW to walk the bands);
    # press again RELEASES back to the live sensor.
    dut.raw_pot.value = 50                    # sensor value we should be overriding
    await settle(dut)
    dut.decision_in.value = 1                 # press: arm
    await RisingEdge(dut.clk)
    dut.decision_in.value = 0
    await settle(dut)
    assert ef(dut) == 200, f"armed low (ref+0) -> {ef(dut)}, expected 200"
    dut.thresh_sel.value = 1                  # sweep severity while armed: caution
    await settle(dut)
    assert ef(dut) == 800, f"armed caution (ref+600) -> {ef(dut)}, expected 800"
    dut.thresh_sel.value = 3                  # severe
    await settle(dut)
    assert ef(dut) == 1800, f"armed severe (ref+1600) -> {ef(dut)}, expected 1800"
    dut.thresh_sel.value = 0
    dut.decision_in.value = 1                 # press again: release
    await RisingEdge(dut.clk)
    dut.decision_in.value = 0
    await settle(dut)
    assert ef(dut) == 50, f"release -> back to live sensor -> {ef(dut)}, expected 50"

    dut._log.info("FIELD CTRL: source-select, severity bias, 12-bit clamp, mute-freeze, color override, "
                  "and decision-inject all correct; every finale effect gated off in Act 1")
