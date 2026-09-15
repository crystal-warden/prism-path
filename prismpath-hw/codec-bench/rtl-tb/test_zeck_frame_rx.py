# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""zeck_frame_rx vs real walker frames: build the spiral-mesh frame zeck [class+1=2, tick+1, band+1]
with the reference packer, stream it in byte-by-byte with a realistic intra-frame byte spacing and an
inter-frame idle gap, and assert the fabric recovers each band. This is the native-decode path the
walker demo uses: the wire is decoded in the PL, no MCU. GAP_TICKS is overridden small for sim speed
(Makefile.frame: -GGAP_TICKS=100)."""
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

HERE = Path(__file__).resolve().parent
from prismpath.telemetry import zeckendorf as zeck  # noqa: E402
from prismpath.telemetry import packed  # noqa: E402


def frame_bytes(tick, band):
    return packed.pack(zeck.encode_stream([2, tick + 1, band + 1]), 8)   # class+1=2, tick+1, band+1


async def feed_byte(dut, b, inter):
    dut.byte_in.value = b
    dut.byte_valid.value = 1
    await RisingEdge(dut.clk)
    dut.byte_valid.value = 0
    for _ in range(inter):
        await RisingEdge(dut.clk)


@cocotb.test()
async def frames(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    dut.byte_valid.value = 0
    dut.byte_in.value = 0
    for _ in range(5):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    got = []

    async def mon():
        while True:
            await RisingEdge(dut.clk)
            if dut.band_valid.value == 1:
                got.append(int(dut.band.value))
    cocotb.start_soon(mon())

    INTER_BYTE = 12       # < GAP_TICKS (>= 8 so a byte fully shifts out first)
    INTER_FRAME = 200     # > GAP_TICKS: the idle that realigns the next frame
    cases = [(0, 0), (1, 1), (5, 2), (42, 3), (1000, 4), (3, 0), (7, 1), (255, 2), (2, 3), (99, 4)]
    expected = [band for _, band in cases]
    for tick, band in cases:
        for b in frame_bytes(tick, band):
            await feed_byte(dut, b, INTER_BYTE)
        for _ in range(INTER_FRAME):
            await RisingEdge(dut.clk)

    assert got == expected, f"got {got} != expected {expected}"
    dut._log.info(f"ZECK FRAME RX: {len(got)}/{len(expected)} walker frames decoded to band in the fabric")


@cocotb.test()
async def bad_band_dropped(dut):
    # A frame whose band+1 decodes outside 1..5 is not a real band (bands are 0..4). The old code took
    # code_val[2:0]-1, so a decoded 6 or 7 aliased onto a low band and was emitted as if genuine. It is
    # now dropped: no band_valid strobe, and the surrounding good frames still decode.
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    dut.byte_valid.value = 0
    dut.byte_in.value = 0
    for _ in range(5):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    got = []

    async def mon():
        while True:
            await RisingEdge(dut.clk)
            if dut.band_valid.value == 1:
                got.append(int(dut.band.value))
    cocotb.start_soon(mon())

    INTER_BYTE = 12
    INTER_FRAME = 200

    def raw_frame(codes):
        return packed.pack(z.encode_stream(codes), 8)

    # good band 2, then a frame whose third code is 7 (band+1=7 -> would alias to band 6), then good band 3
    frames = [raw_frame([2, 6, 3]),        # class+1=2, tick+1=6, band+1=3 -> band 2
              raw_frame([2, 6, 7]),        # band+1=7: out of range, must be dropped
              raw_frame([2, 43, 4])]       # class+1=2, tick+1=43, band+1=4 -> band 3
    for frame in frames:
        for b in frame:
            await feed_byte(dut, b, INTER_BYTE)
        for _ in range(INTER_FRAME):
            await RisingEdge(dut.clk)

    assert got == [2, 3], f"got {got}, expected [2, 3] (the out-of-range band dropped)"
    dut._log.info("ZECK FRAME RX: out-of-range band dropped, good frames decoded")
