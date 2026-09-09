# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""RTL Zeckendorf decoder vs the reference: feed the decoder the SAME reference wire bits the encoder
emits (seed 42 corpus, 128 events x 4 wire ints) and assert every recovered int equals the original.
decode(reference_bits) == the ints proves the fabric decoder is the exact inverse of the wire that
zeck_enc was already certified to produce (test_zeck_enc.py)."""
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

HERE = Path(__file__).resolve().parent
from prismpath.telemetry import zeckendorf as z  # noqa: E402


def corpus():
    random.seed(42)
    out = []
    for lo, hi in ((1, 6), (1, 1001)):
        for _ in range(64):
            out.append([random.randint(lo, hi) for _ in range(4)])
    return out


@cocotb.test()
async def conformance(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    dut.in_valid.value = 0
    dut.in_bit.value = 0
    for _ in range(3):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    recovered = []

    async def monitor():
        while True:
            await RisingEdge(dut.clk)
            if dut.out_valid.value == 1:
                recovered.append(int(dut.out_val.value))
    cocotb.start_soon(monitor())

    expected = []
    for ints in corpus():
        expected.extend(ints)
        for ch in z.encode_stream(ints):     # one char per wire bit, terminators included
            dut.in_valid.value = 1
            dut.in_bit.value = int(ch)
            await RisingEdge(dut.clk)
        dut.in_valid.value = 0
    for _ in range(4):                        # let the last terminator's strobe drain
        await RisingEdge(dut.clk)

    assert recovered == expected, (
        f"decoded {len(recovered)} ints, expected {len(expected)}; "
        f"first divergence at {next((i for i,(a,b) in enumerate(zip(recovered,expected)) if a!=b), 'len')}"
    )
    dut._log.info(f"RTL ZECK DECODER CONFORMANT: 128/128 events, {len(recovered)} wire ints recovered exactly")
