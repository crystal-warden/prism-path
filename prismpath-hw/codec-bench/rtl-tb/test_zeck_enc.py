# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""RTL Zeckendorf encoder vs the reference: same seed 42 corpus as the MCU bench (64 typical +
64 stress events, 4 wire ints each); collected bits packed MSB first must equal the reference's
packed wire bytes for every event."""
import random
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

HERE = Path(__file__).resolve().parent
from prismpath.telemetry import packed  # noqa: E402
from prismpath.telemetry import zeckendorf as zeck  # noqa: E402


def corpus():
    random.seed(42)
    out = []
    for lo, hi in ((1, 6), (1, 1001)):
        for _ in range(64):
            ints = [random.randint(lo, hi) for _ in range(4)]
            out.append((ints, packed.pack(zeck.encode_stream(ints), 8)))
    return out


@cocotb.test()
async def conformance(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    dut.in_valid.value = 0
    for _ in range(3):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    failed = 0
    for n, (ints, expected) in enumerate(corpus()):
        bits = []
        for val in ints:
            dut.in_val.value = val
            dut.in_valid.value = 1
            while True:
                await RisingEdge(dut.clk)
                if dut.in_ready.value:
                    break
            dut.in_valid.value = 0
            while True:
                await RisingEdge(dut.clk)
                if dut.out_valid.value:
                    bits.append(int(dut.out_bit.value))
                if dut.done.value:
                    break
        wire = bytearray((len(bits) + 7) // 8)
        for idx, b in enumerate(bits):
            if b:
                wire[idx >> 3] |= 0x80 >> (idx & 7)
        if bytes(wire) != expected:
            failed += 1
            dut._log.error(f"event {n} {ints}: rtl {bytes(wire).hex()} != ref {expected.hex()}")
    assert failed == 0, f"{failed}/128 events diverged"
    dut._log.info("RTL ZECK ENCODER CONFORMANT: 128/128 events byte identical to the reference")


@cocotb.test()
async def zero_input_refused(dut):
    # A zero has no Zeckendorf code (the encoding is defined for n >= 1). Presenting it while in_ready is
    # high used to complete the producer's handshake and emit nothing, silently. The encoder now pulses
    # err instead, and never claims a code for it.
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    dut.in_valid.value = 0
    dut.in_val.value = 0
    for _ in range(3):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    dut.in_val.value = 0
    dut.in_valid.value = 1
    saw_err = False
    saw_out = False
    saw_done = False
    for _ in range(12):
        await RisingEdge(dut.clk)
        if int(dut.err.value):
            saw_err = True
        if int(dut.out_valid.value):
            saw_out = True
        if int(dut.done.value):
            saw_done = True
    dut.in_valid.value = 0
    assert saw_err, "encoder did not flag err on a zero input"
    assert not saw_out, "encoder emitted a wire bit for a zero input"
    assert not saw_done, "encoder claimed a completed code for a zero input"

    # recovery: a real value after the refusal still encodes to the reference wire
    expected = packed.pack(z.encode_stream([7]), 8)
    dut.in_val.value = 7
    dut.in_valid.value = 1
    while True:
        await RisingEdge(dut.clk)
        if int(dut.in_ready.value):
            break
    dut.in_valid.value = 0
    bits = []
    while True:
        await RisingEdge(dut.clk)
        if int(dut.out_valid.value):
            bits.append(int(dut.out_bit.value))
        if int(dut.done.value):
            break
    wire = bytearray((len(bits) + 7) // 8)
    for idx, b in enumerate(bits):
        if b:
            wire[idx >> 3] |= 0x80 >> (idx & 7)
    assert bytes(wire) == expected, f"post-refusal encode {bytes(wire).hex()} != ref {expected.hex()}"
    dut._log.info("RTL ZECK ENCODER: zero refused with err, non-zero still encodes")
