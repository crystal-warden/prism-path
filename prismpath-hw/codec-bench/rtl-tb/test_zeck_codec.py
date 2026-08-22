# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""RTL Zeckendorf CODEC on the fabric datapath: zeck_enc -> zeck_dec wired mouth-to-ear inside
zeck_codec_core. Proves (a) PEEK: for a value n the captured wire equals the reference AND the
in-fabric decode returns n; (b) SELF-TEST: a sweep n=1..MAX round-trips decode(encode(n))==n with
pass_count==total and first_fail==0 — the exact tally the on-silicon measurement reads back."""
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "adapters" / "telemetry"))
import zeckendorf as z  # noqa: E402


def wire_bits(bits_int, length):
    return "".join(str((bits_int >> (length - 1 - j)) & 1) for j in range(length))


async def reset(dut):
    dut.rst.value = 1
    dut.peek_go.value = 0
    dut.peek_in.value = 0
    dut.selftest_go.value = 0
    dut.selftest_max.value = 0
    for _ in range(3):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)


async def peek(dut, n):
    dut.peek_in.value = n
    dut.peek_go.value = 1
    await RisingEdge(dut.clk)
    dut.peek_go.value = 0
    for _ in range(500):
        await RisingEdge(dut.clk)
        if dut.peek_done.value == 1:
            return int(dut.peek_bits.value), int(dut.peek_len.value), int(dut.peek_dec.value)
    raise TimeoutError(f"peek({n}) never completed")


@cocotb.test()
async def codec(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    await reset(dut)

    # (a) PEEK: the fabric-produced wire equals the reference AND the in-fabric decode returns n
    fails = 0
    probes = list(range(1, 60)) + [100, 233, 1000, 6765, 99999]
    for n in probes:
        bits, length, dec = await peek(dut, n)
        ref = z.encode_stream([n])
        got = wire_bits(bits, length)
        if got != ref or dec != n:
            fails += 1
            dut._log.error(f"peek {n}: wire {got} vs ref {ref}; dec {dec}")
    assert fails == 0, f"{fails} peek mismatches"
    dut._log.info(f"PEEK ok: fabric wire == reference AND decode == n for all {len(probes)} probes")

    # (b) SELF-TEST sweep n=1..MAX, entirely in the fabric
    MAX = 300
    dut.selftest_max.value = MAX
    dut.selftest_go.value = 1
    await RisingEdge(dut.clk)
    dut.selftest_go.value = 0
    for _ in range(400000):
        await RisingEdge(dut.clk)
        if dut.selftest_done.value == 1:
            break
    else:
        raise TimeoutError("selftest never completed")
    pc = int(dut.pass_count.value)
    tot = int(dut.total.value)
    ff = int(dut.first_fail.value)
    err = int(dut.dec_err.value)
    assert tot == MAX and pc == MAX and ff == 0 and err == 0, \
        f"selftest pass={pc} total={tot} first_fail={ff} err={err}"
    dut._log.info(f"SELF-TEST on the fabric datapath: {pc}/{tot} round-trips decode(encode(n))==n, first_fail=0")
