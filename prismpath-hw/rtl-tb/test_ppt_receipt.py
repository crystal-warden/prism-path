# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Fabric Decision Receipts: drive a series of decisions, collect the serial receipt stream (looped
back through uart_rx), and assert every field is faithful and the FNV-1a-32 digest chain is exact —
so a passive off-chip reader can detect any dropped or altered receipt with no processor in the loop."""
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge

SYNC = 0xA5
FNV_INIT = 2166136261
FNV_PRIME = 16777619


def fnv1a32(data, h):
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFF
    return h


async def collect_bytes(dut, out):
    while True:
        await RisingEdge(dut.clk)
        if dut.rx_valid.value == 1:
            out.append(int(dut.rx_data.value) & 0xFF)


async def commit_decision(dut, field, node, pol):
    dut.field.value = field
    dut.node.value = node
    dut.policy_id.value = pol
    dut.commit.value = 1
    await RisingEdge(dut.clk)
    dut.commit.value = 0
    # 18 bytes x 10 bits x DIV(20) = 3600 cycles to serialize + fully transmit the last byte;
    # a fixed generous wait keeps decisions non-overlapping (no drops) without racing `busy`.
    for _ in range(5000):
        await RisingEdge(dut.clk)


@cocotb.test()
async def receipts(dut):
    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.rst.value = 1
    dut.commit.value = 0
    dut.field.value = 0
    dut.node.value = 0
    dut.policy_id.value = 0
    for _ in range(5):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)

    stream = []
    cocotb.start_soon(collect_bytes(dut, stream))

    decisions = [(200, 3, 1), (1000, 2, 1), (1631, 1, 2), (208, 3, 2), (2608, 1, 7)]
    for f, n, p in decisions:
        await commit_decision(dut, f, n, p)
    for _ in range(200):
        await RisingEdge(dut.clk)

    # decisions are non-overlapping, so the stream is exactly N contiguous 18-byte records
    assert len(stream) == 18 * len(decisions), \
        f"got {len(stream)} bytes, expected {18 * len(decisions)} (dropped/garbled?)"
    records = [stream[k * 18:(k + 1) * 18] for k in range(len(decisions))]
    for k, rec in enumerate(records):
        assert rec[0] == SYNC, f"record {k} not sync-framed: {rec[0]:#04x}"

    running = FNV_INIT
    prev_ts = -1
    for idx, (rec, (f, n, p)) in enumerate(zip(records, decisions)):
        def be(bs):
            v = 0
            for b in bs:
                v = (v << 8) | b
            return v
        seq = be(rec[1:5])
        ts = be(rec[5:9])
        pol = rec[9]
        field = be(rec[10:12])
        node = be(rec[12:14])
        digest = be(rec[14:18])
        assert seq == idx, f"receipt {idx}: seq {seq} != {idx}"
        assert pol == p and field == f and node == n, \
            f"receipt {idx}: got pol={pol} field={field} node={node}, expected {p}/{f}/{n}"
        assert ts > prev_ts, f"receipt {idx}: tstamp not monotonic ({ts} <= {prev_ts})"
        prev_ts = ts
        running = fnv1a32(rec[1:14], running)   # FNV over the 13 content bytes, chained
        assert digest == running, f"receipt {idx}: digest {digest:#010x} != FNV {running:#010x}"

    assert int(dut.dropped.value) == 0, f"dropped={int(dut.dropped.value)}"
    dut._log.info(f"FABRIC DECISION RECEIPTS: {len(records)}/{len(decisions)} faithful, "
                  f"FNV chain exact, tstamps monotonic, 0 dropped")
