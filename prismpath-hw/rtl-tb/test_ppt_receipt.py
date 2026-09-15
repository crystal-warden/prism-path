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


def fnv1a32(data, running_digest):
    for byte in data:
        running_digest = ((running_digest ^ byte) * FNV_PRIME) & 0xFFFFFFFF
    return running_digest


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
    for field_value, node_index, policy_id in decisions:
        await commit_decision(dut, field_value, node_index, policy_id)
    for _ in range(200):
        await RisingEdge(dut.clk)

    # decisions are non-overlapping, so the stream is exactly N contiguous 18-byte records
    assert len(stream) == 18 * len(decisions), \
        f"got {len(stream)} bytes, expected {18 * len(decisions)} (dropped/garbled?)"
    records = [stream[record_index * 18:(record_index + 1) * 18] for record_index in range(len(decisions))]
    for record_index, rec in enumerate(records):
        assert rec[0] == SYNC, f"record {record_index} not sync-framed: {rec[0]:#04x}"

    running = FNV_INIT
    prev_ts = -1
    for idx, (rec, (field_value, node_index, policy_id)) in enumerate(zip(records, decisions)):
        def be(data_bytes):
            value = 0
            for byte in data_bytes:
                value = (value << 8) | byte
            return value
        seq = be(rec[1:5])
        tstamp = be(rec[5:9])
        pol = rec[9]
        field = be(rec[10:12])
        node = be(rec[12:14])
        digest = be(rec[14:18])
        assert seq == idx, f"receipt {idx}: seq {seq} != {idx}"
        assert pol == policy_id and field == field_value and node == node_index, \
            f"receipt {idx}: got pol={pol} field={field} node={node}, expected {policy_id}/{field_value}/{node_index}"
        assert tstamp > prev_ts, f"receipt {idx}: tstamp not monotonic ({tstamp} <= {prev_ts})"
        prev_ts = tstamp
        running = fnv1a32(rec[1:14], running)   # FNV over the 13 content bytes, chained
        assert digest == running, f"receipt {idx}: digest {digest:#010x} != FNV {running:#010x}"

    # 0 here is a property of the pacing above, not of the counter: the fixed wait in
    # commit_decision is exactly what keeps the decisions non-overlapping. What the counter does
    # under back pressure is a separate test, below.
    assert int(dut.dropped.value) == 0, f"dropped={int(dut.dropped.value)}"
    dut._log.info(f"FABRIC DECISION RECEIPTS: {len(records)}/{len(decisions)} faithful, "
                  f"FNV chain exact, tstamps monotonic, 0 dropped")


@cocotb.test()
async def receipt_backpressure_drops(dut):
    """The drop path, which the paced test above can never reach. A decision that lands while a
    receipt is still serializing is dropped, and the point of the test is WHICH way it is dropped:
    the module counts it and emits nothing, so seq stays contiguous. An off-chip reader therefore
    cannot recognize a drop from a gap in seq - the FNV chain over the receipts that were emitted is
    still exact - and `dropped` is the only place the loss is recorded."""
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

    # first decision starts a receipt; the next two arrive mid-serialization and must be dropped
    for field_value, node_index, policy_id in ((100, 1, 3), (101, 2, 3), (102, 3, 3)):
        dut.field.value = field_value
        dut.node.value = node_index
        dut.policy_id.value = policy_id
        dut.commit.value = 1
        await RisingEdge(dut.clk)
        dut.commit.value = 0
        for _ in range(40):            # far inside the ~3600 cycle serialization of one receipt
            await RisingEdge(dut.clk)
    for _ in range(5000):
        await RisingEdge(dut.clk)

    assert int(dut.dropped.value) == 2, f"expected 2 dropped decisions, got {int(dut.dropped.value)}"
    assert len(stream) == 18, f"expected one 18-byte receipt, got {len(stream)} bytes"
    assert stream[0] == SYNC, f"receipt not sync-framed: {stream[0]:#04x}"
    assert int(dut.seq.value) == 1, f"seq {int(dut.seq.value)} != 1: a drop must not consume a seq"
    digest = 0
    for byte in stream[14:18]:
        digest = (digest << 8) | byte
    assert digest == fnv1a32(stream[1:14], FNV_INIT), "the surviving receipt's digest is not the chain head"
    dut._log.info("FABRIC DECISION RECEIPTS under back pressure: 2 dropped, 1 emitted, "
                  "seq contiguous, digest chain exact")
