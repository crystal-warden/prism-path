"""test_finale_hyst.py — the fabric-native resident FSM vs the frozen hyst_band corpus.

The tb plays the PS role against the full finale datapath: it replays the signed policy's exact
load-write sequence (gen_pack_svh.policy_writes, the same bytes the pack loader would replay),
arms AUTO_CTRL with the stateful+safe bits, and mocks the XADC DRP so the pot is a driven value.
The fabric then free-runs exactly as silicon does, and per corpus event the tb reads CUR_NODE
(0x30) and asserts the resident band equals the frozen trail_settled — the fixpoint trail both
software references agreed on. A stateless demo_input pass on the same image then asserts the
certified path is untouched (regression: AUTO_CTRL[1]=0 must behave exactly as today).
"""
import json
import sys
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge

HERE = Path(__file__).resolve().parent
BENCH = Path("/home/cwadmin/cwprojects/prismpath-hw")          # demo bench: flows + corpus live here
sys.path.insert(0, str(HERE.parent / "tools"))
import gen_pack_svh as gp                                       # noqa: E402

FLOWS = BENCH / "demo" / "flows"
R_STATUS, R_RESULT, R_AUTO_CTRL, R_POT_NOW, R_CUR_NODE = 0x18, 0x1C, 0x28, 0x2C, 0x30

CUR_POT = {"v": 300}          # the DRP mock serves this (12-bit), updated by the test body


async def drp_mock(dut):
    """XADC over DRP, always ready: drdy held high with the current pot on drp_do. The DUT's DRP
    FSM issues its FIRST den the cycle after reset — an edge-triggered mock started later misses
    it and the FSM wedges in its wait state, so serve unconditionally (st=0 ignores drdy; st=1
    completes in one cycle; the pot refreshes every 2 cycles)."""
    while True:
        await RisingEdge(dut.clk)
        dut.drp_do.value = (CUR_POT["v"] & 0xFFF) << 4
        dut.drp_drdy.value = 1


async def axi_write(dut, addr, data):
    dut.s_axi_awaddr.value = addr
    dut.s_axi_awvalid.value = 1
    dut.s_axi_wdata.value = data & 0xFFFFFFFF
    dut.s_axi_wstrb.value = 0xF
    dut.s_axi_wvalid.value = 1
    dut.s_axi_bready.value = 1
    for _ in range(20):
        await RisingEdge(dut.clk)
        if dut.s_axi_bvalid.value:
            break
    else:
        raise AssertionError(f"AXI write timeout addr=0x{addr:02x}")
    dut.s_axi_awvalid.value = 0
    dut.s_axi_wvalid.value = 0
    await RisingEdge(dut.clk)
    dut.s_axi_bready.value = 0


async def axi_read(dut, addr):
    dut.s_axi_araddr.value = addr
    dut.s_axi_arvalid.value = 1
    dut.s_axi_rready.value = 1
    for _ in range(20):
        await RisingEdge(dut.clk)
        if dut.s_axi_rvalid.value:
            break
    else:
        raise AssertionError(f"AXI read timeout addr=0x{addr:02x}")
    val = int(dut.s_axi_rdata.value)
    dut.s_axi_arvalid.value = 0
    await RisingEdge(dut.clk)
    dut.s_axi_rready.value = 0
    return val


def policy_write_list(stem: str):
    """The PS-identical load sequence for a signed flow, arm word included (stateful+safe from
    the signed image header — the same derivation the baked pack generator uses)."""
    data = (FLOWS / f"{stem}.ppt").read_bytes()
    dbg = json.load(open(FLOWS / f"{stem}.json"))
    img = gp.parse_ppt(data)
    colors = gp.image_colors(data)
    h = gp.policy_pack.read_ppt_header(data)
    arm = (dbg["fields"]["pot"], img["start"], h["stateful"], h["safe_node"])
    return gp.policy_writes(img, colors, arm), h


async def load_and_arm(dut, stem: str):
    writes, hdr = policy_write_list(stem)
    await axi_write(dut, R_AUTO_CTRL, 0)                # disarm: the next arm is a clean rising edge
    for reg, val in writes:
        await axi_write(dut, reg, val)
    return hdr


SETTLE = 90                                             # cycles: DRP latch + >2 full evaluates


@cocotb.test()
async def finale_hysteresis_corpus(dut):
    corpus = json.load(open(FLOWS / "hyst_corpus.json"))
    names = corpus["node_names"]

    cocotb.start_soon(Clock(dut.clk, 10, "ns").start())
    dut.resetn.value = 0
    for sig in ("s_axi_awvalid", "s_axi_wvalid", "s_axi_bready", "s_axi_arvalid", "s_axi_rready",
                "btn_i", "sw_i", "inj", "ps_led", "drp_drdy", "drp_do"):
        getattr(dut, sig).value = 0
    dut.uart_rx_pin.value = 1                           # UART idle is high
    await ClockCycles(dut.clk, 10)
    dut.resetn.value = 1
    await ClockCycles(dut.clk, 10)
    cocotb.start_soon(drp_mock(dut))

    # ---- sanity: the governed field is the raw pot at reset defaults (profile 0, src pot) ----
    CUR_POT["v"] = 300
    hdr = await load_and_arm(dut, "hyst_band")
    assert hdr["stateful"] and hdr["safe_node"] == 2, "hyst_band header must declare stateful+safe"
    await ClockCycles(dut.clk, SETTLE)
    pot_now = (await axi_read(dut, R_POT_NOW)) & 0xFFFF
    assert pot_now == 300, f"eff_field is not the raw pot at reset defaults: POT_NOW={pot_now}"
    cn = await axi_read(dut, R_CUR_NODE)
    assert (cn >> 16) & 1, "CUR_NODE[16] must read back stateful=1"
    assert (cn & 0xFFFF) == 0, f"armed start must be low(0), got {cn & 0xFFFF}"

    # ---- the corpus: every stream re-arms (clean start), then free-runs to each settled band ----
    events = 0
    for st in corpus["streams"]:
        # the oracle arms INTO the stream's first sample: park the pot there BEFORE the arm, else
        # the freshly armed FSM free-runs on the previous stream's leftover pot and legitimately
        # walks off the clean start (caught live at stress_dwell's path-dependent 665 first sample)
        CUR_POT["v"] = st["pots"][0]
        await load_and_arm(dut, "hyst_band")            # arm edge -> deliberate clean start
        for pot, want in zip(st["pots"], st["trail_settled"]):
            CUR_POT["v"] = pot
            await ClockCycles(dut.clk, SETTLE)
            got = (await axi_read(dut, R_CUR_NODE)) & 0xFFFF
            assert got == want, (f"{st['name']}: pot={pot} resident={names[got]} "
                                 f"expected={names[want]} after {events} good events")
            events += 1
        # secondary observation point: the decided target (RESULT) agrees with the resident band
        tgt = (await axi_read(dut, R_RESULT)) & 0xFFFF
        assert tgt == st["trail_settled"][-1], \
            f"{st['name']}: RESULT target {tgt} != settled band {st['trail_settled'][-1]}"
    dut._log.info(f"HYST CORPUS PASS: {events} events across {len(corpus['streams'])} streams")

    # ---- stateless regression: demo_input on the same image, AUTO_CTRL[1]=0, certified path ----
    hdr = await load_and_arm(dut, "demo_input")
    assert not hdr["stateful"], "demo_input must be stateless"
    exp = [(100, 3), (700, 2), (1700, 1), (1640, 1), (660, 3), (4095, 1), (0, 3), (666, 2)]
    for pot, want in exp:                               # demo_input nodes: decide0 high1 mid2 low3
        CUR_POT["v"] = pot
        await ClockCycles(dut.clk, SETTLE)
        cn = await axi_read(dut, R_CUR_NODE)
        assert not ((cn >> 16) & 1), "stateless arm must read back stateful=0"
        tgt = (await axi_read(dut, R_RESULT)) & 0xFFFF
        assert tgt == want, f"stateless regression: pot={pot} target={tgt} expected={want}"
    dut._log.info("STATELESS REGRESSION PASS: demo_input decides identically with the mux at 0")
