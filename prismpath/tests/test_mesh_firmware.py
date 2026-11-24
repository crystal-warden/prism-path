# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The mesh firmware's own logic (prismpath-hw/mesh/main/mesh_node.c over the C core) on the host, three simulated
nodes on one in-memory radio (prismpath-hw/mesh/host/), with no ESP-IDF and no board.

The seven checks the boards run in the board validation pass (prismpath-hw/mesh/mesh_checks.py, through board_run.py)
run here first, frame by frame, with releases and statements written by prismpath/distribution/frames.py and the
mesh's signer: a release staged and committed on all three, a bad signature refused, a replay refused across a
reset, a widening refused without its statement, a revocation, and expiry refused by default and held on a node
built with HOLD. Beyond them: controller statements in frames of type 6, an action floor over the radio with the
mesh layout (AF9, AF10), the install parts read from their second copy (IS10), the NVS partition table against the
largest durable state the core allows, and the build settings."""
import hashlib
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1].parent
MESH = ROOT / "prismpath-hw" / "mesh"
if not (MESH / "main" / "mesh_node.c").exists():
    pytest.skip("the mesh firmware is in prismpath-hw, which this tree does not carry", allow_module_level=True)
pytest.importorskip("cryptography")
for path in (str(MESH), str(MESH / "host"), str(ROOT / "prismpath-hw")):
    if path not in sys.path:
        sys.path.insert(0, path)

import mesh_checks as checks  # noqa: E402
import gen_mesh_tables as tables  # noqa: E402
import sim_fleet as sim  # noqa: E402
from prismpath import canon  # noqa: E402
from prismpath.distribution import frames  # noqa: E402
from prismpath.kernel import causes  # noqa: E402
from prismpath.tests._dist import GEN  # noqa: E402

SEEDS = [hashlib.sha256(f"node {k}".encode()).digest() for k in range(3)]
ALLOW, REFUSE = checks.ALLOW, checks.REFUSE
BASIS_FLOOR = 2
TABLE_A, TABLE_B = tables.tables()
H_A, H_B = canon.sha256_hex(TABLE_A), canon.sha256_hex(TABLE_B)


def _pub(name: str) -> bytes:
    return GEN.public_raw(GEN.test_key(name))


def _signer(**args) -> tables.Signer:
    return tables.Signer(authority=GEN.test_key("A"), controller=GEN.test_key("C"), **args)


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    if shutil.which("cc") is None:
        pytest.skip("no C compiler (cc) on this host, so the mesh firmware is not built here")
    return sim.build(tmp_path_factory.mktemp("mesh_sim"))


def _fleet(binary, *, fresh=0, install=(), holds=(0, 0, 0)) -> sim.SimFleet:
    keys = [_pub(name) for name in install]
    lines = sim.anchor_lines(_pub("A"), _pub("C"), fresh=fresh, domain=tables.domain_sha256(),
                             layout=tables.layout_sha256(), fields=tables.LAYOUT, install=keys,
                             fingerprint=tables.anchor_fingerprint(_pub("A"), _pub("C"), fresh, keys, 2) if keys else "")
    return sim.SimFleet(binary, lines, SEEDS, holds)


@pytest.fixture(scope="module")
def seven(binary):
    fleet = _fleet(binary)
    try:
        yield checks.run_checks(fleet, _signer(), after_flash=fleet.booted), fleet
    finally:
        fleet.close()


def _passed(result: dict, nodes: int = 3) -> None:
    assert result["passed"] is True and len(result["boards"]) == nodes, result


def test_the_simulated_checks_are_the_board_checks():
    """One list of checks: board_run.py runs checks.run_checks on the boards, and these tests run it here."""
    import board_run
    assert board_run.checks is checks
    assert checks.CHECKS == ["flashed", "release_b_committed", "bad_signature_refused", "replay_refused_across_a_reset",
                             "widening_refused", "revocation_applied_then_refused", "expiry_refused_by_default",
                             "hold_keeps_deciding", "hold_dropped_on_revocation"]


def test_check_1_every_node_starts_from_one_build_with_its_own_instance_key(seven):
    out, fleet = seven
    _passed(out["flashed"])
    assert len(set(fleet.public.values())) == 3


def test_check_2_release_b_is_staged_and_committed_on_all_three_which_flip_together(seven):
    out, fleet = seven
    _passed(out["release_b_committed"])
    assert all(detail.endswith("A answered 1, B answers 2") for detail in out["release_b_committed"]["detail"].values())
    assert all(heard > 0 for heard in fleet.heard.values())        # each node hears the others' state frames


def test_check_3_a_bad_signature_is_refused_on_all_three(seven):
    _passed(seven[0]["bad_signature_refused"])


def test_check_4_a_replay_is_refused_before_and_after_a_reset(seven):
    _passed(seven[0]["replay_refused_across_a_reset"])


def test_check_5_a_widening_without_its_statement_is_refused(seven):
    _passed(seven[0]["widening_refused"])


def test_check_6_a_revocation_is_applied_and_the_revoked_release_refused(seven):
    _passed(seven[0]["revocation_applied_then_refused"])


def test_check_7_expiry_is_refused_by_default_and_held_on_the_hold_build_until_a_revocation(seven):
    out, fleet = seven
    _passed(out["expiry_refused_by_default"], 2)
    _passed(out["hold_keeps_deciding"], 1)
    _passed(out["hold_dropped_on_revocation"], 1)
    assert fleet.holds == [0, 0, 1]


def _commit(fleet, signer, table, seq, replaces=""):
    checks.deliver_all(fleet, signer.release_with_statement(table, seq, replaces=replaces))
    return checks.commit(fleet, signer.stream, seq, canon.sha256_hex(table))


def test_controller_statements_in_frames_of_type_6_set_the_epoch_and_freshness_lapses(binary):
    """H9, H15, H16 on the firmware: each node takes a statement of its stream under the controller key and reports
    its epoch id, takes nothing from one signed by the authority key or naming another stream and sends no record
    for either, reports epoch 0 after a reset, and with `fresh` 3600 lapses 300 seconds after its fresh statement's
    `expires` (X1)."""
    fleet, signer = _fleet(binary, fresh=3600), _signer()
    try:
        _commit(fleet, signer, TABLE_A, 1)
        now = fleet.time()
        sent = fleet.control(frames.encode(frames.Epoch(1, signer.statement(7, fresh=True, stream_seq=1,
                                                                           expires=now + 3600))))
        forged = fleet.control(frames.encode(frames.Epoch(2, signer.statement(9, key=GEN.test_key("A")))))
        other = fleet.control(frames.encode(frames.Epoch(3, signer.statement(9, stream="mesh/other"))))
        assert all(records == [] for answer in (sent, forged, other) for records in answer.values())
        assert all(record.epoch == 7 for records in fleet.beat().values() for record in records)
        assert all(record.epoch == 0 for records in fleet.reset().values() for record in records)
        assert all(record.epoch == 0 for records in fleet.beat().values() for record in records)
        lapsed = fleet.wait(3901)
        assert {node_id: [(record.event, record.cause) for record in records] for node_id, records in lapsed.items()} \
            == {node_id: [("lapsed", "dist:expired")] for node_id in fleet.ids}
    finally:
        fleet.close()


def test_an_action_floor_over_the_radio_decides_under_the_mesh_layout(binary):
    """Section 21, AF9, AF10 on the firmware's layout: command 0, its parameter level 1 and the node's own reading
    clear 2, stale after 5 seconds. A narrow floor signed by both install keys is applied on all three and allows
    command 2 at level 15 while clear is fresh, is silent when clear is stale or the level is out of its bounds, and
    a floor that bounds the level from one side only is refused with dist:floor-broad. A table whose fields the
    compiler would number otherwise than the layout is refused before it is sealed."""
    signer = _signer(install=[GEN.test_key("J"), GEN.test_key("K")])
    fleet = _fleet(binary, install=("J", "K"))
    try:
        applied = fleet.deliver(*signer.floor(tables.floor_table()))
        assert all([record.event for record in records] == ["staged", "install-widened"] for records in applied.values())
        floor_allowed = causes.NAMES["dist:floor-allowed"]
        assert set(fleet.ask(tables.regs(2, 15, 1), "-,-,1").values()) == {(ALLOW, floor_allowed, BASIS_FLOOR, 0)}
        lapsed = causes.NAMES["dist:policy-lapsed"]
        assert set(fleet.ask(tables.regs(2, 15, 1), "-,-,9").values()) == {(REFUSE, lapsed, 0, 0)}
        assert set(fleet.ask(tables.regs(2, 25, 1), "-,-,1").values()) == {(REFUSE, lapsed, 0, 0)}
        broad = fleet.deliver(*signer.floor(tables.compile_policy("when command == 2 and level >= 10 and clear == 1"),
                                            seq=2))
        assert all([(record.event, record.cause) for record in records] == [("refused", "dist:floor-broad")]
                   for records in broad.values())
        with pytest.raises(ValueError):
            tables.compile_policy("when command == 2 and clear == 1")       # clear would be register 1
    finally:
        fleet.close()


def test_the_install_parts_are_read_from_their_second_copy(binary):
    """IS10 on the firmware's two NVS partitions: a node whose first copy of the install record and of its floor
    no longer reads starts from the second and still decides under the floor, and a node that holds neither copy
    reports dist:install-lost."""
    signer = _signer(install=[GEN.test_key("J"), GEN.test_key("K")])
    fleet = _fleet(binary, install=("J", "K"))
    try:
        fleet.deliver(*signer.floor(tables.floor_table()))
        index = {part: k for k, part in enumerate(["anchor", "counter", "trust", "floor", "active", "previous", "staged",
                                                   "pending", "install", "rates", "set_floor", "set_fallback",
                                                   "set_ceiling", "fresh"])}
        fleet.lines([f"corrupt 0 0 {index['install']}", f"corrupt 0 0 {index['set_floor']}",
                     f"corrupt 1 0 {index['install']}", f"corrupt 1 1 {index['install']}"])
        restarted = fleet.reset()
        assert restarted["node0"] == [] and restarted["node2"] == []
        assert [(record.event, record.cause) for record in restarted["node1"]] == [("refused", "dist:install-lost")]
        answers = fleet.ask(tables.regs(2, 15, 1), "-,-,1")
        assert answers["node0"][:3] == answers["node2"][:3] == (ALLOW, causes.NAMES["dist:floor-allowed"], BASIS_FLOOR)
        assert answers["node1"][0] == REFUSE
    finally:
        fleet.close()


def test_the_nvs_partitions_hold_the_largest_durable_state_the_core_allows(binary):
    """The review's finding: the default NVS partition of 24 kB is too small. partitions.csv gives `nvs` 128 kB and
    `nvs_copy` 64 kB. At the bounds of pp_dist.h every part takes 69,494 bytes with the instance key's seed, and the
    install parts 28,048 bytes on the second medium. Each partition holds them, PHY calibration (1,904 bytes, on
    `nvs`), room to write its largest part again and the one free page NVS keeps."""
    fleet = _fleet(binary)
    try:
        sizes = {int(words[1]): int(words[2]) for words in (line.split() for line in fleet.lines(["bounds"]))}
    finally:
        fleet.close()
    copied = [sizes[part] for part in (256, 512, 1024, 2048, 4096)]
    main = [*sizes.values(), 32]
    assert len(sizes) == 14 and sum(main) == 69494 and sum(copied) == 28048 and sizes[2] == 20
    table = sim.partitions(MESH / "partitions.csv")
    assert table["nvs"][3] == 0x20000 and table["nvs_copy"][3] == 0x10000
    assert sim.nvs_pages(main, extra_entries=sim.nvs_entries(1904) + 1) <= table["nvs"][3] // sim.NVS_PAGE
    assert sim.nvs_pages(copied) <= table["nvs_copy"][3] // sim.NVS_PAGE
    assert sim.nvs_pages(main, extra_entries=sim.nvs_entries(1904) + 1) > 0x6000 // sim.NVS_PAGE    # 24 kB is not
    spans = sorted((offset, offset + size) for _kind, _sub, offset, size in table.values())
    assert all(end <= start for (_s, end), (start, _e) in zip(spans, spans[1:]))                     # no overlap
    assert table["factory"][2] % 0x10000 == 0 and spans[-1][1] <= 0x200000                             # 2 MB flash


def test_one_build_runs_on_every_crystal_with_the_partition_table():
    """The ESP32 classic boards run one build: the crystal is detected (CONFIG_XTAL_FREQ_AUTO), and the build takes
    partitions.csv. A built sdkconfig beside the project holds the same, as fleet/run.py checks after each build."""
    defaults = (MESH / "sdkconfig.defaults").read_text(encoding="utf-8").splitlines()
    assert {"CONFIG_XTAL_FREQ_AUTO=y", "CONFIG_PARTITION_TABLE_CUSTOM=y",
            'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"'} <= set(defaults)
    from fleet import run
    for built in (MESH / "sdkconfig", MESH / "sdkconfig.default", MESH / "sdkconfig.hold"):
        if built.exists():
            run.check_settings(built, {"CONFIG_XTAL_FREQ_AUTO": "y", "CONFIG_PARTITION_TABLE_CUSTOM": "y"})


def test_the_firmware_carries_the_layout_and_domain_its_generator_writes():
    """AF10, CL4: main/tables.h holds the layout hash and the domain hash gen_mesh_tables.py computes, and the
    anchor names a controller key, as P4 lets a `/2` anchor."""
    text = (MESH / "main" / "tables.h").read_text(encoding="utf-8")
    array = lambda hex_text: ", ".join(f"0x{byte:02x}" for byte in bytes.fromhex(hex_text))  # noqa: E731
    assert array(tables.layout_sha256()) in text and array(tables.domain_sha256()) in text
    assert ".has_controller = 1" in text and '.stream = "mesh/demo"' in text
    assert tables.header(_pub("A"), _pub("C")).count("MESH_LAYOUT") == 1
