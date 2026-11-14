# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The network policy image, its table, and the XDP program's userspace path against the Python decision."""
import itertools
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from integrations.governed_net import differential, frame as fr, owner_rules, protocol as p, xdp_userspace
from integrations.governed_net.policy import POLICY_PATH, SOURCE_PATH, NetPolicy, write_build

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "formal" / "diff"))
import core_diff  # noqa: E402
from prismpath.kernel import causes  # noqa: E402

# the field space the exhaustive check walks: every command and class the protocol can carry, and every
# argument and length on and beside each bound the rules name
SPACE = {"version": [1], "cmd": list(range(1, 12)), "hclass": [0, 1, 2, 3, 4, 5, 255],
         "arg0": [0, 1, 2, 3, 4, 50, 51, 2 ** 31 - 1], "arg1": [0, 1, 4096, 4097, 2 ** 31 - 1],
         "name_len": [0, 1, 64], "data_len": [0, 1, 1024]}


@pytest.fixture(scope="module")
def policy():
    return NetPolicy.load()


@pytest.fixture(scope="module")
def built(tmp_path_factory, policy):
    out = tmp_path_factory.mktemp("gnet")
    build = write_build(out / "policy", policy)
    return policy, build, xdp_userspace.build(out / "bin")


def readings():
    keys = list(SPACE)
    for values in itertools.product(*(SPACE[key] for key in keys)):
        yield dict(zip(keys, values))


def test_image_is_canonical_and_from_its_source(policy):
    done = subprocess.run([sys.executable, "-m", "prismpath.cli", "canonicalize", str(SOURCE_PATH)], capture_output=True,
                          check=True, cwd=REPO)
    assert done.stdout.rstrip(b"\n") == policy.image
    assert POLICY_PATH.read_bytes().rstrip(b"\n") == policy.image


def test_every_target_names_a_registered_routing_cause(policy):
    for label in policy.labels:
        kind, cause, code = policy.rule_decision(policy.labels.index(label))
        if kind != "allow":
            assert causes.code(cause) == code
            assert causes.cause_class(code) == "routing"


def test_image_equals_the_plain_rules_on_the_whole_space(policy):
    count = 0
    for reading in readings():
        decision = policy.decide(policy.reading_bytes(reading))
        assert (decision.kind, decision.cause) == owner_rules.expected(reading), reading
        count += 1
    assert count == 11 * 7 * 8 * 5 * 3 * 3


@pytest.mark.skipif(not core_diff.ORACLE.exists(), reason="the Lean oracle is not built (PRISMPATH_CORE_ORACLE)")
def test_lean_oracle_agrees_on_the_whole_space(policy):
    all_readings = [policy.reading_bytes(reading) for reading in readings()]
    cases = [{"id": "net", "image": policy.image, "readings": all_readings, "render_seed": 0}]
    rows = core_diff.lean_leg(cases)
    oracle = rows["net"]["readings"]
    assert len(oracle) == len(all_readings)
    for raw, verdict in zip(all_readings, oracle):
        mine = policy.verdict(raw)
        assert core_diff.normalize_reading(verdict) == core_diff.normalize_reading(mine)


def test_table_reads_only_the_protocol_fields_in_order(policy):
    magic, version, n_fields, n_interns = struct.unpack_from("<IHHH", policy.ppt)
    assert (magic, version, n_fields, n_interns) == (0x4D545050, 1, len(p.SCHEMA), 1)
    assert len(policy.labels) == 13


def test_xdp_userspace_agrees_with_python_on_the_whole_space(built):
    policy, build, binary = built
    frames = []
    for reading in readings():
        cmd = reading["cmd"]
        req = p.Request(cmd=cmd, request_id=11, hclass=reading["hclass"], handle=1 if reading["hclass"] else 0,
                        arg0=reading["arg0"], arg1=reading["arg1"], name=b"n" * reading["name_len"],
                        data=b"d" * reading["data_len"])
        frames.append(fr.build(p.encode(req)))
    rows = xdp_userspace.batch(binary, build["ppt"], build["actions"], frames)
    counts = differential.compare(policy, frames, rows)
    assert counts["disagree"] == 0, counts["first"]
    assert counts["receipts_compared"] > 0


def test_differential_small_corpus(built):
    policy, build, binary = built
    parts = differential.corpus(4000, seed=3)
    for frames in parts.values():
        counts = differential.compare(policy, frames, xdp_userspace.batch(binary, build["ppt"], build["actions"], frames))
        assert counts["disagree"] == 0, counts["first"]


def test_the_differential_sees_a_wrong_table(built, tmp_path):
    """A fault in the kernel's inputs must show: allow every rule in the action file, then swap two rules."""
    policy, build, binary = built
    frames = differential.corpus(2000, seed=4)["random"]
    actions = bytearray(Path(build["actions"]).read_bytes())
    for rule in range(len(policy.labels)):
        actions[40 + 4 * rule] = 1
    wrong = tmp_path / "wrong.actions"
    wrong.write_bytes(bytes(actions))
    rows = xdp_userspace.batch(binary, build["ppt"], wrong, frames)
    assert differential.compare(policy, frames, rows)["disagree"] > 0
    # the table itself: the first atom is `hclass > 4`; make it `hclass > 200`
    table = bytearray(Path(build["ppt"]).read_bytes())
    field, op, ty, value = struct.unpack_from("<HBBi", table, 28)
    assert (field, value) == (p.SCHEMA.index("hclass"), 4)
    struct.pack_into("<HBBi", table, 28, field, op, ty, 200)
    bent = tmp_path / "bent.ppt"
    bent.write_bytes(bytes(table))
    rows = xdp_userspace.batch(binary, bent, build["actions"], frames)
    assert differential.compare(policy, frames, rows)["disagree"] > 0


def test_fail_closed(built):
    policy, build, binary = built
    frames = differential.structured()[:3000]
    closed = differential.fail_closed(binary, build, policy, frames)
    assert closed["allowed_with_empty_tables"] == 0
    assert closed["allowed_with_full_ring"] == 0
    assert closed["other_traffic_unchanged"]


def test_other_traffic_is_never_read(built):
    policy, build, binary = built
    good = p.encode(p.Request(cmd=p.WRITE, request_id=1, hclass=p.H_TC_FILE, handle=1, data=b"x"))
    frames = [fr.build(good, dport=22), fr.build(good, dport=p.PORT - 1), fr.build(good, proto=6),
              fr.build(good, ethertype=0x0806), fr.build(good, frag=0x0010), fr.build(b"garbage", dport=443)]
    rows = xdp_userspace.batch(binary, build["ppt"], build["actions"], frames)
    assert [row.outcome for row in rows] == [fr.OTHER] * len(frames)
    assert [row.emitted for row in rows] == [0] * len(frames)


def test_toolchain_write_is_dropped_with_its_cause(built):
    policy, build, binary = built
    raw = p.encode(p.Request(cmd=p.WRITE, request_id=1, hclass=p.H_TC_FILE, handle=1, data=b"x"))
    (row,) = xdp_userspace.batch(binary, build["ppt"], build["actions"], [fr.build(raw)])
    assert (row.outcome, row.cause) == (fr.DROP_POLICY, causes.code("agent:toolchain-write"))


def test_household_traffic_all_passes(built):
    policy, build, binary = built
    frames = differential.household()
    rows = xdp_userspace.batch(binary, build["ppt"], build["actions"], frames)
    assert [row.outcome for row in rows] == [fr.OTHER] * len(frames)
    assert all(row.emitted == 0 for row in rows)


def test_same_port_other_host_passes_but_server_host_is_matched(built):
    policy, build, binary = built
    good = p.encode(p.Request(cmd=p.READ, request_id=1, hclass=p.H_WS_FILE, handle=9, arg1=100))
    other_host = fr.build(good, dst="192.0.2.99")           # the agent port, different host
    the_server = fr.build(good, dst=fr.SERVER_IP)           # the configured server and port
    other_port = fr.build(good, dport=p.PORT + 1)           # the server host, different port
    rows = xdp_userspace.batch(binary, build["ppt"], build["actions"], [other_host, the_server, other_port])
    assert rows[0].outcome == fr.OTHER                       # another host: passed
    assert rows[1].outcome == fr.ALLOW                       # the server: decided and allowed
    assert rows[2].outcome == fr.OTHER                       # another port: passed


def test_counters_agree_with_python(built):
    policy, build, binary = built
    frames = differential.structured()[:4000] + differential.household()
    got = []
    xdp_userspace.batch(binary, build["ppt"], build["actions"], frames, counters=got)
    assert got and got[0] == differential.tally(policy, frames)


def test_full_differential_including_household(built):
    policy, build, binary = built
    parts = differential.corpus(4000, seed=11)
    assert "household" in parts
    for name, frames in parts.items():
        counts = differential.compare(policy, frames, xdp_userspace.batch(binary, build["ppt"], build["actions"], frames))
        assert counts["disagree"] == 0, (name, counts["first"])
