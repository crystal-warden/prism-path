# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The constrained profile (spec-policy-distribution.md B12) on the host: prismpath-hw/dist/pp_dist.c built with
PP_DIST_PROFILE_MIN, as the Uno builds it, under host_check_min.c with the host cc and
`-Wall -Wextra -Werror -fsanitize=address,undefined`.

The same corpus cases and machine scripts the full C core answers are run on this build, and each answer is the
full core's and the Python reference's, but where B12 says the profile answers otherwise. Case 122 is this
profile's: on an ordered link it stages a release whose sealed envelope it never held whole, and drops a chunk out of
order. The relay of B10 (prismpath-hw/esp-relay-c6) is run on its forwarding code for case 121, and the fleet entries
of the Uno and the C6 are held with no board attached. The skips name their reason when there is no compiler."""
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from prismpath.distribution import envelope as env
from prismpath.distribution import state_record
from prismpath.distribution.kinds import Refused
from prismpath.kernel import causes
from prismpath.tests import _dist
from prismpath.tests import test_distribution_c as full
from prismpath.tests.test_distribution_c import (
    host_check,  # noqa: F401  the full core's harness, a fixture
)

ROOT = Path(__file__).resolve().parents[2]
HW = ROOT / "prismpath-hw"
DIST = HW / "dist"
MONOCYPHER = HW / "mesh" / "main"
RELAY = HW / "esp-relay-c6"
CC = shutil.which("cc")
AVR_GCC = shutil.which("avr-gcc")
MIN = ["-DPP_DIST_PROFILE_MIN"]
S, N, E, H, BODIES = full.S, full.N, full.E, full.H, full.BODIES
INVALID = f"dropped {causes.NAMES['dist:frame-invalid']}"


def _build(tmp_path_factory, name: str, sources: list, flags: list) -> Path:
    if not (DIST / "pp_dist.c").exists():
        pytest.skip("the C core is in prismpath-hw, which this tree does not carry")
    if CC is None:
        pytest.skip("no C compiler (cc) on this host, so the C core is not built here")
    out = tmp_path_factory.mktemp(name) / name
    subprocess.run([CC, *full.FLAGS, *flags, *map(str, sources), "-o", str(out)], check=True, capture_output=True,
                   text=True)
    return out


@pytest.fixture(scope="module")
def host_check_min(tmp_path_factory):
    return _build(tmp_path_factory, "host_check_min",
                  [DIST / "host_check_min.c", DIST / "pp_dist.c", MONOCYPHER / "monocypher.c",
                   MONOCYPHER / "monocypher-ed25519.c"], [*MIN, f"-I{DIST}", f"-I{MONOCYPHER}"])


@pytest.fixture(scope="module")
def host_relay(tmp_path_factory):
    return _build(tmp_path_factory, "host_relay", [RELAY / "host_relay.c", RELAY / "main" / "relay.c"],
                  [f"-I{RELAY / 'main'}", f"-I{DIST}"])


def _harness(binary, lines: list) -> list:
    done = subprocess.run([str(binary)], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=120,
                          check=False)
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()


# ------------------------------------------------------------------ the build is its own

def test_the_profile_builds_none_of_the_full_core_and_holds_no_envelope_buffer(tmp_path):
    """B12: the MIN build of pp_dist.c defines the profile and nothing of the full core, and no member of its state is
    sized to hold a sealed envelope or an envelope, so it checks one only as it arrives."""
    if CC is None:
        pytest.skip("no C compiler (cc) on this host")
    obj = tmp_path / "min.o"
    subprocess.run([CC, "-std=c11", "-Wall", "-Wextra", "-Werror", *MIN, f"-I{DIST}", f"-I{MONOCYPHER}", "-c",
                    str(DIST / "pp_dist.c"), "-o", str(obj)], check=True, capture_output=True, text=True)
    names = subprocess.run(["nm", str(obj)], capture_output=True, text=True, check=True).stdout
    defined = {line.split()[-1] for line in names.splitlines() if re.match(r"^[0-9a-f]+ [TtDdBbRr] ", line)}
    assert {"pp_min_frame", "pp_min_stage", "pp_min_sealed", "pp_validate_image", "pp_sha256"} <= defined
    assert not defined & {"pp_verify", "pp_pep_open", "pp_assembler_receive", "pp_read_envelope", "pp_counting"}
    header = (DIST / "pp_dist.h").read_text(encoding="utf-8")
    profile = header[header.index("#ifdef PP_DIST_PROFILE_MIN"):]
    assert not re.search(r"\[(PP_MAX_SEALED|PP_MAX_ENVELOPE|PP_TRUST_BOUND)[^\]]*\]", profile)
    used = set(re.findall(r"\bcrypto_\w+", (DIST / "pp_dist.c").read_text(encoding="utf-8").split(
        "#else /* PP_DIST_PROFILE_MIN */")[1]))
    assert {"crypto_sha512_update", "crypto_eddsa_reduce", "crypto_eddsa_check_equation"} <= used
    assert "crypto_ed25519_check" not in used         # the one pass check, never the check of a whole message


# ------------------------------------------------------------------ case 122, the ordered link

def _anchor_lines(seed: str = full.INSTANCE_SEED) -> list:
    public = _dist.public("A")
    return [f"key {env.key_id(public)} {public.hex()} 0", f"machine 0 1 {seed}"]


def _frame_steps(binary, frames_in: list, now: int = N, setup=()) -> list:
    """Each frame in order through a provisioned profile PEP: one (event, records) pair a frame."""
    lines = _anchor_lines() + [f"provision {S} {now}", *setup]
    lines += [f"frame {data.hex()} {10 * index} {now}" for index, data in enumerate(frames_in)] + ["done"]
    out = _harness(binary, lines)
    assert out[0].startswith("records ")
    steps = out[1 + len(setup):]
    return [(steps[k], steps[k + 1]) for k in range(0, len(steps), 2)]


def test_case_122_an_ordered_link_stages_a_release_never_held_whole_and_drops_a_chunk_out_of_order(host_check_min):
    """case_122: B11, B12. Through the profile, frame for frame as frames.Assembler answers on an ordered link, the
    chunks of a release in offset order are staged with the record of G1, and a chunk out of order, one repeated or
    one that skips ahead drops the transfer with dist:frame-invalid and stages nothing. The harness hands each frame
    from one buffer it writes over after the call, and the profile holds no buffer of an envelope's size, so the
    sealed envelope was never held whole."""
    frames = full._frames_module()
    case = next(case for case in full.C_CASES if case["name"].startswith("001_round_trip"))
    statement = _dist.widening()
    sealed = _dist.seal("policy.ppt", BODIES[0], seq=1, targets=("mesh",), widens=True)
    covering = _dist.seal("trust.widening", statement, seq=1, release=env.release_id([("policy.ppt", H[0])]),
                          policy_sha256=H[0], targets=("mesh",), widens=True)
    for limit in (64, 216, 250):
        offer, *chunks = frames.frames_for(7, sealed, BODIES[0], limit)
        sealed_chunks = [data for data in chunks if frames.decode(data, limit).part == frames.SEALED]
        assert len(sealed_chunks) >= 3, limit
        runs = {"in order": [offer, *chunks], "second first": [offer, sealed_chunks[1]],
                "skips one": [offer, sealed_chunks[0], sealed_chunks[2]],
                "repeat": [offer, sealed_chunks[0], sealed_chunks[0]], "reversed": [offer, *reversed(sealed_chunks)]}
        for name, run in runs.items():
            sequence = [(data, 10 * index) for index, data in enumerate(run)]
            python = full._python_events(frames, case, sequence, ordered=True, limit=limit)
            steps = _frame_steps(host_check_min, run)
            assert [event for event, _records in steps] == [
                "whole" if line.startswith("whole ") else line for line in python], (name, limit)
            staged = [record for _event, line in steps for record in full._records(line)]
            if name == "in order":   # a first install needs its statement (W3); the profile still stages the table
                assert [(r.event, r.cause) for r in staged] == [("refused", "dist:widening-unsigned")]
            else:
                assert staged == [] and INVALID in [event for event, _records in steps], (name, limit)
        whole = list(frames.frames_for(8, covering, statement, limit)) + [offer, *chunks]
        steps = _frame_steps(host_check_min, whole)
        records = [record for _event, line in steps for record in full._records(line)]
        assert [(r.event, r.cause, r.staged_seq) for r in records] == [("staged", None, 1), ("staged", None, 1)], limit


def test_a_commit_and_an_abort_frame_are_carried_out_on_the_staged_release(host_check_min):
    """B8, C1, A1 over the ordered link: a commit frame with a delay makes the release active only once the delay has
    passed on a tick, an abort frame that names nothing staged changes nothing, and one that names it drops it."""
    frames = full._frames_module()
    statement = _dist.widening()
    covering = _dist.seal("trust.widening", statement, seq=1, release=env.release_id([("policy.ppt", H[0])]),
                          policy_sha256=H[0], targets=("mesh",), widens=True)
    release = _dist.seal("policy.ppt", BODIES[0], seq=1, targets=("mesh",), widens=True)
    sent = list(frames.frames_for(1, covering, statement)) + list(frames.frames_for(2, release, BODIES[0]))
    commit = frames.encode(frames.commit_for(3, S, 1, H[0], 120))
    lines = _anchor_lines() + [f"provision {S} {N}"]
    lines += [f"frame {data.hex()} 0 {N}" for data in sent] + [f"frame {commit.hex()} 1000 {N}", f"tick 1119 {N}",
                                                                  f"tick 1120 {N}", "done"]
    out = _harness(host_check_min, lines)
    assert out[-4] == "control 4" and out[-3] == "records" and out[-2] == "records"
    assert [(r.event, r.active_seq) for r in full._records(out[-1])] == [("committed", 1)]
    renewal = _dist.seal("policy.ppt", BODIES[0], seq=2, targets=("mesh",), replaces=H[0], widens=False)
    other = frames.encode(frames.abort_for(4, S, 2, H[2]))
    named = frames.encode(frames.abort_for(4, S, 2, H[0]))
    tail = [f"frame {data.hex()} 2000 {N}" for data in frames.frames_for(5, renewal, BODIES[0])]
    out = _harness(host_check_min, lines[:-1] + [*tail, f"frame {other.hex()} 2100 {N}",
                                                  f"frame {named.hex()} 2200 {N}", "done"])
    assert full._events(out[-5]) == [("staged", None)]                   # W2: a renewal goes in on its signature
    assert full._events(out[-3]) == [("beat", None)] and full._events(out[-1]) == [("aborted", None)]


# ------------------------------------------------------------------ V2 to V11 against the corpus

def _profile_case(case: dict):
    """The case as the profile holds it (B12): the one authority key that one entry of the sealed envelope names, or
    an authority key it does not name, with that key's retired or revoked mark. None when the case needs more than
    the profile keeps: two held keys named, a key of another role named, revoked envelopes or policies it would have
    to keep a list of, or more than two envelope ids at the floor."""
    trust = case["trust"]
    if len(case["pep"]["floor"]["ids"]) > 2:
        return None
    if trust is None:
        return dict(case)
    if trust["revoked_envelopes"] or trust["revoked_policies"]:
        return None
    try:
        named = [kid for kid, _sig in env.unseal(bytes.fromhex(case["sealed"]))[1]]
    except Exception:  # noqa: BLE001  a container that does not read names no key
        named = []
    held = [kid for kid in named if kid in trust["keys"]]
    if len(held) > 1 or any(trust["keys"][kid]["role"] != "authority" for kid in held):
        return None
    kid = held[0] if held else next(k for k, v in trust["keys"].items() if v["role"] == "authority" and
                                    k not in trust["retired"] and k not in trust["revoked_keys"])
    trust = dict(trust, keys={kid: trust["keys"][kid]}, retired=[k for k in trust["retired"] if k == kid],
                 revoked_keys=[k for k in trust["revoked_keys"] if k == kid])
    return dict(case, trust=trust)


# B12: where the profile answers otherwise, and why. Every other case in its reach answers as recorded.
DECLARED = {
    "004_members_out_of_order_on_mesh": "its scanner reads canonical bytes only and says dist:bad-format",
    "070_a_later_list_dropping_the_key_on_mesh": "it keeps no list, so it cannot see a key dropped from one (R6)",
    "074_without_the_new_key_on_mesh": "it keeps no key a rotation adds, so it checks no signature by one (O2)",
    "131_a_ninth_key_on_mesh": "it keeps no key a rotation adds, so it has no ninth (K5)",
}


def _run_profile(binary, cases: list, piece: int = 7) -> dict:
    out = {}
    for line in _harness(binary, [f"piece {piece}"] + [line for case in cases for line in full._lines(case)]):
        name, code, unchanged, time_floor, envelope_id = line.split(" ")
        out[name] = {"cause": causes.name(int(code)) if int(code) else None, "unchanged": unchanged == "1",
                     "time_floor": None if time_floor == "-" else int(time_floor),
                     "envelope_id": None if envelope_id == "-" else envelope_id}
    return out


@pytest.mark.parametrize("piece", [1, 7, 64])
def test_every_corpus_case_in_the_profile_s_reach_answers_as_recorded(host_check_min, piece):
    """V1 to V11, E9, B12. Each C case of the corpus the profile can hold runs with every byte handed over in pieces of
    1, 7 or 64 bytes, and answers the cause, the unchanged flag, the time floor and the envelope id the Python
    verifier recorded, but for the cases B12 names, which answer as B12 says."""
    cases = [reduced for case in full.C_CASES if (reduced := _profile_case(case)) is not None]
    assert len(cases) >= 70
    got = _run_profile(host_check_min, cases, piece)
    assert sorted(got) == sorted(case["name"] for case in cases)
    differ = {case["name"] for case in cases if got[case["name"]] != case["expect"]}
    assert differ == set(DECLARED)
    assert got["004_members_out_of_order_on_mesh"]["cause"] == "dist:bad-format"
    for name in DECLARED:
        assert got[name]["cause"] in (None, "dist:bad-format")


def test_the_scanner_answers_as_the_python_reader_on_mutated_envelopes(host_check_min):
    """E2, E9, B12. The fuzz the full core runs, on the streaming scanner: each mutation of a good envelope sealed by
    key A is read by both or refused by both, where the profile says dist:bad-format for what the reference calls
    document:not-canonical. A mutation of `meta` that keeps it an object of at most three levels is left out when
    Python refuses it by E11, as on the full core."""
    import random
    good = next(case for case in full.C_CASES if case["name"].startswith("001_round_trip"))
    envelope_bytes, _entries = env.unseal(bytes.fromhex(good["sealed"]))
    gen = full._generator()
    rng = random.Random(17)
    alphabet = b'{}[]",:0123456789-.eE \\u"abcdefnrt\x00\xc3\xa9\xff'
    cases, expected = [], {}
    for index in range(400):
        raw = bytearray(envelope_bytes)
        for _ in range(rng.randint(1, 3)):
            at = rng.randrange(len(raw))
            choice = rng.random()
            if choice < 0.4:
                raw[at] = rng.choice(alphabet)
            elif choice < 0.7:
                del raw[at]
            else:
                raw.insert(at, rng.choice(alphabet))
        raw = bytes(raw)
        if not 1 <= len(raw) <= env.MAX_ENVELOPE:
            continue
        cause, meta_member = full._python_reads(raw)
        if meta_member:
            continue
        case = _profile_case(dict(good, name=f"fuzz_{index}", sealed=env.seal(raw, [gen.test_key("A")]).hex()))
        cases.append(case)
        expected[case["name"]] = "dist:bad-format" if cause == "document:not-canonical" else cause
    assert len(cases) > 250
    got = _run_profile(host_check_min, cases)
    wrong = {name: (got[name]["cause"], cause) for name, cause in expected.items()
             if (got[name]["cause"] if got[name]["cause"] == "dist:bad-format" else None) != cause}
    assert wrong == {}


def test_case_014_a_tampered_envelope_byte_is_sig_invalid_before_the_scanner_s_answer(host_check_min):
    """case_014: E9, V1, V3, B12. The scanner reads every byte as it arrives, and its answer waits for V3: each changed
    byte of a good envelope under its good signature is sig:invalid, the ones that no longer read included."""
    good = next(case for case in full.C_CASES if case["name"].startswith("001_round_trip"))
    sealed = bytes.fromhex(good["sealed"])
    envelope_bytes, _entries = env.unseal(sealed)
    start = len(sealed) - len(envelope_bytes)
    cases = []
    for at in (0, 1, len(envelope_bytes) // 2, len(envelope_bytes) - 1):
        tampered = bytearray(sealed)
        tampered[start + at] = ord("{") if tampered[start + at] != ord("{") else ord("[")
        cases.append(_profile_case(dict(good, name=f"tampered_{at}", sealed=bytes(tampered).hex())))
    got = _run_profile(host_check_min, cases)
    assert {name: result["cause"] for name, result in got.items()} == {case["name"]: "sig:invalid" for case in cases}
    assert all(result["envelope_id"] is None for result in got.values())


# ------------------------------------------------------------------ the machine, step for step against pep.py

def _min_steps(binary, script: list) -> list:
    return _harness(binary, full._c_lines(script, hold=False))


def _same(binary, tmp_path, script, *, statements=True) -> list:
    """`script` on the Python machine and on the profile, which must sign the same records byte for byte."""
    script, quiet = full._with_statements(script) if statements else (script, set())
    python = full._python_steps(script, hold=False, tmp_path=tmp_path)
    assert _min_steps(binary, script) == python
    return [line for index, line in enumerate(python) if index not in quiet]


def test_case_046_047_048_052_053_stage_commit_and_abort_sign_the_python_machine_s_records(host_check_min, tmp_path):
    """case_046: G1. case_047: G2. case_048: C1. case_052: C5, H4. case_053: A1. The full core's script, through the
    profile. A table below the staged seq is refused by G2 without writing over the staged one (B12)."""
    script = [("provision", S, N), ("commit", S, 1, H[0], N),
              ("stage", full._sealed(0, 1), BODIES[0].hex(), N),
              ("stage", full._sealed(1, 2, signer="U"), BODIES[1].hex(), N),
              ("stage", full._sealed(1, 3), BODIES[1].hex(), N), ("stage", full._sealed(0, 2), BODIES[0].hex(), N),
              ("commit", S, 3, H[0], N), ("commit", S, 3, H[1], N),
              ("stage", full._sealed(2, 4), BODIES[2].hex(), N), ("abort", S, 5, H[2], N), ("abort", S, 4, H[2], N),
              ("stage", full._sealed(1, 3), BODIES[1].hex(), N), ("record", "beat", N), ("restart", N),
              ("stage", full._sealed(1, 3), BODIES[1].hex(), N)]
    lines = _same(host_check_min, tmp_path, script)
    assert full._events(lines[5]) == [("refused", "dist:seq-replay")]
    committed = full._records(lines[7])[0]
    assert (committed.event, committed.active_seq, committed.floor) == ("committed", 3, 3)
    assert full._records(lines[11])[0].event == "beat"            # Q3: the committed envelope again changes nothing


def test_case_060_061_062_063_the_widening_rule_signs_the_python_machine_s_records(host_check_min, tmp_path):
    """case_060: W2. case_061: W2, W3, W6. case_062: W4, W5. case_063: W2, W3. The full core's script, through the
    profile, which reads each widening statement as it arrives and keeps only what it covers."""
    def release(index, seq, statement=None, **args):
        steps = []
        if statement is not None:
            body = _dist.widening(statement)
            steps.append(("stage", _dist.seal("trust.widening", body, seq=seq, release=env.release_id(
                [("policy.ppt", H[index])]), policy_sha256=H[index], targets=("mesh",), **args).hex(), body.hex(), N))
        return steps + [("stage", full._sealed(index, seq, **args), BODIES[index].hex(), N)]

    script = [("provision", S, N)]
    script += release(0, 1)
    script += release(0, 1, [], widens=True) + [("commit", S, 1, H[0], N)]
    script += release(0, 2, replaces=H[0], widens=False) + [("commit", S, 2, H[0], N)]
    script += release(2, 3, replaces=H[2], widens=False)
    script += release(2, 4, replaces=H[0], widens=True)
    script += release(2, 5, replaces=H[0], widens=False)
    script += release(2, 6, [], replaces=H[0], widens=False)
    script += release(2, 7, [H[0]], replaces=H[0], widens=True)
    script += release(1, 8, [H[1]], replaces=H[0], widens=True)
    events = [full._events(line) for line in _same(host_check_min, tmp_path, script, statements=False)]
    assert events[1] == [("refused", "dist:widening-unsigned")] and events[4] == events[6] == [("committed", None)]
    assert events[13] == [("staged", None)] and events[15] == [("refused", "dist:widening-unsigned")]


def test_case_024_026_050_077_143_time_expiry_and_a_lapse_sign_the_python_machine_s_records(host_check_min, tmp_path):
    """case_026: T1, V13. case_050: C3. case_077: X1, X2, REFUSE, the only expiry response of the profile (B12).
    case_143: C3, V12. A release that expires lapses on a tick, the time floor holds over a restart, and a renewal
    staged before its active release lapsed is refused at commit."""
    late = E - 100
    script = [("provision", S, N), ("stage", full._sealed(0, 1, not_before=late), BODIES[0].hex(), late),
              ("stage", full._sealed(1, 2, expires=late - 10, widens=False), BODIES[1].hex(), N),
              ("commit", S, 1, H[0], N), ("tick", E - 1), ("tick", E), ("record", "beat", E),
              ("stage", full._sealed(1, 2, expires=N + 10, widens=False), BODIES[1].hex(), E), ("restart", N),
              ("stage", full._sealed(2, 3, expires=late - 10, widens=False), BODIES[2].hex(), N)]
    lines = _same(host_check_min, tmp_path / "expiry", script)
    assert full._events(lines[2]) == [("refused", "dist:expired")]
    assert full._events(lines[5])[0] == ("lapsed", "dist:expired")
    assert full._events(lines[9]) == [("refused", "dist:expired")]       # the time floor held over the restart
    renewal = ([("provision", S, N)] + full._release_steps(0, 1, [], widens=True, expires=N + 100)
               + [("commit", S, 1, H[0], N)] + full._release_steps(0, 2, replaces=H[0], widens=False)
               + [("tick", N + 100), ("commit", S, 2, H[0], N + 100)])
    last = full._records(_same(host_check_min, tmp_path / "renewal", renewal, statements=False)[-1])[-1]
    assert (last.event, last.cause, last.state) == ("refused", "dist:widening-unsigned", "no-policy")


@pytest.mark.parametrize("ground", ["envelope", "policy", "key", "floor"])
def test_case_069_a_revocation_that_removes_the_ground_lapses_the_release(host_check_min, tmp_path, ground):
    """case_069: R2, R4, R5, B12. A list that names the active envelope, its policy, the one key or a floor above its
    seq lapses the release with dist:revoked and drops a staged release on that ground. The profile reads the list
    as it arrives and keeps of it only what touches what it holds."""
    staged = _dist.seal("policy.ppt", BODIES[0], seq=4, targets=("mesh",), widens=True)
    active = _dist.seal("policy.ppt", BODIES[0], seq=3, targets=("mesh",), widens=True)
    ids = [env.envelope_id(env.unseal(sealed)[0]) for sealed in (active, staged)]
    lists = {"envelope": {"envelopes": ids},
             "policy": {"policies": [H[0]]}, "key": {"keys": [_dist.key_id("A")]}, "floor": {"floors": {S: 5}}}[ground]
    script = [("provision", S, N), ("stage", active.hex(), BODIES[0].hex(), N), ("commit", S, 3, H[0], N),
              ("stage", staged.hex(), BODIES[0].hex(), N), full._revoke(1, N, **lists), ("restart", N),
              ("stage", active.hex(), BODIES[0].hex(), N)]
    lines = _same(host_check_min, tmp_path / ground, script)
    applied = full._records(lines[-3])
    assert [(record.event, record.cause) for record in applied] == [("lapsed", "dist:revoked"), ("trust-applied", None)]
    assert applied[-1].state == "no-policy" and not applied[-1].staged
    again = {"envelope": "dist:revoked", "policy": "dist:revoked", "key": "sig:revoked-key", "floor": "dist:seq-replay"}
    assert full._events(lines[-1]) == [("refused", again[ground])]


def test_case_066_068_071_079_revocation_lists_sign_the_python_machine_s_records(host_check_min, tmp_path):
    """case_066: R1. case_068: R4, Q4. case_071: R7. case_079: X4. One trust sequence with no step skipped, a floor
    that only rises, lists past 64 entries or 16 streams, and a list read ten years on, each as the Python machine
    answers. The profile counts a list it never holds."""
    many = [hashlib.sha256(bytes([index])).hexdigest() for index in range(65)]
    script = [("provision", S, N), full._revoke(1, N, floors={S: 9}), full._revoke(1, N, floors={S: 9}),
              full._revoke(3, N), ("stage", full._sealed(1, 9), BODIES[1].hex(), N),
              ("stage", full._sealed(1, 10), BODIES[1].hex(), N), full._revoke(2, N, floors={S: 5}),
              ("record", "beat", N), full._revoke(3, N, envelopes=many),
              full._revoke(3, N, floors={f"s{index}": 1 for index in range(17)}),
              full._revoke(3, N + 10 * 365 * 86400, envelopes=many[:4], floors={f"s{index}": 1 for index in range(2)})]
    lines = _same(host_check_min, tmp_path, script)
    assert full._events(lines[2]) == [("beat", None)] and full._events(lines[3])[0][1] == "dist:trust-replay"
    assert full._events(lines[4])[0][1] == "dist:seq-replay" and full._events(lines[5]) == [("staged", None)]
    assert full._events(lines[6]) == [("trust-applied", None)] and full._records(lines[7])[0].floor == 9
    assert full._events(lines[8])[0][1] == full._events(lines[9])[0][1] == "dist:too-large"
    assert full._events(lines[10]) == [("trust-applied", None)]


def test_case_072_073_123_a_rotation_and_a_controller_key_keep_the_one_trust_sequence(host_check_min, tmp_path):
    """case_072: O1, O3. case_073: O3, S5. case_123: O1, R1. K7, B12. The profile takes every trust statement on the one
    trust sequence. A rotation that retires its key leaves the release active under it deciding (O3) and refuses
    what that key signs after with sig:revoked-key, as the Python machine does. A `trust.controller` moves the
    sequence and names no key it keeps."""
    script = [("provision", S, N), ("stage", full._sealed(0, 1), BODIES[0].hex(), N), ("commit", S, 1, H[0], N),
              full._rotate(1, N, "B", signers=("A", "B")), full._rekey("C", 2), full._revoke(3, N),
              full._rotate(5, N, "Q", signers=("A", "Q")), full._rotate(4, N, "B", retire="A", signers=("A", "B")),
              ("stage", full._sealed(1, 2, signer="A"), BODIES[1].hex(), N), ("record", "beat", N),
              ("restart", N), ("record", "beat", N)]
    lines = _same(host_check_min, tmp_path, script)
    assert [full._events(lines[k]) for k in (3, 4, 5)] == [[("trust-applied", None)]] * 3
    assert full._events(lines[6])[0][1] == "dist:trust-replay" and full._events(lines[7]) == [("trust-applied", None)]
    assert full._events(lines[8])[0][1] == "sig:revoked-key"
    assert full._records(lines[9])[0].state == full._records(lines[11])[0].state == "active"


def test_case_027_038_a_pep_with_no_clock_and_a_delayed_commit(host_check_min):
    """case_027: T2. case_038: B8. A profile PEP with no clock restarts at its saved time floor and still refuses an
    envelope that expired before it, and a commit with a delay of 120 ms is active at the PEP's time plus the delay."""
    late = E - 100
    first = ("stage", full._sealed(0, 1, not_before=late), BODIES[0].hex(), N)
    (statement, _release), _quiet = full._with_statements([first])
    public = _dist.public("A")
    lines = [f"key {env.key_id(public)} {public.hex()} 0", f"machine 0 0 {full.INSTANCE_SEED}", f"provision {S} {N}",
             f"stage {statement[1]} {statement[2]} {N}", f"stage {first[1]} {BODIES[0].hex()} {N}",
             f"restart {N - 86400 * 40}",
             f"stage {full._sealed(1, 2, expires=late - 10, widens=False)} {BODIES[1].hex()} {N - 86400 * 40}",
             f"commit {S} 1 {H[0]} 120 1000 {late}", f"tick 1119 {late}", f"tick 1120 {late}", "done"]
    out = _harness(host_check_min, lines)
    assert full._records(out[4])[0].cause == "dist:expired"
    assert out[5] == "records" and out[6] == "records" and full._records(out[7])[0].event == "committed"


def test_case_085_the_profile_s_records_read_under_its_instance_key(host_check_min):
    """case_085: H1, H2, H5. Every record the profile signs reads back under its instance key, carries no Facet body
    and no extension, and a changed byte does not read."""
    script, _quiet = full._with_statements([("provision", S, N), ("stage", full._sealed(0, 1), BODIES[0].hex(), N),
                                            ("commit", S, 1, H[0], N)])
    signed = bytes.fromhex(_min_steps(host_check_min, script)[-1].split()[1])
    record = state_record.read(signed, _dist.instance_key().public_raw)
    assert (record.event, record.body, record.extensions, len(signed)) == ("committed", b"", b"", 212)
    with pytest.raises(Refused):
        state_record.read(signed[:30] + bytes([signed[30] ^ 1]) + signed[31:], _dist.instance_key().public_raw)


# ------------------------------------------------------------------ the relay (B10) and case 121

def _relay(binary, lines: list) -> list:
    return _harness(binary, lines)


def _through_relay(binary, frames_in: list) -> list:
    """Each frame heard on the radio, through the relay to the UART, read back by the PEP's side of the link."""
    out = _relay(binary, [f"radio {data.hex()}" for data in frames_in])
    line = b"".join(bytes.fromhex(item.split()[1]) for item in out if item.startswith("uart "))
    back = _relay(binary, [f"link {line.hex()}"])
    assert back[-1] == "link-done"
    return [bytes.fromhex(item.split()[1]) for item in back[:-1]]


def test_case_121_the_relay_forwards_every_frame_unchanged_and_the_pep_behind_it_decides(host_check, host_relay):  # noqa: F811
    """case_121: B10. The corpus stream that drops, repeats and corrupts frames, through the relay's own forwarding
    code (esp-relay-c6/main/relay.c) to the UART and back off the line, is the same frames in the same order, and the
    C core's assembler answers it with the corpus's events. The relay passes the corrupted frames as they came: what
    it carries is checked by the PEP behind it, not by the relay."""
    frames = full._frames_module()
    entry = next(item for item in full.CORPUS["frames"] if item["case"] == 121)
    sent = [bytes.fromhex(step["frame"]) for step in entry["steps"]]
    assert _through_relay(host_relay, sent) == [data for data in sent if 0 < len(data) <= 250]
    case = dict(next(case for case in full.C_CASES if case["name"].startswith("001_round_trip")),
                trust=entry["trust"], pep=entry["pep"], now=entry["now"])
    relayed = [(data, step["at"]) for data, step in zip(_through_relay(host_relay, sent), entry["steps"])]
    events = full._c_events(host_check, case, relayed, ordered=entry["ordered"], limit=entry["limit"])
    python = full._python_events(frames, case, relayed, ordered=entry["ordered"], limit=entry["limit"])
    assert events == python
    assert any(line.startswith("whole ") for line in events)


def test_a_release_through_the_relay_is_staged_and_committed_by_the_profile(host_relay, host_check_min):
    """B10, B11, B12: what the Uno sees. A release, its statement and a commit, from the radio through the relay into
    the profile, is staged and committed. A UART frame from the PEP goes to the radio whole, and a frame past the
    link's limit or broken on the line is dropped."""
    frames = full._frames_module()
    statement = _dist.widening()
    covering = _dist.seal("trust.widening", statement, seq=1, release=env.release_id([("policy.ppt", H[0])]),
                          policy_sha256=H[0], targets=("mesh",), widens=True)
    release = _dist.seal("policy.ppt", BODIES[0], seq=1, targets=("mesh",), widens=True)
    sent = list(frames.frames_for(1, covering, statement)) + list(frames.frames_for(2, release, BODIES[0]))
    sent.append(frames.encode(frames.commit_for(3, S, 1, H[0])))
    steps = _frame_steps(host_check_min, _through_relay(host_relay, sent))
    records = [(r.event, r.cause) for _event, line in steps for r in full._records(line)]
    assert records == [("staged", None), ("staged", None), ("committed", None)]
    state = bytes([3, 1, 0, 0]) + bytes(212)
    line = bytes([0xC0]) + state.replace(b"\xdb", b"\xdb\xdd").replace(b"\xc0", b"\xdb\xdc") + bytes([0xC0])
    broken = bytes([0xC0, 1, 0xDB, 0x00, 2, 0xC0])
    out = _relay(host_relay, [f"uart {(line + broken).hex()}", f"radio {bytes(251).hex()}"])
    assert out == [f"radio {state.hex()}", "uart-done", "dropped"]


def test_the_relay_holds_no_key_and_links_no_part_of_the_core():
    """B10, owner decision 13: the relay's sources include no Ed25519 and no part of the C core, its component builds
    neither, and a relay image built here carries none of their symbols."""
    sources = {path.name: path.read_text(encoding="utf-8") for path in (RELAY / "main").glob("*.[ch]")}
    assert set(sources) == {"relay.c", "relay.h", "relay_main.c"}
    for name, text in sources.items():
        assert "monocypher" not in text and "pp_dist" not in text, name
    component = (RELAY / "main" / "CMakeLists.txt").read_text(encoding="utf-8").split("idf_component_register")[1]
    assert "monocypher" not in component and "pp_dist" not in component
    sys.path.insert(0, str(HW))
    from fleet import relay_checks
    elf = RELAY / "build" / "pp_relay_c6.elf"
    if not elf.is_file():
        pytest.skip("the relay image is built with ESP-IDF, which has not built it in this tree")
    result = relay_checks.holds_no_key(elf)
    assert result["passed"], result


# ------------------------------------------------------------------ the fleet entries and probers, no board attached

@pytest.fixture
def fleet():
    if not (HW / "fleet" / "run.py").exists():
        pytest.skip("the fleet harness is in prismpath-hw, which this tree does not carry")
    sys.path.insert(0, str(HW))
    from fleet import families, probe, run
    return families, probe, run


def test_the_c6_and_the_uno_have_their_entries_and_capabilities(fleet):
    families, _probe, _run = fleet
    entries = families.FAMILIES
    assert entries["esp32-c6"].capability == families.FULL and entries["esp32-c6"].project == HW / "mesh"
    relay = entries["esp32-c6-relay"]
    assert (relay.capability, relay.kind, relay.probed, relay.project) == (families.CANNOT, "relay", "esp32-c6", RELAY)
    uno = entries["atmega328p"]
    assert (uno.capability, uno.tool, uno.checks) == (families.ONE_PASS, "make", "fleet.uno_checks")
    command = uno.flash_command("/dev/serial/by-path/uno")
    assert command[0] == "avrdude" and "/dev/serial/by-path/uno" in command
    assert any(arg.startswith("eeprom:w:") and arg.endswith("uno_anchor.eep:r") for arg in command)


def test_the_avr_prober_reads_the_signature_and_keys_the_board_by_its_bridge(fleet):
    _families, probe, _run = fleet
    signature = {"/p/uno": "0x1e,0x95,0xf\n", "/p/other": "0x1e,0x98,0x1\n"}
    serials = {"/p/uno": "95530343834351A0E1C1"}
    run, serial = signature.get, lambda path: serials.get(path, "")
    board = probe.avr("/p/uno", run, serial)
    assert (board.family, board.board_id, board.chip) == ("atmega328p", "95530343834351A0E1C1", "ATmega328P")
    assert probe.avr("/p/other", run, serial) is None and probe.avr("/p/none", run, serial) is None
    assert probe.avr("/p/uno", run, lambda path: "") is None         # no stable id, so it is listed as unknown
    assert probe.avr in probe.PROBERS and probe.PROBERS.index(probe.avr) > probe.PROBERS.index(probe.espressif)


def test_a_relay_is_never_run_as_a_pep_and_the_uno_builds_with_make(fleet, tmp_path):
    """Owner decision 13 in the test rig: a C6 named with --relay runs the relay entry, a family of capability
    `cannot` refuses a checks module that runs it as a PEP, and the Uno's build is the Makefile's."""
    families, probe, run = fleet
    c6 = probe.Board("esp32-c6", "40:4c:ca:00:00:01", "/p/c6", "ESP32-C6")
    uno = probe.Board("atmega328p", "95530343834351A0E1C1", "/p/uno", "ATmega328P")
    assigned = run.assign([c6, uno], ["40:4c:ca:00:00:01"])
    assert [board.family for board in assigned] == ["esp32-c6-relay", "atmega328p"]
    with pytest.raises(RuntimeError, match="has no relay entry"):
        run.assign([uno], [uno.board_id])
    from fleet import relay_checks, uno_checks

    class PepChecks:
        pass
    with pytest.raises(RuntimeError, match="never run as a PEP"):
        run.checks_for(families.FAMILIES["esp32-c6-relay"], PepChecks)
    assert run.checks_for(families.FAMILIES["esp32-c6-relay"], relay_checks) is relay_checks
    assert run.checks_for(families.FAMILIES["atmega328p"], uno_checks) is uno_checks
    commands = []
    built = run.build(families.FAMILIES["atmega328p"], "", lambda command, cwd: commands.append(command) or 0)
    assert built == HW / "avr"
    assert commands == [["make", "-C", str(HW / "avr"), "dist", "anchor"]]


def test_the_uno_checks_pass_on_the_host_build_of_the_same_c(fleet, host_check_min, tmp_path):
    """The board checks of fleet/uno_checks.py, through a link that is the host build of the profile provisioned as
    uno_anchor.py provisions the Uno: a release with real `meta` staged and committed, and a bad signature refused."""
    sys.path.insert(0, str(HW / "mesh"))
    sys.path.insert(0, str(HW / "avr"))
    import gen_mesh_tables as tables
    import uno_anchor
    from fleet import uno_checks
    gen = full._generator()
    signer = tables.Signer(authority=gen.test_key("A"), controller=gen.test_key("C"))
    seed = bytes.fromhex(full.INSTANCE_SEED)
    eeprom = uno_anchor.image(seed, _dist.public("A"))
    assert eeprom[:4] == b"PPU1" and len(eeprom) == 4 + 32 + 32 + 65

    class HostLink:
        """The profile on the host, its frames framed and unframed as the line carries them."""
        def __init__(self):
            self.lines = [*_anchor_lines(), f"provision {tables.STREAM} {tables.NOT_BEFORE}"]

        def exchange(self, sent, seconds=0):
            on_line = b"".join(uno_checks.encode(frame) for frame in sent)
            self.lines += [f"frame {frame.hex()} 0 {tables.NOT_BEFORE}" for frame in uno_checks.decode(on_line)]
            out = _harness(host_check_min, self.lines + ["done"])
            records = [item for line in out[1:] if line.startswith("records") for item in line.split()[1:]]
            new, self.seen = records[getattr(self, "seen", 0):], len(records)
            framed = b"".join(uno_checks.encode(bytes([3, 1, 0, 0]) + bytes.fromhex(item)) for item in new)
            return [frame[4:] for frame in uno_checks.decode(framed)]

    results = uno_checks.checks(HostLink(), signer, _dist.instance_key().public_raw)
    assert results["release_committed"]["passed"] is True, results
    assert results["bad_signature_refused"]["passed"] is True, results


# ------------------------------------------------------------------ the Uno build, an estimate and not a measurement

def test_the_uno_image_builds_and_its_estimate_is_recorded(tmp_path):
    """The constrained profile for the ATmega328P builds with avr-gcc, and avr-size's flash and static RAM are the ones
    recorded in prismpath-hw/avr/uno_dist_build_estimate.json for the same compiler. Those numbers are a build time
    estimate. They are not a measurement on the board, which the board validation pass of 2026-11-30 makes."""
    if AVR_GCC is None:
        pytest.skip("no avr-gcc on this host, so the Uno image is not built here")
    avr, elf = HW / "avr", tmp_path / "ppt_uno_dist.elf"
    sources = [avr / "ppt_uno_dist.c", DIST / "pp_dist.c", MONOCYPHER / "monocypher.c",
               MONOCYPHER / "monocypher-ed25519.c"]
    subprocess.run([AVR_GCC, "-mmcu=atmega328p", "-DF_CPU=16000000UL", *MIN, "-std=gnu11", "-Os", "-Wall", "-Wextra",
                    "-Werror", "-ffunction-sections", "-fdata-sections", f"-I{DIST}", f"-I{MONOCYPHER}",
                    "-Wl,--gc-sections,--noinhibit-exec", "-o", str(elf), *map(str, sources)],
                   capture_output=True, text=True, cwd=tmp_path, check=False)   # ld reports an overflow, keeps the image
    assert elf.is_file()
    sizes = subprocess.run(["avr-size", "-A", str(elf)], capture_output=True, text=True, check=True).stdout
    section = {name: int(size) for name, size, *_ in (line.split() for line in sizes.splitlines()[2:] if line.strip())
               if name in (".text", ".data", ".bss")}
    recorded = json.loads((avr / "uno_dist_build_estimate.json").read_text(encoding="utf-8"))
    assert recorded["measured_on_board"] is False
    version = subprocess.run([AVR_GCC, "-dumpversion"], capture_output=True, text=True, check=True).stdout.strip()
    if version != recorded["compiler"].split()[-1]:
        pytest.skip(f"avr-gcc {version} is not the compiler the estimate was recorded with")
    assert {"text": section[".text"], "data": section[".data"], "bss": section[".bss"]} == recorded["sections"]
    assert recorded["flash_bytes"] == section[".text"] + section[".data"]
    assert recorded["static_ram_bytes"] == section[".data"] + section[".bss"]
