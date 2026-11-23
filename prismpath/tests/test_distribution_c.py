# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The C core of policy distribution (prismpath-hw/dist/, spec-policy-distribution.md section 19) on the host.

The test builds `host_check.c` with the host `cc`, the vendored Monocypher and
`-Wall -Wextra -Werror -fsanitize=address,undefined`, from the same sources the mesh firmware and the cFS app
compile, and replays every corpus case the C core runs: a case marked `C` whose enforcement point is of a kind
the core has (`mesh` or `cfs`, I1). Each must report the cause, the unchanged flag, the time floor and the
envelope id the Python verifier recorded. A short fuzz from fixed seeds then holds the scanner to the Python
reader. It skips, naming the reason, when there is no C compiler or the tree does not carry prismpath-hw."""
import hashlib
import json
import random
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from prismpath.distribution import envelope as env
from prismpath.distribution.kinds import Refused
from prismpath.kernel import causes

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "prismpath-hw" / "dist"
MONOCYPHER = ROOT / "prismpath-hw" / "mesh" / "main"
CORPUS = json.loads((ROOT / "prismpath" / "portable" / "conformance" / "distribution.json").read_text(encoding="utf-8"))
C_KINDS = ("mesh", "cfs")
C_CASES = [case for case in CORPUS["cases"] if "C" in case["runs_on"] and case["pep"]["kind"] in C_KINDS]
CC = shutil.which("cc")
FLAGS = ["-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
         "-fno-sanitize-recover=all"]


@pytest.fixture(scope="module")
def host_check(tmp_path_factory):
    if not (DIST / "pp_dist.c").exists():
        pytest.skip("the C core is in prismpath-hw, which this tree does not carry")
    if CC is None:
        pytest.skip("no C compiler (cc) on this host, so the C core is not built here")
    out = tmp_path_factory.mktemp("dist_c") / "host_check"
    sources = [DIST / "host_check.c", DIST / "pp_dist.c", MONOCYPHER / "monocypher.c",
               MONOCYPHER / "monocypher-ed25519.c"]
    subprocess.run([CC, *FLAGS, f"-I{DIST}", f"-I{MONOCYPHER}", "-o", str(out), *map(str, sources)], check=True,
                   capture_output=True, text=True)
    return out


def _lines(case: dict) -> list:
    """The harness's input for one corpus case."""
    lines = [f"case {case['name']}"]
    trust = case["trust"]
    if trust is None:
        lines.append("trust 0 0 - 0")
    else:
        for kid, key in trust["keys"].items():
            lines.append(f"key {kid} {key['public']} {0 if key['role'] == 'authority' else 1}")
        for member, word in (("retired", "retired"), ("revoked_keys", "revoked_key"),
                             ("revoked_envelopes", "revoked_envelope"), ("revoked_policies", "revoked_policy")):
            lines += [f"{word} {item}" for item in trust[member]]
        lines += [f"raised {stream} {seq}" for stream, seq in trust["floors"].items()]
        lines.append(f"trust 1 {trust['trust_seq']} {trust['trust_id'] or '-'} {trust['time_floor']}")
    pep = case["pep"]
    lines.append(f"pep {pep['kind']} {pep['stream']} {pep['floor']['seq']} {pep['body_bound']} {int(pep['has_clock'])}")
    lines += [f"floor_id {item}" for item in pep["floor"]["ids"]]
    staged = pep["staged"]
    if staged is not None:
        lines.append(f"staged {staged['stream']} {staged['seq']} {staged['policy_sha256']} {staged['release']} "
                     f"{staged['replaces'] or '-'} {int(staged['widens'])}")
    lines += [f"now {case['now']}", f"sealed {case['sealed'] or '-'}", f"body {case['body'] or '-'}", "end"]
    return lines


def _run(host_check, cases: list) -> dict:
    text = "\n".join(line for case in cases for line in _lines(case)) + "\n"
    done = subprocess.run([str(host_check)], input=text, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    out = {}
    for line in done.stdout.splitlines():
        name, code, unchanged, time_floor, envelope_id = line.split(" ")
        out[name] = {"cause": causes.name(int(code)) if int(code) else None, "unchanged": unchanged == "1",
                     "time_floor": None if time_floor == "-" else int(time_floor),
                     "envelope_id": None if envelope_id == "-" else envelope_id}
    return out


def test_every_cause_code_the_core_reports_is_the_registered_one(host_check):
    defined = re.findall(r"#define PP_CAUSE_\w+ (\d+)\s+/\* ([a-z]+:[a-z-]+) \*/", (DIST / "pp_dist.h").read_text())
    assert len(defined) >= 28
    assert {name: causes.NAMES[name] for _code, name in defined} == {name: int(code) for code, name in defined}


def test_the_corpus_holds_c_cases_on_the_mesh_kind():
    assert len(C_CASES) >= 40 and {case["pep"]["kind"] for case in C_CASES} == {"mesh"}


def test_every_c_case_of_the_corpus_replays_to_its_recorded_result(host_check):
    """Each case the C core runs, by its corpus name, with exactly the Python verifier's result."""
    got = _run(host_check, C_CASES)
    assert sorted(got) == sorted(case["name"] for case in C_CASES)
    wrong = {case["name"]: (got[case["name"]], case["expect"]) for case in C_CASES if got[case["name"]] != case["expect"]}
    assert wrong == {}


def _python_reads(raw: bytes):
    """The Python reader's cause, and whether it is a refusal of a meta member (E1, E11), which the C scanner
    does not make (E9)."""
    try:
        env.read(raw)
    except Refused as refused:
        return refused.cause, str(refused).startswith("dist:bad-format: meta ")
    return None, False


def test_the_scanner_answers_as_the_python_reader_on_mutated_envelopes(host_check):
    """A fixed seed fuzz of the envelope reader: each mutation of a good mesh envelope is sealed by the test key A
    and must be refused by C at V4 with the Python reader's cause, or read by both. A mutation inside `meta`
    that keeps it an object of at most three levels is read by C, which skips meta's member forms (E9), and is
    left out of the comparison when Python refuses it by E11."""
    good = next(case for case in C_CASES if case["name"].startswith("001_round_trip"))
    envelope_bytes, _entries = env.unseal(bytes.fromhex(good["sealed"]))
    gen = _generator()
    rng = random.Random(16)
    alphabet = b'{}[]",:0123456789-.eE \\u"abcdefnrt\x00\xc3\xa9\xff'
    cases, expected = [], {}
    for index in range(300):
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
        cause, meta_member = _python_reads(raw)
        if meta_member:
            continue                                # a meta member that E11 refuses and E9 skips
        case = dict(good, name=f"fuzz_{index}", sealed=env.seal(raw, [gen.test_key("A")]).hex())
        cases.append(case)
        expected[case["name"]] = cause
    assert len(cases) > 200
    got = _run(host_check, cases)
    wrong = {name: (got[name]["cause"], cause) for name, cause in expected.items()
             if (got[name]["cause"] if got[name]["cause"] in ("dist:bad-format", "document:not-canonical") else None)
             != cause}
    assert wrong == {}


def _generator():
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen_distribution_corpus",
                                                  ROOT / "prismpath" / "portable" / "gen_distribution_corpus.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_case_014_a_tampered_envelope_byte_is_sig_invalid_and_the_scanner_is_never_reached(host_check):
    """case_014: E9, V1, V3. Each byte of a good envelope changed under its good signature is sig:invalid, the
    bytes that would no longer read as an envelope included, so V3 runs before the scanner reads anything."""
    good = next(case for case in C_CASES if case["name"].startswith("001_round_trip"))
    sealed = bytes.fromhex(good["sealed"])
    envelope_bytes, entries = env.unseal(sealed)
    start = len(sealed) - len(envelope_bytes)
    cases = []
    for at in (0, 1, len(envelope_bytes) // 2, len(envelope_bytes) - 1):
        tampered = bytearray(sealed)
        tampered[start + at] = ord("{") if tampered[start + at] != ord("{") else ord("[")
        cases.append(dict(good, name=f"tampered_{at}", sealed=bytes(tampered).hex()))
    got = _run(host_check, cases)
    assert {name: result["cause"] for name, result in got.items()} == {case["name"]: "sig:invalid" for case in cases}
    assert all(result["envelope_id"] is None for result in got.values())


# ------------------------------------------------------------------ the machine, step for step against pep.py

from prismpath.distribution import state_record  # noqa: E402
from prismpath.distribution.pep import PepRefused  # noqa: E402
from prismpath.tests import _dist  # noqa: E402

INSTANCE_SEED = _generator().test_key("I").private_bytes_raw().hex()
EVENT_CODES = {name: code for code, name in enumerate(state_record.EVENTS)}


def _python_steps(script: list, *, hold: bool, tmp_path) -> list:
    """The Python machine (pep.Pep on a modelled mesh node) run through `script`, each step's output as the
    harness prints it."""
    out, point = [], None
    for step in script:
        op, args = step[0], step[1:]
        if op == "provision":
            clock = _dist.Clock(args[1])
            point = _dist.MeshPep(tmp_path, clock=clock, expiry_response="hold" if hold else "refuse")
        elif op == "lose":
            names = {"floor": "floor.json", "counter": "counter.json", "trust": "trust.json", "setting": "setting.json"}
            with open(point.pep.store.path(names[args[0]]), "wb") as handle:
                handle.write(b"{")
            continue
        elif op == "setting":
            point.expiry_response = "hold" if args[0] else "refuse"
            continue
        elif op == "revoke_policy":             # the store as a revocation applied after staging leaves it
            from dataclasses import replace
            point.pep.trust = replace(point.pep.trust, revoked_policies=point.pep.trust.revoked_policies | {args[0]})
            out.append("records")
            continue
        elif op == "restart":
            point.clock.now = args[0]
            try:
                point.pep = point.open(provision=False)
            except PepRefused:
                out.append("refused-start")
                continue
        else:
            point.clock.now = args[-1]
            pep = point.pep
            if op == "stage":
                pep.stage(bytes.fromhex(args[0]), bytes.fromhex(args[1]))
            elif op == "commit":
                pep.commit(args[0], args[1], args[2])
            elif op == "abort":
                pep.abort(args[0], args[1], args[2])
            elif op == "tick":
                pep.tick()
            elif op == "rollback":
                try:
                    pep.rollback()
                except PepRefused:
                    out.append("none")
                    continue
            elif op == "record":
                pep.record(args[0])
            elif op == "decide":
                answer = pep.decide(lambda: 0)
                out.append(f"decide {causes.NAMES[answer['cause']] if answer['cause'] else 0} "
                           f"{int(answer['mark'] == 'held')}")
                continue
        out.append(" ".join(["records", *(record.hex() for record in point.pep.drain())]))
    return out


def _c_lines(script: list, *, hold: bool) -> list:
    key = _generator().test_key("A")
    public = _generator().public_raw(key)
    lines = [f"key {env.key_id(public)} {public.hex()} 0", f"machine {int(hold)} 1 {INSTANCE_SEED}"]
    for step in script:
        op, args = step[0], step[1:]
        if op == "commit":
            lines.append(f"commit {args[0]} {args[1]} {args[2]} 0 0 {args[3]}")
        elif op == "tick":
            lines.append(f"tick 0 {args[0]}")
        elif op == "record":
            lines.append(f"record {EVENT_CODES[args[0]]} {args[1]}")
        elif op == "setting":
            lines.append(f"setting {int(args[0])}")
        else:
            lines.append(" ".join([op, *(str(arg) for arg in args)]))
    return lines + ["done"]


def _c_steps(host_check, script: list, *, hold: bool) -> list:
    done = subprocess.run([str(host_check)], input="\n".join(_c_lines(script, hold=hold)) + "\n",
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()


def _same(host_check, tmp_path, script, *, hold=False) -> list:
    python = _python_steps(script, hold=hold, tmp_path=tmp_path)
    c = _c_steps(host_check, [step for step in script if step[0] not in ()], hold=hold)
    assert c == python
    return python


def _records(line: str) -> list:
    return [state_record.read(bytes.fromhex(item), _dist.instance_key().public_raw) for item in line.split()[1:]]


N, E = _dist.NOW, _dist.EXPIRES
BODIES = [_dist.image(5), _dist.image(7), _dist.image(9)]
H = [hashlib.sha256(body).hexdigest() for body in BODIES]
S = _dist.STREAM


def _sealed(index: int, seq: int, **args) -> str:
    return _dist.seal("policy.ppt", BODIES[index], seq=seq, targets=("mesh",), **args).hex()


def test_case_046_047_048_052_053_stage_commit_and_abort_answer_as_the_python_machine(host_check, tmp_path):
    """case_046: G1. case_047: G2. case_048: C1. case_052: C5, H4. case_053: A1. Each step's state records are
    byte for byte the ones pep.py signs, so the C core reports what the Python machine reports."""
    script = [("provision", S, N), ("commit", S, 1, H[0], N),
              ("stage", _sealed(0, 1), BODIES[0].hex(), N),
              ("stage", _sealed(1, 2, signer="U"), BODIES[1].hex(), N),
              ("stage", _sealed(1, 3), BODIES[1].hex(), N), ("stage", _sealed(0, 2), BODIES[0].hex(), N),
              ("commit", S, 3, H[0], N), ("commit", S, 3, H[1], N),
              ("stage", _sealed(2, 4), BODIES[2].hex(), N), ("abort", S, 5, H[2], N), ("abort", S, 4, H[2], N),
              ("stage", _sealed(1, 3), BODIES[1].hex(), N), ("record", "beat", N), ("restart", N),
              ("stage", _sealed(1, 3), BODIES[1].hex(), N)]
    lines = _same(host_check, tmp_path, script)
    staged, refused = _records(lines[2])[0], _records(lines[3])[0]
    assert (staged.event, refused.event, refused.cause) == ("staged", "refused", "dist:unknown-key")
    assert _records(lines[5])[0].cause == "dist:seq-replay"
    assert _records(lines[1])[0].cause == "dist:not-staged" and _records(lines[6])[0].cause == "dist:not-staged"
    committed = _records(lines[7])[0]
    assert (committed.event, committed.active_seq, committed.floor) == ("committed", 3, 3)
    assert [_records(lines[k])[0].event for k in (9, 10)] == ["beat", "aborted"]
    assert _records(lines[11])[0].event == "beat"            # Q3: the committed envelope again changes nothing


def test_case_024_026_050_077_a_lost_floor_a_clock_set_back_and_expiry_answer_as_the_python_machine(host_check, tmp_path):
    """case_024: Q5, X3. case_026: T1, V13. case_050: C3, the staged release dropped when it expired or was
    revoked before its commit. case_077: X1, X2, X3."""
    late = E - 100
    script = [("provision", S, N), ("stage", _sealed(0, 1, not_before=late), BODIES[0].hex(), late),
              ("stage", _sealed(1, 2, expires=late - 10), BODIES[1].hex(), N),
              ("commit", S, 1, H[0], N), ("tick", E - 1), ("decide", E - 1), ("tick", E), ("decide", E),
              ("stage", _sealed(1, 2, expires=N + 10), BODIES[1].hex(), E), ("restart", N),
              ("stage", _sealed(2, 3, expires=late - 10), BODIES[2].hex(), N),
              ("lose", "floor"), ("restart", N), ("stage", _sealed(2, 4), BODIES[2].hex(), N),
              ("commit", S, 4, H[2], N), ("record", "beat", N), ("decide", N)]
    lines = _same(host_check, tmp_path, script)
    revoked = _same(host_check, tmp_path / "revoked", [("provision", S, N), ("stage", _sealed(1, 1), BODIES[1].hex(), N),
                                                        ("revoke_policy", H[1]), ("commit", S, 1, H[1], N),
                                                        ("commit", S, 1, H[1], N)])
    assert _records(revoked[3])[0].cause == "dist:revoked" and _records(revoked[4])[0].cause == "dist:not-staged"
    assert _records(lines[2])[0].cause == "dist:expired"
    assert _records(lines[6])[0].event == "lapsed" and lines[7] == f"decide {causes.NAMES['dist:policy-lapsed']} 0"
    assert _records(lines[10])[0].cause == "dist:expired"        # the time floor held over the restart
    assert _records(lines[12])[0].cause == "dist:floor-lost" and _records(lines[14])[0].state == "locked"


def _hold_script(widen_rollback: bool) -> list:
    return [("provision", S, N), ("stage", _sealed(0, 1, expires=E - 100), BODIES[0].hex(), N),
            ("commit", S, 1, H[0], N), ("stage", _sealed(1, 2), BODIES[1].hex(), N), ("commit", S, 2, H[1], N),
            ("tick", E), ("decide", E), ("record", "beat", E), ("rollback", E), ("restart", E), ("decide", E),
            ("stage", _sealed(0, 3, not_before=E, expires=E + 1000), BODIES[0].hex(), E),
            ("commit", S, 3, H[0], E), ("decide", E), ("record", "beat", E)]


def test_case_106_107_110_112_hold_and_refuse_answer_as_the_python_machine(host_check, tmp_path):
    """case_106: X6, X1. case_107: X6, X7. case_110: X9. case_112: X10. Under REFUSE the release lapses at
    expiry. Under HOLD it keeps deciding, held with dist:held, marked and bit 5 set until a release that passes
    every rule ends the hold, a rollback is refused, and a restart with the other setting is refused."""
    refuse = _same(host_check, tmp_path / "refuse", _hold_script(False))
    assert _records(refuse[5])[0].event == "lapsed" and refuse[6].startswith(f"decide {causes.NAMES['dist:policy-lapsed']}")
    hold = _same(host_check, tmp_path / "hold", _hold_script(False) + [("setting", False), ("restart", E)], hold=True)
    held = _records(hold[5])[0]
    assert (held.event, held.cause, held.held) == ("held", "dist:held", True) and hold[6] == "decide 0 1"
    assert _records(hold[8])[0].cause == "dist:held" and hold[10] == "decide 0 1"
    committed = _records(hold[12])[0]
    assert (committed.event, committed.held, committed.active_seq) == ("committed", False, 3) and hold[13] == "decide 0 0"
    assert hold[-1] == "refused-start"


def test_case_085_the_core_s_state_records_read_under_its_instance_key(host_check, tmp_path):
    """case_085: H1, H2, H6. Every record the C core signed reads back under its instance key, and a changed
    byte does not."""
    lines = _c_steps(host_check, [("provision", S, N), ("stage", _sealed(0, 1), BODIES[0].hex(), N),
                                  ("commit", S, 1, H[0], N)], hold=False)
    signed = bytes.fromhex(lines[-1].split()[1])
    assert state_record.read(signed, _dist.instance_key().public_raw).event == "committed"
    with pytest.raises(Refused):
        state_record.read(signed[:30] + bytes([signed[30] ^ 1]) + signed[31:], _dist.instance_key().public_raw)


def test_case_027_038_a_pep_with_no_clock_and_a_delayed_commit(host_check):
    """case_027: T2. A PEP with no clock restarts at its saved time floor and still refuses an envelope that
    expired before it. case_038: B8. A commit with a delay of 120 ms is active at the PEP's time plus the
    delay, not before."""
    key = _generator().test_key("A")
    public = _generator().public_raw(key)
    late = E - 100
    lines = [f"key {env.key_id(public)} {public.hex()} 0", f"machine 0 0 {INSTANCE_SEED}", f"provision {S} {N}",
             f"stage {_sealed(0, 1, not_before=late)} {BODIES[0].hex()} {N}", f"restart {N - 86400 * 40}",
             f"stage {_sealed(1, 2, expires=late - 10)} {BODIES[1].hex()} {N - 86400 * 40}",
             f"commit {S} 1 {H[0]} 120 1000 {late}", f"tick 1119 {late}", f"decide {late}", f"tick 1120 {late}",
             f"decide {late}", "done"]
    done = subprocess.run([str(host_check)], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    out = done.stdout.splitlines()
    assert _records(out[3])[0].cause == "dist:expired"
    assert out[4] == "records" and out[5] == "records" and out[6] == f"decide {causes.NAMES['dist:policy-lapsed']} 0"
    assert _records(out[7])[0].event == "committed" and out[8] == "decide 0 0"


# ------------------------------------------------------------------ the frame reassembly, against frames.py

def _frames_module():
    return pytest.importorskip("prismpath.distribution.frames", reason="frames.py lands with the frame binding (PR 15)")


def _python_events(frames, case: dict, sequence: list, *, ordered: bool, limit: int) -> list:
    from prismpath.distribution import verify as verifier
    gen = _generator()
    trust = gen.trust_from_document(case["trust"])
    pep = gen.pep_from_document(case["pep"])
    clock = {"ms": 0}
    assembler = frames.Assembler(frames.admit_through_v8(
        lambda sealed, body: verifier.verify(sealed, body, trust=trust, pep=pep, now=case["now"])),
        clock=lambda: clock["ms"] / 1000, ordered=ordered, limit=limit, body_bound=640)
    out = []
    for data, now_ms in sequence:
        clock["ms"] = now_ms
        event = assembler.receive(data)
        if event is None:
            out.append("none")
        elif isinstance(event, frames.Assembled):
            out.append(f"whole {event.sealed.hex() or '-'} {event.body.hex() or '-'}")
        elif isinstance(event, frames.Dropped):
            out.append(f"dropped {causes.NAMES[event.cause]}")
        else:
            out.append(f"control {data[0]}")
    return out


def _c_events(host_check, case: dict, sequence: list, *, ordered: bool, limit: int) -> list:
    lines = [line for line in _lines(case) if not line.startswith(("sealed", "body", "end"))]
    lines += [f"assembler {int(ordered)} {limit} 640"] + [f"frame {data.hex()} {now_ms}" for data, now_ms in sequence]
    done = subprocess.run([str(host_check)], input="\n".join(lines + ["done"]) + "\n", capture_output=True,
                          text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()


def _streams(frames, case: dict, limit: int):
    """Frame streams from fixed seeds: shuffled, repeated, lost and corrupted chunks, chunks outside the offer
    and for no offer, other transfers, control frames and a transfer left past its 5 seconds."""
    sealed, body = bytes.fromhex(case["sealed"]), bytes.fromhex(case["body"])
    rng = random.Random(121)
    whole = list(frames.frames_for(7, sealed, body, limit))
    yield "in order", [(data, 10 * index) for index, data in enumerate(whole)]
    prefix = whole[0][4:20]
    # B9: an offer past 2,440 sealed bytes, a body longer than the signed body_size, and an envelope that fails
    # its signature, whose body chunks are then never read
    yield "sealed too long", [(frames.encode(frames.Offer(7, prefix, 2441, len(body)), limit), 0)] + \
        [(data, 1) for data in whole[1:]]
    yield "body longer than signed", [(frames.encode(frames.Offer(7, prefix, len(sealed), len(body) + 1), limit), 0)] + \
        [(data, 1) for data in whole[1:]]
    envelope_bytes, entries = env.unseal(sealed)
    forged = env.seal_entries(envelope_bytes, [(entries[0][0], bytes(64))])
    yield "forged signature", [(data, 1) for data in frames.frames_for(9, forged, body, limit)]
    for trial in range(40):
        sequence, now = [], 0
        for _round in range(rng.randint(1, 3)):
            batch = whole[:1] + rng.sample(whole[1:], len(whole) - 1) if rng.random() < 0.7 else list(whole)
            for data in batch:
                roll = rng.random()
                now += rng.choice((1, 5, 50, 900))
                if roll < 0.1:
                    continue                                       # lost
                if roll < 0.2:
                    damaged = bytearray(data)
                    damaged[rng.randrange(len(damaged))] ^= 1 << rng.randrange(8)
                    data = bytes(damaged)                          # corrupted on the way
                elif roll < 0.25:
                    data = frames.encode(frames.Chunk(8, frames.SEALED, 0, b"x"), limit)   # a transfer with no offer
                elif roll < 0.28:
                    data = frames.encode(frames.Chunk(7, frames.SEALED, len(sealed) - 1, b"xy"), limit)  # past it
                elif roll < 0.31:
                    data = frames.encode(frames.commit_for(7, _dist.STREAM, 1, "ab" * 32, 120), limit)
                sequence.append((data, now))
                if rng.random() < 0.15:
                    sequence.append((data, now))                   # repeated
            if rng.random() < 0.2:
                now += 5001                                        # B7: past the transfer's 5 seconds
        yield f"trial {trial}", sequence


@pytest.mark.parametrize("ordered", [False, True])
def test_case_035_036_037_120_121_the_assembler_answers_frame_for_frame_as_frames_py(host_check, ordered):
    """case_035: B6. case_036: B6. case_037: B7. case_120: B9, its frame half. case_121: B10. On each stream the
    C assembler answers every frame as frames.Assembler does: staged when the parts are whole and the envelope
    passed V8, frame-invalid for a chunk outside the offer, with no offer or a part with the wrong hash, silent
    after 5 seconds, no body read before the envelope is admitted, and on an ordered link a chunk out of order
    drops the transfer (B11; the one pass check that never holds the envelope whole is the constrained profile's)."""
    frames = _frames_module()
    case = next(case for case in C_CASES if case["name"].startswith("001_round_trip"))
    staged = 0
    for limit in (64, 250):
        for name, sequence in _streams(frames, case, limit):
            python = _python_events(frames, case, sequence, ordered=ordered, limit=limit)
            assert _c_events(host_check, case, sequence, ordered=ordered, limit=limit) == python, (name, limit)
            staged += sum(line.startswith("whole") for line in python)
    assert staged >= (2 if ordered else 5)
