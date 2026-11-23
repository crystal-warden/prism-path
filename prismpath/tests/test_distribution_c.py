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

from prismpath import canon
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
            point = _dist.MeshPep(tmp_path, clock=clock, expiry_response="hold" if hold else "refuse",
                                  authorities=list(args[2]) if len(args) > 2 else ["A"])
        elif op == "lose":
            names = {"floor": "floor.json", "counter": "counter.json", "trust": "trust.json", "setting": "setting.json"}
            with open(point.pep.store.path(names[args[0]]), "wb") as handle:
                handle.write(b"{")
            continue
        elif op == "setting":
            point.expiry_response = "hold" if args[0] else "refuse"
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
    first = script[0]
    authorities = first[3] if first[0] == "provision" and len(first) > 3 else ("A",)
    lines = []
    for name in authorities:
        public = _generator().public_raw(_generator().test_key(name))
        lines.append(f"key {env.key_id(public)} {public.hex()} 0")
    lines.append(f"machine {int(hold)} 1 {INSTANCE_SEED}")
    for step in script:
        op, args = step[0], step[1:]
        if op == "provision":
            lines.append(f"provision {args[0]} {args[1]}")
        elif op == "commit":
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


_SIGNERS = {}


def _signer_of(sealed: bytes) -> str:
    """The test key name whose key id signs `sealed` first."""
    if not _SIGNERS:
        for name in ["A", "B", "C", "D", "E", "F", "G", "H", "Q", "R", "U", *(f"K{n}" for n in range(20))]:
            _SIGNERS[_dist.key_id(name)] = name
    return _SIGNERS.get(env.unseal(sealed)[1][0][0], "A")


def _with_statements(script: list) -> tuple:
    """`script` with a widening statement covering any node staged before each release that says it widens, so
    the widening rule (V12) passes as the step under test intends. Returns the script and the indexes of the
    steps it added, whose output the tests do not read."""
    out, quiet, printed = [], set(), 0                     # `printed`: the output lines before this step
    for step in script:
        if step[0] == "stage":
            sealed = bytes.fromhex(step[1])
            try:
                envelope = env.read(env.unseal(sealed)[0], reads_meta=False)
            except Refused:
                envelope = None
            if envelope is not None and envelope.artifact == "policy.ppt" and envelope.widens:
                statement = _dist.widening()
                quiet.add(printed)
                printed += 1
                out.append(("stage", _dist.seal("trust.widening", statement, seq=envelope.seq, release=envelope.release,
                                                policy_sha256=envelope.policy_sha256, targets=("mesh",),
                                                replaces=envelope.replaces, widens=True,
                                                signer=_signer_of(sealed)).hex(), statement.hex(), step[-1]))
        out.append(step)
        printed += step[0] not in ("lose", "setting")      # the two steps that print nothing
    return out, quiet


def _same(host_check, tmp_path, script, *, hold=False, statements=True) -> list:
    """`script` run on the Python machine and on the C core, which must print the same lines, returned with the
    lines of the statements `_with_statements` staged left out. A statement staged for a release that is then
    refused for another reason leaves a staged release that holds only the statement, which displaces what was
    staged before, so a release meant to be refused before V12 is sealed with `widens` false and gets none."""
    script, quiet = _with_statements(script) if statements else (script, set())
    python = _python_steps(script, hold=hold, tmp_path=tmp_path)
    c = _c_steps(host_check, [step for step in script if step[0] not in ()], hold=hold)
    assert c == python
    return [line for index, line in enumerate(python) if index not in quiet]


def _records(line: str) -> list:
    return [state_record.read(bytes.fromhex(item), _dist.instance_key().public_raw) for item in line.split()[1:]]


N, E = _dist.NOW, _dist.EXPIRES
BODIES = [_dist.image(5), _dist.image(7), _dist.image(9)]
H = [hashlib.sha256(body).hexdigest() for body in BODIES]
S = _dist.STREAM


def _sealed(index: int, seq: int, **args) -> str:
    """A mesh release of BODIES[index] at `seq`. It says it widens unless told otherwise, and `_same` stages the
    widening statement that covers it (W3), so a script reads as if the widening rule were met."""
    args.setdefault("widens", True)
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
    # a release refused before the widening rule says it does not widen, so no statement is staged for it
    script = [("provision", S, N), ("stage", _sealed(0, 1, not_before=late), BODIES[0].hex(), late),
              ("stage", _sealed(1, 2, expires=late - 10, widens=False), BODIES[1].hex(), N),
              ("commit", S, 1, H[0], N), ("tick", E - 1), ("decide", E - 1), ("tick", E), ("decide", E),
              ("stage", _sealed(1, 2, expires=N + 10, widens=False), BODIES[1].hex(), E), ("restart", N),
              ("stage", _sealed(2, 3, expires=late - 10, widens=False), BODIES[2].hex(), N),
              ("lose", "floor"), ("restart", N), ("stage", _sealed(2, 4), BODIES[2].hex(), N),
              ("commit", S, 4, H[2], N), ("record", "beat", N), ("decide", N)]
    lines = _same(host_check, tmp_path, script)
    revoked = _same(host_check, tmp_path / "revoked", [("provision", S, N), ("stage", _sealed(1, 1), BODIES[1].hex(), N),
                                                        _revoke(1, N, policies=[H[1]]), ("commit", S, 1, H[1], N)])
    assert _records(revoked[2])[-1].event == "trust-applied" and _records(revoked[3])[0].cause == "dist:not-staged"
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
    script, _quiet = _with_statements([("provision", S, N), ("stage", _sealed(0, 1), BODIES[0].hex(), N),
                                       ("commit", S, 1, H[0], N)])
    lines = _c_steps(host_check, script, hold=False)
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
    first = ("stage", _sealed(0, 1, not_before=late), BODIES[0].hex(), N)
    (statement, _release), _quiet = _with_statements([first])
    lines = [f"key {env.key_id(public)} {public.hex()} 0", f"machine 0 0 {INSTANCE_SEED}", f"provision {S} {N}",
             f"stage {statement[1]} {statement[2]} {N}",
             f"stage {first[1]} {BODIES[0].hex()} {N}", f"restart {N - 86400 * 40}",
             f"stage {_sealed(1, 2, expires=late - 10, widens=False)} {BODIES[1].hex()} {N - 86400 * 40}",
             f"commit {S} 1 {H[0]} 120 1000 {late}", f"tick 1119 {late}", f"decide {late}", f"tick 1120 {late}",
             f"decide {late}", "done"]
    done = subprocess.run([str(host_check)], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    out = done.stdout.splitlines()
    out = out[:1] + out[2:]                                  # the widening statement's ack
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
        lambda sealed: verifier.verify_envelope(sealed, trust=trust, pep=pep, now=case["now"])),
        clock=lambda: clock["ms"] / 1000, ordered=ordered, limit=limit, artifact_bound=640)
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



# ------------------------------------------------------------------ the trust statements, against pep.py

def _revoke(seq: int, now: int, signer: str = "A", **lists) -> tuple:
    body = _dist.revocation(**lists)
    sealed = _dist.seal("trust.revocation", body, seq=seq, stream="@trust", signer=signer, targets=("mesh",))
    return ("stage", sealed.hex(), body.hex(), now)


def _events(line: str) -> list:
    return [(record.event, record.cause) for record in _records(line)]


def test_case_031_066_067_068_070_071_079_revocations_answer_as_the_python_machine(host_check, tmp_path):
    """case_031: B2, R3. case_066: R1. case_067: R2. case_068: R4, Q4. case_070: R6, a list that drops a revoked
    key is dist:trust-replay and the key stays refused. case_071: R7. case_079: X4, E5, a revocation read ten years
    after it was made. Each step's signed state records are the Python machine's."""
    many = [hashlib.sha256(bytes([index])).hexdigest() for index in range(65)]
    b = [_dist.key_id("B")]
    first = _revoke(1, N, keys=b)
    script = [("provision", S, N, ("A", "B")), first, first, _revoke(2, N, keys=b, floors={S: 9}),
              _revoke(3, N), _revoke(1, N, keys=b), _revoke(5, N, keys=b),
              ("stage", _sealed(1, 8, signer="B"), BODIES[1].hex(), N), ("stage", _sealed(1, 9), BODIES[1].hex(), N),
              ("stage", _sealed(1, 10), BODIES[1].hex(), N), _revoke(3, N, keys=b, floors={S: 5}), ("record", "beat", N),
              _revoke(4, N, keys=b, envelopes=many), _revoke(4, N, keys=b, floors={f"s{index}": 1 for index in range(17)}),
              _revoke(4, N + 10 * 365 * 86400, keys=b, envelopes=many[:4], floors={f"s{index}": 1 for index in range(2)}),
              ("stage", _sealed(2, 11, signer="B"), BODIES[2].hex(), N), ("restart", N),
              ("stage", _sealed(2, 11, signer="B"), BODIES[2].hex(), N)]
    lines = _same(host_check, tmp_path, script)
    assert _events(lines[1]) == [("trust-applied", None)] and _events(lines[2]) == [("beat", None)]
    assert _events(lines[3]) == [("trust-applied", None)]
    assert _events(lines[4])[0][1] == "dist:trust-replay"                  # case 70: a list that drops the key
    assert _events(lines[5])[0][1] == _events(lines[6])[0][1] == "dist:trust-replay"
    assert _events(lines[7])[0][1] == "sig:revoked-key" and _events(lines[8])[0][1] == "dist:seq-replay"
    assert _events(lines[9]) == [("staged", None)] and _events(lines[10]) == [("trust-applied", None)]
    assert _records(lines[11])[0].floor == 9                               # a lower number never lowers it
    assert _events(lines[12])[0][1] == _events(lines[13])[0][1] == "dist:too-large"
    assert _events(lines[14]) == [("trust-applied", None)] and _events(lines[17])[0][1] == "sig:revoked-key"


@pytest.mark.parametrize("ground", ["envelope", "policy", "key", "floor"])
def test_case_069_108_a_revocation_that_removes_the_ground_lapses_the_release_held_or_not(host_check, tmp_path, ground):
    """case_069: R5. case_108: X8, R5. The active envelope, the policy hash, the only key that signed it or a floor
    above its seq: the release lapses with dist:revoked and a staged release on that ground is dropped, and a held
    PEP lapses the same way, which ends the hold."""
    staged = _dist.seal("policy.ppt", BODIES[0], seq=4, signer="B", targets=("mesh",), widens=True)
    active = _dist.seal("policy.ppt", BODIES[0], seq=3, signer="B", targets=("mesh",), widens=True)
    lists = {"envelope": {"envelopes": [env.envelope_id(env.unseal(active)[0]), env.envelope_id(env.unseal(staged)[0])]},
             "policy": {"policies": [H[0]]}, "key": {"keys": [_dist.key_id("B")]}, "floor": {"floors": {S: 5}}}[ground]
    for hold in (False, True):
        script = [("provision", S, N, ("A", "B")), ("stage", active.hex(), BODIES[0].hex(), N), ("commit", S, 3, H[0], N),
                  ("stage", staged.hex(), BODIES[0].hex(), N)]
        if hold:
            script += [("tick", E)]
        script += [_revoke(1, E if hold else N, **lists), ("decide", E if hold else N), ("restart", N), ("decide", N)]
        lines = _same(host_check, tmp_path / f"{ground}_{hold}", script, hold=hold)
        applied = _records(lines[-4])
        assert [(record.event, record.cause) for record in applied] == [("lapsed", "dist:revoked"), ("trust-applied", None)]
        assert applied[-1].state == "no-policy" and not applied[-1].held and not applied[-1].staged


def test_case_132_the_assembler_holds_a_trust_body_and_a_table_to_their_own_bounds(host_check):
    """case_132: E6, B9, the frame half on a mesh node. A full size revocation list assembles over frames, a body
    offered at 16,385 bytes drops the transfer, and a 641 byte table is dropped from its signed size once its
    envelope is admitted, frame for frame as frames.Assembler answers."""
    frames = _frames_module()
    full = next(case for case in C_CASES if case["name"].startswith("132_a_full_size_revocation_list"))
    table = next(case for case in C_CASES if case["name"].startswith("132_a_641_byte_table"))
    sealed, body = bytes.fromhex(full["sealed"]), bytes.fromhex(full["body"])
    assert len(body) > 640
    whole = [(data, 1) for data in frames.frames_for(3, sealed, body, frames.ESPNOW_LIMIT)]
    prefix = whole[0][0][4:20]
    past = [(frames.encode(frames.Offer(4, prefix, len(sealed), 16385)), 1)]
    big = [(data, 1) for data in frames.frames_for(5, bytes.fromhex(table["sealed"]), bytes.fromhex(table["body"]),
                                                    frames.ESPNOW_LIMIT)]
    for case, sequence in ((full, whole), (full, past), (table, big)):
        python = _python_events(frames, case, sequence, ordered=False, limit=frames.ESPNOW_LIMIT)
        assert _c_events(host_check, case, sequence, ordered=False, limit=frames.ESPNOW_LIMIT) == python
    assert _python_events(frames, full, whole, ordered=False, limit=frames.ESPNOW_LIMIT)[-1].startswith("whole")
    assert _python_events(frames, full, past, ordered=False, limit=frames.ESPNOW_LIMIT) == [
        f"dropped {causes.NAMES['dist:too-large']}"]
    assert f"dropped {causes.NAMES['dist:too-large']}" in _python_events(frames, table, big, ordered=False,
                                                                        limit=frames.ESPNOW_LIMIT)


def test_a_durable_floor_that_does_not_read_opens_the_pep_locked(host_check):
    """Q5: the boards keep each part of the durable state under its own NVS name (pp_durable_pack). A floor whose
    bytes are not one opens a PEP that is locked and admits nothing."""
    key = _generator().test_key("A")
    public = _generator().public_raw(key)
    lines = [f"key {env.key_id(public)} {public.hex()} 0", f"machine 0 1 {INSTANCE_SEED}", f"provision {S} {N}",
             f"stage {_sealed(0, 1)} {BODIES[0].hex()} {N}", f"commit {S} 1 {H[0]} 0 0 {N}", "lose floor",
             f"restart {N}", f"stage {_sealed(1, 2)} {BODIES[1].hex()} {N}", f"decide {N}", "done"]
    done = subprocess.run([str(host_check)], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    out = done.stdout.splitlines()
    record = _records(out[4])[0]
    assert (record.cause, record.state, record.active_seq) == ("dist:floor-lost", "locked", 0)
    assert out[5] == f"decide {causes.NAMES['dist:floor-lost']} 0"


def _machine(host_check, steps: list) -> list:
    key = _generator().test_key("A")
    public = _generator().public_raw(key)
    lines = [f"key {env.key_id(public)} {public.hex()} 0", f"machine 0 1 {INSTANCE_SEED}", *steps, "done"]
    done = subprocess.run([str(host_check)], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()


def test_a_state_record_writes_the_counter_alone_and_the_durable_state_fits_its_parts(host_check):
    """H3, C4: the core persists in parts. A state record writes only the counter, 12 bytes, however long the PEP
    runs, and the largest part a commit writes is a release, a few kilobytes on a mesh node, inside a 24 kilobyte
    NVS partition."""
    out = _machine(host_check, ["sizes", f"provision {S} {N}", f"stage {_sealed(0, 1)} {BODIES[0].hex()} {N}",
                                f"commit {S} 1 {H[0]} 0 0 {N}", "written", *[f"record 0 {N}"] * 500, "written"])
    durable, release, machine = (int(value) for value in out[0].split()[1:])
    assert durable < 64 * 1024 and release < 16 * 1024
    total, writes, largest = (int(value) for value in out[4].split()[1:])
    assert largest < 8 * 1024 and total < 24 * 1024
    total, writes, largest = (int(value) for value in out[-1].split()[1:])
    assert (total, writes, largest) == (12 * 500, 500, 12)


def test_a_widening_statement_holds_at_most_64_hashes(host_check):
    """W4: a statement whose from holds 64 hashes is staged and kept at its real size, and one with 65 is
    dist:too-large."""
    def statement(count: int) -> bytes:
        hashes = sorted(hashlib.sha256(bytes([index])).hexdigest() for index in range(count))
        return canon.canon2_bytes({"encoding": "canon/2", "format": "prismpath.dist-widening/1", "from": hashes})
    steps = [f"provision {S} {N}"]
    for seq, count in ((1, 64), (2, 65)):
        body = statement(count)
        sealed = _dist.seal("trust.widening", body, seq=seq, targets=("mesh",), policy_sha256=H[0],
                            release=env.release_id([("policy.ppt", H[0])]))
        steps.append(f"stage {sealed.hex()} {body.hex()} {N}")
    out = _machine(host_check, steps)
    assert _events(out[1]) == [("staged", None)] and _events(out[2]) == [("refused", "dist:too-large")]


def _after_loss(host_check, steps: list, cut: list) -> str:
    """Run `steps`, then `cut` with the power lost after each count of writes in turn, then a restart and the
    durable state read back. One line per count."""
    out = []
    for writes in range(12):
        script, _quiet = _with_statements(steps + [("stop", writes)] + cut + [("restart", N), ("state",)])
        lines = _c_steps(host_check, script, hold=False)
        out.append(lines[-1])
    return out


def test_a_power_loss_at_each_write_of_a_commit_or_a_rollback_leaves_one_release_with_a_known_previous(host_check):
    """C4 on the C core. A commit writes its parts one at a time, previous, active, staged, so after a power loss
    at any write the restarted node holds either the old release, with the new one still staged to commit again,
    or the new one with the old one as its previous. A rollback cut off holds either release, and never a
    previous that is neither the old previous nor the release itself."""
    built = [("provision", S, N)]                                     # each release with its statement (RB3)
    for index, seq in ((0, 1), (1, 2)):
        built += [("stage", _sealed(index, seq), BODIES[index].hex(), N), ("commit", S, seq, H[index], N)]
    built += [("stage", _sealed(2, 3), BODIES[2].hex(), N)]
    states = _after_loss(host_check, built, [("commit", S, 3, H[2], N)])
    assert set(states) <= {"state 2 1 3", "state 2 2 3", "state 3 2 -"}, states
    assert states[0] == "state 2 1 3" and states[-1] == "state 3 2 -"
    for writes, state in enumerate(states):
        if state != "state 3 2 -":                                   # committed again after the restart
            again, _quiet = _with_statements(built + [("stop", writes), ("commit", S, 3, H[2], N), ("restart", N),
                                                      ("commit", S, 3, H[2], N), ("state",)])
            assert _c_steps(host_check, again, hold=False)[-1] == "state 3 2 -", writes
    committed = built + [("commit", S, 3, H[2], N)]
    rolled = _after_loss(host_check, committed, [("rollback", N)])
    assert set(rolled) <= {"state 3 2 -", "state 3 - -", "state 2 - -"}, rolled
    assert rolled[0] == "state 3 2 -" and rolled[-1] == "state 2 - -"


# ------------------------------------------------------------------ rotations, against pep.py

def _rotate(seq: int, now: int, add: str, retire: str = "", signers=("A",)) -> tuple:
    body = _dist.rotation(add, retire)
    sealed = _dist.trust_statement("trust.rotation", body, seq=seq, signers=signers, targets=("mesh",))
    return ("stage", sealed.hex(), body.hex(), now)


def test_case_072_073_074_076_123_rotations_answer_as_the_python_machine(host_check, tmp_path):
    """case_072: O1, O2, O3. case_073: O3, S5. case_074: O2. case_076: O1. case_123: O1, R1. A rotation signed by the
    old and the new key is applied, a release under the new key commits, the retired key no longer counts while the
    release active under it keeps deciding, a rotation by an unknown key or without the new key's signature is
    refused, a rotation and a revocation share one trust sequence, and one that skips a number is refused."""
    script = [("provision", S, N), ("stage", _sealed(0, 1, signer="A"), BODIES[0].hex(), N), ("commit", S, 1, H[0], N),
              _rotate(1, N, "B", signers=("B",)), _rotate(1, N, "B", signers=("A",)), _rotate(1, N, "B", signers=("A", "U")),
              _rotate(2, N, "Q", signers=("A", "Q")), _rotate(1, N, "B", retire="A", signers=("A", "B")),
              ("stage", _sealed(1, 2, signer="A"), BODIES[1].hex(), N), ("decide", N), ("restart", N), ("decide", N),
              _rotate(2, N, "Q", signers=("B", "Q")), _revoke(2, N, signer="B"), _rotate(4, N, "U", signers=("B", "U")),
              ("stage", _sealed(1, 2, signer="B"), BODIES[1].hex(), N), ("commit", S, 2, H[1], N)]
    lines = _same(host_check, tmp_path, script)
    assert _events(lines[3])[0][1] == "dist:unknown-key"
    assert _events(lines[4])[0][1] == _events(lines[5])[0][1] == "dist:rotation-invalid"
    assert _events(lines[6])[0][1] == "dist:trust-replay" and _events(lines[7]) == [("trust-applied", None)]
    assert _events(lines[8])[0][1] == "sig:revoked-key" and lines[9] == lines[11] == "decide 0 0"
    assert _events(lines[12]) == [("trust-applied", None)] and _events(lines[13])[0][1] == "dist:trust-replay"
    assert _events(lines[14])[0][1] == "dist:trust-replay"
    assert _events(lines[16]) == [("committed", None)]


def test_a_rotation_that_names_a_key_it_may_not_answers_as_the_python_machine(host_check, tmp_path):
    """O3, O4 on the C core (case 75 runs in Python and Rust). A retire of an unknown key, an add of the node's
    own instance key, of a revoked key and of a key the store retired are each dist:rotation-invalid, and the trust sequence does not move."""
    body = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-rotation/1",
                               "add": _generator().public_raw(_generator().test_key("I")).hex(), "retire": ""})
    own = ("stage", _dist.trust_statement("trust.rotation", body, seq=1, signers=("A", "I"), targets=("mesh",)).hex(),
           body.hex(), N)
    script = [("provision", S, N), _rotate(1, N, "B", retire="U", signers=("A", "B")), own,
              _revoke(1, N, keys=[_dist.key_id("C")]), _rotate(2, N, "C", signers=("A", "C")),
              _rotate(2, N, "B", retire="A", signers=("A", "B")), _rotate(3, N, "A", signers=("B", "A"))]
    lines = _same(host_check, tmp_path, script)
    assert [_events(lines[k])[0][1] for k in (1, 2, 4, 6)] == ["dist:rotation-invalid"] * 4
    assert _records(lines[6])[0].trust_seq == 2


def test_case_131_a_ninth_key_and_a_seventeenth_retired_answer_as_the_python_machine(host_check, tmp_path):
    """case_131: K5. Seventeen rotations, each adding a key and retiring the one before, forget the first retired key,
    so a pack it signed is dist:unknown-key where it was sig:revoked-key, and a rotation that would hold a ninth key
    that is not retired is dist:too-large."""
    names = [f"K{index}" for index in range(18)]
    script = [("provision", S, N, ("A",))]
    previous = "A"
    for seq, name in enumerate(names[:17], start=1):
        script.append(_rotate(seq, N, name, retire=previous, signers=(previous, name)))
        previous = name
    script += [("stage", _sealed(0, 1, signer="A"), BODIES[0].hex(), N),
               ("stage", _sealed(0, 1, signer="K0"), BODIES[0].hex(), N)]
    lines = _same(host_check, tmp_path, script)
    assert all(_events(line) == [("trust-applied", None)] for line in lines[1:18])
    assert _events(lines[18])[0][1] == "dist:unknown-key" and _events(lines[19])[0][1] == "sig:revoked-key"
    eight = [("provision", S, N, ("A", "B", "C", "D", "E", "F", "G", "R"))]
    eight += [_rotate(1, N, "U", signers=("A", "U")), _rotate(1, N, "U", retire="B", signers=("A", "U"))]
    lines = _same(host_check, tmp_path / "eight", eight)
    assert _events(lines[1])[0][1] == "dist:too-large" and _events(lines[2]) == [("trust-applied", None)]


def test_case_082_a_node_never_provisioned_takes_no_rotation(host_check):
    """case_082: P1. It holds no key, so no rotation installs a first one."""
    unprovisioned = _c_steps(host_check, [_rotate(1, N, "B", signers=("B",))], hold=False)
    assert _events(unprovisioned[0]) == [("refused", "dist:unknown-key")]


def test_a_rotation_into_a_full_store_holds_the_new_key_as_the_python_machine_does(host_check, tmp_path):
    """K5 at its bound. With 8 keys that count and 16 retired held, a rotation that adds a key and retires one
    forgets the oldest retired key and its slot before the new key is held, so the C core keeps the new key as the
    Python machine does and a pack signed by it is staged on both. A pack signed by the first retired key, now
    forgotten, is dist:unknown-key, and one signed by the key the last rotation retired is sig:revoked-key."""
    live = ["B", "C", "D", "E", "F", "G", "H"]
    script = [("provision", S, N, ("A", *live))]
    retired = []
    for seq in range(1, 18):                                          # 16 to fill the retired ids, then one more
        name = f"K{seq}"
        retired.append(live.pop(0))
        script.append(_rotate(seq, N, name, retire=retired[-1], signers=("A", name)))
        live.append(name)
    script += [("stage", _sealed(0, 1, signer="K17"), BODIES[0].hex(), N),
               ("stage", _sealed(1, 2, signer=retired[0]), BODIES[1].hex(), N),      # forgotten at the seventeenth
               ("stage", _sealed(1, 2, signer=retired[-1]), BODIES[1].hex(), N)]     # retired by the seventeenth
    lines = _same(host_check, tmp_path, script)
    assert all(_events(line) == [("trust-applied", None)] for line in lines[1:18])
    assert _events(lines[18]) == [("staged", None)]
    assert _events(lines[19]) == [("refused", "dist:unknown-key")]
    assert _events(lines[20]) == [("refused", "sig:revoked-key")]


def test_case_134_a_trust_statement_reaches_the_node_whatever_its_targets_say(host_check, tmp_path):
    """case_134: V5, R1, on the C core. A revocation naming only `host` is applied by a mesh node as the Python
    machine applies it, and the rotation naming every kind after it is taken at the next trust sequence."""
    body = _dist.revocation(keys=[_dist.key_id("R")])
    only_host = _dist.trust_statement("trust.revocation", body, seq=1, targets=("host",))
    rotation = _dist.rotation("B")
    every = _dist.trust_statement("trust.rotation", rotation, seq=2, signers=("A", "B"), targets=("host", "mesh"))
    script = [("provision", S, N), ("stage", only_host.hex(), body.hex(), N), ("stage", every.hex(), rotation.hex(), N)]
    lines = _same(host_check, tmp_path, script)
    assert _events(lines[1]) == _events(lines[2]) == [("trust-applied", None)]
    assert _records(lines[2])[0].trust_seq == 2


def test_a_rollback_is_held_to_what_a_commit_checks_on_the_c_core(host_check, tmp_path):
    """RB2 on the C core (case 54 runs in Python): a rollback to a kept release whose only signing key is revoked,
    or that is below a raised floor, is refused with that check's cause as the Python machine refuses it."""
    kept = [("provision", S, N, ("A", "B")),                          # each release with its statement (RB3)
            ("stage", _sealed(0, 1), BODIES[0].hex(), N), ("commit", S, 1, H[0], N),
            ("stage", _sealed(1, 2, signer="B"), BODIES[1].hex(), N), ("commit", S, 2, H[1], N)]
    for name, revoke, cause in (("key", _revoke(1, N, keys=[_dist.key_id("A")]), "sig:revoked-key"),
                                ("floor", _revoke(1, N, floors={S: 2}), "dist:seq-replay")):
        lines = _same(host_check, tmp_path / name, kept + [revoke, ("rollback", N)])
        assert _events(lines[-1]) == [("refused", cause)], name



def test_case_060_061_062_063_109_the_widening_rule_answers_as_the_python_machine(host_check, tmp_path):
    """case_060: W2. case_061: W2, W3, W6. case_062: W4, W5. case_063: W2, W3. case_109: X8. A mesh node cannot decide
    whether a table allows more, but a table has no order, so one that is not byte for byte the active table is
    larger. A release goes in on its signature alone only as a renewal, with `widens` false and `replaces` the
    active hash. Another `replaces`, `widens` true, or another table need a covering statement, and another table
    that says it does not widen is refused even with one. It is checked at staging and again at commit, and a
    held node keeps the rule. The cFS half of case 60, a table taken on the signer's word, is in
    integrations/cfs/tests."""
    def release(index, seq, statement=None, **args):
        steps = []
        if statement is not None:
            body = _dist.widening(statement)
            steps.append(("stage", _dist.seal("trust.widening", body, seq=seq, release=env.release_id(
                [("policy.ppt", H[index])]), policy_sha256=H[index], targets=("mesh",), **args).hex(), body.hex(), N))
        return steps + [("stage", _sealed(index, seq, **args), BODIES[index].hex(), N)]

    script = [("provision", S, N)]
    script += release(0, 1)                                                    # 63: a first install, no statement
    script += release(0, 1, [], widens=True) + [("commit", S, 1, H[0], N)]     # 63: with one
    script += release(0, 2, replaces=H[0], widens=False) + [("commit", S, 2, H[0], N)]    # 60: a renewal
    script += release(2, 3, replaces=H[2], widens=False)                       # 61: another replaces
    script += release(2, 4, replaces=H[0], widens=True)                        # 61: widens, no statement
    script += release(2, 5, replaces=H[0], widens=False)                       # 61: another table, no statement
    script += release(2, 6, [], replaces=H[0], widens=False)                   # 61: and with one (W6)
    script += release(2, 7, [H[0]], replaces=H[0], widens=True)                # 62: from the active hash
    script += release(1, 8, [H[1]], replaces=H[0], widens=True)                # 62: from another only
    lines = _same(host_check, tmp_path, script, statements=False)
    events = [_events(line) for line in lines]
    assert events[1] == [("refused", "dist:widening-unsigned")]
    assert events[4] == events[6] == [("committed", None)]
    assert events[7] == events[8] == events[9] == [("refused", "dist:widening-unsigned")]
    assert events[10] == [("staged", None)] and events[11] == [("refused", "dist:widening-unsigned")]
    assert events[13] == [("staged", None)] and events[15] == [("refused", "dist:widening-unsigned")]
    held = [("provision", S, N)] + release(0, 1, [], widens=True, expires=N + 100) + [
        ("commit", S, 1, H[0], N), ("tick", N + 100)] + release(1, 2, replaces=H[0], widens=False,
                                                               expires=N + 1000)
    lines = _same(host_check, tmp_path / "held", held, hold=True, statements=False)
    assert _events(lines[-1]) == [("refused", "dist:widening-unsigned")] and _records(lines[-1])[0].held


COMMITS = [entry for entry in CORPUS["commits"] if "C" in entry["runs_on"]]


def test_case_137_138_every_commit_case_of_the_corpus_answers_on_the_c_core_as_recorded(host_check, tmp_path):
    """case_137, case_138: C2, E10. Each commit case of the corpus on a mesh node: a table whose signed release id
    also names a `policy.spiral` the transport withheld is dist:incomplete at commit, on a first install with
    nothing active after and on an update with the old release still active, and the same update without the
    spiral in its id commits. The C core answers as the Python machine and as the corpus records."""
    assert {entry["case"] for entry in COMMITS} == {137, 138} and all(e["kind"] == "mesh" for e in COMMITS)
    for entry in COMMITS:
        script = [("provision", S, entry["now"])]
        for step in entry["steps"]:
            if step["op"] == "stage":
                script.append(("stage", step["sealed"], step["body"], entry["now"]))
            else:
                script.append(("commit", S, step["seq"], step["policy_sha256"], entry["now"]))
        lines = _same(host_check, tmp_path / entry["name"], script, statements=False)
        last = _records(lines[-1])[-1]
        assert {"cause": last.cause, "active_seq": last.active_seq} == entry["expect"], entry["name"]


def _release_steps(index: int, seq: int, froms=None, **args) -> list:
    """The steps that stage a mesh release of BODIES[index] at `seq`, its widening statement of `froms` first
    when `froms` is given, with `args` on both envelopes."""
    steps = []
    if froms is not None:
        body = _dist.widening(froms)
        steps.append(("stage", _dist.seal("trust.widening", body, seq=seq, release=env.release_id(
            [("policy.ppt", H[index])]), policy_sha256=H[index], targets=("mesh",), **args).hex(), body.hex(), N))
    return steps + [("stage", _sealed(index, seq, **args), BODIES[index].hex(), N)]


def test_case_139_140_a_first_install_or_a_rollback_that_says_it_does_not_widen_is_refused_on_the_c_core(
        host_check, tmp_path):
    """case_139: W2, W6. A first install with `widens` false is refused at staging even with a statement whose
    `from` is empty, so nothing commits. case_140: RB3, W6. A rollback from table B to a kept renewal of table A
    that says it does not widen is refused even though the kept release holds a statement whose `from` is empty,
    and B stays active. The C core answers as the Python machine."""
    first = [("provision", S, N)] + _release_steps(0, 1, [], widens=False) + [("commit", S, 1, H[0], N)]
    events = [_events(line) for line in _same(host_check, tmp_path / "first", first, statements=False)]
    assert events[1] == [("staged", None)] and events[2] == [("refused", "dist:widening-unsigned")]
    assert events[3] == [("refused", "dist:incomplete")]
    back = ([("provision", S, N)] + _release_steps(0, 1, [], widens=True) + [("commit", S, 1, H[0], N)]
            + _release_steps(0, 2, [], replaces=H[0], widens=False) + [("commit", S, 2, H[0], N)]
            + _release_steps(1, 3, [], replaces=H[0], widens=True) + [("commit", S, 3, H[1], N), ("rollback", N)])
    lines = _same(host_check, tmp_path / "back", back, statements=False)
    assert [_events(lines[index]) for index in (3, 6, 9)] == [[("committed", None)]] * 3
    assert _events(lines[-1]) == [("refused", "dist:widening-unsigned")] and _records(lines[-1])[0].active_seq == 3


def test_case_143_a_renewal_whose_active_release_lapsed_before_its_commit_is_refused_on_the_c_core(host_check, tmp_path):
    """case_143: C3, V12, W2. A renewal staged with `widens` false and no statement, whose active release then
    expires, is dist:widening-unsigned at commit on the C core as on the Python machine, and nothing is active."""
    script = ([("provision", S, N)] + _release_steps(0, 1, [], widens=True, expires=N + 100) + [("commit", S, 1, H[0], N)]
              + _release_steps(0, 2, replaces=H[0], widens=False) + [("tick", N + 100), ("commit", S, 2, H[0], N + 100)])
    lines = _same(host_check, tmp_path, script, statements=False)
    assert _events(lines[4]) == [("staged", None)] and _events(lines[5])[0][0] == "lapsed"
    last = _records(lines[-1])[-1]
    assert (last.event, last.cause, last.state) == ("refused", "dist:widening-unsigned", "no-policy")
