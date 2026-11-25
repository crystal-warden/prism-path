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
ROLE_CODES = {"authority": 0, "controller": 2}  # PP_ROLE_AUTHORITY, PP_ROLE_CONTROLLER; any other role is 1
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
            lines.append(f"key {kid} {key['public']} {ROLE_CODES.get(key['role'], 1)}")
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


def _python_steps(script: list, *, hold: bool, tmp_path, controller=None, fresh=0, clock=True) -> list:
    """The Python machine (pep.Pep on a modelled mesh node) run through `script`, each step's output as the
    harness prints it. `controller` names the test key of a `/2` anchor's controller key, with its `fresh` (H16), and
    `clock` 0 is a node with no real time clock (T2)."""
    out, point = [], None
    for step in script:
        op, args = step[0], step[1:]
        if op == "provision":
            point = _dist.MeshPep(tmp_path, clock=_dist.Clock(args[1]), expiry_response="hold" if hold else "refuse",
                                  authorities=list(args[2]) if len(args) > 2 else ["A"], controller=controller,
                                  fresh=fresh, has_clock=clock, stream=args[0])
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
            elif op == "statement":
                taken = pep.take_statement(bytes.fromhex(args[0]))
                assert pep.drain() == []                                 # H9: a statement sends no record
                out.append(f"statement {int(taken)} {pep.epoch}")
                continue
            elif op == "decide":
                answer = pep.decide(lambda: 0)
                out.append(f"decide {causes.NAMES[answer['cause']] if answer['cause'] else 0} "
                           f"{int(answer['mark'] == 'held')}")
                continue
        out.append(" ".join(["records", *(record.hex() for record in point.pep.drain())]))
    return out


def _c_lines(script: list, *, hold: bool, controller=None, fresh=0, clock=True) -> list:
    first = script[0]
    authorities = first[3] if first[0] == "provision" and len(first) > 3 else ("A",)
    lines = []
    for name, role in [*((name, 0) for name in authorities), *(((controller, 2),) if controller else ())]:
        public = _generator().public_raw(_generator().test_key(name))
        lines.append(f"key {env.key_id(public)} {public.hex()} {role}")
    lines.append(f"machine {int(hold)} {int(clock)} {INSTANCE_SEED}")
    if fresh:
        lines.append(f"fresh {fresh}")
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


def _c_steps(host_check, script: list, *, hold: bool, **anchor) -> list:
    done = subprocess.run([str(host_check)], input="\n".join(_c_lines(script, hold=hold, **anchor)) + "\n",
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


def _same(host_check, tmp_path, script, *, hold=False, statements=True, **anchor) -> list:
    """`script` run on the Python machine and on the C core, which must print the same lines, returned with the
    lines of the statements `_with_statements` staged left out. A statement staged for a release that is then
    refused for another reason leaves a staged release that holds only the statement, which displaces what was
    staged before, so a release meant to be refused before V12 is sealed with `widens` false and gets none."""
    script, quiet = _with_statements(script) if statements else (script, set())
    python = _python_steps(script, hold=hold, tmp_path=tmp_path, **anchor)
    c = _c_steps(host_check, [step for step in script if step[0] not in ()], hold=hold, **anchor)
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
    """H3, H10, C4: the core persists in parts. A state record writes only the counter and the two counts of H10
    that ride with it, 20 bytes, however long the PEP runs, and the largest part a commit writes is a release, a few
    kilobytes on a mesh node, inside a 24 kilobyte NVS partition. The durable state with its install parts stays
    under 96 kilobytes and a held statement under 5."""
    out = _machine(host_check, ["sizes", f"provision {S} {N}", f"stage {_sealed(0, 1)} {BODIES[0].hex()} {N}",
                                f"commit {S} 1 {H[0]} 0 0 {N}", "written", *[f"record 0 {N}"] * 500, "written"])
    durable, release, machine, _record, statement = (int(value) for value in out[0].split()[1:])
    assert durable < 96 * 1024 and release < 16 * 1024 and statement < 5 * 1024
    total, writes, largest = (int(value) for value in out[4].split()[1:])
    assert largest < 8 * 1024 and total < 24 * 1024
    total, writes, largest = (int(value) for value in out[-1].split()[1:])
    assert (total, writes, largest) == (20 * 500, 500, 20)


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


def test_case_308_a_withheld_artifact_at_commit_is_incomplete(host_check):
    """case_308: C2, E10, the mesh half of the host case. A release whose signed release id covers a policy.ppt and a
    policy.spiral is committed with only its policy.ppt staged: dist:incomplete and nothing is committed. The same
    table with a release id over what is staged then commits."""
    body, policy = BODIES[0], canon.sha256_hex(BODIES[0])
    withheld = env.release_id([("policy.ppt", policy), ("policy.spiral", canon.sha256_hex(b"a withheld spiral"))])
    statement = _dist.widening()
    steps = [f"provision {S} {N}"]
    for seq, release in ((1, withheld), (2, env.release_id([("policy.ppt", policy)]))):
        cover = _dist.seal("trust.widening", statement, seq=seq, release=release, policy_sha256=policy,
                           targets=("mesh",), widens=True)
        table = _dist.seal("policy.ppt", body, seq=seq, release=release, targets=("mesh",), widens=True)
        steps += [f"stage {cover.hex()} {statement.hex()} {N}", f"stage {table.hex()} {body.hex()} {N}",
                  f"commit {S} {seq} {policy} 0 0 {N}"]
    out = _machine(host_check, steps)
    assert _events(out[2])[-1] == ("staged", None) and _events(out[3]) == [("refused", "dist:incomplete")]
    assert _events(out[6])[-1] == ("committed", None)


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
    spiral in its id commits. case_294, case_295: W10, W11. A table carried by a change statement from the active
    hash commits and the same table alone does not, and a change statement that says it widens, sits on a first
    install, names another hash or follows a widening statement of its release is refused. The C core answers as
    the Python machine and as the corpus records."""
    assert {entry["case"] for entry in COMMITS} == {137, 138, 294, 295} and all(e["kind"] == "mesh" for e in COMMITS)
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


# ------------------------------------------------------------------ section 21 on the C core: install statements, the
# action floor, the fallback policy and the ceiling on a mesh node
#
# The Python machine on this branch has no section 21, so these steps are held to the spec's expectations directly:
# each install statement is built here from its canon/2 document and sealed by the test keys, and each record the C
# core signs is read back under its instance key with the type 3 entry of H10.

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

G = _generator()
NB = _dist.NOT_BEFORE
ZERO = "0" * 64
DOMAIN = hashlib.sha256(b"the mesh domain this node was built with").hexdigest()
FINGERPRINT = hashlib.sha256(b"the anchor").hexdigest()
LAYOUT = hashlib.sha256(b"the layout document of the node").hexdigest()
COMMAND, PARAMETER, INDEPENDENT, PROPOSER = range(4)
# AF10: register 0 the command, 1 its parameter, 2 a reading the PEP takes itself (5 s), 3 the proposer's reading
FIELDS = [(0, COMMAND, -1000, 1000, 0), (1, PARAMETER, 0, 100, 0), (2, INDEPENDENT, 0, 1, 5), (3, PROPOSER, 0, 1, 0)]
EVENTS21 = [*state_record.EVENTS, "fallback", "install-applied", "install-widened", "answered"]
SUBJECT = {"install.floor": 1, "install.fallback": 2, "install.ceiling": 3, "install.trust": 4}
ALLOW, REFUSE = 1, 2
BASIS = {0: None, 1: "release", 2: "floor", 3: "fallback", 4: "operator"}


def _pub(name: str) -> bytes:
    return G.public_raw(G.test_key(name))


def _kid(name: str) -> str:
    return env.key_id(_pub(name))


def _ppt(edges, *, atoms=None, nodes=2, pad_to=0, fields=4) -> bytes:
    """A `.ppt` image of a start node 0 whose edges are `edges`, each a postfix program of atom indexes and the
    opcodes "and", "or", "not", "true", "false", all to node 1, over `atoms` (register, op, type, value). Unused
    TRUE words pad it to `pad_to` bytes."""
    import struct
    opcodes = {"not": 0x8000, "and": 0x8001, "or": 0x8002, "true": 0x8003, "false": 0x8004}
    atoms = atoms or []
    words, table = [], []
    for program in edges:
        table.append((1, len(words), len(program)))
        words += [opcodes[word] if isinstance(word, str) else word for word in program]
    node_list = [(0, len(edges))] + [(len(edges), 0)] * (nodes - 1)
    def build(extra):
        out = struct.pack("<4sHHHHHHHHHHHBB", b"PPTM", 1, fields, 0, len(atoms), nodes, len(edges), len(words) + extra,
                          0, 0xFFFF, 16, 16, 0, 0)
        out += b"".join(struct.pack("<HBBi", *atom) for atom in atoms)
        out += b"".join(struct.pack("<HH", *node) for node in node_list)
        out += b"".join(struct.pack("<HHH", *edge) for edge in table)
        out += b"".join(struct.pack("<H", word) for word in words + [0x8003] * extra)
        return out
    image = build(0)
    return build((pad_to - len(image)) // 2) if pad_to else image


EQ, NE, LT, LE, GT, GE = range(6)
INT = 2


def _rule(command: int, low: int = 10, high: int = 20, *, extra=()) -> tuple:
    """One narrow floor rule: the command register equal to `command` and the parameter in [low, high], each a
    conjunct of the whole program (AF9), with `extra` atoms joined by `and`."""
    atoms = [(0, EQ, INT, command), (1, GE, INT, low), (1, LE, INT, high), *extra]
    return atoms, len(atoms)


def _floor_table(commands=(3,), *, low=10, high=20, extra=(), pad_to=0) -> bytes:
    atoms, edges = [], []
    for command in commands:
        rule, n = _rule(command, low, high, extra=extra)
        first = len(atoms)
        atoms += rule
        program = [first, first + 1, "and"] + [word for k in range(2, n) for word in (first + k, "and")]
        edges.append(program)
    return _ppt(edges, atoms=atoms, pad_to=pad_to)


FLOOR = _floor_table()
FLOOR_B = _floor_table((3, 4))
FALLBACK = _ppt([[0]], atoms=[(0, GE, INT, 100)])       # allows a command of 100 and above
FALLBACK_B = _ppt([[0]], atoms=[(0, GE, INT, 200)])
RELEASE = BODIES[0]                                      # allows x >= 5, where x is register 0


def _regs(command: int, parameter: int = 15, independent: int = 1, proposer: int = 0) -> str:
    import struct
    return (b"\x00" * 4 + b"".join(struct.pack("<ii", INT, value)
                                   for value in (command, parameter, independent, proposer))).hex()


def _release_id(name: str, body: bytes) -> str:
    return hashlib.sha256(canon.canon2_bytes([[name, hashlib.sha256(body).hexdigest()]])).hexdigest()


def _ceiling(*bodies, hashes=None) -> bytes:
    listed = sorted(hashes if hashes is not None else {hashlib.sha256(body).hexdigest() for body in bodies})
    return canon.canon2_bytes({"bodies": listed, "encoding": "canon/2", "format": "prismpath.dist-ceiling/1"})


def _trust_body(keys, threshold, operators=()) -> bytes:
    return canon.canon2_bytes({"encoding": "canon/2", "format": "prismpath.dist-install-trust/1",
                               "keys": sorted(_pub(name).hex() for name in keys),
                               "operators": sorted(_pub(name).hex() for name in operators), "threshold": threshold})


def _install(artifact: str, body: bytes = b"", *, seq: int = 1, signers=("J", "K"), as_=None, widens=None,
             replaces: str = "", meta=None, not_before: int = NB, expires: int = 0, targets=("mesh",), stream=S,
             policy=None, release=None, body_size=None, envelope_only=False):
    """An install statement as the engineer's tool seals it, and its body: (sealed hex, body hex)."""
    trust = artifact == "install.trust"
    if as_ is None and not trust:
        as_ = "none" if body == b"" else ("policy.list" if artifact == "install.ceiling" else "policy.ppt")
    if meta is None:
        meta = {} if trust else {"as": as_}
        if artifact == "install.floor" and as_ == "policy.ppt":
            meta.update(layout=LAYOUT, command=0)
    if widens is None:
        widens = trust or (artifact in ("install.floor", "install.fallback") and as_ != "none")
    body_sha = hashlib.sha256(body).hexdigest()
    if policy is None:
        policy = ZERO if trust or as_ == "none" else body_sha
    if release is None:
        release = ZERO if trust else _release_id(as_, body)
    doc = {"artifact": artifact, "body_sha256": body_sha, "body_size": len(body) if body_size is None else body_size,
           "encoding": "canon/2", "expires": expires, "format": "prismpath.dist/1", "meta": meta,
           "not_before": not_before, "policy_sha256": policy, "release": release, "replaces": replaces, "seq": seq,
           "stream": stream, "targets": sorted(targets), "widens": widens}
    raw = canon.canon2_bytes(doc)
    if envelope_only:
        return raw
    return env.seal(raw, [G.test_key(name) for name in signers]).hex(), body.hex() or "-"


def _envelope_id(sealed_hex: str) -> str:
    return hashlib.sha256(env.unseal(bytes.fromhex(sealed_hex))[0]).hexdigest()


def _install_id(*, floor=None, fallback=None, ceiling=None, trust_seq=0, trust_id=FINGERPRINT) -> str:
    """H10: the install id of the sets held, each (sealed hex, seq) or None, and the install trust state."""
    out = b""
    for held in (floor, fallback, ceiling):
        if held is None:
            out += b"\x00" * 40
        else:
            out += hashlib.sha256(bytes.fromhex(_envelope_id(held[0]))).digest() + held[1].to_bytes(8, "little")
    out += trust_seq.to_bytes(8, "little") + bytes.fromhex(trust_id)
    return hashlib.sha256(out).hexdigest()[:32]


def _anchor(keys=("J", "K"), threshold=2, *, operators=(), seq=0, fingerprint=FINGERPRINT, authorities=("A",),
            domain=DOMAIN, bring=()) -> list:
    """The lines of an anchor of `authorities` with an install member of `keys` (None for none), and the statements
    the engineer brings with it."""
    lines = ["anchor_clear", *(f"akey {_kid(name)} {_pub(name).hex()}" for name in authorities)]
    if keys is not None:
        lines += [f"ikey {_pub(name).hex()}" for name in keys] + [f"iop {_pub(name).hex()}" for name in operators]
        lines.append(f"install {threshold} {seq} {domain} {fingerprint}")
    lines += [f"bring {sealed} {body}" for sealed, body in bring]
    return lines


def _node(*, hold=False, clock=True, layout=True) -> list:
    lines = [f"machine {int(hold)} {int(clock)} {INSTANCE_SEED}", f"domain {DOMAIN}"]
    if layout:
        lines += [f"layout {LAYOUT}", *(f"field {reg} {role} {low} {high} {stale}" for reg, role, low, high, stale in FIELDS)]
    return lines


def _run21(host_check, lines: list) -> list:
    done = subprocess.run([str(host_check)], input="\n".join([*lines, "done"]) + "\n", capture_output=True, text=True,
                          timeout=120)
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()


def _read21(item: str) -> dict:
    """One state record of the C core, its signature checked under the instance key, with its type 3 entry."""
    raw = bytes.fromhex(item)
    x = int.from_bytes(raw[146:148], "little")
    body = raw[:148 + x]
    Ed25519PublicKey.from_public_bytes(_dist.instance_key().public_raw).verify(
        raw[148 + x:], b"DSSEv1 36 application/vnd.prismpath.dist-state %d " % len(body) + body)
    out = {"event": EVENTS21[raw[5]], "state": state_record.STATES[raw[6] & 3], "staged": bool(raw[6] & 0x80),
           "held": bool(raw[6] & 0x20), "fallback": bool(raw[6] & 0x10),
           "cause": causes.name(raw[7]) if raw[7] else None, "time": int.from_bytes(raw[32:40], "little"),
           "active_seq": int.from_bytes(raw[96:104], "little"), "floor": int.from_bytes(raw[104:112], "little"),
           "trust_seq": int.from_bytes(raw[136:144], "little"), "size": len(raw), "entries": x}
    if x:
        entry = raw[148:148 + x]
        assert (entry[0], int.from_bytes(entry[1:3], "little"), x) == (3, 27, 30)   # H10: type 3 alone, 27 bytes
        out.update(install_id=entry[3:19].hex(), trust_low=int.from_bytes(entry[19:21], "little"), subject=entry[21],
                   answers=int.from_bytes(entry[22:26], "little"), overrides=int.from_bytes(entry[26:30], "little"))
    return out


def _recs(line: str) -> list:
    assert line.startswith("records"), line
    return [_read21(item) for item in line.split()[1:]]


def _last(line: str) -> dict:
    return _recs(line)[-1]


def _ask(line: str) -> dict:
    words = line.split()
    assert words[0] == "ask", line
    return {"outcome": int(words[1]), "cause": causes.name(int(words[2])) if int(words[2]) else None,
            "basis": BASIS[int(words[3])], "held": words[4] == "1", "policy": None if words[5] == "-" else words[5],
            "would": int(words[6]), "would_cause": causes.name(int(words[7])) if int(words[7]) else None,
            "would_policy": None if words[8] == "-" else words[8], "override": words[9] == "1",
            "counted": words[10] == "1", "rule": int(words[11]), "window": int(words[12]), "count": int(words[13]),
            "rate_escalated": words[14] == "1", "decided_rule": int(words[15]), "would_rule": int(words[16])}


def _stage(statement, now=N) -> str:
    return f"stage {statement[0]} {statement[1]} {now}"


def _h16(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()[:32]


def _release_steps21(body: bytes, seq: int, *, now=N, widens=True, replaces="", not_before=NB, expires=E) -> list:
    """Stage a mesh release of `body` with its widening statement, and commit it."""
    release = env.release_id([("policy.ppt", canon.sha256_hex(body))])
    policy = canon.sha256_hex(body)
    lines = []
    if widens:
        statement = _dist.widening()
        lines.append(f"stage {_dist.seal('trust.widening', statement, seq=seq, release=release, policy_sha256=policy, targets=('mesh',), replaces=replaces, widens=True, not_before=not_before).hex()} {statement.hex()} {now}")
    lines.append(f"stage {_dist.seal('policy.ppt', body, seq=seq, targets=('mesh',), widens=widens, replaces=replaces, not_before=not_before, expires=expires).hex()} {body.hex()} {now}")
    lines.append(f"commit {S} {seq} {policy} 0 0 {now}")
    return lines


def _refused(line: str):
    """The cause and subject of the one refused record of a step."""
    record = _last(line)
    assert record["event"] == "refused", record
    return record["cause"], record["subject"]


def test_case_162_an_install_statement_out_of_its_form_is_refused_and_nothing_changes(host_check):
    """case_162: IS1, IS2, IS5. Signed only by authority keys, an expiry, two target kinds, another stream, a body one
    byte short, a body the image check refuses, no `as`, and a not_before 301 seconds ahead of a PEP with a clock."""
    short = _install("install.fallback", FALLBACK, seq=2)
    statements = [
        _install("install.fallback", FALLBACK, seq=2, signers=("A",)),
        _install("install.fallback", FALLBACK, seq=2, expires=NB + 30 * 86400),
        _install("install.fallback", FALLBACK, seq=2, targets=("host", "mesh")),
        _install("install.fallback", FALLBACK, seq=2, stream="mesh/other"),
        (short[0], FALLBACK[:-1].hex()),
        _install("install.fallback", b"PPTX" + FALLBACK[4:], seq=2),
        _install("install.fallback", FALLBACK, seq=2, meta={"other": 1}),
        _install("install.fallback", FALLBACK, seq=2, not_before=N + 301),
    ]
    held = _install("install.fallback", FALLBACK_B, seq=1)
    out = _run21(host_check, [*_node(), *_anchor(bring=[held]), f"provision {S} {N}", "installid",
                              *(_stage(one) for one in statements), "installid"])
    assert [_refused(line) for line in out[2:-1]] == [
        ("dist:unknown-key", 2), ("dist:bad-format", 0), ("dist:bad-format", 0), ("dist:target-mismatch", 2),
        ("dist:body-mismatch", 2), ("image:bad-magic", 2), ("dist:bad-format", 0), ("dist:not-yet-valid", 2)]
    assert out[1] == out[-1] == f"installid {_install_id(fallback=(held[0], 1))}"


def test_case_163_236_the_roles_are_apart_at_the_anchor_and_after(host_check):
    """case_163: IS2, K4, O4. case_236: P2, K4. An anchor that holds one key in both roles, or whose install key or
    operator key is the instance key, or whose install key is also an operator key, is refused and the PEP is left
    as it was. A release, a widening statement, a revocation and a rotation signed only by install keys are
    dist:unknown-key, and a rotation that adds an install key, held or retired, is dist:rotation-invalid."""
    release = _dist.seal("policy.ppt", RELEASE, seq=1, targets=("mesh",), widens=True, signer="J")
    statement = _dist.widening()
    widening = _dist.seal("trust.widening", statement, seq=1, policy_sha256=canon.sha256_hex(RELEASE),
                          release=env.release_id([("policy.ppt", canon.sha256_hex(RELEASE))]), targets=("mesh",),
                          widens=True, signer="J")
    revocation = _dist.trust_statement("trust.revocation", _dist.revocation(), seq=1, signers=("J",), targets=("mesh",))
    rotation = _dist.trust_statement("trust.rotation", _dist.rotation(_pub("B").hex()), seq=1, signers=("J", "B"),
                                     targets=("mesh",))
    adds_install = _dist.trust_statement("trust.rotation", _dist.rotation(_pub("K").hex()), seq=1, signers=("A", "K"),
                                         targets=("mesh",))
    adds_retired = _dist.trust_statement("trust.rotation", _dist.rotation(_pub("L").hex()), seq=1, signers=("A", "L"),
                                         targets=("mesh",))
    drop_l = _install("install.trust", _trust_body(("J", "K"), 2), seq=1, signers=("J", "K", "L"), widens=False)
    out = _run21(host_check, [
        *_node(), *_anchor(("A", "K")), f"provision {S} {N}",                       # one key in both roles
        *_anchor(("I", "K")), f"provision {S} {N}",                                 # the instance key
        *_anchor(("J", "K"), operators=("I",)), f"provision {S} {N}",               # an operator key that is it
        *_anchor(("J", "K"), operators=("K",)), f"provision {S} {N}",               # an install key also an operator
        *_anchor(("J", "K", "L")), f"provision {S} {N}",
        f"stage {release.hex()} {RELEASE.hex()} {N}", f"stage {widening.hex()} {statement.hex()} {N}",
        f"stage {revocation.hex()} {_dist.revocation().hex()} {N}",
        f"stage {rotation.hex()} {_dist.rotation(_pub('B').hex()).hex()} {N}",
        _stage(drop_l),
        f"stage {adds_install.hex()} {_dist.rotation(_pub('K').hex()).hex()} {N}",
        f"stage {adds_retired.hex()} {_dist.rotation(_pub('L').hex()).hex()} {N}"])
    assert out[:4] == [f"provision-refused {causes.NAMES['dist:rotation-invalid']}"] * 4
    assert _last(out[4])["event"] == "provisioned"
    assert [_refused(line)[0] for line in out[5:9]] == ["dist:unknown-key"] * 4
    assert _last(out[9])["event"] == "install-applied"
    assert [_refused(line)[0] for line in out[10:]] == ["dist:rotation-invalid"] * 2


def test_case_165_177_the_install_threshold_and_the_retired_install_keys(host_check):
    """case_165: IS2. With three install keys at a threshold of 2, one good signature is dist:unknown-key, two apply,
    and one good with one by a retired install key is sig:revoked-key. case_177: IS11. Nine install keys retired one
    after another forget the first, so a floor it signs with one current key is dist:unknown-key."""
    retire_l = _install("install.trust", _trust_body(("J", "K", "M"), 2), seq=1, signers=("J", "K", "M"))
    out = _run21(host_check, [
        *_node(), *_anchor(("J", "K", "L")), f"provision {S} {N}", _stage(retire_l),
        _stage(_install("install.fallback", FALLBACK, seq=1, signers=("J",))),
        _stage(_install("install.fallback", FALLBACK, seq=1, signers=("J", "K"))),
        _stage(_install("install.fallback", FALLBACK_B, seq=2, signers=("J", "L")))])
    assert _last(out[1])["event"] == "install-widened"
    assert _refused(out[2])[0] == "dist:unknown-key"
    assert [one["event"] for one in _recs(out[3])] == ["staged", "install-widened"]
    assert _refused(out[4])[0] == "sig:revoked-key"
    steps, keys = [], ["K0"]
    for n in range(1, 10):                           # K0 to K8 retired in turn, the ninth forgetting K0
        steps.append(_stage(_install("install.trust", _trust_body(("J", f"K{n}"), 2), seq=n, signers=("J", f"K{n - 1}", f"K{n}"))))
        keys.append(f"K{n}")
    out = _run21(host_check, [*_node(), *_anchor(("J", "K0")), f"provision {S} {N}", *steps,
                              _stage(_install("install.fallback", FALLBACK, seq=1, signers=("J", "K0"))),
                              _stage(_install("install.fallback", FALLBACK, seq=1, signers=("J", "K1")))])
    assert all(_last(line)["event"] == "install-widened" for line in out[1:10])
    assert [_refused(line)[0] for line in out[10:]] == ["dist:unknown-key", "sig:revoked-key"]


def test_case_166_a_threshold_of_1_takes_install_statements_by_provisioning_only(host_check):
    """case_166: IS4, IS2. With an install threshold of 1 a floor and an install.trust in a message are
    dist:target-mismatch whatever their signatures, and the same floor brought by provisioning is held."""
    floor = _install("install.floor", FLOOR, seq=1, signers=("J",))
    trust = _install("install.trust", _trust_body(("J", "K"), 1), seq=1, signers=("J", "K"))
    out = _run21(host_check, [*_node(), *_anchor(("J",), 1), f"provision {S} {N}", _stage(floor), _stage(trust),
                              "installid", *_anchor(("J",), 1, bring=[floor]), f"provision {S} {N}", "installid"])
    assert [_refused(line) for line in out[1:3]] == [("dist:target-mismatch", 1), ("dist:target-mismatch", 4)]
    assert out[3] == f"installid {_install_id()}"
    assert (_last(out[4])["event"], _last(out[4])["cause"]) == ("provisioned", "dist:install-widened")
    assert out[5] == f"installid {_install_id(floor=(floor[0], 1))}"


def test_case_169_the_install_sequence_of_each_kind_only_rises(host_check):
    """case_169: IS6. A floor at 2 and another at 3 below or beside the held one at 3 are dist:seq-replay, the same
    one again changes nothing, one at 5 applies, one at 4 is dist:seq-replay, and a fallback policy at 1 applies."""
    held = _install("install.floor", FLOOR, seq=3)
    out = _run21(host_check, [*_node(), *_anchor(), f"provision {S} {N}", _stage(held),
                              _stage(_install("install.floor", FLOOR_B, seq=2)),
                              _stage(_install("install.floor", FLOOR_B, seq=3)), _stage(held),
                              _stage(_install("install.floor", FLOOR_B, seq=5)),
                              _stage(_install("install.floor", FLOOR, seq=4)),
                              _stage(_install("install.fallback", FALLBACK, seq=1))])
    assert _last(out[1])["event"] == "install-widened"
    assert [_refused(line)[0] for line in out[2:4]] == ["dist:seq-replay"] * 2
    assert [one["event"] for one in _recs(out[4])] == ["beat"]
    assert _last(out[5])["event"] == "install-widened"
    assert _refused(out[6])[0] == "dist:seq-replay"
    assert (_last(out[7])["event"], _last(out[7])["subject"]) == ("install-widened", 2)


def test_case_180_an_install_statement_never_moves_the_time_floor(host_check):
    """case_180: IS5, T1. A mesh node with no clock and a release that expires in a month takes an action floor whose
    not_before is a year ahead, and its time floor and its release stay as they were."""
    floor = _install("install.floor", FLOOR, seq=1, not_before=NB + 365 * 86400)
    out = _run21(host_check, [*_node(clock=False), *_anchor(), f"provision {S} {N}", *_release_steps21(RELEASE, 1),
                              _stage(floor), f"record 0 {N}"])
    committed, applied, beat = _last(out[3]), _last(out[4]), _last(out[5])
    assert committed["event"] == "committed" and applied["event"] == "install-widened"
    assert (beat["time"], beat["state"], beat["active_seq"]) == (committed["time"], "active", 1)


def test_case_223_a_mesh_floor_skips_the_meta_members_it_does_not_read(host_check):
    """case_223: IS1, IS5, the mesh half. A floor whose meta holds `counts` as a string is applied, since the mesh
    reader reads `as`, `layout`, `command`, `rate` and `answer_rate` and skips the rest (E9)."""
    floor = _install("install.floor", FLOOR, meta={"as": "policy.ppt", "command": 0, "counts": "three",
                                                    "layout": LAYOUT})
    out = _run21(host_check, [*_node(), *_anchor(), f"provision {S} {N}", _stage(floor)])
    assert _last(out[1])["event"] == "install-widened"


def test_case_174_an_install_key_retired_later_does_not_remove_what_it_signed(host_check):
    """case_174: IS11, AF3. An install.trust adds L, a floor L signs applies, a second drops K, a floor K signs is
    sig:revoked-key, and after a restart the fallback policy K signed is still held."""
    fallback = _install("install.fallback", FALLBACK, seq=1, signers=("J", "K"))
    out = _run21(host_check, [
        *_node(), *_anchor(("J", "K")), f"provision {S} {N}", _stage(fallback),
        _stage(_install("install.trust", _trust_body(("J", "K", "L"), 2), seq=1, signers=("J", "K", "L"))),
        _stage(_install("install.floor", FLOOR, seq=1, signers=("J", "L"))),
        _stage(_install("install.trust", _trust_body(("J", "L"), 2), seq=2, signers=("J", "L"), widens=False)),
        _stage(_install("install.floor", FLOOR_B, seq=2, signers=("J", "K"))), f"restart {N}", "installid"])
    assert [_last(line)["event"] for line in out[1:5]] == ["install-widened", "install-widened", "install-widened",
                                                          "install-applied"]
    assert _refused(out[5])[0] == "sig:revoked-key"
    assert out[7] == f"installid {_install_id(floor=(_install('install.floor', FLOOR, seq=1, signers=('J', 'L'))[0], 1), fallback=(fallback[0], 1), trust_seq=2, trust_id=_envelope_id(_install('install.trust', _trust_body(('J', 'L'), 2), seq=2, signers=('J', 'L'), widens=False)[0]))}"


def test_case_175_an_install_trust_statement_is_held_to_its_rules_and_the_trust_store_never_moves(host_check):
    """case_175: IS11, IS7. Two above the install trust sequence, no signature by the key it adds, fewer signatures
    than the threshold, five keys, a threshold of 0, and adding the instance key, a trusted authority key, a revoked
    key id or a retired install key, and one signed only by authority keys."""
    revoke = _dist.trust_statement("trust.revocation", _dist.revocation(keys=[_kid("X")]), seq=1, signers=("A",),
                                   targets=("mesh",))
    retire = _install("install.trust", _trust_body(("J", "K", "M"), 2), seq=1, signers=("J", "K", "M"))
    def trust(keys, threshold, signers, seq=2, body=None):
        return _install("install.trust", body or _trust_body(keys, threshold), seq=seq, signers=signers)
    five = canon.canon2_bytes({"encoding": "canon/2", "format": "prismpath.dist-install-trust/1",
                               "keys": sorted(_pub(name).hex() for name in ("J", "K", "M", "P", "Q")),
                               "operators": [], "threshold": 2})
    out = _run21(host_check, [
        *_node(), *_anchor(("J", "K", "L")), f"provision {S} {N}",
        f"stage {revoke.hex()} {_dist.revocation(keys=[_kid('X')]).hex()} {N}", _stage(retire),
        _stage(trust(("J", "K", "M", "P"), 2, ("J", "K", "P"), seq=3)),
        _stage(trust(("J", "K", "M", "P"), 2, ("J", "K"))),
        _stage(trust(("J", "K", "M", "P"), 2, ("J", "P"))),
        _stage(trust(None, 2, ("J", "K"), body=five)),
        _stage(trust(None, 0, ("J", "K"), body=_trust_body(("J", "K"), 0))),
        _stage(trust(("J", "K", "I"), 2, ("J", "K", "I"))),
        _stage(trust(("J", "K", "A"), 2, ("J", "K", "A"))),
        _stage(trust(("J", "K", "X"), 2, ("J", "K", "X"))),
        _stage(trust(("J", "K", "L"), 2, ("J", "K", "L"))),
        _stage(trust(("J", "K"), 2, ("A",))), f"record 0 {N}"])
    assert _last(out[1])["event"] == "trust-applied" and _last(out[2])["event"] == "install-widened"
    assert [_refused(line)[0] for line in out[3:13]] == [
        "dist:trust-replay", "dist:rotation-invalid", "dist:unknown-key", "dist:too-large", "dist:bad-format",
        "dist:rotation-invalid", "dist:rotation-invalid", "dist:rotation-invalid", "dist:rotation-invalid",
        "dist:unknown-key"]
    assert (_last(out[13])["trust_seq"], _last(out[13])["trust_low"]) == (1, 1)


def test_case_176_four_keys_at_a_threshold_of_4_add_a_fifth_in_two_statements(host_check):
    """case_176: IS11, the C half. A sealed envelope holds four signatures (S2), so a statement that would need five
    cannot be sealed. The engineer drops a key at a threshold of 3, then adds the new one, and both are applied."""
    with pytest.raises(Refused):
        _install("install.trust", _trust_body(("J", "K", "L", "M", "P"), 4), signers=("J", "K", "L", "M", "P"))
    out = _run21(host_check, [
        *_node(), *_anchor(("J", "K", "L", "M"), 4), f"provision {S} {N}",
        _stage(_install("install.trust", _trust_body(("J", "K", "L"), 3), seq=1, signers=("J", "K", "L", "M"))),
        _stage(_install("install.trust", _trust_body(("J", "K", "L", "P"), 3), seq=2, signers=("J", "K", "L", "P")))])
    assert [_last(line)["event"] for line in out[1:]] == ["install-widened", "install-widened"]   # lowers, then adds


def test_case_218_an_install_trust_or_a_rate_that_widens_says_so(host_check):
    """case_218: IS11, IS12, AF8. An install.trust that adds a key with widens false is dist:widening-unsigned, one
    that lowers the threshold with widens true is applied as install-widened, and a floor of the same table with a
    looser rate and widens false is dist:widening-unsigned."""
    rate = lambda allows: {"as": "policy.ppt", "command": 0, "layout": LAYOUT,  # noqa: E731
                           "rate": {"allows": allows, "window": 60}}
    floor = _install("install.floor", FLOOR, seq=1, meta=rate(3), signers=("J", "K", "L"))
    out = _run21(host_check, [
        *_node(), *_anchor(("J", "K", "L"), 3), f"provision {S} {N}", _stage(floor),
        _stage(_install("install.trust", _trust_body(("J", "K", "L", "M"), 3), seq=1, signers=("J", "K", "L", "M"),
                        widens=False)),
        _stage(_install("install.trust", _trust_body(("J", "K", "L"), 2), seq=1, signers=("J", "K", "L"))),
        _stage(_install("install.floor", FLOOR, seq=2, meta=rate(5), widens=False, replaces=canon.sha256_hex(FLOOR)))])
    assert _last(out[1])["event"] == "install-widened"
    assert _refused(out[2]) == ("dist:widening-unsigned", 4)
    assert (_last(out[3])["event"], _last(out[3])["cause"]) == ("install-widened", "dist:install-widened")
    assert _refused(out[4]) == ("dist:widening-unsigned", 1)


def test_case_221_224_233_operator_keys_are_kept_apart_and_never_used_on_a_mesh_node(host_check):
    """case_221: OP1, IS11, the PEP's half. An anchor enrolls one operator key, an install.trust that adds a second
    is dist:widening-unsigned with widens false and applied as install-widened with widens true, one that adds an
    install key as an operator is dist:rotation-invalid, and an operator key signs neither an install statement
    nor a release. case_224: K4, O4, IS11. An anchor whose operator key is an authority or an install key is refused,
    a rotation that adds an operator key, held or retired, is dist:rotation-invalid, and so is an install.trust that
    puts one key in both lists or adds as an operator a key retired as an install key; one that drops an operator
    key retires it, and adding it again is dist:rotation-invalid. case_233: IS13, IS11. With a threshold of 1, an
    install provisioning drops an operator key, and an answer that key signs is dist:target-mismatch."""
    floor = _install("install.floor", FLOOR, seq=1, signers=("O",))
    release = _dist.seal("policy.ppt", RELEASE, seq=1, targets=("mesh",), widens=True, signer="O")
    adds_op = _dist.trust_statement("trust.rotation", _dist.rotation(_pub("O").hex()), seq=1, signers=("A", "O"),
                                    targets=("mesh",))
    adds_retired_op = _dist.trust_statement("trust.rotation", _dist.rotation(_pub("P").hex()), seq=1,
                                            signers=("A", "P"), targets=("mesh",))
    both = canon.canon2_bytes({"encoding": "canon/2", "format": "prismpath.dist-install-trust/1",
                               "keys": sorted([_pub("J").hex(), _pub("K").hex(), _pub("Q").hex()]),
                               "operators": sorted([_pub("O").hex(), _pub("Q").hex()]), "threshold": 2})
    out = _run21(host_check, [
        *_node(), *_anchor(("J", "K"), operators=("A",)), f"provision {S} {N}",
        *_anchor(("J", "K"), operators=("J",)), f"provision {S} {N}",
        *_anchor(("J", "K", "L"), operators=("O",)), f"provision {S} {N}",
        _stage(_install("install.trust", _trust_body(("J", "K", "L"), 2, ("O", "P")), seq=1, signers=("J", "K", "P"),
                        widens=False)),
        _stage(_install("install.trust", _trust_body(("J", "K", "L"), 2, ("O", "P")), seq=1, signers=("J", "K", "P"))),
        _stage(_install("install.trust", _trust_body(("J", "L"), 2, ("K", "O", "P")), seq=2, signers=("J", "L"))),
        _stage(floor), f"stage {release.hex()} {RELEASE.hex()} {N}",
        f"stage {adds_op.hex()} {_dist.rotation(_pub('O').hex()).hex()} {N}",
        _stage(_install("install.trust", _trust_body(("J", "K", "L"), 2, ("O",)), seq=2, signers=("J", "K"),
                        widens=False)),
        f"stage {adds_retired_op.hex()} {_dist.rotation(_pub('P').hex()).hex()} {N}",
        _stage(_install("install.trust", both, seq=3, signers=("J", "K", "Q"))),
        _stage(_install("install.trust", _trust_body(("J", "K"), 2, ("O",)), seq=3, signers=("J", "K"), widens=False)),
        _stage(_install("install.trust", _trust_body(("J", "K"), 2, ("L", "O")), seq=4, signers=("J", "K", "L"))),
        _stage(_install("install.trust", _trust_body(("J", "K"), 2, ("O", "P")), seq=4, signers=("J", "K", "P")))])
    assert out[:2] == [f"provision-refused {causes.NAMES['dist:rotation-invalid']}"] * 2
    assert _last(out[2])["event"] == "provisioned"
    assert _refused(out[3]) == ("dist:widening-unsigned", 4)
    assert (_last(out[4])["event"], _last(out[4])["subject"]) == ("install-widened", 4)
    assert _refused(out[5]) == ("dist:rotation-invalid", 4)
    assert [_refused(line)[0] for line in out[6:9]] == ["dist:unknown-key", "dist:unknown-key", "dist:rotation-invalid"]
    assert (_last(out[9])["event"], _last(out[9])["trust_low"]) == ("install-applied", 2)   # P retired
    assert [_refused(line)[0] for line in out[10:12]] == ["dist:rotation-invalid"] * 2
    assert (_last(out[12])["event"], _last(out[12])["trust_low"]) == ("install-applied", 3)   # L retired as install
    assert [_refused(line)[0] for line in out[13:]] == ["dist:rotation-invalid"] * 2
    answer_body = canon.canon2_bytes({"answer": "allow", "encoding": "canon/2", "format": "prismpath.dist-answer/1",
                                      "pep": _h16(_dist.instance_key().public_raw), "receipt": ZERO})
    def answer(signer):
        raw = canon.canon2_bytes({"artifact": "operator.answer", "body_sha256": canon.sha256_hex(answer_body),
                                  "body_size": len(answer_body), "encoding": "canon/2", "expires": N + 600,
                                  "format": "prismpath.dist/1", "meta": {}, "not_before": N, "policy_sha256": ZERO,
                                  "release": ZERO, "replaces": "", "seq": 1, "stream": S, "targets": ["mesh"],
                                  "widens": False})
        return f"stage {env.seal(raw, [G.test_key(signer)]).hex()} {answer_body.hex()} {N}"
    out = _run21(host_check, [
        *_node(), *_anchor(("J",), 1, operators=("O", "P")), f"provision {S} {N}", answer("O"),
        "bring " + " ".join(_install("install.trust", _trust_body(("J",), 1, ("O",)), seq=1, signers=("J",),
                                     widens=False)), f"install_provision {N}", answer("P"), f"record 0 {N}"])
    assert _refused(out[1])[0] == "dist:target-mismatch"
    assert (_last(out[2])["event"], _last(out[2])["trust_low"]) == ("install-applied", 1)
    assert _refused(out[3])[0] == "dist:target-mismatch"
    assert (_last(out[4])["trust_seq"], _last(out[4])["floor"]) == (0, 0)


def test_case_170_a_provisioning_never_lowers_the_install_part_and_a_disjoint_key_set_starts_it_again(host_check):
    """case_170: IS6, IS10, P4. A PEP holding a floor at 5 and a fallback policy is provisioned with its own install
    key set and a floor at 4 (seq-replay, the held floor stays), with an anchor alone, with a lower install trust
    sequence (dist:trust-replay), with a higher one that shares a key and drops another and brings a floor at 1
    (the key set changes, the dropped key is retired, the install trust id is the anchor's fingerprint and the
    floor at 1 is seq-replay), and with a higher one that shares no key and brings a floor at 1 and no fallback
    policy (the floor is held, every old key retired, the fallback policy dropped). The floor at 5 is then
    sig:revoked-key."""
    floor5 = _install("install.floor", FLOOR, seq=5)
    fallback = _install("install.fallback", FALLBACK, seq=1)
    second, third = (hashlib.sha256(name).hexdigest() for name in (b"second anchor", b"third anchor"))
    floor1_shared = _install("install.floor", FLOOR_B, seq=1, signers=("J", "L"))
    floor1_new = _install("install.floor", FLOOR_B, seq=1, signers=("P", "Q"))
    out = _run21(host_check, [
        *_node(), *_anchor(seq=1, bring=[floor5, fallback]), f"provision {S} {N}", "installid",
        *_anchor(seq=1, bring=[_install("install.floor", FLOOR_B, seq=4)]), f"provision {S} {N}", "installid",
        *_anchor(seq=1), f"provision {S} {N}", "installid",
        *_anchor(seq=0), f"provision {S} {N}",
        *_anchor(("J", "L"), seq=2, fingerprint=second, bring=[floor1_shared]), f"provision {S} {N}", "installid",
        _stage(_install("install.fallback", FALLBACK_B, seq=2, signers=("J", "K"))),
        *_anchor(("P", "Q"), seq=3, fingerprint=third, bring=[floor1_new]), f"provision {S} {N}", "installid",
        _stage(floor5)])
    held = _install_id(floor=(floor5[0], 5), fallback=(fallback[0], 1), trust_seq=1)
    assert [out[1], out[3], out[5]] == [f"installid {held}"] * 3
    assert out[6] == f"provision-refused {causes.NAMES['dist:trust-replay']}"
    assert out[8] == f"installid {_install_id(floor=(floor5[0], 5), fallback=(fallback[0], 1), trust_seq=2, trust_id=second)}"
    assert _refused(out[9])[0] == "sig:revoked-key"                          # K was retired
    assert out[11] == f"installid {_install_id(floor=(floor1_new[0], 1), trust_seq=3, trust_id=third)}"
    assert _refused(out[12])[0] == "sig:revoked-key"


def test_a_provisioning_refuses_a_brought_set_its_staging_would_refuse_and_keeps_a_seq_replay_record(host_check):
    """P2 step 3, CL3, IS10, IS12, the C half of the Python and Rust tests. A statement brought with an anchor is held,
    before anything changes, to what staging it in order meets, as pp_apply_set holds it: a fallback policy outside the
    held ceiling, one outside a ceiling brought before it, one with widens false that nothing replaces, and on a node
    whose ceiling is lost a ceiling that is not the lost one again each refuse the provisioning and leave the install
    part as it was. The lost ceiling sent again naming its hash is applied. A set below the held seq is
    dist:seq-replay and the provisioning goes on (case 170), and that refusal is reported beside provisioned."""
    wide = _ceiling(FLOOR, FALLBACK)
    ceiling = _install("install.ceiling", wide, seq=1)
    narrower = _install("install.ceiling", _ceiling(FLOOR), seq=2, widens=False, replaces=canon.sha256_hex(wide))
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[ceiling]), f"provision {S} {N}", "installid",
        *_anchor(bring=[_install("install.fallback", FALLBACK_B, seq=1)]), f"provision {S} {N}", "installid",
        *_anchor(bring=[narrower, _install("install.fallback", FALLBACK, seq=1)]), f"provision {S} {N}", "installid",
        *_anchor(bring=[_install("install.fallback", FALLBACK, seq=1, widens=False)]), f"provision {S} {N}",
        "installid"])
    held = f"installid {_install_id(ceiling=(ceiling[0], 1))}"
    assert out[1] == held
    assert [out[2], out[4], out[6]] == [f"provision-refused {causes.NAMES['dist:above-ceiling']}"] * 2 + [
        f"provision-refused {causes.NAMES['dist:widening-unsigned']}"]
    assert [out[3], out[5], out[7]] == [held] * 3
    lost_hash = canon.sha256_hex(wide)
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[ceiling]), f"provision {S} {N}", "lose set_ceiling", "lose2 set_ceiling",
        f"restart {N}",
        *_anchor(bring=[_install("install.ceiling", _ceiling(FLOOR, FALLBACK, RELEASE), seq=2, widens=False,
                                 replaces=lost_hash)]), f"provision {S} {N}",
        *_anchor(bring=[_install("install.ceiling", wide, seq=2, widens=False, replaces=lost_hash)]),
        f"provision {S} {N}", "installid"])
    assert out[2] == f"provision-refused {causes.NAMES['dist:widening-unsigned']}"
    resent = _install("install.ceiling", wide, seq=2, widens=False, replaces=lost_hash)
    assert [(one["event"], one["cause"]) for one in _recs(out[3])] == [("provisioned", None)]
    assert out[4] == f"installid {_install_id(ceiling=(resent[0], 2))}"
    fallback2 = _install("install.fallback", FALLBACK, seq=2)
    out = _run21(host_check, [
        *_node(), *_anchor(), f"provision {S} {N}", _stage(fallback2),
        *_anchor(bring=[_install("install.fallback", FALLBACK_B, seq=1)]), f"provision {S} {N}", "installid"])
    assert [(one["event"], one["cause"]) for one in _recs(out[2])] == [("refused", "dist:seq-replay"),
                                                                       ("provisioned", None)]
    assert out[3] == f"installid {_install_id(fallback=(fallback2[0], 2))}"


def test_case_171_227_a_locked_pep_and_an_install_provisioning_keep_their_state(host_check):
    """case_171: IS6, FB1. A locked PEP with a threshold of 2 applies a fallback policy and stays locked. case_227:
    IS13, IS6, P3. With a threshold of 1, a floor of section 6 at 7, a time floor a day ahead of its clock and a floor
    at 2, an install provisioning with a floor at 3 is applied as install-applied with the floor, the trust sequence
    and the time floor unchanged, the same again changes nothing, one at 2 is seq-replay, a release at 6 is
    seq-replay, and a locked PEP takes an install provisioning and stays locked."""
    out = _run21(host_check, [*_node(), *_anchor(), f"provision {S} {N}", "lose floor", f"restart {N}",
                              _stage(_install("install.fallback", FALLBACK, seq=1))])
    assert out[1] == "records"                       # a start sends no record of its own
    record = _last(out[2])
    assert (record["event"], record["state"], record["fallback"]) == ("install-widened", "locked", True)
    ahead = NB + 86400
    floor2 = _install("install.floor", FLOOR, seq=2, signers=("J",))
    renewal = _install("install.floor", FLOOR, seq=3, signers=("J",), widens=False, replaces=canon.sha256_hex(FLOOR))
    out = _run21(host_check, [
        *_node(clock=False), *_anchor(("J",), 1, bring=[floor2]), f"provision {S} {N}",
        *_release_steps21(RELEASE, 7, not_before=ahead, expires=ahead + 30 * 86400), f"record 0 {N}",
        "bring " + " ".join(renewal), f"install_provision {N}", "bring " + " ".join(renewal), f"install_provision {N}",
        "bring " + " ".join(_install("install.floor", FLOOR_B, seq=2, signers=("J",))), f"install_provision {N}",
        f"stage {_dist.seal('policy.ppt', BODIES[1], seq=6, targets=('mesh',), widens=True).hex()} {BODIES[1].hex()} {N}",
        "lose floor", f"restart {N}",
        "bring " + " ".join(_install("install.floor", FLOOR, seq=4, signers=("J",), widens=False,
                                     replaces=canon.sha256_hex(FLOOR))), f"install_provision {N}"])
    before = _last(out[4])
    assert (before["floor"], before["time"], before["trust_seq"]) == (7, ahead, 0)
    applied = _last(out[5])
    assert (applied["event"], applied["subject"], applied["floor"], applied["time"], applied["trust_seq"]) == (
        "install-applied", 1, 7, ahead, 0)
    assert _last(out[6])["event"] == "beat"
    assert _refused(out[7])[0] == "dist:seq-replay"
    assert _refused(out[8])[0] == "dist:seq-replay"
    assert (_last(out[10])["event"], _last(out[10])["state"]) == ("install-applied", "locked")


def test_case_172_the_authority_s_revocation_never_reaches_an_install_statement(host_check):
    """case_172: IS7, AF3, the PEP's half. A revocation that lists an install key id, the floor's envelope id and its
    policy hash is applied, the floor allows as before and the install key still counts, and a rotation whose retire
    names an install key is dist:rotation-invalid."""
    floor = _install("install.floor", FLOOR, seq=1)
    body = _dist.revocation(keys=[_kid("J")], envelopes=[_envelope_id(floor[0])], policies=[canon.sha256_hex(FLOOR)])
    revocation = _dist.trust_statement("trust.revocation", body, seq=1, signers=("A",), targets=("mesh",))
    rotation = _dist.trust_statement("trust.rotation", _dist.rotation(_pub("B").hex(), _kid("K")), seq=2,
                                     signers=("A", "B"), targets=("mesh",))
    out = _run21(host_check, [*_node(), *_anchor(), f"provision {S} {N}", _stage(floor),
                              f"stage {revocation.hex()} {body.hex()} {N}", f"ask {N} {_regs(3)} -",
                              _stage(_install("install.fallback", FALLBACK, seq=1)),
                              f"stage {rotation.hex()} {_dist.rotation(_pub('B').hex(), _kid('K')).hex()} {N}"])
    assert _last(out[2])["event"] == "trust-applied"
    assert _ask(out[3])["basis"] == "floor"
    assert _last(out[4])["event"] == "install-widened"
    assert _refused(out[5])[0] == "dist:rotation-invalid"


def test_case_178_the_empty_set_withdraws_its_kind(host_check):
    """case_178: IS1, IS6, IS12. The empty floor at a higher seq withdraws the floor with install-applied, the held
    floor again is seq-replay, and the empty ceiling withdraws the ceiling with install-widened."""
    floor = _install("install.floor", FLOOR, seq=1)
    ceiling = _install("install.ceiling", _ceiling(FLOOR, RELEASE), seq=1)
    out = _run21(host_check, [*_node(), *_anchor(), f"provision {S} {N}", _stage(ceiling), _stage(floor),
                              _stage(_install("install.floor", seq=2, widens=False, replaces=canon.sha256_hex(FLOOR))),
                              _stage(floor), "installid",
                              _stage(_install("install.ceiling", seq=2, widens=True,
                                              replaces=canon.sha256_hex(_ceiling(FLOOR, RELEASE)))), "installid"])
    assert (_last(out[1])["event"], _last(out[2])["event"]) == ("install-applied", "install-widened")
    assert (_last(out[3])["event"], _last(out[3])["subject"]) == ("install-applied", 1)
    assert _refused(out[4])[0] == "dist:seq-replay"
    assert out[5] == f"installid {_install_id(ceiling=(ceiling[0], 1))}"
    record = _last(out[6])
    assert (record["event"], record["cause"], record["subject"]) == ("install-widened", "dist:install-widened", 3)
    assert out[7] == f"installid {_install_id()}"


def test_a_withdrawn_kind_holds_nothing_in_python_as_in_the_c_core(host_check, tmp_path):
    """IS6, H10, IS12: the empty set withdraws its kind and the PEP holds nothing of it. The Python machine and the C
    core, given one anchor, a ceiling and the empty ceiling after it, send the same install id, which is the install
    id of a PEP that holds no set. The same empty set again changes nothing, and the next ceiling that says it does
    not widen names the empty string as `replaces`, not the empty set's zero policy hash, in both."""
    from prismpath.distribution import install
    from prismpath.distribution.adapters.mesh import MeshAdapter
    ceiling = "install.ceiling"
    point = _dist.MeshPep(tmp_path / "mesh", install_keys=["J", "K"], install_threshold=2)
    record = point.pep.installed.record
    domain, fingerprint = install.domain_sha256(MeshAdapter()), record.trust_id
    before = record.install_id().hex()
    listed = _ceiling(RELEASE)

    def py(seq, bodies, **args):
        return point.send(point.install_set(ceiling, bodies, seq, **args))[-1]

    assert py(1, {"policy.list": listed}).event == "install-applied"
    withdrawn = point.install_set(ceiling, {"none": b""}, 2, widens=True)
    assert point.send(withdrawn)[-1].event == "install-widened"
    after = point.pep.installed.record.install_id().hex()
    assert point.send(withdrawn)[-1].event == "beat" and point.pep.installed.record.install_id().hex() == after
    assert point.pep.installed.ceiling is None
    assert py(3, {"policy.list": listed}, replaces=ZERO).cause == "dist:widening-unsigned"
    assert py(3, {"policy.list": listed}, replaces="").event == "install-applied"

    def c(seq, **args):
        return _stage(_install(ceiling, listed, seq=seq, **args))

    empty = _install(ceiling, seq=2, widens=True, replaces=hashlib.sha256(listed).hexdigest())
    out = _run21(host_check, [f"machine 0 1 {INSTANCE_SEED}", f"domain {domain}",
                              *_anchor(domain=domain, fingerprint=fingerprint), f"provision {S} {N}", "installid",
                              c(1), _stage(empty), "installid", _stage(empty), "installid",
                              c(3, widens=False, replaces=ZERO), c(3, widens=False, replaces="")])
    assert out[1] == f"installid {before}" == f"installid {_install_id(trust_id=fingerprint)}"
    assert _last(out[2])["event"] == "install-applied" and _last(out[3])["event"] == "install-widened"
    assert out[4] == f"installid {after}" == out[1] and out[6] == out[4]
    assert _refused(out[7])[0] == "dist:widening-unsigned" and _last(out[8])["event"] == "install-applied"


def test_case_182_234_the_older_forms_stay_refused(host_check):
    """case_182: IS9, L2. A PEP that holds an install statement and committed nothing refuses the older forms, again
    after a second provisioning and after its install record is made unreadable. case_234: L2, P3. A PEP that never
    held one refuses them on a stream it committed on, also after it is provisioned again."""
    out = _run21(host_check, [*_node(), *_anchor(bring=[_install("install.floor", FLOOR)]), f"provision {S} {N}",
                              f"legacy {S}", f"legacy mesh/other", *_anchor(), f"provision {S} {N}", f"legacy {S}",
                              "lose install", "lose2 install", f"restart {N}", f"legacy {S}"])
    refused = f"legacy {causes.NAMES['dist:legacy-refused']}"
    assert out[1:3] == [refused, refused] and out[4] == refused and out[6] == refused
    assert _refused(out[5])[0] == "dist:install-lost"
    out = _run21(host_check, [*_node(), *_anchor(None), f"provision {S} {N}", f"legacy {S}",
                              *_release_steps21(RELEASE, 1), f"legacy {S}", f"legacy mesh/other",
                              *_anchor(None), f"provision {S} {N}", f"legacy {S}"])
    assert out[1] == "legacy 0" and out[5] == refused and out[6] == "legacy 0" and out[8] == refused


def test_case_195_197_198_201_the_fallback_policy_decides_whenever_no_release_does(host_check):
    """case_195: FB1, FB2, FB3. A mesh PEP with a fallback policy sees its release expire, has its release revoked,
    starts with nothing committed and loses its floor of section 6: the fallback policy decides each time, event
    fallback with dist:expired, dist:revoked, dist:fallback and dist:floor-lost, bit 4 set, no-policy three times and
    locked once, the active hash zeros, and no decision is dist:policy-lapsed. case_198: FB4. Going to it sends the
    state record and nothing else. case_201: FB7, X2. A cut off PEP decides under its release until it expires and
    then under the fallback policy for a year. case_197: FB1, X3. With an action floor and no fallback policy, the
    release expires to no-policy with lapsed, bit 4 clear, and what the floor is silent on is dist:policy-lapsed."""
    fallback = _install("install.fallback", FALLBACK, seq=1)
    second = BODIES[1]
    revoke = _dist.trust_statement("trust.revocation", _dist.revocation(policies=[canon.sha256_hex(second)]), seq=1,
                                   signers=("A",), targets=("mesh",))
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[fallback]), f"provision {S} {N}", *_release_steps21(RELEASE, 1),
        f"ask {E - 1} {_regs(150)} -", f"tick 0 {E}", f"ask {E} {_regs(150)} -", f"ask {E + 365 * 86400} {_regs(150)} -",
        *_release_steps21(second, 2, now=N, replaces=""),
        f"stage {revoke.hex()} {_dist.revocation(policies=[canon.sha256_hex(second)]).hex()} {N}",
        f"ask {N} {_regs(150)} -", f"restart {N}", "lose floor", f"restart {N}", f"ask {N} {_regs(150)} -"])
    assert _ask(out[4])["basis"] == "release"
    expired = _recs(out[5])
    assert [(one["event"], one["cause"], one["state"], one["fallback"], one["active_seq"]) for one in expired] == [
        ("fallback", "dist:expired", "no-policy", True, 0)]                  # FB4: one record and nothing else
    assert [_ask(line)["basis"] for line in out[6:8]] == ["fallback", "fallback"]
    assert [(one["event"], one["cause"], one["fallback"]) for one in _recs(out[11])] == [
        ("fallback", "dist:revoked", True), ("trust-applied", None, True)]
    assert _ask(out[12])["basis"] == "fallback"
    assert [(one["event"], one["cause"], one["state"]) for one in _recs(out[13])] == [
        ("fallback", "dist:fallback", "no-policy")]
    assert [(one["event"], one["cause"], one["state"], one["fallback"]) for one in _recs(out[14])] == [
        ("fallback", "dist:floor-lost", "locked", True)]
    assert (_ask(out[15])["basis"], _ask(out[15])["cause"]) == ("fallback", None)
    out = _run21(host_check, [*_node(), *_anchor(bring=[_install("install.floor", FLOOR)]), f"provision {S} {N}",
                              *_release_steps21(RELEASE, 1), f"tick 0 {E}", f"ask {E} {_regs(150)} -"])
    lapsed = _last(out[4])
    assert (lapsed["event"], lapsed["cause"], lapsed["fallback"]) == ("lapsed", "dist:expired", False)
    assert (_ask(out[5])["basis"], _ask(out[5])["cause"]) == (None, "dist:policy-lapsed")


def test_case_199_the_only_way_out_of_the_fallback_policy_is_a_commit(host_check):
    """case_199: FB5, FB2. Under the fallback policy a release with no widening statement, or one whose `from` holds
    the fallback policy's hash, is dist:widening-unsigned, and one whose `from` is empty commits with bit 4 clear. A
    locked PEP under its fallback policy admits no release and decides under it until it is provisioned."""
    fallback = _install("install.fallback", FALLBACK, seq=1)
    release = _dist.seal("policy.ppt", RELEASE, seq=1, targets=("mesh",), widens=True)
    named = _dist.widening([canon.sha256_hex(FALLBACK)])
    statement = _dist.seal("trust.widening", named, seq=1, policy_sha256=canon.sha256_hex(RELEASE),
                           release=env.release_id([("policy.ppt", canon.sha256_hex(RELEASE))]), targets=("mesh",),
                           widens=True)
    commit = f"commit {S} 1 {canon.sha256_hex(RELEASE)} 0 0 {N}"
    out = _run21(host_check, [*_node(), *_anchor(bring=[fallback]), f"provision {S} {N}",
                              f"stage {release.hex()} {RELEASE.hex()} {N}", commit,
                              f"stage {statement.hex()} {named.hex()} {N}", f"stage {release.hex()} {RELEASE.hex()} {N}",
                              commit, *_release_steps21(RELEASE, 2)])
    assert _refused(out[1])[0] == "dist:widening-unsigned"
    assert _refused(out[4])[0] == "dist:widening-unsigned"
    assert _refused(out[2])[0] == "dist:not-staged"
    committed = _last(out[8])
    assert (committed["event"], committed["fallback"], committed["state"]) == ("committed", False, "active")
    out = _run21(host_check, [*_node(), *_anchor(bring=[fallback]), f"provision {S} {N}", "lose floor", f"restart {N}",
                              *_release_steps21(RELEASE, 1), f"ask {N} {_regs(150)} -",
                              *_anchor(bring=[]), f"provision {S} {N}", f"ask {N} {_regs(150)} -"])
    assert [_refused(line)[0] for line in out[2:5]] == ["dist:floor-lost"] * 3
    assert _ask(out[5])["basis"] == "fallback"
    assert _last(out[6])["state"] == "no-policy" and _ask(out[7])["basis"] == "fallback"


def test_case_204_205_everything_the_pep_decides_under_is_inside_its_ceiling(host_check):
    """case_204: CL2, C3, RB2. A staged release, and a kept one, outlive a narrower ceiling they are above and are
    refused with dist:above-ceiling at the commit and at the rollback and dropped. case_205: CL3, IS12, the C half. A
    floor, a fallback policy and a ceiling the held floor is above are dist:above-ceiling with nothing changed; a
    ceiling the active release is above, with widens false, narrows, so it is applied as install-applied and the
    release lapses with dist:above-ceiling, to the fallback policy and to no-policy."""
    wide = _ceiling(RELEASE, BODIES[1], BODIES[2])
    def ceiling(seq, *bodies, widens=False, replaces=canon.sha256_hex(wide)):
        return _install("install.ceiling", _ceiling(*bodies), seq=seq, widens=widens, replaces=replaces)
    staged = _dist.seal("policy.ppt", BODIES[1], seq=2, targets=("mesh",), widens=True)
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[_install("install.ceiling", wide)]), f"provision {S} {N}",
        *_release_steps21(RELEASE, 1)[:2],                                   # staged, not committed
        _stage(ceiling(2, BODIES[1], BODIES[2])), "state", f"commit {S} 1 {canon.sha256_hex(RELEASE)} 0 0 {N}", "state"])
    assert _last(out[3])["event"] == "install-applied" and out[4] == "state - - 1"
    assert _refused(out[5])[0] == "dist:above-ceiling" and out[6] == "state - - -"
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[_install("install.ceiling", wide)]), f"provision {S} {N}",
        *_release_steps21(RELEASE, 1), *_release_steps21(BODIES[1], 2, replaces=canon.sha256_hex(RELEASE)),
        _stage(ceiling(2, BODIES[1], BODIES[2])), "state", f"rollback {N}", "state"])
    assert _last(out[7])["event"] == "install-applied" and out[8] == "state 2 1 -"
    assert _refused(out[9])[0] == "dist:above-ceiling" and out[10] == "state 2 - -"
    floor_out = _install("install.floor", FLOOR_B, seq=2)
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[_install("install.ceiling", _ceiling(FLOOR, FALLBACK, RELEASE))]), f"provision {S} {N}",
        _stage(_install("install.floor", FLOOR)), _stage(floor_out), _stage(_install("install.fallback", FALLBACK_B)),
        _stage(_install("install.ceiling", _ceiling(FALLBACK, RELEASE), seq=2,
                        replaces=canon.sha256_hex(_ceiling(FLOOR, FALLBACK, RELEASE)))), "installid"])
    assert _last(out[1])["event"] == "install-widened"
    assert [_refused(line) for line in out[2:5]] == [("dist:above-ceiling", 1), ("dist:above-ceiling", 2),
                                                     ("dist:above-ceiling", 3)]
    for bring, after in (([_install("install.fallback", FALLBACK)], ("fallback", True)), ([], ("lapsed", False))):
        everything = _ceiling(FALLBACK, RELEASE)
        out = _run21(host_check, [
            *_node(), *_anchor(bring=[_install("install.ceiling", everything), *bring]), f"provision {S} {N}",
            *_release_steps21(RELEASE, 1),
            _stage(_install("install.ceiling", _ceiling(FALLBACK), seq=2, replaces=canon.sha256_hex(everything)))])
        records = _recs(out[4])
        assert [(one["event"], one["cause"]) for one in records] == [
            ("staged", None), ("install-applied", None), (after[0], "dist:above-ceiling")]
        assert records[-1]["fallback"] is after[1] and records[-1]["active_seq"] == 0


def test_case_207_208_each_decision_names_its_basis_and_the_set_that_decided(host_check):
    """case_207: RC1. A release allows and refuses with basis release, the action floor allows with basis floor, the
    fallback policy allows and refuses with basis fallback, each with the policy hash of its set, and a PEP with no
    fallback policy refuses in no-policy with no basis and dist:policy-lapsed. case_208: RC2, RC3. A held PEP decides
    under its release with the hold mark, and a floor allow carries the hold mark and dist:floor-allowed."""
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[_install("install.floor", FLOOR), _install("install.fallback", FALLBACK)]),
        f"provision {S} {N}", f"ask {N} {_regs(150)} -", f"ask {N} {_regs(50)} -", *_release_steps21(RELEASE, 1),
        f"ask {N} {_regs(7)} -", f"ask {N} {_regs(4)} -", f"ask {N} {_regs(3)} -"])
    asked = [_ask(line) for line in (out[1], out[2], out[6], out[7], out[8])]
    assert [(one["outcome"], one["basis"], one["policy"]) for one in asked] == [
        (ALLOW, "fallback", _h16(FALLBACK)), (REFUSE, "fallback", _h16(FALLBACK)), (ALLOW, "release", _h16(RELEASE)),
        (REFUSE, "release", _h16(RELEASE)), (ALLOW, "floor", _h16(FLOOR))]
    assert (asked[-1]["cause"], asked[-1]["would"], asked[-1]["would_policy"]) == (
        "dist:floor-allowed", REFUSE, _h16(RELEASE))
    out = _run21(host_check, [*_node(), *_anchor(bring=[_install("install.floor", FLOOR)]), f"provision {S} {N}",
                              f"ask {N} {_regs(50)} -"])
    assert (_ask(out[1])["basis"], _ask(out[1])["cause"], _ask(out[1])["policy"]) == (None, "dist:policy-lapsed", None)
    out = _run21(host_check, [*_node(hold=True), *_anchor(bring=[_install("install.floor", FLOOR)]),
                              f"provision {S} {N}", *_release_steps21(RELEASE, 1), f"tick 0 {E}",
                              f"ask {E} {_regs(7)} -", f"ask {E} {_regs(3)} -"])
    assert _last(out[4])["event"] == "held"
    release, floor = _ask(out[5]), _ask(out[6])
    assert (release["basis"], release["held"], release["outcome"]) == ("release", True, ALLOW)
    assert (floor["basis"], floor["held"], floor["cause"]) == ("floor", True, "dist:floor-allowed")


def test_case_210_a_record_carries_the_install_entry_in_one_frame(host_check):
    """case_210: H10, H1, B10. After three floor allows of which one overrode the release, a record carries a type 3
    entry of 27 bytes with the install id, the low 16 bits of the install trust sequence and counts of 3 and 1 that
    never go down, also after a restart, and a new floor is install-applied with subject 1 and another install id.
    Each record is 242 bytes, a frame of 246, with no type 1 or type 2 entry."""
    floor = _install("install.floor", _floor_table((7, 3)))
    renewal = _install("install.floor", _floor_table((7, 3)), seq=2, widens=False,
                       replaces=canon.sha256_hex(_floor_table((7, 3))))
    trust = _install("install.trust", _trust_body(("J", "K"), 2), seq=1, widens=False)
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[floor]), f"provision {S} {N}", _stage(trust), *_release_steps21(RELEASE, 1),
        f"ask {N} {_regs(7)} -", f"ask {N} {_regs(7)} -", f"ask {N} {_regs(3)} -", f"record 0 {N}", f"record 0 {N}",
        f"restart {N}", f"record 0 {N}", _stage(renewal)])
    first, none, after = _last(out[8]), _last(out[9]), _last(out[11])
    held = _install_id(floor=(floor[0], 1), trust_seq=1, trust_id=_envelope_id(trust[0]))
    assert (first["install_id"], first["trust_low"], first["answers"], first["overrides"]) == (held, 1, 3, 1)
    assert (none["answers"], none["overrides"]) == (after["answers"], after["overrides"]) == (3, 1)
    applied = _last(out[12])
    assert (applied["event"], applied["subject"]) == ("install-applied", 1)
    assert applied["install_id"] == _install_id(floor=(renewal[0], 2), trust_seq=1, trust_id=_envelope_id(trust[0]))
    every = [one for line in out if line.startswith("records") for one in _recs(line)]
    assert {one["size"] for one in every} == {242} and all(one["entries"] == 30 for one in every)
    assert 4 + 242 <= 250                                                   # B10: a state frame of 246 bytes


def test_case_215_183_a_lost_ceiling_freezes_and_a_lost_set_or_record_is_reported(host_check):
    """case_215: IS10. A PEP whose ceiling no copy holds reports dist:install-lost, its release keeps deciding, and an
    offer, a rollback and a floor are dist:install-lost until a ceiling at a new seq is applied, after which a release
    inside it stages; a PEP that held a ceiling and lost its install record refuses a release with dist:install-lost
    until it is provisioned. case_183: IS10, IS6. One changed byte of a stored floor beside a good second copy reads
    the good copy; with no good copy the floor is lost, leaves the install id and the PEP decides as one that never
    had it, the same floor again changes nothing and one at a new seq applies. A PEP with one copy of its install
    record unreadable uses the second, and with both holds no set, reports dist:install-lost, keeps deciding under
    its release and takes no install statement in a message and no release until it is provisioned."""
    ceiling_body = _ceiling(RELEASE, BODIES[1], BODIES[2])
    ceiling = _install("install.ceiling", ceiling_body)
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[ceiling]), f"provision {S} {N}", *_release_steps21(RELEASE, 1),
        *_release_steps21(BODIES[1], 2, replaces=canon.sha256_hex(RELEASE)),
        "lose set_ceiling", "lose2 set_ceiling", f"restart {N}", f"ask {N} {_regs(7)} -",
        f"stage {_dist.seal('policy.ppt', BODIES[2], seq=3, targets=('mesh',), widens=True).hex()} {BODIES[2].hex()} {N}",
        f"rollback {N}", _stage(_install("install.floor", FLOOR)),
        _stage(_install("install.ceiling", ceiling_body, seq=2, widens=True)),
        *_release_steps21(BODIES[2], 3, replaces=canon.sha256_hex(BODIES[1]))[:2]])
    assert _refused(out[7]) == ("dist:install-lost", 3)
    assert _ask(out[8])["basis"] == "release"
    assert [_refused(line)[0] for line in out[9:12]] == ["dist:install-lost"] * 3
    assert _last(out[12])["event"] == "install-widened"
    assert _last(out[13])["event"] == _last(out[14])["event"] == "staged"
    floor = _install("install.floor", FLOOR)
    ceiling = _install("install.ceiling", _ceiling(FLOOR, RELEASE, BODIES[1]))
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[floor, ceiling]), f"provision {S} {N}", *_release_steps21(RELEASE, 1), "installid",
        "corrupt set_floor", f"restart {N}", "installid", "lose2 set_floor", f"restart {N}",
        "installid", f"ask {N} {_regs(3)} -", _stage(floor), "installid", _stage(_install("install.floor", FLOOR, seq=2)),
        "lose install", f"restart {N}", "installid", "lose2 install", f"restart {N}", f"ask {N} {_regs(7)} -",
        _stage(_install("install.floor", FLOOR, seq=3)), *_release_steps21(BODIES[1], 2, replaces=canon.sha256_hex(RELEASE))[1:2],
        *_anchor(bring=[]), f"provision {S} {N}", "installid"])
    both = _install_id(floor=(floor[0], 1), ceiling=(ceiling[0], 1))
    assert out[4] == f"installid {both}" and out[5] == "records" and out[6] == f"installid {both}"
    assert _refused(out[7]) == ("dist:install-lost", 1)
    assert out[8] == f"installid {_install_id(ceiling=(ceiling[0], 1))}"
    assert (_ask(out[9])["basis"], _ask(out[9])["outcome"]) == ("release", REFUSE)
    assert _last(out[10])["event"] == "beat" and out[11] == out[8]
    assert _last(out[12])["event"] == "install-widened"
    assert out[13] == "records" and out[14] == f"installid {_install_id(floor=(_install('install.floor', FLOOR, seq=2)[0], 2), ceiling=(ceiling[0], 1))}"
    lost = _recs(out[15])
    assert [(one["event"], one["cause"], one["install_id"]) for one in lost] == [("refused", "dist:install-lost", "0" * 32)]
    assert _ask(out[16])["basis"] == "release"
    assert [_refused(line)[0] for line in out[17:19]] == ["dist:install-lost"] * 2
    assert _last(out[19])["event"] == "provisioned" and out[20] == f"installid {_install_id()}"


def test_case_167_an_install_set_over_frames_applies_when_verified_and_no_commit_or_abort_reaches_it(host_check):
    """case_167: IS4, the mesh half. With an install threshold of 2 a floor and a ceiling of 64 hashes, held to the
    trust bound, assemble over the frame binding past an admit check that holds the install record, and each
    applies when it verifies, durably before its event, with no commit. A forged abort and commit that name the
    floor change nothing."""
    frames = _frames_module()
    floor = _install("install.floor", FLOOR, seq=1)
    hashes = sorted({canon.sha256_hex(FLOOR), canon.sha256_hex(RELEASE),
                     *(hashlib.sha256(bytes([n])).hexdigest() for n in range(62))})
    ceiling = _install("install.ceiling", _ceiling(hashes=hashes), seq=1)
    whole = []
    for transfer, (sealed, body) in enumerate((ceiling, floor), start=3):
        lines = ["case frames", "trust 1 0 - 0", f"pep mesh {S} 0 640 1", f"ikey {_pub('J').hex()}",
                 f"ikey {_pub('K').hex()}", "install 2", f"now {N}", "assembler 0 250 640",
                 *(f"frame {data.hex()} {index}" for index, data in enumerate(
                     frames.frames_for(transfer, bytes.fromhex(sealed), bytes.fromhex(body), 250)))]
        done = subprocess.run([str(host_check)], input="\n".join(lines + ["done"]) + "\n", capture_output=True,
                              text=True, timeout=60)
        assert done.returncode == 0, done.stderr
        events = done.stdout.splitlines()
        assert events[-1] == f"whole {sealed} {body}" and all(one == "none" for one in events[:-1])
        whole.append(events[-1].split()[1:])
    policy = canon.sha256_hex(FLOOR)
    out = _run21(host_check, [*_node(), *_anchor(), f"provision {S} {N}", *(f"stage {a} {b} {N}" for a, b in whole),
                              "installid", f"abort {S} 1 {policy} {N}", f"commit {S} 1 {policy} 0 0 {N}",
                              f"restart {N}", "installid"])
    assert [one["event"] for one in _recs(out[1])] == ["staged", "install-applied"]
    assert [one["event"] for one in _recs(out[2])] == ["staged", "install-widened"]
    held = f"installid {_install_id(floor=(floor[0], 1), ceiling=(ceiling[0], 1))}"
    assert out[3] == out[7] == held
    assert _last(out[4])["event"] == "beat" and _refused(out[5])[0] == "dist:not-staged"


def test_case_189_190_the_action_floor_never_lapses_and_a_release_never_narrows_it(host_check):
    """case_189: AF3. The floor allows the same request after the release expires, after a revocation of everything
    the authority signed, after the floor of section 6 is lost, after every unsigned message, after the install key
    that signed it is retired and ten years past its not_before. case_190: AF4, the PEP's half. A release that
    refuses what the floor allows is renewed with no widening statement and the floor still allows it."""
    ask = f"ask {{}} {_regs(3)} -"
    everything = _dist.revocation(keys=[_kid("A")], policies=[canon.sha256_hex(RELEASE)])
    revocation = _dist.trust_statement("trust.revocation", everything, seq=1, signers=("A",), targets=("mesh",))
    out = _run21(host_check, [
        *_node(), *_anchor(("J", "K", "L"), bring=[_install("install.floor", FLOOR, signers=("J", "K"))]),
        f"provision {S} {N}", *_release_steps21(RELEASE, 1), ask.format(N),
        *_release_steps21(RELEASE, 2, widens=False, replaces=canon.sha256_hex(RELEASE)), ask.format(N),
        f"tick 0 {E}", ask.format(E), f"stage {revocation.hex()} {everything.hex()} {E}", ask.format(E),
        "lose floor", f"restart {E}", ask.format(E), f"abort {S} 2 {canon.sha256_hex(RELEASE)} {E}",
        f"commit {S} 2 {canon.sha256_hex(RELEASE)} 0 0 {E}", f"statement 09 {E}", ask.format(E),
        _stage(_install("install.trust", _trust_body(("J", "L"), 2), seq=1, signers=("J", "L"), widens=False), E),
        ask.format(E), ask.format(NB + 10 * 365 * 86400)])
    assert _last(out[6])["event"] == "committed" and len(_recs(out[5])) == 1       # renewed with no statement
    asked = [_ask(line) for line in out if line.startswith("ask")]
    assert len(asked) == 8 and all((one["outcome"], one["basis"]) == (ALLOW, "floor") for one in asked)
    assert _last(out[8])["event"] == "lapsed" and _last(out[18])["event"] == "install-applied"


def test_case_191_three_sets_at_their_bounds_fit_a_mesh_node(host_check):
    """case_191: AF5, IS5. A floor and a fallback policy of 640 bytes and a ceiling of 64 hashes are held with no
    release, a request the floor is silent on is decided by the fallback policy, the install record packs under
    1,024 bytes, and a floor of 641 bytes is dist:too-large from its signed body_size."""
    floor_body = _floor_table(pad_to=640)
    fallback_body = _ppt([[0]], atoms=[(0, GE, INT, 100)], pad_to=640)
    assert len(floor_body) == len(fallback_body) == 640
    hashes = sorted({canon.sha256_hex(floor_body), canon.sha256_hex(fallback_body),
                     *(hashlib.sha256(bytes([n])).hexdigest() for n in range(62))})
    assert len(hashes) == 64
    sets = [_install("install.ceiling", _ceiling(hashes=hashes)), _install("install.floor", floor_body),
            _install("install.fallback", fallback_body)]
    big = _install("install.floor", b"\x00" * 641, seq=2)
    out = _run21(host_check, [*_node(), *_anchor(bring=sets), f"provision {S} {N}", "installid",
                              f"ask {N} {_regs(150)} -", "sizes", _stage(big)])
    assert out[1] == f"installid {_install_id(floor=(sets[1][0], 1), fallback=(sets[2][0], 1), ceiling=(sets[0][0], 1))}"
    assert (_ask(out[2])["basis"], _ask(out[2])["outcome"]) == ("fallback", ALLOW)
    record_bytes = int(out[3].split()[4])
    assert record_bytes < 1024 and 2 * record_bytes < 2048                       # IS10: two copies under 2,048
    assert _refused(out[4]) == ("dist:too-large", 1)


def test_case_219_a_set_spreads_by_itself_and_the_install_ids_show_the_mix(host_check):
    """case_219: H13, H6, IS4, the PEPs' half. A first action floor brought by provisioning reports provisioned with
    dist:install-widened, and of three mesh PEPs sent a new floor, two apply it and one, whose ceiling does not list
    it, refuses it, with no abort and three install ids that show the mix."""
    first = _install("install.floor", FLOOR)
    new = _install("install.floor", FLOOR_B, seq=2)
    ids = []
    for listed in ((FLOOR, FLOOR_B), (FLOOR, FLOOR_B), (FLOOR,)):
        ceiling = _install("install.ceiling", _ceiling(*listed))
        out = _run21(host_check, [*_node(), *_anchor(bring=[ceiling, first]), f"provision {S} {N}", _stage(new),
                                  "installid"])
        assert (_last(out[0])["event"], _last(out[0])["cause"]) == ("provisioned", "dist:install-widened")
        ids.append((_last(out[1])["event"], out[2].split()[1]))
    assert [event for event, _id in ids] == ["install-widened", "install-widened", "refused"]
    assert ids[0][1] == ids[1][1] != ids[2][1]                                   # the mix, PEP by PEP


def test_the_action_floor_is_narrow_and_tests_only_what_the_proposer_cannot_write(host_check):
    """case_213: AF9, AF10, the mesh half (the cfs half is in test_distribution_c_cfs.py). A floor whose edge tests no command,
    tests the command only inside an or, leaves a parameter unbounded or bounded by its whole domain, has a second
    decision node or nine rules, names a register the layout does not label as its command, or tests the proposer's
    reading is dist:floor-broad; one whose layout is another layout's hash, or reaches a PEP built with no layout, is
    dist:target-mismatch; eight narrow rules apply, the floor allows inside the bound and leaves the rest to the
    release, and a rule that tests an independent field is silent when its value is stale or absent."""
    no_command = _ppt([[0, 1, "and"]], atoms=[(1, GE, INT, 10), (1, LE, INT, 20)])
    in_or = _ppt([[0, 3, "or", 1, "and", 2, "and"]], atoms=[(0, EQ, INT, 3), (1, GE, INT, 10), (1, LE, INT, 20),
                                                            (0, EQ, INT, 4)])
    unbounded = _ppt([[0]], atoms=[(0, EQ, INT, 3)])
    whole = _floor_table(low=0, high=100)
    two_nodes = _ppt([[0, 1, "and", 2, "and"], ["true"]], atoms=_rule(3)[0])
    two_nodes = bytearray(two_nodes)
    import struct
    struct.pack_into("<HH", two_nodes, 28 + 8 * 3 + 4, 1, 1)                  # node 1 decides by edge 1
    struct.pack_into("<HH", two_nodes, 28 + 8 * 3, 0, 1)
    nine = _floor_table(tuple(range(1, 10)))
    proposer = _floor_table(extra=[(3, EQ, INT, 1)])
    eight = _floor_table(tuple(range(1, 9)))
    fresh = _floor_table((3,), extra=[(2, EQ, INT, 1)])
    def floor(body, seq, **meta):
        return _install("install.floor", bytes(body), seq=seq,
                        meta={"as": "policy.ppt", "command": 0, "layout": LAYOUT, **meta})
    broad = [floor(no_command, 1), floor(in_or, 1), floor(unbounded, 1), floor(whole, 1), floor(two_nodes, 1),
             floor(nine, 1), floor(eight, 1, command=1), floor(proposer, 1)]
    out = _run21(host_check, [*_node(), *_anchor(), f"provision {S} {N}", *(_stage(one) for one in broad),
                              _stage(floor(eight, 1, layout=ZERO)), _stage(floor(eight, 1)),
                              *_release_steps21(RELEASE, 1), f"ask {N} {_regs(3, 15)} -", f"ask {N} {_regs(3, 25)} -",
                              f"ask {N} {_regs(9, 15)} -", _stage(floor(fresh, 2)),
                              f"ask {N} {_regs(3, 15)} 0,0,5,0", f"ask {N} {_regs(3, 15)} 0,0,6,0",
                              f"ask {N} {_regs(3, 15)} -", f"ask {N} {_regs(3, 15, independent=0)} 0,0,1,0"])
    assert [_refused(line) for line in out[1:9]] == [("dist:floor-broad", 1)] * 8
    assert _refused(out[9]) == ("dist:target-mismatch", 1)
    assert _last(out[10])["event"] == "install-widened"
    inside, outside, other = (_ask(line) for line in out[14:17])
    assert (inside["basis"], outside["basis"], outside["outcome"]) == ("floor", "release", REFUSE)
    assert (other["basis"], other["outcome"]) == ("release", ALLOW)
    assert _last(out[17])["event"] == "install-widened"
    assert [_ask(line)["basis"] for line in out[18:22]] == ["floor", "release", "release", "release"]
    out = _run21(host_check, [*_node(layout=False), *_anchor(), f"provision {S} {N}", _stage(floor(eight, 1))])
    assert _refused(out[1]) == ("dist:target-mismatch", 1)


def test_the_signed_rate_counts_overrides_durably_on_a_mesh_node(host_check):
    """case_194: AF8, H10, the mesh half (the cfs half is in test_distribution_c_cfs.py). With a rate of 3 in 60 seconds, five overrides in one
    window are allowed three times and then left to the release, a restart after the second changing nothing; a
    request the release allows is never counted; the next window allows again; the counts of H10 rise only with
    floor answers."""
    meta = {"as": "policy.ppt", "command": 0, "layout": LAYOUT, "rate": {"allows": 3, "window": 60}}
    floor = _install("install.floor", _floor_table((3, 7)), meta=meta)
    ask = lambda now, command=3: f"ask {now} {_regs(command)} -"  # noqa: E731
    out = _run21(host_check, [*_node(), *_anchor(bring=[floor]), f"provision {S} {N}", *_release_steps21(RELEASE, 1),
                              ask(N), ask(N + 1), f"restart {N + 2}", ask(N + 2), ask(N + 3), ask(N + 4),
                              ask(N + 5, 7), ask(N + 6, 7), ask(N + 61), f"record 0 {N + 61}"])
    asked = [_ask(line) for line in out if line.startswith("ask")]
    assert [(one["basis"], one["outcome"], one["count"]) for one in asked] == [
        ("floor", ALLOW, 1), ("floor", ALLOW, 2), ("floor", ALLOW, 3), ("release", REFUSE, 0), ("release", REFUSE, 0),
        ("floor", ALLOW, 0), ("floor", ALLOW, 0), ("floor", ALLOW, 1)]
    assert asked[0]["window"] == asked[2]["window"] == N and asked[-1]["window"] == N + 61
    assert [one["override"] for one in asked if one["basis"] == "floor"] == [True, True, True, False, False, True]
    assert (_last(out[-1])["answers"], _last(out[-1])["overrides"]) == (6, 4)


# ------------------------------------------------------------------ IS14, IS15: the install change statement

def _change(kind: str, carried: bytes, seq: int, source: str, *, replaces=None, widens=False, policy=None,
            signers=("J", "K"), targets=("mesh",), not_before=NB):
    """An install change statement for the set of `kind` whose table is `carried` at `seq`, from `source`."""
    statement = canon.canon2_bytes({"basis": "prismpath.table-compare/1", "encoding": "canon/2",
                                    "format": "prismpath.dist-install-change/1", "from": source, "set": kind})
    return _install("install.change", statement, seq=seq, meta={}, widens=widens,
                    replaces=source if replaces is None else replaces,
                    policy=canon.sha256_hex(carried) if policy is None else policy,
                    release=_release_id("policy.ppt", carried), signers=signers, targets=targets, not_before=not_before)


NARROW_FLOOR = _floor_table(low=12, high=18)            # allows less than FLOOR: the parameter in [12, 18]


def test_case_296_an_install_change_statement_out_of_its_form_is_refused(host_check):
    """case_296: IS14, IS2, V5, IS4, the mesh half. A change statement that says it widens, replaces nothing, names
    another hash than its replaces, carries a ceiling or the empty set is dist:bad-format, one signed by authority keys
    is dist:unknown-key, a second one for a set that has one staged is dist:incomplete, and a node whose install
    threshold is 1 takes none in a message. Nothing is staged."""
    held = canon.sha256_hex(FLOOR)
    good = _change("install.floor", NARROW_FLOOR, 2, held)
    out = _run21(host_check, [
        *_node(), *_anchor(), f"provision {S} {N}", _stage(_install("install.floor", FLOOR)), "installid",
        _stage(_change("install.floor", NARROW_FLOOR, 2, held, widens=True)),
        _stage(_change("install.floor", NARROW_FLOOR, 2, held, replaces="")),
        _stage(_change("install.floor", NARROW_FLOOR, 2, held, replaces=canon.sha256_hex(FALLBACK))),
        _stage(_change("install.ceiling", NARROW_FLOOR, 2, held)),
        _stage(_change("install.floor", NARROW_FLOOR, 2, held, policy=ZERO)),
        _stage(_change("install.floor", NARROW_FLOOR, 2, held, signers=("A",))), "installid",
        _stage(good)])
    assert [_refused(line)[0] for line in out[3:9]] == ["dist:bad-format"] * 5 + ["dist:unknown-key"]
    assert out[9] == out[2]
    assert (_last(out[10])["event"], _last(out[10])["subject"]) == ("staged", 1)
    out = _run21(host_check, [
        *_node(), *_anchor(("J", "K", "L")), f"provision {S} {N}", _stage(_install("install.floor", FLOOR)),
        _stage(good), _stage(_change("install.floor", NARROW_FLOOR, 2, held, not_before=NB + 1))])
    assert _refused(out[3]) == ("dist:incomplete", 1)
    out = _run21(host_check, [*_node(), *_anchor(threshold=1, bring=[_install("install.floor", FLOOR)]),
                              f"provision {S} {N}", _stage(_change("install.floor", NARROW_FLOOR, 2, held))])
    assert _refused(out[1]) == ("dist:target-mismatch", 1)


def test_case_297_299_a_narrower_floor_or_fallback_carried_by_a_change_statement_is_applied(host_check):
    """case_297: IS15, IS12, the mesh half. With a change statement from the held set's policy hash, a floor table
    and a fallback table that allow less with widens false are applied as install-applied with no cause, and a
    narrower floor with no change statement is dist:widening-unsigned with the floor before it still held. case_299:
    IS15, IS4. The change statement staged survives a restart, and the floor it carries is then applied."""
    floor, fallback = _install("install.floor", FLOOR), _install("install.fallback", FALLBACK)
    narrow = _install("install.floor", NARROW_FLOOR, seq=2, widens=False, replaces=canon.sha256_hex(FLOOR))
    narrow_fallback = _install("install.fallback", FALLBACK_B, seq=2, widens=False,
                               replaces=canon.sha256_hex(FALLBACK))
    out = _run21(host_check, [
        *_node(), *_anchor(), f"provision {S} {N}", _stage(floor), _stage(fallback),
        _stage(_change("install.floor", NARROW_FLOOR, 2, canon.sha256_hex(FLOOR))), _stage(narrow),
        _stage(_change("install.fallback", FALLBACK_B, 2, canon.sha256_hex(FALLBACK))), _stage(narrow_fallback),
        "installid",
        _stage(_install("install.floor", _floor_table(low=13, high=17), seq=3, widens=False,
                        replaces=canon.sha256_hex(NARROW_FLOOR))), "installid"])
    assert [(_last(line)["event"], _last(line)["cause"], _last(line)["subject"]) for line in out[3:7]] == [
        ("staged", None, 1), ("install-applied", None, 1), ("staged", None, 2), ("install-applied", None, 2)]
    assert out[7] == f"installid {_install_id(floor=(narrow[0], 2), fallback=(narrow_fallback[0], 2))}"
    assert _refused(out[8]) == ("dist:widening-unsigned", 1) and out[9] == out[7]
    out = _run21(host_check, [
        *_node(), *_anchor(), f"provision {S} {N}", _stage(floor),
        _stage(_change("install.floor", NARROW_FLOOR, 2, canon.sha256_hex(FLOOR))), "restart", _stage(narrow)])
    assert (_last(out[-1])["event"], _last(out[-1])["cause"]) == ("install-applied", None)


def test_case_298_a_change_statement_stands_only_for_a_set_it_can_carry(host_check):
    """case_298: IS15, AF8, V10, the mesh half. A change statement on a node with no floor, and one from another hash,
    are dist:widening-unsigned with nothing staged. Beside a change statement a floor with a looser rate is
    dist:widening-unsigned, and a set that says it widens is dist:incomplete."""
    held = canon.sha256_hex(FLOOR)
    other = canon.sha256_hex(FALLBACK)
    out = _run21(host_check, [
        *_node(), *_anchor(), f"provision {S} {N}", _stage(_change("install.floor", NARROW_FLOOR, 2, held)),
        _stage(_install("install.floor", FLOOR)), _stage(_change("install.floor", NARROW_FLOOR, 2, other))])
    assert _refused(out[1]) == ("dist:widening-unsigned", 1) and _refused(out[3]) == ("dist:widening-unsigned", 1)
    rate = lambda allows: {"as": "policy.ppt", "command": 0, "layout": LAYOUT,  # noqa: E731
                           "rate": {"allows": allows, "window": 60}}
    out = _run21(host_check, [
        *_node(), *_anchor(), f"provision {S} {N}", _stage(_install("install.floor", FLOOR, meta=rate(3))),
        _stage(_change("install.floor", NARROW_FLOOR, 2, held)),
        _stage(_install("install.floor", NARROW_FLOOR, seq=2, meta=rate(5), widens=False, replaces=held)),
        _stage(_change("install.floor", NARROW_FLOOR, 3, held)),
        _stage(_install("install.floor", NARROW_FLOOR, seq=3, meta=rate(3), widens=True, replaces=held))])
    assert _last(out[2])["event"] == "staged" and _refused(out[3]) == ("dist:widening-unsigned", 1)
    assert _last(out[4])["event"] == "staged" and _refused(out[5]) == ("dist:incomplete", 1)


# ------------------------------------------------------------------ the controller key and statement (K6, K7, H9, H15, H16)

from prismpath.distribution import statement as statements  # noqa: E402

YEAR = 365 * 86400


def _signed(key="C", *, key_seq=0, stream=S, epoch=1, fresh=False, trust_seq=0, stream_seq=0, expires=0) -> str:
    """A controller statement signed by the test key `key`, as statement.py builds it."""
    statement = statements.Statement(key_seq=key_seq, stream=state_record.stream_prefix(stream), epoch=epoch,
                                     fresh=fresh, trust_seq=trust_seq, stream_seq=stream_seq, expires=expires)
    return statements.build(statement, _dist.instance_key(key)).hex()


def _fresh(epoch, expires, *, key="C", trust_seq=0, stream_seq=1, **args) -> str:
    return _signed(key, epoch=epoch, fresh=True, trust_seq=trust_seq, stream_seq=stream_seq, expires=expires, **args)


def _rekey(key: str, seq: int, now: int = N, signer: str = "A") -> tuple:
    """Stage a `trust.controller` naming the test key `key` at trust sequence `seq`."""
    body = _dist.controller_key(key)
    sealed = _dist.trust_statement("trust.controller", body, seq=seq, signers=(signer,), targets=("mesh",))
    return ("stage", sealed.hex(), body.hex(), now)


def _taken(line: str) -> tuple:
    words = line.split()
    assert words[0] == "statement", line
    return words[1] == "1", int(words[2])


def _one(line: str):
    records = _records(line)
    assert len(records) == 1, line
    return records[0]


def test_the_core_reads_and_checks_a_controller_statement_byte_for_byte_as_statement_py(host_check, tmp_path):
    """H9: a statement of 102 and of 126 bytes built by statement.py is taken by the C core, and one with any byte
    of it changed is not, so both read and sign the same bytes."""
    script = [("provision", S, N), ("statement", _signed(epoch=7), N),
              ("statement", _fresh(8, N + 3600, stream_seq=0), N)]
    good = _fresh(9, N + 3600, stream_seq=0)
    for at in (0, 4, 5, 13, 29, 37, 38, 46, 54, 61, 62, 125):
        changed = bytearray(bytes.fromhex(good))
        changed[at] ^= 0x01
        script.append(("statement", changed.hex(), N))
    out = _same(host_check, tmp_path, script, controller="C", fresh=3600)
    assert [_taken(line) for line in out[1:]] == [(True, 7), (True, 8)] + [(False, 8)] * 12


def test_case_256_a_restarted_node_reports_epoch_0_until_it_takes_a_current_statement(host_check, tmp_path):
    """case_256: H15, H6, H9, the `mesh` half (a `host` PEP is not of the C core). The node takes the controller's
    epoch id, reports it, reports 0 after a restart and the new id once it takes the next statement, with the state
    records pep.py signs byte for byte."""
    out = _same(host_check, tmp_path, [("provision", S, N), ("statement", _signed(epoch=3), N), ("record", "beat", N),
                                       ("restart", N + 1), ("record", "beat", N + 1),
                                       ("statement", _signed(epoch=4), N + 1), ("record", "beat", N + 1)],
                controller="C")
    assert _taken(out[1]) == (True, 3) and _one(out[2]).epoch == 3
    assert _one(out[4]).epoch == 0 and _taken(out[5]) == (True, 4) and _one(out[6]).epoch == 4


def test_case_257_a_node_takes_no_epoch_from_anything_but_a_good_statement(host_check, tmp_path):
    """case_257: H9, K6. An epoch id with no statement, a statement signed by an authority key, one by an unknown key,
    one with a byte changed and one with another key sequence change nothing and send no record, and a node with no
    controller key takes no good statement."""
    good = _signed(epoch=5)
    changed = good[:60] + ("0" if good[60] != "0" else "1") + good[61:]
    out = _same(host_check, tmp_path / "held", [("provision", S, N), ("statement", (5).to_bytes(8, "little").hex(), N),
                                                ("statement", _signed("A", epoch=5), N),
                                                ("statement", _signed("U", epoch=5), N), ("statement", changed, N),
                                                ("statement", _signed(key_seq=1, epoch=5), N),
                                                ("record", "beat", N)], controller="C")
    assert [_taken(line) for line in out[1:6]] == [(False, 0)] * 5 and _one(out[6]).epoch == 0
    bare = _same(host_check, tmp_path / "bare", [("provision", S, N), ("statement", good, N)])
    assert _taken(bare[1]) == (False, 0)


def test_case_258_a_higher_epoch_is_taken_and_never_lowered(host_check, tmp_path):
    """case_258: H9. A statement above the id held is taken, the same again and a lower one change nothing."""
    out = _same(host_check, tmp_path, [("provision", S, N), ("statement", _signed(epoch=6), N),
                                       ("statement", _signed(epoch=6), N), ("statement", _signed(epoch=2), N),
                                       ("record", "beat", N)], controller="C")
    assert [_taken(line) for line in out[1:4]] == [(True, 6), (False, 6), (False, 6)] and _one(out[4]).epoch == 6


def test_case_259_a_trust_controller_names_a_new_key_and_starts_the_epoch_again(host_check, tmp_path):
    """case_259: K7, H9, H15. The statement is applied with `trust-applied` and epoch 0. Then a statement by the old
    key, one by the new key with the old key sequence, and one by the new key with the new key sequence and an epoch
    id below the one held before: nothing, nothing, taken. The new key is durable across a restart."""
    out = _same(host_check, tmp_path, [("provision", S, N), ("statement", _signed(epoch=9), N), _rekey("D", 1),
                                       ("statement", _signed("C", key_seq=1, epoch=20), N),
                                       ("statement", _signed("D", key_seq=0, epoch=20), N),
                                       ("statement", _signed("D", key_seq=1, epoch=3), N), ("restart", N + 1),
                                       ("statement", _signed("D", key_seq=1, epoch=4), N + 1)], controller="C")
    applied = _one(out[2])
    assert (applied.event, applied.epoch, applied.trust_seq) == ("trust-applied", 0, 1)
    assert [_taken(line) for line in out[3:6]] == [(False, 0), (False, 0), (True, 3)] and _taken(out[7]) == (True, 4)


def test_case_260_a_trust_controller_may_not_name_a_key_of_another_role(host_check, tmp_path):
    """case_260: K6, K7, K4. A `trust.controller` whose key is an authority key, the node's instance key, a revoked
    key, the controller key it replaced before and a retired key is `dist:rotation-invalid` each time, as pep.py
    answers. One whose key is an install key or an operator key the node holds is too (section 21), and an anchor
    whose controller key is also an authority key is refused at provisioning."""
    out = _same(host_check, tmp_path, [("provision", S, N, ("A", "B")), _rekey("A", 1), _rekey("I", 1),
                                       _revoke(1, N, keys=[_kid("R")]), _rekey("R", 2), _rekey("D", 2), _rekey("C", 3),
                                       _rotate(3, N, "E", retire="B", signers=("A", "E")), _rekey("B", 4)],
                controller="C")
    refused = [_one(out[k]) for k in (1, 2, 4, 6, 8)]
    assert [(one.event, one.cause) for one in refused] == [("refused", "dist:rotation-invalid")] * 5
    assert _one(out[5]).event == "trust-applied" and _one(out[7]).event == "trust-applied"
    assert _one(out[8]).trust_seq == 3
    ckey = f"ckey {_kid('C')} {_pub('C').hex()}"
    lines = [*_node(), *_anchor(("J", "K"), operators=("O",)), ckey, f"provision {S} {N}"]
    for key in ("J", "O"):
        body = _dist.controller_key(key)
        lines.append(f"stage {_dist.trust_statement('trust.controller', body, seq=1, targets=('mesh',)).hex()} "
                     f"{body.hex()} {N}")
    lines += [*_anchor(None), f"ckey {_kid('A')} {_pub('A').hex()}", f"provision {S} {N}"]
    got = _run21(host_check, lines)
    assert [_refused(line)[0] for line in got[1:3]] == ["dist:rotation-invalid"] * 2
    assert got[3] == f"provision-refused {causes.NAMES['dist:rotation-invalid']}"


def test_case_261_the_controller_key_signs_no_envelope_and_no_rotation_adds_it(host_check, tmp_path):
    """case_261: K6, K4, S3, O4, IS11. A release, a revocation and a rotation signed only by the controller key are
    `dist:unknown-key`, as pep.py answers, and a rotation and an install.trust that add the controller key are
    `dist:rotation-invalid`."""
    release = _dist.seal("policy.ppt", BODIES[0], signer="C", targets=("mesh",))
    out = _same(host_check, tmp_path, [("provision", S, N), ("stage", release.hex(), BODIES[0].hex(), N),
                                       _revoke(1, N, signer="C"), _rotate(1, N, "B", signers=("C",)),
                                       _rotate(1, N, "C", signers=("A", "C")), ("record", "beat", N)],
                controller="C")
    assert [_one(line).cause for line in out[1:5]] == ["dist:unknown-key"] * 3 + ["dist:rotation-invalid"]
    assert _one(out[5]).trust_seq == 0 and _one(out[5]).state == "no-policy"
    trust = _install("install.trust", _trust_body(("J", "K", "C"), 2), signers=("J", "K", "C"))
    got = _run21(host_check, [*_node(), *_anchor(("J", "K")), f"ckey {_kid('C')} {_pub('C').hex()}",
                              f"provision {S} {N}", _stage(trust)])
    assert _refused(got[1]) == ("dist:rotation-invalid", SUBJECT["install.trust"])


def test_case_269_a_node_cut_off_past_its_fresh_statement_lapses(host_check, tmp_path):
    """case_269: H16, X1, X7, the `mesh` half (the `cfs` half waits for the cfs kind in the C core). With `fresh`
    3600 the node takes a fresh statement and, cut off for 3901 seconds, lapses with dist:expired, as pep.py does.
    A node built with HOLD is held instead, with bit 5 set."""
    script = [("provision", S, N), ("stage", _sealed(0, 1), BODIES[0].hex(), N), ("commit", S, 1, H[0], N),
              ("statement", _fresh(1, N + 3600), N), ("tick", N + 3900), ("tick", N + 3901)]
    out = _same(host_check, tmp_path / "refuse", script, controller="C", fresh=3600)
    assert _taken(out[3]) == (True, 1) and _records(out[4]) == []
    lapsed = _one(out[5])
    assert (lapsed.event, lapsed.cause, lapsed.state) == ("lapsed", "dist:expired", "no-policy")
    held = _same(host_check, tmp_path / "hold", script, hold=True, controller="C", fresh=3600)
    record = _one(held[5])
    assert (record.event, record.state, record.held) == ("held", "active", True)


def test_case_270_what_gives_freshness(host_check, tmp_path):
    """case_270: H16, H9, T1. With `fresh` 3600, a statement for another stream changes nothing, one whose trust
    sequence is below the node's, one whose stream seq is below its floor and one 3901 seconds ahead give no
    freshness, one 3900 seconds ahead gives it and one with `fresh` 0 gives none: the node lapses 300 seconds after
    the fifth's `expires` and not before. The epoch ids of all but the first are taken, and the time floor does not
    move."""
    good = {"trust_seq": 1, "stream_seq": 1}
    script = [("provision", S, N), ("stage", _sealed(0, 1), BODIES[0].hex(), N), ("commit", S, 1, H[0], N),
              _revoke(1, N),
              ("statement", _fresh(1, N + 3600, stream="other/stream", **good), N),
              ("statement", _fresh(2, N + 3600, **{**good, "trust_seq": 0}), N),
              ("statement", _fresh(3, N + 3600, **{**good, "stream_seq": 0}), N),
              ("statement", _fresh(4, N + 3901, **good), N), ("statement", _fresh(5, N + 3900, **good), N),
              ("statement", _signed(epoch=6, expires=N + 7200), N), ("record", "beat", N),
              ("tick", N + 4200), ("tick", N + 4201)]
    out = _same(host_check, tmp_path, script, controller="C", fresh=3600)
    assert [_taken(line) for line in out[4:10]] == [(False, 0), (True, 2), (True, 3), (True, 4), (True, 5), (True, 6)]
    assert _one(out[10]).time == N and _records(out[11]) == []
    assert (_one(out[12]).event, _one(out[12]).cause) == ("lapsed", "dist:expired")


def test_case_271_freshness_off_decides_a_year_and_a_kept_statement_survives_a_restart(host_check, tmp_path):
    """case_271: H16, P4. A node with `fresh` 0 cut off for a year with a release that expires in two decides under
    it the whole year, and a node with `fresh` 3600 still holds its fresh statement after a restart: it lapses when
    that statement runs out."""
    long = _dist.seal("policy.ppt", BODIES[0], seq=1, targets=("mesh",), widens=True, expires=N + 2 * YEAR).hex()
    off = _same(host_check, tmp_path / "off", [("provision", S, N), ("stage", long, BODIES[0].hex(), N),
                                               ("commit", S, 1, H[0], N), ("tick", N + YEAR), ("decide", N + YEAR)],
                controller="C")
    assert _records(off[3]) == [] and off[4] == "decide 0 0"
    on = _same(host_check, tmp_path / "on", [("provision", S, N), ("stage", long, BODIES[0].hex(), N),
                                             ("commit", S, 1, H[0], N), ("statement", _fresh(1, N + 3600), N),
                                             ("restart", N + 10), ("tick", N + 3900), ("tick", N + 3901)],
                controller="C", fresh=3600)
    assert _records(on[5]) == [] and (_one(on[6]).event, _one(on[6]).cause) == ("lapsed", "dist:expired")
    assert all(record.epoch == 0 for record in _records(on[4]))


def test_case_276_a_broadcast_starves_no_stream(host_check, tmp_path):
    """case_276: H9. Statements for `mesh/a` and `mesh/b` in turn, each in a frame of type 6 that the C assembler
    passes to the node as frames.py does, reach a node on each stream, which takes every statement of its own stream
    and none of the other's."""
    from prismpath.distribution import frames
    sent = [(stream, _signed(stream=stream, epoch=turn)) for turn in (1, 2, 3) for stream in ("mesh/a", "mesh/b")]
    encoded = [frames.encode(frames.Epoch(turn, bytes.fromhex(data))) for turn, (_s, data) in enumerate(sent)]
    assert all(isinstance(frames.decode(frame), frames.Epoch) for frame in encoded)
    lines = ["trust 1 0 - 0", f"pep mesh {S} 0 640 1", f"assembler 0 250 640",
             *(f"frame {frame.hex()} 0" for frame in encoded), f"frame {bytes([6, 1, 0, 0]).hex()}{'00' * 8} 0", "done"]
    done = subprocess.run([str(host_check)], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=60)
    assert done.stdout.splitlines() == ["control 6"] * 6 + [f"dropped {causes.NAMES['dist:frame-invalid']}"]
    for stream in ("mesh/a", "mesh/b"):
        script = [("provision", stream, N), *(("statement", frame[4:].hex(), N) for frame in encoded)]
        out = _same(host_check, tmp_path / stream.replace("/", "_"), script, controller="C")
        assert [_taken(line)[0] for line in out[1:]] == [name == stream for name, _data in sent]


def test_case_277_a_stolen_key_at_the_top_keeps_no_good_statement_from_freshness(host_check, tmp_path):
    """case_277: H9, H16, H15. A statement by the stolen controller key with epoch id 2^64 - 1 is taken, a good fresh
    statement still gives freshness, and after a restart the node takes the controller's next epoch id."""
    out = _same(host_check, tmp_path, [("provision", S, N), ("stage", _sealed(0, 1), BODIES[0].hex(), N),
                                       ("commit", S, 1, H[0], N), ("statement", _signed(epoch=2 ** 64 - 1), N),
                                       ("statement", _fresh(1, N + 3600), N), ("restart", N + 5),
                                       ("statement", _signed(epoch=2), N + 5), ("tick", N + 3901)],
                controller="C", fresh=3600)
    assert _taken(out[3]) == (True, 2 ** 64 - 1) and _taken(out[4]) == (False, 2 ** 64 - 1)
    assert _taken(out[6]) == (True, 2) and _one(out[7]).cause == "dist:expired"


def test_case_278_a_clockless_node_takes_time_once_a_start(host_check, tmp_path):
    """case_278: H16, T1, T2. A `mesh` node with no clock and `fresh` 3600 that was off for 30 days starts and takes a
    good fresh statement as a raise of its time floor to its `expires` less 3600, with freshness. One a year ahead in
    the same start gives none and moves nothing. A node with a clock takes no time and no freshness from one a year
    ahead (a `host` PEP is not of the C core, and a mesh node with a clock is the same rule)."""
    true_time = N + 30 * 86400
    long = _dist.seal("policy.ppt", BODIES[0], seq=1, targets=("mesh",), widens=True, expires=N + 2 * YEAR).hex()
    out = _same(host_check, tmp_path / "clockless", [("provision", S, N), ("restart", N),
                                                     ("statement", _fresh(1, true_time + 3600, stream_seq=0), N),
                                                     ("record", "beat", N),
                                                     ("statement", _fresh(2, true_time + YEAR, stream_seq=0), N),
                                                     ("record", "beat", N), ("tick", true_time + 3900),
                                                     ("record", "beat", true_time + 3901)],
                controller="C", fresh=3600, clock=False)
    assert _taken(out[2]) == (True, 1) and _one(out[3]).time == true_time
    assert _taken(out[4]) == (True, 2) and _one(out[5]).time == true_time
    clocked = _same(host_check, tmp_path / "clocked", [("provision", S, N), ("stage", long, BODIES[0].hex(), N),
                                                       ("commit", S, 1, H[0], N),
                                                       ("statement", _fresh(1, N + YEAR), N), ("record", "beat", N),
                                                       ("tick", N + 3901)], controller="C", fresh=3600)
    assert _taken(clocked[3]) == (True, 1) and _one(clocked[4]).time == N and _records(clocked[5]) == []


def test_case_279_a_store_gains_a_controller_key_and_keeps_its_bound(host_check, tmp_path):
    """case_279: K7, K5, H6. A node provisioned with no controller key gains the key a `trust.controller` names and
    takes a statement under it. A store of 8 authority keys and no controller key refuses one with dist:too-large. A
    `trust.controller` naming the key already held keeps it at the new key sequence, and a statement under the old
    key sequence is not taken."""
    bare = _same(host_check, tmp_path / "bare", [("provision", S, N), _rekey("C", 1),
                                                 ("statement", _signed(key_seq=1, epoch=3), N)])
    assert _one(bare[1]).event == "trust-applied" and _taken(bare[2]) == (True, 3)
    full = _same(host_check, tmp_path / "full", [("provision", S, N, tuple("ABDEFGHJ")), _rekey("C", 1)])
    assert _one(full[1]).cause == "dist:too-large"
    held = _same(host_check, tmp_path / "held", [("provision", S, N), _rekey("C", 1),
                                                 ("statement", _signed(key_seq=0, epoch=5), N),
                                                 ("statement", _signed(key_seq=1, epoch=5), N), ("restart", N + 1),
                                                 ("statement", _signed(key_seq=1, epoch=6), N + 1)], controller="C")
    assert _one(held[1]).event == "trust-applied"
    assert _taken(held[2]) == (False, 0) and _taken(held[3]) == (True, 5) and _taken(held[5]) == (True, 6)


def test_case_280_an_anchor_whose_controller_key_is_of_another_role_is_refused(host_check):
    """case_280: P2, K4, K6. Anchors whose controller key is an install key, an operator key or the node's instance
    key are refused at provisioning, and the node is unchanged: its controller key and its epoch id stay."""
    def anchor(controller):
        return [*_anchor(("J", "K"), operators=("O",)), f"ckey {_kid(controller)} {_pub(controller).hex()}"]
    got = _run21(host_check, [*_node(), *anchor("C"), f"provision {S} {N}", f"statement {_signed(epoch=5)} {N}",
                              *anchor("J"), f"provision {S} {N}", *anchor("O"), f"provision {S} {N}",
                              *anchor("I"), f"provision {S} {N}", f"statement {_signed(epoch=6)} {N}"])
    assert _taken(got[1]) == (True, 5)
    assert got[2:5] == [f"provision-refused {causes.NAMES['dist:rotation-invalid']}"] * 3
    assert _taken(got[5]) == (True, 6)


def test_case_306_a_power_loss_between_a_narrower_ceiling_and_its_lapse_still_lapses_the_release(host_check):
    """case_306: CL3, C10, IS12, the C half. A mesh node commits a release inside its ceiling and applies a narrower
    ceiling the release is above, and the power is lost after each count of part writes in turn. After the restart
    the node holds the old ceiling and still the release, or the new ceiling and no release: the start lapses a
    release the held ceiling is above with dist:above-ceiling, so no cut leaves the release under the new ceiling."""
    wide = _ceiling(RELEASE, BODIES[1])
    narrow = _install("install.ceiling", _ceiling(BODIES[1]), seq=2, widens=False, replaces=canon.sha256_hex(wide))
    first = _install("install.ceiling", wide)
    seen = set()
    for writes in range(12):
        out = _run21(host_check, [*_node(), *_anchor(bring=[first]), f"provision {S} {N}", *_release_steps21(RELEASE, 1),
                                  f"stop {writes}", _stage(narrow), f"restart {N}", "installid", "state"])
        held = out[-2].split()[1]
        active = out[-1].split()[1]
        if held == _install_id(ceiling=(narrow[0], 2)):
            assert active == "-", (writes, out[-3:])                  # the new ceiling never runs above the release
            lapsed = [one for line in out[-3:-2] for one in _recs(line) if one["event"] == "lapsed"]
            seen.add("lapsed" if lapsed else "already")
            if lapsed:
                assert lapsed[0]["cause"] == "dist:above-ceiling"
        else:
            assert held == _install_id(ceiling=(first[0], 1)) and active == "1", (writes, out[-3:])
            seen.add("old")
    assert {"old", "lapsed"} <= seen                                  # a cut came between the ceiling and the lapse


def test_case_307_a_ceiling_after_a_lost_one_stands_out_unless_it_is_the_lost_one_again(host_check):
    """case_307: IS10, IS12, the C half. A mesh node whose ceiling no copy holds is sent, with widens false, the
    empty ceiling, a wider list, a narrower list whose replaces is the lost list's policy hash and the lost list
    again with replaces empty: dist:widening-unsigned each time, and still lost after a restart. The lost list again
    naming the lost hash is install-applied, and on another such node a narrower list with widens true is
    install-widened. A node provisioned again with its own install keys keeps the lost ceiling lost."""
    body = _ceiling(RELEASE, BODIES[1])
    lost = canon.sha256_hex(body)
    held = _install("install.ceiling", body)

    def again(seq, *bodies, widens=False, replaces=lost, empty=False):
        return _stage(_install("install.ceiling", b"" if empty else _ceiling(*bodies), seq=seq, widens=widens,
                               replaces=replaces))
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[held]), f"provision {S} {N}", *_release_steps21(RELEASE, 1),
        "lose set_ceiling", "lose2 set_ceiling", f"restart {N}",
        again(2, empty=True), again(2, RELEASE, BODIES[1], BODIES[2]), again(2, BODIES[1]),
        again(2, RELEASE, BODIES[1], replaces=""), f"restart {N}",
        "installid",
        again(2, RELEASE, BODIES[1])])
    assert [_refused(line)[0] for line in out[5:9]] == ["dist:widening-unsigned"] * 4
    assert _refused(out[9]) == ("dist:install-lost", 3)              # still named, still lost at the restart
    assert (_last(out[11])["event"], _last(out[11])["cause"]) == ("install-applied", None)
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[held]), f"provision {S} {N}", "lose set_ceiling", "lose2 set_ceiling",
        f"restart {N}", again(2, BODIES[1], widens=True, replaces="")])
    assert (_last(out[-1])["event"], _last(out[-1])["cause"]) == ("install-widened", "dist:install-widened")
    out = _run21(host_check, [
        *_node(), *_anchor(bring=[held]), f"provision {S} {N}", *_release_steps21(RELEASE, 1),
        "lose set_ceiling", "lose2 set_ceiling", f"restart {N}", *_anchor(seq=1), f"provision {S} {N}",
        *_release_steps21(BODIES[1], 2, replaces=canon.sha256_hex(RELEASE))[:2], f"restart {N}",
        *_release_steps21(BODIES[1], 2, replaces=canon.sha256_hex(RELEASE))[:2]])
    lost_after = [line for line in out if line.startswith("records") and any(
        one["event"] == "refused" and one["cause"] == "dist:install-lost" for one in _recs(line))]
    assert len(lost_after) >= 3, out


def test_a_looser_answer_rate_widens_an_action_floor_on_the_c_core(host_check):
    """IS12, OP4: a looser answer_rate is larger, as a looser rate is, so with widens false it is
    dist:widening-unsigned, and a tighter one is applied, as install.set_larger answers."""
    def floor(seq, allows, window, *, widens=False, replaces=canon.sha256_hex(FLOOR)):
        meta = {"as": "policy.ppt", "layout": LAYOUT, "command": 0, "answer_rate": {"allows": allows, "window": window}}
        return _stage(_install("install.floor", FLOOR, seq=seq, widens=widens, replaces=replaces, meta=meta))
    out = _run21(host_check, [*_node(), *_anchor(), f"provision {S} {N}", floor(1, 5, 60, widens=True, replaces=""),
                              floor(2, 9, 60), floor(2, 5, 30), floor(2, 3, 60)])
    assert _last(out[1])["event"] == "install-widened"
    assert [_refused(line)[0] for line in out[2:4]] == ["dist:widening-unsigned"] * 2
    assert _last(out[4])["event"] == "install-applied"


LARGER = json.loads((ROOT / "prismpath" / "portable" / "conformance" / "install_larger.json").read_text(encoding="utf-8"))
LARGER_TABLES = {"T1": BODIES[0], "T2": BODIES[1], "T3": BODIES[2], "F1": FLOOR, "F2": _floor_table((4,))}


def _larger_statement(kind: str, spec, seq: int, *, widens: bool, replaces: str):
    if spec == "empty":
        return _install(kind, b"", seq=seq, widens=widens, replaces=replaces)
    if kind == "install.ceiling":
        return _install(kind, _ceiling(*(LARGER_TABLES[name] for name in spec["list"])), seq=seq, widens=widens,
                        replaces=replaces)
    meta = {"as": "policy.ppt", "layout": LAYOUT, "command": 0}
    for member in ("rate", "answer_rate"):
        if spec[member] is not None:
            meta[member] = {"allows": spec[member][0], "window": spec[member][1]}
    return _install(kind, LARGER_TABLES[spec["table"]], seq=seq, widens=widens, replaces=replaces, meta=meta)


def _larger_replay(host_check, row: dict) -> dict:
    """The event and the cause a fresh mesh node answers the row of install_larger.json with."""
    kind = {"ceiling": "install.ceiling", "floor": "install.floor"}[row["set"]]
    lines, held, seq = [*_node(), *_anchor(), f"provision {S} {N}"], "", 1
    if row["before"] != "none":
        first = _larger_statement(kind, row["held"], 1, widens=kind == "install.floor", replaces="")
        lines.append(_stage(first))
        held, seq = hashlib.sha256(bytes.fromhex(first[1])).hexdigest(), 2
    if row["before"] == "withdrawn":
        lines.append(_stage(_larger_statement(kind, "empty", 2, widens=kind == "install.ceiling", replaces=held)))
        seq = 3
    if row["before"] == "lost":
        part = {"install.ceiling": "set_ceiling", "install.floor": "set_floor"}[kind]
        lines += [f"lose {part}", f"lose2 {part}", f"restart {N}"]
    replaces = {"held": held, "": "", "other": hashlib.sha256(b"a set this PEP never held").hexdigest()}[row["replaces"]]
    lines.append(_stage(_larger_statement(kind, row["new"], seq, widens=row["widens"], replaces=replaces)))
    out = _run21(host_check, lines)
    for line in out[1:-1]:
        if line.startswith("records") and row["before"] != "lost":
            assert _last(line)["event"] in ("install-applied", "install-widened"), (row["name"], line)
    last = _last(out[-1])
    return {"event": last["event"], "cause": last["cause"]}


def test_case_307_every_row_of_the_is12_table_answers_on_the_c_core_as_it_says(host_check):
    """case_307 and IS12 as a table (install_larger.json): every row answers on a mesh node with its event and
    cause, as Python and Rust answer it."""
    wrong = []
    for row in LARGER["rows"]:
        if "mesh" in row["kinds"]:
            got = _larger_replay(host_check, row)
            if got != row["expect"]:
                wrong.append((row["name"], got, row["expect"]))
    assert wrong == []
