# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The `cfs` kind of the C core of policy distribution (prismpath-hw/dist/, spec-policy-distribution.md sections 3,
9 to 12 and 21), on the host.

`host_check.c` is built as test_distribution_c.py builds it, with the table bound of the cFS app
(`-DPP_TABLE_MAX=4692`, the `PP_PolicyTable_t` bytes before `ImageSig`), which a cfs PEP needs. Its release steps
run beside the Python machine on a modelled cFS app (integrations/cfs/dist_kind.py) and must print the same signed
state records byte for byte. Section 21 has no Python machine on this branch, so its steps are held to the spec's
expectations, each table built from a core policy by the app's own generator (policy/gen_image.py).

It skips, naming the reason, when there is no C compiler or the tree does not carry prismpath-hw and
integrations/cfs."""
import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.kernel import causes

pytest.importorskip("cryptography")

from prismpath.tests import test_distribution_c as base  # noqa: E402
from prismpath.tests import _dist  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "prismpath-hw" / "dist"
MONOCYPHER = ROOT / "prismpath-hw" / "mesh" / "main"
CFS = ROOT / "integrations" / "cfs"
CC = shutil.which("cc")
S, N, E, NB = _dist.STREAM, _dist.NOW, _dist.EXPIRES, _dist.NOT_BEFORE
ALLOW, REFUSE, ESCALATE = 1, 2, 3
TIME_US = 1_234_567_890
_ask, _recs, _last, _refused, _stage = base._ask, base._recs, base._last, base._refused, base._stage


@pytest.fixture(scope="module")
def hc(tmp_path_factory):
    """host_check with the cfs table bound."""
    if not (DIST / "pp_dist.c").exists() or not (CFS / "dist_kind.py").exists():
        pytest.skip("the C core and the cFS app are in prismpath-hw and integrations/cfs, which this tree does not carry")
    if CC is None:
        pytest.skip("no C compiler (cc) on this host, so the C core is not built here")
    out = tmp_path_factory.mktemp("dist_c_cfs") / "host_check"
    sources = [DIST / "host_check.c", DIST / "pp_dist.c", MONOCYPHER / "monocypher.c", MONOCYPHER / "monocypher-ed25519.c"]
    subprocess.run([CC, *base.FLAGS, "-DPP_TABLE_MAX=4692", f"-I{DIST}", f"-I{MONOCYPHER}", "-o", str(out),
                    *map(str, sources)], check=True, capture_output=True, text=True)
    return out


# ------------------------------------------------------------------ cfs tables, built by the app's generator
FIELDS = {"cmd_class": "int min=0 max=10", "ground_contact": "bool", "monitor_ok": "bool",
          "slew_deg": "int min=0 max=180", "thrust_pct": "int min=0 max=200"}
CMD, GROUND, MONITOR, SLEW, THRUST = range(5)            # the registers: the field names sorted
COMMAND, PARAMETER, INDEPENDENT, PROPOSER = range(4)
# AF9, AF10: the app's layout labels (fsw/inc/prismpath_app_layout.h), the monitor's verdict 5 seconds fresh
LAYOUT_FIELDS = [(CMD, COMMAND, 0, 10, 0), (GROUND, PROPOSER, 0, 1, 0), (MONITOR, INDEPENDENT, 0, 1, 5),
                 (SLEW, PARAMETER, 0, 180, 0), (THRUST, PARAMETER, 0, 200, 0)]


def _modules():
    from integrations.cfs import dist_kind  # noqa: F401  (registers the cfs row of the Python machine)
    from integrations.cfs.ground import table
    from integrations.cfs.prismpath_app.policy import gen_image
    return table, gen_image


def _layout_hash() -> str:
    table, _gen = _modules()
    return hashlib.sha256(table.layout_document(LAYOUT_FIELDS)).hexdigest()


def cmp(field: str, op: str, value: int) -> list:
    return ["cmp", field, op, ["num", value]]


def rule(command: int, *, slew=(10, 20), thrust=(0, 50), extra=(), target="allow") -> dict:
    """A narrow floor rule: the command and both parameters bounded, with `extra` conjuncts."""
    return {"target": target, "when": ["and", cmp("cmd_class", "==", command), cmp("slew_deg", ">=", slew[0]),
                                       cmp("slew_deg", "<=", slew[1]), cmp("thrust_pct", ">=", thrust[0]),
                                       cmp("thrust_pct", "<=", thrust[1]), *extra]}


def core(rules: list) -> bytes:
    from prismpath.kernel import canon2
    return canon2.dumps({"fields": FIELDS, "format": "prismpath.core/1", "rules": rules})


def body(rules: list, version: int = 1) -> bytes:
    """The cfs.table body of a core policy: the table bytes before ImageSig."""
    table, gen_image = _modules()
    data = table.pack(gen_image.build(core(rules)))
    table.set_version(data, version)
    return bytes(data[:table.OFF["ImageSig"]])


def policy(table_body: bytes) -> str:
    """The policy hash of a cfs.table: its core image's (section 3)."""
    table, _gen = _modules()
    return hashlib.sha256(table.core_of(table_body)).hexdigest()


def regs(cmd: int, slew: int = 15, thrust: int = 20, ground: int = 1, monitor: int = 1) -> str:
    """The register file the app builds from a proposal: a 4 byte prefix, then type and value per field."""
    import struct
    values = {CMD: (2, cmd), GROUND: (1, ground), MONITOR: (1, monitor), SLEW: (2, slew), THRUST: (2, thrust)}
    return (b"\x00" * 4 + b"".join(struct.pack("<ii", *values[k]) for k in range(5))).hex()


def ages(monitor="0") -> str:
    """The ages the app gives: only the monitor's verdict is independent (AF10)."""
    return ",".join(["-", "-", str(monitor), "-", "-"])


# The release the scripts commit: the example policy's rules, allowing classes 1 to 3 within limits.
def release_body(version: int = 1) -> bytes:
    _table, gen_image = _modules()
    from prismpath.kernel import canon2
    doc = canon2.loads(gen_image.CORE.read_bytes().rstrip(b"\n"))
    return body(doc["rules"], version)


def node(*, hold=False, seed=None) -> list:
    lines = [f"machine {int(hold)} 1 {seed or base.INSTANCE_SEED} cfs", f"domain {base.DOMAIN}", f"layout {_layout_hash()}"]
    return lines + [f"field {reg} {role} {low} {high} {stale}" for reg, role, low, high, stale in LAYOUT_FIELDS]


def install(artifact: str, table_body: bytes = b"", *, seq=1, signers=("J", "K"), meta=None, as_=None, widens=None,
            replaces="", **args):
    """An install statement for a cfs PEP (IS1, IS3): a set is a cfs.table, its policy hash the core image's."""
    if as_ is None and artifact != "install.trust":
        as_ = "none" if table_body == b"" else ("policy.list" if artifact == "install.ceiling" else "cfs.table")
    if meta is None and as_ == "cfs.table" and artifact == "install.floor":
        meta = {"as": as_, "command": CMD, "layout": _layout_hash()}
    if "policy" not in args and as_ == "cfs.table":
        args["policy"] = policy(table_body)
    return base._install(artifact, table_body, seq=seq, signers=signers, as_=as_, meta=meta, widens=widens,
                         replaces=replaces, targets=("cfs",), **args)


def release(table_body: bytes, seq: int, *, widens=True, replaces="", now=N, not_before=NB, expires=E,
            signer="A") -> list:
    """Stage a cfs release of `table_body` with its widening statement when it widens, and commit it."""
    pol = policy(table_body)
    rel = env.release_id([("cfs.table", canon.sha256_hex(table_body))])
    lines = []
    if widens:
        statement = _dist.widening()
        lines.append(f"stage {_dist.seal('trust.widening', statement, seq=seq, release=rel, policy_sha256=pol, targets=('cfs',), replaces=replaces, widens=True, not_before=not_before, signer=signer).hex()} {statement.hex()} {now}")
    lines.append(f"stage {_dist.seal('cfs.table', table_body, seq=seq, policy_sha256=pol, targets=('cfs',), widens=widens, replaces=replaces, not_before=not_before, expires=expires, signer=signer).hex()} {table_body.hex()} {now}")
    lines.append(f"commit {S} {seq} {pol} 0 0 {now}")
    return lines


def run(hc, lines: list) -> list:
    return base._run21(hc, lines)


def ask(out_line: str) -> dict:
    return _ask(out_line)


FLOOR = None


def floors():
    """The floor tables of these tests, built once."""
    global FLOOR
    if FLOOR is None:
        FLOOR = {
            "one": body([rule(3)]),
            "two": body([rule(3), rule(4)]),
            "monitor": body([rule(3, extra=[["truthy", "monitor_ok"]])]),
            "ground": body([rule(3, extra=[["truthy", "ground_contact"]])]),
            "escalate": body([rule(3, target="escalate_34")]),
            "fallback": body([{"target": "allow", "when": ["in", "cmd_class", [["num", 5]]]}]),
        }
    return FLOOR


# ------------------------------------------------------------------ the release half, beside the Python machine
def _python(tmp_path, script, *, hold):
    """The Python machine on a modelled cFS app run through `script`, as base._python_steps runs a mesh node."""
    from integrations.cfs.tests.test_cfs_dist import CfsPep
    from prismpath.distribution.pep import PepRefused
    out, point = [], None
    for step in script:
        op, args = step[0], step[1:]
        if op == "provision":
            point = CfsPep(tmp_path, clock=_dist.Clock(args[1]), expiry_response="hold" if hold else "refuse")
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
        out.append(" ".join(["records", *(record.hex() for record in point.pep.drain())]))
    return out


def _c(hc, script, *, hold):
    lines = [f"key {_dist.key_id('A')} {_dist.GEN.public_raw(_dist.GEN.test_key('A')).hex()} 0",
             f"machine {int(hold)} 1 {base.INSTANCE_SEED} cfs"]
    for step in script:
        op, args = step[0], step[1:]
        if op == "commit":
            lines.append(f"commit {args[0]} {args[1]} {args[2]} 0 0 {args[3]}")
        elif op == "tick":
            lines.append(f"tick 0 {args[0]}")
        else:
            lines.append(" ".join([op, *(str(arg) for arg in args)]))
    return base._run21(hc, lines)


def _staged(table_body: bytes, seq: int, *, now=N, widens=True, replaces="", **args) -> list:
    pol = policy(table_body)
    steps = []
    if widens:
        statement = _dist.widening()
        steps.append(("stage", _dist.seal("trust.widening", statement, seq=seq, policy_sha256=pol, targets=("cfs",),
                                          release=env.release_id([("cfs.table", canon.sha256_hex(table_body))]),
                                          replaces=replaces, widens=True, not_before=args.get("not_before", NB)).hex(),
                      statement.hex(), now))
    steps.append(("stage", _dist.seal("cfs.table", table_body, seq=seq, policy_sha256=pol, targets=("cfs",),
                                      widens=widens, replaces=replaces, **args).hex(), table_body.hex(), now))
    return steps


def test_the_cfs_kind_answers_as_the_python_machine_on_a_modelled_cfs_app(hc, tmp_path):
    """A first table with its widening statement, a renewal, a table with another core image on the signer's word,
    an older seq after a restart, an abort, expiry under each setting, a revocation of a held release and a held
    rollback: every signed record the C core makes is the Python machine's, byte for byte."""
    first, renewal = release_body(1), release_body(1)
    other = body([rule(2), rule(3)], 2)
    for hold in (False, True):
        script = [("provision", S, N), *_staged(first, 1), ("commit", S, 1, policy(first), N),
                  *_staged(renewal, 2, widens=False, replaces=policy(first)), ("commit", S, 2, policy(first), N),
                  *_staged(other, 3, widens=False, replaces=policy(first)), ("commit", S, 3, policy(other), N),
                  ("restart", N + 10), *_staged(first, 2, widens=False, replaces=policy(other), now=N + 10),
                  *_staged(first, 4, widens=False, replaces=policy(other), now=N + 10),
                  ("abort", S, 4, policy(first), N + 10), ("rollback", N + 11), ("tick", E), ("tick", E + 1),
                  ("rollback", E + 2), ("restart", E + 3)]
        python = _python(tmp_path / f"py{int(hold)}", script, hold=hold)
        assert _c(hc, script, hold=hold) == python
        records = [record for line in python for record in base._records(line)]
        assert ("held" if hold else "lapsed") in [record.event for record in records]


def test_case_060_a_cfs_table_with_another_core_image_is_taken_on_the_signers_word(hc):
    """case_060: W2, the cfs half on the C core. A cfs PEP compares nothing itself, so a table with another core image,
    `widens` false and `replaces` its active policy hash, commits on its signature alone, and with another `replaces`
    it is dist:widening-unsigned."""
    first, other = release_body(1), body([rule(2), rule(3)], 2)
    out = run(hc, [*node(), *base._anchor(), f"provision {S} {N}", *release(first, 1),
                   *release(other, 2, widens=False, replaces=policy(first))[-2:],
                   *release(other, 3, widens=False, replaces="ab" * 32)[-2:-1]])
    assert _last(out[3])["event"] == "committed" and _last(out[3])["active_seq"] == 1
    assert [one["event"] for one in _recs(out[4])] == ["staged"]
    assert _last(out[5])["event"] == "committed" and _last(out[5])["active_seq"] == 2
    assert _refused(out[6])[0] == "dist:widening-unsigned"


# ------------------------------------------------------------------ section 21 on a cfs PEP
def _image(node_edges, atoms, fields=5) -> bytes:
    """A PPT v1 image whose node k holds the edges `node_edges[k]`, each (target node, postfix program of atom indexes
    and "and"), over `atoms` (register, op, type, value)."""
    import struct
    words, table, nodes = [], [], []
    for edges in node_edges:
        nodes.append((len(table), len(edges)))
        for target, program in edges:
            table.append((target, len(words), len(program)))
            words += [0x8001 if word == "and" else word for word in program]
    out = struct.pack("<4sHHHHHHHHHHHBB", b"PPTM", 1, fields, 0, len(atoms), len(nodes), len(table), len(words), 0,
                      0xFFFF, 16, 16, 0, 0)
    out += b"".join(struct.pack("<HBBi", *atom) for atom in atoms)
    out += b"".join(struct.pack("<HH", *n) for n in nodes)
    out += b"".join(struct.pack("<HHH", *edge) for edge in table)
    return out + b"".join(struct.pack("<H", word) for word in words)


def _crafted(image: bytes, rules) -> bytes:
    """A cfs.table body that carries `image` and `rules` beside a good core image: what a table looks like when its
    PPT image is not one the generator writes."""
    table, gen_image = _modules()
    built = dict(gen_image.build(core([rule(3)])), image=image, rules=list(rules))
    data = table.pack(built)
    table.set_version(data, 1)
    return bytes(data[:table.OFF["ImageSig"]])


def test_case_213_a_cfs_floor_is_narrow_and_only_its_command_inside_its_bounds_is_allowed(hc):
    """case_213: AF9, AF10, the cfs half. A floor whose default allows, one with an allowing rule that tests no
    command, one with two decision nodes, one with nine allowing rules, one whose `command` names a parameter, one
    that leaves a parameter unbounded, one whose bound is the parameter's whole domain are dist:floor-broad, one whose
    `layout` is another layout's hash is dist:target-mismatch, and one with eight rules, each one command with both
    parameters bounded, is applied. The command inside the bound is then allowed with basis floor, and outside it the
    release decides."""
    eq, ge, le = 0, 5, 3
    atoms = [(CMD, eq, 2, 3), (SLEW, ge, 2, 10), (SLEW, le, 2, 20), (THRUST, ge, 2, 0), (THRUST, le, 2, 50)]
    narrow = [0, 1, "and", 2, "and", 3, "and", 4, "and"]
    broad = [
        body([rule(3), {"target": "allow", "when": ["always"]}]),                         # the default allows
        body([{"target": "allow", "when": ["and", cmp("slew_deg", ">=", 10), cmp("slew_deg", "<=", 20),
                                           cmp("thrust_pct", ">=", 0), cmp("thrust_pct", "<=", 50)]}]),
        _crafted(_image([[(1, narrow)], [(2, [0])], []], atoms), [(0, 0)]),                # two decision nodes
        _crafted(_image([[(1, [4 + k, 0, "and", 1, "and", 2, "and", 3, "and"]) for k in range(9)], []],
                        atoms[1:] + [(CMD, eq, 2, k + 1) for k in range(9)]), [(0, 0)] * 9),   # nine allowing rules
        None,                                                                               # `command` a parameter
        body([{"target": "allow", "when": ["and", cmp("cmd_class", "==", 3), cmp("slew_deg", ">=", 10),
                                           cmp("slew_deg", "<=", 20)]}]),                  # thrust unbounded
        body([rule(3, thrust=(0, 200))]),                                                   # the whole domain
    ]
    floor_eight = body([rule(k + 1, slew=(10 * k, 10 * k + 5)) for k in range(8)])
    statements = [install("install.floor", table_body, seq=1) for table_body in broad if table_body is not None]
    statements.insert(4, install("install.floor", floor_eight, seq=1,
                                 meta={"as": "cfs.table", "command": SLEW, "layout": _layout_hash()}))
    statements.append(install("install.floor", floor_eight, seq=1,
                              meta={"as": "cfs.table", "command": CMD, "layout": "ab" * 32}))
    applied = install("install.floor", floor_eight, seq=1)
    lines = [*node(), *base._anchor(), f"provision {S} {N}", *release(release_body(), 1),
             *(_stage(one) for one in statements), _stage(applied),
             f"ask {N} {regs(3, slew=22)} {ages()}", f"ask {N} {regs(3, slew=27)} {ages()}",
             f"ask {N} {regs(9, slew=72)} {ages()}"]
    out = run(hc, lines)
    refused = [_refused(line) for line in out[4:12]]
    assert refused == [("dist:floor-broad", 1)] * 7 + [("dist:target-mismatch", 1)]
    assert _last(out[12])["event"] == "install-widened"
    inside, outside, nine = (ask(line) for line in out[13:16])
    assert (inside["outcome"], inside["basis"], inside["cause"]) == (ALLOW, "floor", "dist:floor-allowed")
    assert (outside["basis"], outside["outcome"]) == ("release", ALLOW)            # class 3 within the release's limits
    assert (nine["basis"], nine["outcome"], nine["cause"]) == ("release", REFUSE, "agent:unclassifiable")


def test_case_216_a_cfs_floor_tests_only_what_the_proposer_cannot_write_and_never_a_stale_reading(hc):
    """case_216: AF10. With `monitor_ok` independent for 5 seconds and `ground_contact` the proposer's, a floor whose
    rule tests `ground_contact` is dist:floor-broad and one that tests `monitor_ok` is applied. Asked with the app's
    own monitor reading not ok whatever the proposer claimed, with the monitor's last message 6 seconds old and with
    none ever received, the floor is silent, so with no release and no fallback policy each is dist:policy-lapsed.
    The sealing tool refuses a layout whose independent field has a staleness bound of 0."""
    out = run(hc, [*node(), *base._anchor(), f"provision {S} {N}",
                   _stage(install("install.floor", floors()["ground"], seq=1)),
                   _stage(install("install.floor", floors()["monitor"], seq=1)),
                   f"ask {N} {regs(3, monitor=1)} {ages(0)}", f"ask {N} {regs(3, monitor=0)} {ages(0)}",
                   f"ask {N} {regs(3, monitor=1)} {ages(6)}", f"ask {N} {regs(3, monitor=1)} {ages('-')}"])
    assert _refused(out[1]) == ("dist:floor-broad", 1)
    assert _last(out[2])["event"] == "install-widened"
    fresh, *silent = (ask(line) for line in out[3:7])
    assert (fresh["outcome"], fresh["basis"]) == (ALLOW, "floor")
    assert [(one["outcome"], one["cause"], one["basis"]) for one in silent] == [(REFUSE, "dist:policy-lapsed", None)] * 3
    table, _gen = _modules()
    with pytest.raises(ValueError):
        table.layout_document([(reg, role, low, high, 0) for reg, role, low, high, _stale in LAYOUT_FIELDS])


ANSWER_RATE = {"allows": 2, "window": 600}


def floor_meta(**more) -> dict:
    return {"as": "cfs.table", "command": CMD, "layout": _layout_hash(), **more}


def refuses_three() -> bytes:
    """A release that refuses command class 3 and allows classes 1 and 2."""
    return body([{"target": "refuse_104", "when": ["in", "cmd_class", [["num", 3]]]},
                 {"target": "allow", "when": ["in", "cmd_class", [["num", 1], ["num", 2]]]}])


def test_case_186_the_action_floor_answers_first_in_every_state(hc, host_check):
    """case_186: AF1. A request the action floor allows is allowed with basis floor when the active release refuses
    it, when a cfs PEP is held, in no-policy, in locked and under the fallback policy, on cfs and on mesh."""
    floor = install("install.floor", floors()["one"])
    fallback = install("install.fallback", floors()["fallback"])
    q = regs(3)
    out = run(hc, [*node(hold=True), *base._anchor(bring=[floor]), f"provision {S} {N}",
                   *release(refuses_three(), 1), f"ask {N} {q} -", f"tick 0 {E}", f"ask {E} {q} -",
                   "lose floor", f"restart {E}", f"record 0 {E}", f"ask {E} {q} -"])
    assert _last(out[5])["event"] == "held" and _last(out[8])["state"] == "locked"
    asked = [ask(out[4]), ask(out[6]), ask(out[9])]
    assert [(one["outcome"], one["basis"], one["held"], one["would"]) for one in asked] == [
        (ALLOW, "floor", False, REFUSE), (ALLOW, "floor", True, REFUSE), (ALLOW, "floor", False, 0)]
    out = run(hc, [*node(), *base._anchor(bring=[floor]), f"provision {S} {N}", f"ask {N} {q} -",
                   *base._anchor(bring=[floor, fallback]), f"provision {S} {N}", f"ask {N} {q} -",
                   f"ask {N} {regs(5)} -"])
    assert [(ask(line)["outcome"], ask(line)["basis"]) for line in (out[1], out[3], out[4])] == [
        (ALLOW, "floor"), (ALLOW, "floor"), (ALLOW, "fallback")]
    mesh_floor, mesh_fallback = base._install("install.floor", base.FLOOR), base._install("install.fallback", base.FALLBACK)
    m = base._regs(3)
    out = run(host_check, [*base._node(hold=True), *base._anchor(bring=[mesh_floor]), f"provision {S} {N}",
                           *base._release_steps21(base.RELEASE, 1), f"ask {N} {m} -", f"tick 0 {E}", f"ask {E} {m} -",
                           "lose floor", f"restart {E}", f"ask {E} {m} -",
                           *base._anchor(bring=[mesh_floor, mesh_fallback]), f"provision {S} {N}", f"ask {N} {m} -"])
    assert all((ask(line)["outcome"], ask(line)["basis"]) == (ALLOW, "floor") for line in out if line.startswith("ask"))
    assert len([line for line in out if line.startswith("ask")]) == 4


def test_case_188_a_floor_escalation_answers_and_a_silent_floor_leaves_the_rest_alone(hc, host_check):
    """case_188: AF2. A cfs floor that escalates a request the release allows escalates it with basis floor and the
    floor's own cause. A request the floor refuses and one it cannot read get the release's own answer, and in
    no-policy with no fallback policy dist:policy-lapsed. A mesh floor is silent on a request it does not allow."""
    escalates = install("install.floor", floors()["escalate"], meta=floor_meta(answer_rate=ANSWER_RATE))
    no_rate = install("install.floor", floors()["escalate"], seq=2)
    refusing = install("install.floor", body([rule(3, target="refuse_104"), rule(4)]), seq=3)
    short = "00000000" + regs(3)[8:24]                                    # the command alone: the rest cannot be read
    out = run(hc, [*node(), *base._anchor(), f"provision {S} {N}", _stage(no_rate), _stage(escalates),
                   *release(release_body(), 1), f"ask {N} {regs(3)} -", _stage(refusing), f"ask {N} {regs(3)} -",
                   f"ask {N} {short} -"])
    assert _refused(out[1]) == ("dist:bad-format", 1)                    # OP4: an escalating floor names its answer rate
    escalated = ask(out[6])
    assert (escalated["outcome"], escalated["basis"], escalated["cause"], escalated["would"]) == (
        ESCALATE, "floor", "route:needs-human", ALLOW)
    released, unread = ask(out[8]), ask(out[9])
    assert (released["basis"], released["outcome"]) == ("release", ALLOW)
    assert (unread["basis"], unread["outcome"], unread["cause"]) == ("release", REFUSE, "route:no-matching-edge")
    out = run(hc, [*node(), *base._anchor(bring=[refusing]), f"provision {S} {N}", f"ask {N} {regs(3)} -",
                   f"ask {N} {short} -"])
    assert [(ask(line)["basis"], ask(line)["cause"]) for line in out[1:3]] == [(None, "dist:policy-lapsed")] * 2
    out = run(host_check, [*base._node(), *base._anchor(bring=[base._install("install.floor", base.FLOOR)]),
                           f"provision {S} {N}", *base._release_steps21(base.RELEASE, 1), f"ask {N} {base._regs(4)} -"])
    assert (ask(out[4])["basis"], ask(out[4])["outcome"]) == ("release", REFUSE)


def test_case_192_a_cfs_floor_can_require_the_monitor_to_agree(hc):
    """case_192: AF6, AF2. A cfs floor that allows a command only while the monitor agrees allows it with basis floor
    when the monitor's verdict is good, and with no release and no fallback policy it is dist:policy-lapsed when the
    verdict is bad."""
    out = run(hc, [*node(), *base._anchor(bring=[install("install.floor", floors()["monitor"])]), f"provision {S} {N}",
                   f"ask {N} {regs(3, monitor=1)} {ages(1)}", f"ask {N} {regs(3, monitor=0)} {ages(1)}"])
    good, bad = ask(out[1]), ask(out[2])
    assert (good["outcome"], good["basis"]) == (ALLOW, "floor")
    assert (bad["outcome"], bad["basis"], bad["cause"]) == (REFUSE, None, "dist:policy-lapsed")


def test_case_194_a_cfs_floor_escalates_past_its_signed_rate_and_counts_each_rule_apart(hc):
    """case_194: AF8, AF5, the cfs half (the mesh half is the rate test of test_distribution_c.py). With two rules and
    a rate of 3 in 60 seconds, the first rule's action, which the release refuses, is allowed three times and then
    escalated twice with dist:floor-rate and basis floor, a restart after the second changing nothing; the second
    rule's action is allowed and counted on its own; an action the release allows is allowed ten times with no count;
    the next window allows again; and a release whose not_before is two windows ahead ends the window early."""
    meta = floor_meta(answer_rate=ANSWER_RATE, rate={"allows": 3, "window": 60})
    floor = install("install.floor", floors()["two"], meta=meta)
    rel = body([{"target": "refuse_104", "when": ["in", "cmd_class", [["num", 3]]]},
                {"target": "allow", "when": ["and", cmp("cmd_class", "==", 4), cmp("slew_deg", ">=", 15)]},
                {"target": "allow", "when": ["in", "cmd_class", [["num", 1], ["num", 2]]]}])
    first = lambda now: f"ask {now} {regs(3)} -"  # noqa: E731
    renewal = release(rel, 2, widens=False, replaces=policy(rel), not_before=N + 300, now=N + 200)[-2]
    out = run(hc, [*node(), *base._anchor(bring=[floor]), f"provision {S} {N}", *release(rel, 1),
                   first(N), first(N + 1), f"restart {N + 2}", first(N + 2), first(N + 3), first(N + 4),
                   f"ask {N + 5} {regs(4, slew=12)} -", *(f"ask {N + 6} {regs(4, slew=18)} -" for _ in range(10)),
                   first(N + 61), first(N + 200), renewal, first(N + 201)])
    asked = [ask(line) for line in out if line.startswith("ask")]
    assert [(one["outcome"], one["basis"], one["cause"], one["count"]) for one in asked[:5]] == [
        (ALLOW, "floor", "dist:floor-allowed", 1), (ALLOW, "floor", "dist:floor-allowed", 2),
        (ALLOW, "floor", "dist:floor-allowed", 3), (ESCALATE, "floor", "dist:floor-rate", 3),
        (ESCALATE, "floor", "dist:floor-rate", 3)]                       # the spent window, which the run's rates name
    assert [(one["counted"], one["rate_escalated"]) for one in asked[3:5]] == [(False, True)] * 2
    assert (asked[5]["outcome"], asked[5]["rule"], asked[5]["count"], asked[5]["counted"]) == (ALLOW, 1, 1, True)
    assert all((one["outcome"], one["basis"], one["counted"], one["would"]) == (ALLOW, "floor", False, ALLOW)
               for one in asked[6:16])
    assert (asked[16]["outcome"], asked[16]["count"], asked[16]["window"]) == (ALLOW, 1, N + 61)
    assert (asked[17]["count"], asked[17]["window"]) == (1, N + 200)
    assert (asked[18]["count"], asked[18]["window"]) == (1, N + 300)    # the time floor moved past the window's end


def test_case_200_a_held_cfs_pep_goes_to_its_fallback_policy_when_a_revocation_ends_the_hold(hc):
    """case_200: FB6, X7, X8. A cfs PEP with HOLD and a fallback policy is held at expiry, bit 5 set and bit 4 clear,
    and a revocation of its release then hands it to the fallback policy, bit 4 set and bit 5 clear, with event
    fallback and dist:revoked."""
    rel = release_body()
    revoke = _dist.trust_statement("trust.revocation", _dist.revocation(policies=[policy(rel)]), seq=1,
                                   signers=("A",), targets=("cfs",))
    out = run(hc, [*node(hold=True), *base._anchor(bring=[install("install.fallback", floors()["fallback"])]),
                   f"provision {S} {N}", *release(rel, 1), f"tick 0 {E}", f"ask {E} {regs(5)} -",
                   f"stage {revoke.hex()} {_dist.revocation(policies=[policy(rel)]).hex()} {E}", f"ask {E} {regs(5)} -"])
    held = _last(out[4])
    assert (held["event"], held["held"], held["fallback"]) == ("held", True, False)
    assert (ask(out[5])["basis"], ask(out[5])["held"]) == ("release", True)
    after = _recs(out[6])
    assert [(one["event"], one["cause"], one["held"], one["fallback"]) for one in after] == [
        ("fallback", "dist:revoked", False, True), ("trust-applied", None, False, True)]
    assert (ask(out[7])["basis"], ask(out[7])["outcome"]) == ("fallback", ALLOW)


def test_case_203_a_list_ceiling_holds_every_table_by_its_body_hash(hc, host_check):
    """case_203: CL1, CL2, IS12, the PEPs' half. A mesh and a cfs PEP with a list are offered a table whose body hash
    is on it, staged, and one off it, dist:above-ceiling; the cfs PEP also a table with the listed core image and
    other rules, dist:above-ceiling; then a floor off the list, dist:above-ceiling; a list that adds the floor's hash
    with widens false, dist:widening-unsigned, and with widens true, install-widened; then the floor is applied."""
    rel = release_body()
    other_rules = bytearray(rel)
    other_rules[20 + 4 * 6] = 1                                       # the last rule refuses instead: the same core image
    other_rules = bytes(other_rules)
    floor_body = floors()["one"]
    listed = base._ceiling(rel)
    wider = base._ceiling(rel, floor_body)
    ceiling = install("install.ceiling", listed)
    def offer(table_body, seq):
        return release(table_body, seq)[:2]
    out = run(hc, [*node(), *base._anchor(bring=[ceiling]), f"provision {S} {N}", *offer(rel, 1),
                   *offer(body([rule(2), rule(3)], 2), 2), *offer(other_rules, 3),
                   _stage(install("install.floor", floor_body)),
                   _stage(install("install.ceiling", wider, seq=2, widens=False, replaces=canon.sha256_hex(listed))),
                   _stage(install("install.ceiling", wider, seq=2, widens=True, replaces=canon.sha256_hex(listed))),
                   _stage(install("install.floor", floor_body))])
    assert _last(out[2])["event"] == "staged"
    assert [_refused(line)[0] for line in (out[4], out[6])] == ["dist:above-ceiling"] * 2
    assert _refused(out[7]) == ("dist:above-ceiling", 1)
    assert _refused(out[8]) == ("dist:widening-unsigned", 3)
    assert [(one["event"], one["cause"]) for one in _recs(out[9])][-1] == ("install-widened", "dist:install-widened")
    assert _last(out[10])["event"] == "install-widened" and _last(out[10])["subject"] == 1
    mesh_list = base._ceiling(base.RELEASE)
    mesh_wider = base._ceiling(base.RELEASE, base.FLOOR)
    out = run(host_check, [*base._node(), *base._anchor(bring=[base._install("install.ceiling", mesh_list)]),
                           f"provision {S} {N}", *base._release_steps21(base.RELEASE, 1)[:2],
                           *base._release_steps21(base.BODIES[1], 2)[:2],
                           _stage(base._install("install.floor", base.FLOOR)),
                           _stage(base._install("install.ceiling", mesh_wider, seq=2, widens=False,
                                                replaces=canon.sha256_hex(mesh_list))),
                           _stage(base._install("install.ceiling", mesh_wider, seq=2, widens=True,
                                                replaces=canon.sha256_hex(mesh_list))),
                           _stage(base._install("install.floor", base.FLOOR))])
    assert _last(out[2])["event"] == "staged" and _refused(out[4])[0] == "dist:above-ceiling"
    assert _refused(out[5]) == ("dist:above-ceiling", 1) and _refused(out[6]) == ("dist:widening-unsigned", 3)
    assert _last(out[7])["event"] == "install-widened" and _last(out[8])["event"] == "install-widened"


def test_case_184_a_widening_install_set_stands_out_and_a_cfs_pep_takes_the_signers_word(hc, host_check):
    """case_184: IS12, X9, W2, the PEPs' half. On mesh a first floor and a wider one with widens true are
    install-widened, the same table again at a higher seq with widens false and `replaces` the held policy hash is
    install-applied, and widens false with another `replaces`, and a narrower table with widens false, are
    dist:widening-unsigned, since mesh compares bytes. A held cfs PEP takes a floor with widens true as
    install-widened with bit 5 still set, refuses a local rollback with dist:held, and takes a wider table with widens
    false and `replaces` the held policy hash as install-applied on the signers' word."""
    one, two = base.FLOOR, base.FLOOR_B
    h1, h2 = canon.sha256_hex(one), canon.sha256_hex(two)
    out = run(host_check, [*base._node(), *base._anchor(), f"provision {S} {N}",
                           _stage(base._install("install.floor", one, seq=1, widens=True)),
                           _stage(base._install("install.floor", two, seq=2, widens=True, replaces=h1)),
                           _stage(base._install("install.floor", two, seq=3, widens=False, replaces=h2)),
                           _stage(base._install("install.floor", two, seq=4, widens=False, replaces=h1)),
                           _stage(base._install("install.floor", one, seq=4, widens=False, replaces=h2))])
    assert [(_last(line)["event"], _last(line)["cause"]) for line in out[1:4]] == [
        ("install-widened", "dist:install-widened"), ("install-widened", "dist:install-widened"),
        ("install-applied", None)]
    assert [_refused(line) for line in out[4:6]] == [("dist:widening-unsigned", 1)] * 2
    narrow, wide = floors()["one"], floors()["two"]
    out = run(hc, [*node(hold=True), *base._anchor(), f"provision {S} {N}", *release(release_body(), 1),
                   *release(release_body(2), 2, replaces=policy(release_body())), f"tick 0 {E}",
                   _stage(install("install.floor", narrow, seq=1, widens=True), E), f"rollback {E}",
                   _stage(install("install.floor", wide, seq=2, widens=False, replaces=policy(narrow)), E)])
    held = _last(out[7])
    assert held["event"] == "held"
    widened = _last(out[8])
    assert (widened["event"], widened["cause"], widened["held"]) == ("install-widened", "dist:install-widened", True)
    assert (_last(out[9])["cause"], _last(out[9])["held"]) == ("dist:held", True)
    applied = _last(out[10])
    assert (applied["event"], applied["cause"], applied["held"]) == ("install-applied", None, True)


def test_case_161_an_anchor_with_install_keys_and_two_sets_is_provisioned_and_both_survive_a_restart(hc, host_check):
    """case_161: IS1, IS2, IS8, IS10, P4, the C half. A cfs PEP is given a /2 trust anchor, read by the core, whose
    install member holds two install keys, with an action floor and a fallback policy brought beside it, and a mesh
    PEP the same with its own sets. At P2 step 4 each prints the anchor's fingerprint and the envelope id of each set
    it holds, the provisioned record carries the install id that names both, and after a restart both are held."""
    from integrations.cfs.ground import provision as ground
    public = lambda name: _dist.GEN.public_raw(_dist.GEN.test_key(name))  # noqa: E731
    doc = ground.anchor_document([public("A")], controller_public=public("C"), stream=S, target="cfs",
                                 install_publics=[public("J"), public("K")], threshold=2, domain=base.DOMAIN)
    floor, fallback = install("install.floor", floors()["one"]), install("install.fallback", floors()["fallback"])
    ids = [base._envelope_id(floor[0]), base._envelope_id(fallback[0])]
    fingerprint = hashlib.sha256(doc).hexdigest()
    out = run(hc, [*node(), f"anchor_doc {doc.hex()}", f"bring {floor[0]} {floor[1]}",
                   f"bring {fallback[0]} {fallback[1]}", f"provision {S} {N}", "held", "installid", f"restart {N + 5}",
                   "held", "installid", f"ask {N + 5} {regs(3)} -", f"ask {N + 5} {regs(5)} -"])
    assert out[0] == f"anchor 0 {S} cfs {fingerprint}"
    provisioned = _last(out[1])
    assert (provisioned["event"], provisioned["cause"]) == ("provisioned", "dist:install-widened")
    assert out[2] == out[5] == f"held {ids[0]} {ids[1]} -"
    want = base._install_id(floor=(floor[0], 1), fallback=(fallback[0], 1), trust_id=fingerprint)
    assert out[3] == out[6] == f"installid {want}" and provisioned["install_id"] == want
    assert [ask(line)["basis"] for line in out[7:9]] == ["floor", "fallback"]
    mesh_floor = base._install("install.floor", base.FLOOR)
    mesh_fallback = base._install("install.fallback", base.FALLBACK)
    out = run(host_check, [*base._node(), *base._anchor(bring=[mesh_floor, mesh_fallback]), f"provision {S} {N}",
                           "held", f"restart {N + 5}", "held"])
    assert out[1] == out[3] == f"held {base._envelope_id(mesh_floor[0])} {base._envelope_id(mesh_fallback[0])} -"


def test_the_core_reads_a_trust_anchor_document_and_refuses_one_out_of_its_form(hc):
    """P2, P4, K4: a /1 anchor and a /2 anchor read, and a /2 anchor whose controller key is an install key, one with
    `fresh` other than 0, one whose key is in another role and one written in another spelling are refused."""
    from integrations.cfs.ground import provision as ground
    from prismpath.distribution import trust
    from prismpath.kernel import canon2
    public = lambda name: _dist.GEN.public_raw(_dist.GEN.test_key(name))  # noqa: E731
    v1 = trust.anchor_bytes([public("A")], target="cfs", stream=S)
    good = ground.anchor_document([public("A"), public("B")], controller_public=public("C"), stream=S,
                                  install_publics=[public("J")], threshold=1, domain=base.DOMAIN)
    doc = canon2.loads(good)
    fresh = canon2.dumps({**doc, "fresh": 3600})
    role = canon2.dumps({**doc, "keys": {k: {**v, "role": "install"} for k, v in doc["keys"].items()}})
    controller = canon2.dumps({**doc, "controller": public("J").hex()})
    spaced = good.replace(b'"fresh":0', b'"fresh": 0')
    out = run(hc, [*node(), *(f"anchor_doc {raw.hex()}" for raw in (v1, good, fresh, role, controller, spaced))])
    assert out[0] == f"anchor 0 {S} cfs {hashlib.sha256(v1).hexdigest()}"
    assert out[1] == f"anchor 0 {S} cfs {hashlib.sha256(good).hexdigest()}"
    bad = causes.code("dist:bad-format")
    assert out[2:] == [f"anchor {bad} - - -"] * 3 + [f"anchor {causes.code('document:not-canonical')} - - -"]


def test_case_226_a_cfs_pep_reads_its_install_record_from_the_second_copy(hc):
    """case_226: IS10, the cfs half on the core. With the first copy of its install record and of its sets unreadable,
    a cfs PEP uses the second copies, holds both sets and reports no loss; with both copies of the record gone it
    holds no set and reports dist:install-lost."""
    floor, fallback = install("install.floor", floors()["one"]), install("install.fallback", floors()["fallback"])
    out = run(hc, [*node(), *base._anchor(bring=[floor, fallback]), f"provision {S} {N}", "lose install",
                   "lose set_floor", f"restart {N}", "held", f"ask {N} {regs(3)} -", "lose2 install", f"restart {N}",
                   "held", f"ask {N} {regs(3)} -"])
    assert [one["event"] for one in _recs(out[1])] == ["fallback"] and out[2] == f"held {base._envelope_id(floor[0])} {base._envelope_id(fallback[0])} -"
    assert ask(out[3])["basis"] == "floor"
    assert [(one["event"], one["cause"]) for one in _recs(out[4])] == [("refused", "dist:install-lost")]
    assert out[5] == "held - - -" and ask(out[6])["basis"] is None


# ------------------------------------------------------------------ OP1 to OP4: the operator's answer on the core
SEED2 = _dist.GEN.test_key("I2").private_bytes_raw().hex()
OPERATOR_RATE = {"allows": 4, "window": 600}


def pep_id(name: str = "I") -> str:
    return hashlib.sha256(_dist.instance_key(name).public_raw).hexdigest()[:32]


def answer(receipt: str, verdict: str = "allow", *, signer="O1", pep=None, now=N, not_before=None, lifetime=300,
           floor=None, stream=S, targets=("cfs",), signed=True) -> str:
    """A stage line of a sealed operator.answer (OP2) to the escalation whose receipt hash is `receipt`."""
    body = canon.canon2_bytes({"answer": verdict, canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-answer/1",
                               "pep": pep or pep_id(), "receipt": receipt})
    start = now - 10 if not_before is None else not_before
    doc = {"artifact": "operator.answer", "body_sha256": canon.sha256_hex(body), "body_size": len(body),
           "encoding": "canon/2", "expires": start + lifetime, "format": env.FORMAT, "meta": {}, "not_before": start,
           "policy_sha256": floor or policy(floors_of()["one"]), "release": env.ZERO_HASH, "replaces": "", "seq": 1,
           "stream": stream, "targets": list(targets), "widens": False}
    raw = canon.canon2_bytes(doc)                     # raw, so a lifetime the writer refuses can be sent
    key = _dist.GEN.test_key(signer)
    sealed = env.seal_entries(raw, [(_dist.key_id(signer), key.sign(env.signed_message(raw)))] if signed else [])
    return f"stage {sealed.hex()} {body.hex()} {now}"


def floors_of():
    return floors()


def escalating(*, threshold=2, keys=("J", "K"), seed=None, answer_rate=OPERATOR_RATE) -> list:
    """A cfs PEP whose install threshold is `threshold`, with operator O1, whose floor allows command 3 once in 60
    seconds past its release, which refuses it, so the asks after the first escalate with dist:floor-rate."""
    meta = floor_meta(rate={"allows": 1, "window": 60}, **({"answer_rate": answer_rate} if answer_rate else {}))
    floor = install("install.floor", floors()["one"], meta=meta, signers=keys[:max(threshold, 1)])
    return [*node(seed=seed), *base._anchor(keys=keys, threshold=threshold, operators=("O1",), bring=[floor]),
            f"provision {S} {N}", *release(refuses_three(), 1), f"ask {N} {regs(3)} -"]


def escalate(receipt: str, now=N, request="0301") -> list:
    return [f"ask {now} {regs(3)} -", f"escalated {receipt} {request}"]


def _cause(line: str):
    """The event, cause and subject of the last record of a step, read without its signature (any instance key)."""
    raw = bytes.fromhex(line.split()[-1])
    return base.EVENTS21[raw[5]], causes.name(raw[7]) if raw[7] else None, raw[148 + 21]


H = [hashlib.sha256(b"escalation %d" % k).hexdigest() for k in range(8)]


def test_case_220_an_answer_is_signed_by_an_operator_used_once_and_bound_to_one_escalation(hc):
    """case_220: OP2, OP3, AF8, the cfs half on the C core. A cfs PEP with an install threshold of 2 escalates a floor
    action with dist:floor-rate. An answer `allow` by the enrolled operator key is applied once, with `answered` and
    subject 5 and the request of its escalation handed back for a receipt with basis operator, and the same answer
    again, also after a restart, is dist:answer-unbound. Answers signed by an install key and by an authority key are
    dist:unknown-key, one whose lifetime is 601 seconds dist:bad-format, one past `expires` dist:expired, one whose
    `receipt` names no escalation and one for an escalation older than 600 seconds dist:answer-unbound, an unsigned
    message that claims to be an answer applies nothing, and an answer `refuse` is applied with its own answer."""
    good = answer(H[0])
    out = run(hc, [*escalating(), *escalate(H[0]), good, "answer", good, f"restart {N}", good,
                   *escalate(H[1]), answer(H[1], signer="J"), answer(H[1], signer="A"), answer(H[1], lifetime=601),
                   answer(H[1], not_before=N - 400), answer("ab" * 32), answer(H[1], now=N + 601),
                   f"ask {N + 601} {regs(3)} -", *escalate(H[2], N + 601), answer(H[2], now=N + 601, signed=False),
                   "answer", answer(H[2], "refuse", now=N + 601), "answer"])
    assert ask(out[5])["cause"] == "dist:floor-rate" and out[6] == "escalated 0"
    applied = _last(out[7])
    assert (applied["event"], applied["subject"], applied["cause"]) == ("answered", 5, None)
    sealed = good.split()[1]
    assert out[8] == f"answer 1 1 {base._envelope_id(sealed)} {H[0]} 0301"
    assert _refused(out[9]) == ("dist:answer-unbound", 5)
    assert _refused(out[11]) == ("dist:answer-unbound", 5)               # after a restart
    assert out[13] == "escalated 0"
    refusals = [_refused(line) for line in out[14:20]]
    # an install key alone is below the install threshold, so nothing counts and the envelope is not read (subject 0)
    assert refusals == [("dist:unknown-key", 0), ("dist:unknown-key", 5), ("dist:bad-format", 0),
                        ("dist:expired", 5), ("dist:answer-unbound", 5), ("dist:answer-unbound", 5)]
    assert ask(out[20])["outcome"] == ALLOW and out[22] == "escalated 0"     # a new window of the floor's rate
    assert _refused(out[23])[0] == "dist:bad-format" and out[24] == "answer 0"   # no signature block: nothing applied
    assert _last(out[25])["event"] == "answered" and out[26].startswith("answer 1 0 ")


def test_case_225_an_answer_reaches_only_cfs_on_the_c_core_and_never_moves_the_time_floor(hc, host_check):
    """case_225: V5, V13, OP1, OP2, the `mesh` and `cfs` halves. A `mesh` PEP with an install threshold of 2 and an
    operator key refuses a well signed operator.answer with dist:target-mismatch, and a cfs PEP with an open floor
    escalation applies a good answer whose `not_before` is above its time floor, which does not move."""
    mesh = run(host_check, [*base._node(), *base._anchor(operators=("O1",)), f"provision {S} {N}",
                            answer(H[0], targets=("mesh",))])
    assert _refused(mesh[1]) == ("dist:target-mismatch", 5)
    out = run(hc, [*escalating(), *escalate(H[0]), answer(H[0], not_before=N + 100), f"record 0 {N}"])
    assert _last(out[7])["event"] == "answered"
    assert _last(out[8])["time"] == N                                  # the time floor did not move to not_before


def test_case_231_an_answer_binds_to_one_pep_and_one_escalation(hc):
    """case_231: OP1, OP2, the cfs half on the C core. A cfs PEP whose install threshold is 1 refuses a well signed
    answer with dist:target-mismatch, and one with a threshold of 2 an answer whose `pep` is another PEP's id with
    dist:answer-unbound. Two cfs PEPs hold escalations under the same receipt hash, and an answer for the first is
    applied there and is dist:answer-unbound on the second."""
    lone = run(hc, [*escalating(threshold=1, keys=("J",)), answer(H[0])])
    assert _refused(lone[-1]) == ("dist:target-mismatch", 5)
    first = run(hc, [*escalating(), *escalate(H[0]), answer(H[0], pep=pep_id("I2")), answer(H[0])])
    assert _refused(first[7]) == ("dist:answer-unbound", 5)
    assert _last(first[8])["event"] == "answered"
    second = run(hc, [*escalating(seed=SEED2), *escalate(H[0]), answer(H[0]), answer(H[0], pep=pep_id("I2"))])
    assert _cause(second[7]) == ("refused", "dist:answer-unbound", 5)
    assert _cause(second[8]) == ("answered", None, 5)               # its own id: the same receipt hash, its own escalation


def test_case_232_operator_answers_are_counted_against_a_signed_rate(hc):
    """case_232: OP4, H1, AF8, the cfs half on the C core. A cfs PEP whose floor has an answer_rate of 2 in 600 seconds
    applies two good `allow` answers for three open escalations, each with a record with event `answered` and subject
    5, a restart after the second changing nothing, refuses the third with dist:floor-rate with its escalation still
    open, and applies a `refuse` for it. A cfs floor that can escalate past its rate and has no answer_rate is
    dist:bad-format."""
    out = run(hc, [*escalating(answer_rate={"allows": 2, "window": 600}), *escalate(H[0]), *escalate(H[1]),
                   *escalate(H[2]), answer(H[0]), f"restart {N}", answer(H[1]), answer(H[2]), answer(H[2], "refuse")])
    sent = [_last(out[k]) for k in (11, 13)]
    assert [(one["event"], one["subject"]) for one in sent] == [("answered", 5)] * 2
    assert _refused(out[14]) == ("dist:floor-rate", 5)
    assert _last(out[15])["event"] == "answered"                      # the escalation stayed open for the refuse
    no_rate = install("install.floor", floors()["one"], meta=floor_meta(rate={"allows": 1, "window": 60}))
    out = run(hc, [*node(), *base._anchor(operators=("O1",)), f"provision {S} {N}", _stage(no_rate)])
    assert _refused(out[1]) == ("dist:bad-format", 1)


@pytest.fixture(scope="module")
def host_check(tmp_path_factory):
    """host_check with the mesh bound, for the mesh halves."""
    if CC is None or not (DIST / "pp_dist.c").exists():
        pytest.skip("no C compiler or no prismpath-hw")
    out = tmp_path_factory.mktemp("dist_c_mesh") / "host_check"
    sources = [DIST / "host_check.c", DIST / "pp_dist.c", MONOCYPHER / "monocypher.c", MONOCYPHER / "monocypher-ed25519.c"]
    subprocess.run([CC, *base.FLAGS, f"-I{DIST}", f"-I{MONOCYPHER}", "-o", str(out), *map(str, sources)], check=True,
                   capture_output=True, text=True)
    return out


# ------------------------------------------------------------------ the cFS app's own harness (integrations/cfs)
APP = CFS / "prismpath_app"


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    """integrations/cfs/tests/dist_check.c: the app's enforcement point, kernel and run with the C core, no cFS."""
    if not (CFS / "tests" / "dist_check.c").exists() or not (DIST / "pp_dist.c").exists():
        pytest.skip("the cFS app and the C core are in integrations/cfs and prismpath-hw, which this tree does not carry")
    if CC is None:
        pytest.skip("no C compiler (cc) on this host, so the cFS app is not built here")
    work = tmp_path_factory.mktemp("dist_check")
    probe = subprocess.run([CC, "-x", "c", "-", "-lcrypto", "-o", str(work / "probe")],
                           input="#include <openssl/sha.h>\nint main(void){return 0;}", capture_output=True, text=True)
    if probe.returncode != 0:
        pytest.skip("no OpenSSL development files (the run's Merkle accumulator uses OpenSSL's SHA-256)")
    out = work / "dist_check"
    includes = [f"-I{ROOT / 'prismpath-hw'}", f"-I{DIST}", f"-I{ROOT / 'prismpath-ebpf'}", f"-I{MONOCYPHER}",
                f"-I{APP / 'fsw' / 'inc'}", f"-I{APP / 'fsw' / 'src'}", f"-I{APP / 'fsw' / 'tables'}"]
    subprocess.run([CC, *base.FLAGS, "-DPP_TABLE_MAX=4692", *includes, "-o", str(out), str(CFS / "tests" / "dist_check.c"),
                    str(DIST / "pp_dist.c"), str(MONOCYPHER / "monocypher.c"), str(MONOCYPHER / "monocypher-ed25519.c"),
                    "-lcrypto"], check=True, capture_output=True, text=True)
    return out


def _private(name: str):
    return _dist.GEN.test_key(name)


def _public(name: str) -> bytes:
    return _dist.GEN.public_raw(_dist.GEN.test_key(name))


def app_table(rules=None, version: int = 1) -> bytes:
    """A whole table struct as the ground signs it: the body, and its core image attested by the authority A."""
    table, gen_image = _modules()
    from prismpath.ledgers import core_evidence
    if rules is None:
        from prismpath.kernel import canon2
        rules = canon2.loads(gen_image.CORE.read_bytes().rstrip(b"\n"))["rules"]
    data = table.pack(gen_image.build(core(rules)))
    table.set_version(data, version)
    data[table.OFF["ImageSig"]:table.OFF["ImageSig"] + 64] = _private("A").sign(
        core_evidence.IMAGE_DOMAIN + table.core_of(data))
    return bytes(data)


def app_anchor(*, install=(), threshold=2, stale=0, operators=()) -> bytes:
    """The /2 trust anchor the ground writes for the app: A the authority, C the controller, and install keys whose
    domain is the app's layout document as it was built with `stale` (CL4)."""
    from integrations.cfs.ground import provision
    return provision.anchor_document([_public("A")], controller_public=_public("C"), stream=S, target="cfs",
                                     install_publics=[_public(name) for name in install], threshold=threshold,
                                     operator_publics=[_public(name) for name in operators],
                                     domain=provision.domain(stale))


def app_head(*, install=(), stale=0, bring=(), operators=(), threshold=2, seed=None) -> list:
    from integrations.cfs.ground import table
    lines = [f"authority {_public('A').hex()}", f"instance {seed or base.INSTANCE_SEED}",
             f"anchor {app_anchor(install=install, stale=stale, operators=operators, threshold=threshold).hex()}",
             f"stale {stale}"]

    return lines + [f"bring {table.statement_file(sealed, body).hex()}" for sealed, body in bring]


def offer(sealed: bytes, body: bytes, transfer: int, now: int) -> list:
    table, _gen = _modules()
    return [f"frame {frame.hex()} 0 {now}" for frame in table.frames(sealed, body, transfer)]


def release_lines(data: bytes, seq: int, transfer: int, *, now=N, widens=True, replaces="", froms=None,
                  not_before=NB, expires=E, sig=None, commit=True) -> list:
    """The frames of a release of the table `data` and of its widening statement, and its commit frame."""
    table, _gen = _modules()
    pairs = table.seal_table(data, [_private("A")], seq=seq, stream=S, not_before=not_before, expires=expires,
                             replaces=replaces, widens=widens, froms=froms)
    lines = []
    for k, (sealed, body_bytes) in enumerate(pairs):
        lines += offer(sealed, body_bytes, transfer + k, now)
    if commit:
        frame = table.commit_frame(transfer, S, seq, table.policy_of(data))
        lines.append(f"control {frame.hex()} {(sig or table.image_sig(data)).hex()} 0 {now}")
    return lines


def app_run(exe, tmp_path, lines: list) -> list:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "run").mkdir(exist_ok=True)
    (tmp_path / "dist").mkdir(exist_ok=True)
    done = subprocess.run([str(exe), str(tmp_path / "run"), str(tmp_path / "dist")],
                          input="\n".join([*lines, "done"]) + "\n", capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr[-4000:]
    return done.stdout.splitlines()


def steps(out: list) -> list:
    """[(records, step flags)] of every step, the lines of `out` that are neither."""
    pairs, k = [], 0
    while k < len(out):
        if out[k].startswith("records"):
            pairs.append((_recs(out[k]), [int(word) for word in out[k + 1].split()[1:]]))
            k += 2
        else:
            k += 1
    return pairs


def decisions(out: list) -> list:
    keys = ("kind", "cause", "rule", "basis", "held", "receipted", "receipt", "not_enacted", "record_error", "escalated")
    return [dict(zip(keys, map(int, line.split()[1:]))) for line in out if line.startswith("decision")]


def payload(cmd_class=3, ground=0, slew=0, thrust=0) -> str:
    from integrations.cfs.tests import run_scenario
    return run_scenario.reading_payload(dict(cmd_class=cmd_class, ground_contact=ground, slew_deg=slew,
                                             thrust_pct=thrust)).hex()


def test_d9_a_table_offered_on_the_bus_loads_through_the_table_service_and_an_older_seq_is_refused_after_a_reset(
        app, tmp_path):
    """D9, Q1 to Q3, section 9.5 on the cFS app. A first table offered on the command topic in frames, with its
    widening statement, is staged and committed through the table service, and decides, its receipts in the run. A
    table service that refuses the load leaves the core where it was, and the commit goes in at the next try; a commit
    whose image attestation does not verify is refused with sig:invalid and the release stays staged; a ground table
    load from a file has no envelope and is refused with dist:not-staged. After a processor reset the run, the floor
    and the release continue, and a table at an older seq is dist:seq-replay. The run, sealed and downlinked, verifies
    with both keys pinned."""
    table, _gen = _modules()
    from integrations.cfs.ground import downlink
    first, second, third = app_table(version=1), app_table(version=2), app_table([rule(2), rule(3)], version=3)
    bad_sig = bytes(64)
    lines = [*app_head(), f"start 0 0 1 {N}", *release_lines(first, 1, 10, sig=bad_sig), "state",
             *release_lines(first, 1, 10)[-1:], "state", "service",
             f"propose {payload(3)} 1 - {N}", f"propose {payload(2, thrust=150)} 1 - {N}",
             *release_lines(second, 2, 20, widens=False, replaces=table.policy_of(first), commit=False),
             "tblfail 1", *release_lines(second, 2, 20, widens=False, replaces=table.policy_of(first))[-1:], "state",
             *release_lines(second, 2, 20, widens=False, replaces=table.policy_of(first))[-1:], "state", "service",
             f"groundload {first.hex()}", f"propose {payload(1, slew=30)} 1 - {N}", "seal 1000",
             "reset", f"start 0 0 1 {N + 5}", "state", "service", f"propose {payload(3)} 1 - {N + 5}",
             *release_lines(third, 1, 30, now=N + 5, commit=False), "state", "seal 2000"]
    out = app_run(app, tmp_path / "a", lines)
    done = steps(out)
    assert [(one["event"], one["cause"]) for one in done[0][0]] == [("provisioned", None)]
    states = [line for line in out if line.startswith("state")]
    services = [line for line in out if line.startswith("service")]
    refused = [one for records, _flags in done for one in records if one["event"] == "refused"]
    assert refused[0]["cause"] == "sig:invalid" and states[0] == "state 0 0 0 0 0 0"
    assert states[1] == "state 1 1 1 0 0 1" and services[0] == "service 1"
    busy = [flags for _records, flags in done if flags[6]]
    assert len(busy) == 1 and states[2] == "state 1 1 1 0 0 1"            # the table service kept v1, and so did the core
    assert states[3] == "state 1 2 2 0 0 1" and services[1] == "service 2"
    assert f"validation {causes.code('dist:not-staged')}" in out
    assert states[4] == "state 1 2 2 0 0 1" and services[2] == "service 2"   # after the reset, and shown again
    assert refused[-1]["cause"] == "dist:seq-replay" and states[5] == "state 1 2 2 0 0 1"
    made = decisions(out)
    assert [(one["kind"], one["receipted"], one["receipt"]) for one in made] == [(0, 1, 0), (1, 1, 1), (0, 1, 2),
                                                                                (0, 1, 3)]
    assert [line for line in out if line.startswith("sealed")] == ["sealed 0", "sealed 0"]
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "authority.pub").write_bytes(_public("A"))
    (keys / "instance.pub").write_bytes(_public("I"))
    summary = downlink.verify(downlink.fetch(tmp_path / "a" / "run", tmp_path / "ground"), keys)
    assert summary["receipts"] == 4 and summary["disagree"] == 0 and summary["cases"] == 2
    assert [one["leaves"] for one in summary["roots"]] == [3, 4]


def test_case_025_the_cfs_app_with_its_store_lost_locks_by_default_and_admits_from_the_minimum_when_set(app, tmp_path):
    """case_025: Q5. With the Critical Data Store record lost at a processor reset, the app under LOCK is locked: it
    admits no table, with dist:floor-lost, and refuses every proposal unreceipted. Under MINIMUM it provisions itself
    again from its anchor with the floor one below the minimum, so a release below it is dist:seq-replay and one at it
    is committed and decides."""
    first = app_table(version=1)
    prefix = [*app_head(), f"start 0 0 5 {N}", *release_lines(first, 6, 10), "reset", "lose record"]
    out = app_run(app, tmp_path / "lock", [*prefix, f"start 0 0 5 {N + 1}", "state",
                                           *release_lines(app_table(version=2), 9, 20, now=N + 1),
                                           f"propose {payload(3)} 1 - {N + 1}"])
    done = steps(out)
    locked = [k for k, (_records, flags) in enumerate(done) if flags[3]]
    assert len(locked) == 1 and [line for line in out if line.startswith("state")][-1] == "state 0 0 0 1 0 0"
    assert {one["cause"] for records, _flags in done[locked[0] + 1:] for one in records} == {"dist:floor-lost"}
    assert decisions(out)[-1]["receipted"] == 0 and decisions(out)[-1]["basis"] == 0
    out = app_run(app, tmp_path / "minimum", [*prefix, f"start 0 1 5 {N + 1}", "state",
                                              *release_lines(app_table(version=2), 4, 20, now=N + 1),
                                              *release_lines(app_table(version=3), 5, 30, now=N + 1), "state",
                                              f"propose {payload(3)} 1 - {N + 1}"])
    done = steps(out)
    started = [pair for pair in done if pair[1][4]]
    assert len(started) == 1 and [one["event"] for one in started[0][0]] == ["provisioned"]
    states = [line for line in out if line.startswith("state")]
    assert states[-2] == "state 0 0 4 0 0 0" and states[-1] == "state 1 5 5 0 0 1"
    refused = [one["cause"] for records, _flags in done for one in records if one["event"] == "refused"]
    # the release at 4 and its widening statement, then its commit, which names nothing staged
    assert refused == ["dist:seq-replay", "dist:seq-replay", "dist:not-staged"]
    assert decisions(out)[-1]["receipted"] == 1 and decisions(out)[-1]["kind"] == 0


def _python_app(tmp_path, script, *, hold):
    """The Python machine on a modelled cFS app, through the steps the app's harness runs, each step's records."""
    from integrations.cfs.tests.test_cfs_dist import CfsPep
    from prismpath.distribution.pep import PepRefused
    out, point = [], None
    for op, *args in script:
        if op == "start":
            point = CfsPep(tmp_path, clock=_dist.Clock(args[0]), expiry_response="hold" if hold else "refuse")
        elif op == "reset":
            point.clock.now = args[0]
            try:
                point.pep = point.open(provision=False)
            except PepRefused:
                out.append(None)
                continue
        else:
            point.clock.now = args[-1]
            if op == "stage":
                for sealed, body_bytes in args[0]:
                    point.pep.stage(sealed, body_bytes)
            elif op == "commit":
                point.pep.commit(S, args[0], args[1])
            elif op == "tick":
                point.pep.tick()
            elif op == "rollback":
                try:
                    point.pep.rollback()
                except PepRefused:
                    pass
        out.append([record.hex() for record in point.pep.drain()])
    return out


def _app_script(script) -> list:
    """The harness lines of `script`, each step's lines in a group."""
    table, _gen = _modules()
    groups, transfer = [], 100
    for op, *args in script:
        if op == "start":
            groups.append([f"start {{hold}} 0 1 {args[0]}"])
        elif op == "reset":
            groups.append(["reset", f"start {{hold}} 0 1 {args[0]}"])
        elif op == "stage":
            group = []
            for sealed, body_bytes in args[0]:
                group += offer(sealed, body_bytes, transfer, args[-1])
                transfer += 1
            groups.append(group)
        elif op == "commit":
            frame = table.commit_frame(1, S, args[0], args[1])
            groups.append([f"control {frame.hex()} {args[2].hex()} 0 {args[-1]}"])
        elif op == "tick":
            groups.append([f"tick 0 {args[0]}"])
        elif op == "rollback":
            groups.append([f"rollback {args[0]}"])
    return groups


@pytest.mark.parametrize("hold", [False, True])
def test_case_106_107_108_109_110_the_cfs_app_answers_expiry_as_the_python_machine_under_each_setting(app, tmp_path,
                                                                                                         hold):
    """case_106: X6, X1. case_107: X6, X7. case_108: X8, R5. case_109: X8. case_110: X9. The app's own harness under
    the setting left alone and under HOLD: its release lapses at expiry, or is held with bit 5 in every record, the
    hold mark on every receipt in a case of its own and an event when it begins and ends; a held app refuses a table
    below the floor, an expired one and a larger one without a statement, refuses a rollback with dist:held, takes a
    release that passes every rule with bit 5 clear, lapses with dist:revoked at a revocation, and locks with
    dist:floor-lost when its store is lost. Every signed record is the Python machine's, byte for byte."""
    table, _gen = _modules()
    from integrations.cfs.ground import downlink, reference
    first, second, third = app_table(version=1), app_table(version=2), app_table([rule(2), rule(3)], version=3)
    p1, p3 = table.policy_of(first), table.policy_of(third)
    seal = lambda data, seq, **args: table.seal_table(data, [_private("A")], seq=seq, stream=S, **args)  # noqa: E731
    script = [("start", N), ("stage", seal(first, 1, not_before=NB, expires=E - 100), N), ("commit", 1, p1, table.image_sig(first), N),
              ("stage", seal(second, 2, not_before=NB, expires=E, widens=False, replaces=p1), N),
              ("commit", 2, p1, table.image_sig(second), N),
              ("tick", E), ("rollback", E),
              ("stage", seal(first, 1, not_before=NB, expires=E + 900), E),                  # below the floor
              ("stage", seal(third, 3, not_before=NB, expires=E - 1, widens=False, replaces=p1), E),   # expired
              ("stage", [seal(third, 4, not_before=E, expires=E + 900, widens=True)[1]], E),  # larger, no statement
              ("reset", E + 1),
              ("stage", seal(third, 5, not_before=E, expires=E + 900, froms=[]), E + 1),
              ("commit", 5, p3, table.image_sig(third), E + 1),
              ("tick", E + 900)]
    python = _python_app(tmp_path / "python", script, hold=hold)
    groups = [[line.format(hold=int(hold)) for line in group] for group in _app_script(script)]
    proposals = {2: N, 5: E, 12: E + 1}                                  # a proposal after these steps
    lines = list(app_head())
    for k, group in enumerate(groups):
        lines += group
        if k in proposals:
            lines.append(f"propose {payload(3)} 1 - {proposals[k]}")
    out = app_run(app, tmp_path / "app", [*lines, "seal 1000"])
    lost_out = app_run(app, tmp_path / "lost", [*lines, "reset", "lose record", f"start {int(hold)} 0 1 {E + 2}",
                                                f"propose {payload(3)} 1 - {E + 2}"])
    record_lines = [line for line in out if line.startswith("records")]
    flag_lines = [line.split()[1:] for line in out if line.startswith("step")]
    c_groups, cursor = [], 0
    for k, group in enumerate(groups):
        c_groups.append([item for line in record_lines[cursor:cursor + len(group)] for item in line.split()[1:]])
        cursor += len(group) + (k in proposals)
    assert c_groups == python                                            # every signed record, byte for byte
    events = [(one["event"], one["cause"], one["held"]) for line in record_lines for one in _recs(line)]
    made = decisions(out)
    if hold:
        held_at = events.index(("held", "dist:held", True))
        assert ("refused", "dist:held", True) in events[held_at:]       # X9: the rollback
        assert {cause for event, cause, mark in events[held_at:events.index(("committed", None, False), held_at)]
                if event == "refused"} == {"dist:held", "dist:seq-replay", "dist:expired", "dist:widening-unsigned"}
        assert all(mark for _event, _cause, mark in events[held_at:events.index(("committed", None, False), held_at)])
        # X7: an event when the hold begins and when it ends, and again when the last release expires
        assert [flags[0] for flags in flag_lines].count("1") == 2 and [flags[1] for flags in flag_lines].count("1") == 1
        assert [(one["receipted"], one["held"]) for one in made[:3]] == [(1, 0), (1, 1), (1, 0)]
        assert reference.held_receipts(tmp_path / "app" / "run") == [1]
    else:
        assert ("lapsed", "dist:expired", False) in events
        assert [(one["receipted"], one["held"]) for one in made[:3]] == [(1, 0), (0, 0), (1, 0)]
    lost_flags = [line.split()[1:] for line in lost_out if line.startswith("step")]
    assert decisions(lost_out)[-1]["receipted"] == 0 and lost_flags[-2][3] == "1"   # the store lost: locked (Q5)
    assert decisions(lost_out)[-1]["cause"] == causes.code("dist:floor-lost")
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "authority.pub").write_bytes(_public("A"))
    (keys / "instance.pub").write_bytes(_public("I"))
    summary = downlink.verify(downlink.fetch(tmp_path / "app" / "run", tmp_path / "ground"), keys)
    assert summary["disagree"] == 0 and summary["receipts"] == (3 if hold else 2)


def test_case_226_a_cfs_app_that_loses_the_file_of_its_install_record_uses_the_copy_in_the_critical_data_store(
        app, tmp_path):
    """case_226: IS10, the cfs half in the app. Provisioned with two install keys, an action floor and a fallback
    policy, the app keeps the first copy of its install record and of each set in files and the second in a Critical
    Data Store area apart from them. After a processor reset with the file of the record and the file of the floor
    gone, it reads the second copies, holds both sets, reports no loss, and asks its floor first; with the copy area
    lost as well it holds no set and reports dist:install-lost."""
    floor = install("install.floor", floors()["one"])
    fallback = install("install.fallback", floors()["fallback"])
    brought = [(bytes.fromhex(sealed), bytes.fromhex(body_hex)) for sealed, body_hex in (floor, fallback)]
    ids = f"held {base._envelope_id(floor[0])} {base._envelope_id(fallback[0])} -"
    head = app_head(install=("J", "K"), bring=brought, stale=5)          # the layout the floor names: a monitor, 5 s
    out = app_run(app, tmp_path / "copy", [*head, f"start 0 0 1 {N}", "held", "reset", "unlink install.ppd",
                                           "unlink floor.ppd", f"start 0 0 1 {N + 1}", "held",
                                           f"propose {payload(3, slew=15, thrust=20)} 1 - {N + 1}",
                                           "reset", "unlink install.ppd", "lose copy", f"start 0 0 1 {N + 2}", "held"])
    helds = [line for line in out if line.startswith("held")]
    assert helds[0] == helds[1] == ids and helds[2] == "held - - -"
    done = steps(out)
    assert [one["event"] for one in done[0][0]] == ["provisioned"] and done[0][1][2] == 1
    first = decisions(out)[0]                                            # the floor answered first, and is enacted
    assert (first["basis"], first["not_enacted"], first["receipted"]) == (2, 0, 1)
    restarts = [records for records, _flags in done[1:]]
    assert ("refused", "dist:install-lost") in [(one["event"], one["cause"]) for records in restarts[-1:]
                                                 for one in records]
    assert all(one["cause"] != "dist:install-lost" for records in restarts[:-1] for one in records)


# ------------------------------------------------------------------ RC4: the cFS app's core run per basis
def _three_ways() -> list:
    """A release that answers command class 3 three ways by its slew (allow, refuse, escalate) and allows 1 and 2."""
    three = ["in", "cmd_class", [["num", 3]]]
    return [{"target": "allow", "when": ["and", three, cmp("slew_deg", "<=", 12)]},
            {"target": "refuse_104", "when": ["and", three, cmp("slew_deg", "<=", 15)]},
            {"target": "escalate_34", "when": three},
            {"target": "allow", "when": ["in", "cmd_class", [["num", 1], ["num", 2]]]}]


def _ground_keys(tmp_path, anchor: bytes = None) -> Path:
    """The ground's keys: the authority's and the instance's, and the install key set the run began under."""
    import json
    from integrations.cfs.ground import downlink
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "authority.pub").write_bytes(_public("A"))
    (keys / "instance.pub").write_bytes(_public("I"))
    if anchor is not None:
        (keys / "install.json").write_text(json.dumps(downlink.install_pin(anchor)))
    return keys


def test_case_193_the_cfs_app_enacts_its_floor_and_fallback_and_writes_a_run_that_verifies_per_basis(app, tmp_path):
    """case_193: AF7, RC1, the cfs lines in the app, with RC4 and AF8 end to end. Provisioned with install keys J, K
    and L at a threshold of 2, a floor that allows command 3 within bounds at a rate of 2 in 60 seconds and a fallback
    policy, the app decides under the fallback policy before any release, then under a release that answers the
    floor's command three ways. Each floor allow is enacted and receipted in the floor's case, with the release's
    answer, allow, refuse and escalate, in a case of the release marked not enacted, so the override count rises by
    two, and the two overrides counted write their rates.jsonl lines. Past the rate the floor's dist:floor-rate
    escalation is refused unreceipted. An install.trust that adds M and drops L applies, and a second floor signed by
    J and M decides. The sealed run, downlinked, verifies with the authority, instance and starting install keys
    pinned, its install.jsonl the statements in the order applied."""
    from integrations.cfs.ground import downlink, reference
    from prismpath.kernel import canon2
    from prismpath.ledgers import core_evidence
    floor_one = install("install.floor", floors()["one"], meta=floor_meta(rate={"allows": 2, "window": 60},
                                                                           answer_rate=ANSWER_RATE))
    fallback = install("install.fallback", floors()["fallback"])
    trust = base._install("install.trust", base._trust_body(("J", "K", "M"), 2), seq=1, signers=("J", "K", "M"),
                          targets=("cfs",))
    floor_two = install("install.floor", floors()["two"], seq=2, signers=("J", "M"))
    pairs = [(bytes.fromhex(sealed), bytes.fromhex(body_hex)) for sealed, body_hex in (floor_one, fallback, trust,
                                                                                        floor_two)]
    near = lambda cmd, slew=15: f"propose {payload(cmd, slew=slew, thrust=20)} 1 - {N}"     # noqa: E731
    lines = [*app_head(install=("J", "K", "L"), bring=pairs[:2], stale=5), f"start 0 0 1 {N}",
             near(5), near(1), *release_lines(app_table(_three_ways()), 1, 10),
             near(3, 11), near(3, 14), near(3, 18), f"beat {N}", "state", near(3, 14), near(1),
             *offer(*pairs[2], 20, N), *offer(*pairs[3], 21, N), "held", near(4), f"seal {TIME_US}"]
    out = app_run(app, tmp_path / "a", lines)
    made = decisions(out)
    # the fallback policy's allow and no-match refusal, the floor's three allows, the rate escalation, the release's
    # allow and the second floor's allow
    assert [(one["basis"], one["kind"], one["receipted"], one["not_enacted"]) for one in made] == [
        (3, 0, 1, 0), (3, 1, 1, 0), (2, 0, 1, 0), (2, 0, 1, 0), (2, 0, 1, 0), (2, 1, 0, 1), (1, 0, 1, 0),
        (2, 0, 1, 0)]
    assert made[5]["escalated"] == 1 and made[5]["cause"] == causes.code("dist:floor-rate")
    beat = out[out.index("state 1 1 1 0 0 1") - 2]
    overrides = downlink.read_state_record(bytes.fromhex(beat.split()[-1]), _public("I"))
    assert (overrides["answers"], overrides["overrides"]) == (3, 2)
    assert [line for line in out if line.startswith("held")] == [
        f"held {base._envelope_id(floor_two[0])} {base._envelope_id(fallback[0])} -"]
    assert "sealed 0" in out
    run = tmp_path / "a" / "run"
    assert reference.bases(run) == [
        ("fallback.v1.1", "fallback", True, 2), ("floor.v1.2", "floor", True, 1), ("would.v1.3", "release", False, 1),
        ("floor.v1.4", "floor", True, 1), ("would.v1.5", "release", False, 1), ("floor.v1.6", "floor", True, 1),
        ("would.v1.7", "release", False, 1), ("v1", "release", True, 1), ("floor.v1.9", "floor", True, 1),
        ("would.v1.10", "release", False, 1)]
    receipts = [canon2.loads(line) for line in core_evidence._lines(run / "receipts.jsonl")]
    would = [one for one in receipts if one["case"].startswith("would.")]
    assert [one.get("target", one.get("cause")) for one in would] == [
        "allow", "refuse_104", "escalate_34", "route:no-matching-edge"]
    leaf = {(one["case"], one["reading"]): core_evidence.sha256_hex(canon2.dumps(one)) for one in receipts}
    window = N // 60 * 60
    assert (run / "rates.jsonl").read_bytes() == reference.rate_line(0, window, 1, leaf[("floor.v1.4", 0)]) + \
        reference.rate_line(0, window, 2, leaf[("floor.v1.6", 0)])
    assert (run / "install.jsonl").read_bytes() == reference.install_lines(pairs)
    manifest = canon2.loads((run / "run.json").read_bytes().rstrip(b"\n"))
    assert manifest["install_trust_seq"] == 1
    images = [canon2.loads(line) for line in core_evidence._lines(run / "images.jsonl")]
    assert images[1] == {"case": "floor.v1.2", "format": core_evidence.IMAGE_FORMAT,
                         "image_sha256": policy(floors()["one"]), "install": base._envelope_id(floor_one[0])}
    keys = _ground_keys(tmp_path, app_anchor(install=("J", "K", "L"), stale=5))
    summary = downlink.verify(downlink.fetch(run, tmp_path / "ground"), keys)
    assert summary["receipts"] == 11 and summary["disagree"] == 0 and summary["cases"] == 10
    (keys / "install.json").unlink()
    with pytest.raises(downlink.Bad) as bad:
        downlink.verify(downlink.fetch(run, tmp_path / "unpinned"), keys)
    assert "install key set pinned" in str(bad.value)


def test_case_193_a_floor_allow_with_no_release_has_no_would_line(app, tmp_path):
    """case_193: AF7, RC1, the cfs lines with no release and no fallback policy. The floor's allow is enacted and
    receipted in its case, and `would` is none, so no line of the release is written for it: the floor's case is
    marked `asked` false, and the run verifies with the install keys pinned."""
    from integrations.cfs.ground import downlink, reference
    floor_one = install("install.floor", floors()["one"])
    pairs = [(bytes.fromhex(floor_one[0]), bytes.fromhex(floor_one[1]))]
    out = app_run(app, tmp_path / "a", [*app_head(install=("J", "K"), bring=pairs, stale=5), f"start 0 0 1 {N}",
                                        f"propose {payload(3, slew=15, thrust=20)} 1 - {N}", f"seal {TIME_US}"])
    assert [(one["basis"], one["kind"], one["receipted"]) for one in decisions(out)] == [(2, 0, 1)]
    run = tmp_path / "a" / "run"
    assert reference.bases(run) == [("floor.v1.1", "floor", True, 1)] and reference.unasked(run) == ["floor.v1.1"]
    keys = _ground_keys(tmp_path, app_anchor(install=("J", "K"), stale=5))
    summary = downlink.verify(downlink.fetch(run, tmp_path / "ground"), keys)
    assert (summary["receipts"], summary["disagree"], summary["escalations"]) == (1, 0, 0)


def test_case_193_a_floor_allow_under_the_fallback_policy_has_its_would_line(app, tmp_path):
    """case_193: AF7, FB1, RC4, the cfs lines under the fallback policy. With no release and a fallback policy that
    allows only command 5, the floor's allow of command 3 is enacted in the floor's case, and the fallback policy's
    own answer for the same reading, its no-match refusal, is a line in a case of the fallback policy marked not
    enacted, named by the fallback policy's statement. The run verifies with the install keys pinned."""
    from integrations.cfs.ground import downlink, reference
    from prismpath.kernel import canon2
    from prismpath.ledgers import core_evidence
    floor_one = install("install.floor", floors()["one"])
    fallback = install("install.fallback", floors()["fallback"])
    pairs = [(bytes.fromhex(sealed), bytes.fromhex(body_hex)) for sealed, body_hex in (floor_one, fallback)]
    out = app_run(app, tmp_path / "a", [*app_head(install=("J", "K"), bring=pairs, stale=5), f"start 0 0 1 {N}",
                                        f"propose {payload(3, slew=15, thrust=20)} 1 - {N}",
                                        f"propose {payload(5)} 1 - {N}", f"seal {TIME_US}"])
    assert [(one["basis"], one["kind"], one["receipted"]) for one in decisions(out)] == [(2, 0, 1), (3, 0, 1)]
    run = tmp_path / "a" / "run"
    assert reference.bases(run) == [("floor.v1.1", "floor", True, 1), ("would.fallback.v1.2", "fallback", False, 1),
                                    ("fallback.v1.3", "fallback", True, 1)]
    cases = [canon2.loads(line) for line in core_evidence._lines(run / "cases.jsonl")]
    assert cases[1]["install"] == cases[2]["install"] == base._envelope_id(fallback[0]) and not reference.unasked(run)
    receipts = [canon2.loads(line) for line in core_evidence._lines(run / "receipts.jsonl")]
    assert [one.get("target", one.get("cause")) for one in receipts] == ["allow", "route:no-matching-edge", "allow"]
    keys = _ground_keys(tmp_path, app_anchor(install=("J", "K"), stale=5))
    summary = downlink.verify(downlink.fetch(run, tmp_path / "ground"), keys)
    assert (summary["receipts"], summary["cases"], summary["disagree"]) == (3, 3, 0)


def test_a_cfs_app_run_with_no_install_statements_verifies_exactly_as_before(app, tmp_path):
    """RC4: an app that holds no install statement writes install.jsonl and rates.jsonl empty, names neither in
    run.json, and its run verifies with no install key pinned, as a run of the app before RC4 did."""
    from integrations.cfs.ground import downlink
    from prismpath.kernel import canon2
    from prismpath.ledgers import core_evidence
    out = app_run(app, tmp_path / "a", [*app_head(), f"start 0 0 1 {N}", *release_lines(app_table(), 1, 10),
                                        f"propose {payload(3)} 1 - {N}", f"propose {payload(1, slew=30)} 1 - {N}",
                                        f"seal {TIME_US}"])
    assert "sealed 0" in out
    run = tmp_path / "a" / "run"
    assert (run / "install.jsonl").read_bytes() == b"" and (run / "rates.jsonl").read_bytes() == b""
    manifest = canon2.loads((run / "run.json").read_bytes().rstrip(b"\n"))
    assert set(manifest) == {"authority_key_id", "cases", "cases_sha256", "decider", "excluded", "format",
                             "images_sha256", "instance_key_id", "receipts"}
    assert all("basis" not in canon2.loads(line) for line in core_evidence._lines(run / "cases.jsonl"))
    keys = _ground_keys(tmp_path)
    summary = downlink.verify(downlink.fetch(run, tmp_path / "ground"), keys)
    assert summary["receipts"] == 2 and summary["disagree"] == 0 and summary["cases"] == 1
    direct = core_evidence.verify(tmp_path / "ground", sample=None, pin_authority=keys / "authority.pub",
                                  pin_instance=keys / "instance.pub")
    assert {key: direct[key] for key in ("receipts", "cases", "root")} == {
        key: summary[key] for key in ("receipts", "cases", "root")}


# ------------------------------------------------------------------ OP1 to OP4 in the cFS app
def _app_escalating(*, seed=None, threshold=2, keys=("J", "K")) -> list:
    """A cFS app with install keys J and K, operator O1, a floor that allows command 3 once in 60 seconds past its
    release, which refuses it, so the second proposal of command 3 escalates with dist:floor-rate."""
    meta = floor_meta(rate={"allows": 1, "window": 60}, answer_rate={"allows": 2, "window": 600})
    floor = install("install.floor", floors()["one"], meta=meta, signers=keys[:threshold])
    brought = [(bytes.fromhex(floor[0]), bytes.fromhex(floor[1]))]
    rules = [{"target": "refuse_104", "when": ["in", "cmd_class", [["num", 3]]]},
             {"target": "allow", "when": ["in", "cmd_class", [["num", 1], ["num", 2]]]}]
    return [*app_head(install=keys, threshold=threshold, operators=("O1",), bring=brought, stale=5, seed=seed),
            f"start 0 0 1 {N}", *release_lines(app_table(rules), 1, 10),
            f"propose {payload(3, slew=15, thrust=20)} 1 - {N}", f"propose {payload(3, slew=15, thrust=20)} 1 - {N}"]


def _app_answer(receipt: str, verdict="allow", *, pep=None, transfer=40, now=N, floor=None) -> list:
    from integrations.cfs.ground import answer
    sealed, body = answer.seal_answer(_private("O1"), pep=pep or pep_id(), receipt=receipt,
                                      policy=floor or policy(floors()["one"]), answer=verdict, now=now - 10, stream=S)
    return offer(sealed, body, transfer, now)


def _escalation_doc(n: int, time: int) -> bytes:
    """The escalation document the app hashes (PP_Run_EscalationBytes), from the ground's reference reading."""
    from integrations.cfs.ground import reference
    from integrations.cfs.tests import run_scenario
    raw = run_scenario.reading_payload(dict(cmd_class=3, ground_contact=0, slew_deg=15, thrust_pct=20))
    reading = hashlib.sha256(reference.reading_bytes(raw)).hexdigest()
    return canon.canon2_bytes({"case": "v1", "cause_code": 166, "decider": "cfs:prismpath_app",
                               "format": "prismpath.cfs-escalation/1", "n": n,
                               "policy_sha256": policy(floors()["one"]), "reading_sha256": reading, "time": time})


def _answered(out: list) -> list:
    return [line.split()[1:] for line in out if line.startswith("answered")]


def test_case_220_a_cfs_app_opens_a_floor_escalation_and_enacts_an_operator_answer_once(app, tmp_path):
    """case_220: OP2, OP3, AF8, RC4, in the cFS app, end to end. The app's floor escalates a proposal past its rate
    with dist:floor-rate, which no line of a core run carries, so it is refused unreceipted, and opens the escalation
    under the SHA-256 of its escalation document, a line of escalations.jsonl it downlinks. The ground's answer
    `allow`, sealed by the operator key for that receipt hash and the app's PEP id and offered in frames on the command
    topic, is applied with an `answered` record of subject 5, appended to install.jsonl, and enacted: the request
    passes once and leaves a receipt with basis `operator`, the answer's envelope id and the floor's statement, a route
    to allow, before the app carries it out. The same answer again, also after a processor reset, is
    dist:answer-unbound. An answer `refuse` leaves the request refused with its own operator receipt, the escalation's
    dist:floor-rate. Each sealed run, downlinked, verifies under core_evidence with the install keys pinned."""
    from integrations.cfs.ground import downlink, reference
    from prismpath.kernel import canon2
    from prismpath.ledgers import core_evidence
    out = app_run(app, tmp_path / "a", [*_app_escalating()])
    made = decisions(out)
    # the first is the floor's allow within its rate, enacted and receipted; the second is past the rate
    assert [(one["basis"], one["not_enacted"], one["escalated"], one["receipted"]) for one in made] == [
        (2, 0, 0, 1), (2, 1, 1, 0)]
    receipt = [line.split()[1] for line in out if line.startswith("escalation")][0]
    assert receipt == hashlib.sha256(_escalation_doc(2, N)).hexdigest()
    out = app_run(app, tmp_path / "b", [*_app_escalating(), *_app_answer(receipt), *_app_answer(receipt, transfer=41),
                                        "reset", f"start 0 0 1 {N + 1}", *_app_answer(receipt, transfer=42, now=N + 1),
                                        f"seal {TIME_US}"])
    done = steps(out)
    events = [(one["event"], one["cause"], one.get("subject")) for records, _flags in done for one in records]
    assert events.count(("answered", None, 5)) == 1
    assert events.count(("refused", "dist:answer-unbound", 5)) == 2
    answered = _answered(out)
    request = bytes.fromhex(payload(3, slew=15, thrust=20))
    assert len(answered) == 1 and answered[0][1] == receipt and answered[0][2:6] == ["1", "0", "2", request.hex()]
    assert [flags[8:10] for _records, flags in done if flags[8]] == [[1, 1]]
    run = tmp_path / "b" / "run"
    floor_id = core_evidence.canon2.loads(core_evidence._lines(run / "install.jsonl")[0])
    floor_id = env.envelope_id(env.unseal(bytes.fromhex(floor_id["sealed"]))[0])
    assert reference.bases(run) == [("floor.v1.1", "floor", True, 1), ("would.v1.2", "release", False, 1),
                                    ("operator.v1.3", "operator", True, 1)]
    assert reference.operator_cases(run) == [("operator.v1.3", answered[0][0], floor_id, reference.reading_bytes(request))]
    assert (run / "escalations.jsonl").read_bytes() == reference.escalation_lines([_escalation_doc(2, N)])
    statements = [canon2.loads(line) for line in core_evidence._lines(run / "install.jsonl")]
    assert len(statements) == 2 and env.envelope_id(env.unseal(bytes.fromhex(statements[1]["sealed"]))[0]) == answered[0][0]
    receipts = [canon2.loads(line) for line in core_evidence._lines(run / "receipts.jsonl")]
    assert (receipts[-1]["case"], receipts[-1]["decision"], receipts[-1]["target"]) == ("operator.v1.3", "route", "allow")
    images = [canon2.loads(line) for line in core_evidence._lines(run / "images.jsonl")]
    assert images[-1] == {"answer": answered[0][0], "case": "operator.v1.3", "format": core_evidence.IMAGE_FORMAT,
                          "image_sha256": policy(floors()["one"]), "install": floor_id}
    manifest = canon2.loads((run / "run.json").read_bytes().rstrip(b"\n"))
    assert manifest["escalations_sha256"] == core_evidence.sha256_hex((run / "escalations.jsonl").read_bytes())
    keys = _ground_keys(tmp_path, app_anchor(install=("J", "K"), operators=("O1",), stale=5))
    ground = downlink.fetch(run, tmp_path / "ground")
    summary = downlink.verify(ground, keys)
    assert (summary["receipts"], summary["cases"], summary["disagree"], summary["replayed"], summary["escalations"]) == (
        3, 3, 0, 2, 1)
    assert list(downlink.escalations(ground)) == [receipt]
    direct = core_evidence.verify(ground, sample=None, pin_authority=keys / "authority.pub",
                                  pin_instance=keys / "instance.pub", pin_install=keys / "install.json")
    assert direct["root"] == summary["root"]
    # an answer refuse: the request stays refused, with its own operator receipt, the escalation's cause
    out = app_run(app, tmp_path / "c", [*_app_escalating(), *_app_answer(receipt, "refuse"), f"seal {TIME_US}"])
    assert _answered(out)[0][2:6] == ["1", "0", "2", request.hex()]
    run = tmp_path / "c" / "run"
    last = canon2.loads(core_evidence._lines(run / "receipts.jsonl")[-1])
    assert (last["case"], last["decision"], last["cause"], last["cause_code"]) == (
        "operator.v1.3", "refuse", "dist:floor-rate", causes.code("dist:floor-rate"))
    summary = downlink.verify(downlink.fetch(run, tmp_path / "ground-refuse"), keys)
    assert (summary["receipts"], summary["disagree"]) == (3, 0)


def test_case_220_a_cfs_app_receipts_a_floor_rule_escalation_and_each_answer_to_it(app, tmp_path):
    """case_220: OP3, RC4, in the cFS app. A floor whose rule escalates command 3 (escalate_34) under a release that
    refuses it escalates two proposals, each receipted in the floor's case as a route to escalate_34 with the
    release's refusal as its not enacted line, and each opened under its escalation document. An answer `refuse` to
    the first is receipted as the escalation's own refusal, route:needs-human, and an answer `allow` to the second as
    a route to allow that the app carries out. The run verifies with the install keys pinned."""
    from integrations.cfs.ground import downlink, reference
    from prismpath.kernel import canon2
    from prismpath.ledgers import core_evidence
    floor = install("install.floor", floors()["escalate"], meta=floor_meta(answer_rate=ANSWER_RATE))
    brought = [(bytes.fromhex(floor[0]), bytes.fromhex(floor[1]))]
    rules = [{"target": "refuse_104", "when": ["in", "cmd_class", [["num", 3]]]},
             {"target": "allow", "when": ["in", "cmd_class", [["num", 1], ["num", 2]]]}]
    propose = f"propose {payload(3, slew=15, thrust=20)} 1 - {N}"
    lines = [*app_head(install=("J", "K"), operators=("O1",), bring=brought, stale=5), f"start 0 0 1 {N}",
             *release_lines(app_table(rules), 1, 10), propose, propose]
    out = app_run(app, tmp_path / "a", lines)
    made = decisions(out)
    assert [(one["basis"], one["kind"], one["receipted"], one["escalated"], one["not_enacted"]) for one in made] == [
        (2, 2, 1, 1, 0)] * 2
    escalated = [line.split()[1] for line in out if line.startswith("escalation")]
    pol = policy(floors()["escalate"])
    out = app_run(app, tmp_path / "b", [*lines, *_app_answer(escalated[0], "refuse", floor=pol),
                                        *_app_answer(escalated[1], transfer=41, floor=pol), f"seal {TIME_US}"])
    assert [one[2:4] for one in _answered(out)] == [["1", "0"], ["1", "0"]]
    run = tmp_path / "b" / "run"
    assert [one[:2] for one in reference.bases(run)] == [
        ("floor.v1.1", "floor"), ("would.v1.2", "release"), ("floor.v1.3", "floor"), ("would.v1.4", "release"),
        ("operator.v1.5", "operator"), ("operator.v1.6", "operator")]
    receipts = [canon2.loads(line) for line in core_evidence._lines(run / "receipts.jsonl")]
    assert [one.get("target", one.get("cause")) for one in receipts] == [
        "escalate_34", "refuse_104", "escalate_34", "refuse_104", "route:needs-human", "allow"]
    assert set(downlink.escalations(run)) == set(escalated)
    keys = _ground_keys(tmp_path, app_anchor(install=("J", "K"), operators=("O1",), stale=5))
    summary = downlink.verify(downlink.fetch(run, tmp_path / "ground"), keys)
    assert (summary["receipts"], summary["cases"], summary["disagree"], summary["escalations"]) == (6, 6, 0, 2)


def test_case_231_a_cfs_app_takes_no_answer_at_a_threshold_of_one_nor_one_for_another_pep(app, tmp_path):
    """case_231: OP1, OP2, in the cFS app. An app whose install threshold is 1 refuses a well signed answer with
    dist:target-mismatch, and one whose threshold is 2 refuses an answer that names another PEP's id with
    dist:answer-unbound and applies the one that names its own."""
    lone = app_run(app, tmp_path / "lone", [*_app_escalating(threshold=1, keys=("J",)), *_app_answer("ab" * 32)])
    assert ("refused", "dist:target-mismatch") in [(one["event"], one["cause"]) for records, _f in steps(lone)
                                                   for one in records]
    out = app_run(app, tmp_path / "two", [*_app_escalating()])
    receipt = [line.split()[1] for line in out if line.startswith("escalation")][0]
    out = app_run(app, tmp_path / "three", [*_app_escalating(), *_app_answer(receipt, pep=pep_id("I2")),
                                            *_app_answer(receipt, transfer=41)])
    events = [(one["event"], one["cause"]) for records, _flags in steps(out) for one in records]
    assert events[-2:] == [("refused", "dist:answer-unbound"), ("answered", None)]


def test_case_232_a_cfs_app_holds_operator_answers_to_the_signed_answer_rate(app, tmp_path):
    """case_232: OP4, H1, AF8, in the cFS app. With an answer_rate of 2 in 600 seconds, three escalations get two
    `allow` answers applied, a processor reset between them changing nothing, and the third is dist:floor-rate with
    its escalation still open, so a `refuse` for it is applied."""
    lines = [*_app_escalating(), f"propose {payload(3, slew=15, thrust=20)} 1 - {N}",
             f"propose {payload(3, slew=15, thrust=20)} 1 - {N}"]
    out = app_run(app, tmp_path / "first", lines)
    receipts = [line.split()[1] for line in out if line.startswith("escalation")]
    assert len(receipts) == 3 and len(set(receipts)) == 3
    out = app_run(app, tmp_path / "second", [*lines, *_app_answer(receipts[0]), "reset", f"start 0 0 1 {N + 1}",
                                             *_app_answer(receipts[1], transfer=41, now=N + 1),
                                             *_app_answer(receipts[2], transfer=42, now=N + 1),
                                             *_app_answer(receipts[2], "refuse", transfer=43, now=N + 1)])
    events = [(one["event"], one["cause"], one.get("subject")) for records, _flags in steps(out) for one in records
              if one["event"] in ("answered", "refused")]
    assert events == [("answered", None, 5), ("answered", None, 5), ("refused", "dist:floor-rate", 5),
                      ("answered", None, 5)]
    assert [one[0] for one in _answered(out)] and len(_answered(out)) == 3
