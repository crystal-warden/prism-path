# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The shipped core run verifier (`prismpath.ledgers.core_evidence`, `prismpath evidence verify`).

A run is produced for the test from the cases in `fixtures/core_evidence/cases.jsonl` (written by
`formal/diff/core_evidence.py cases --cases 60 --seed 5`; `test_core_evidence.py` holds the file to that
command in a research checkout) with test keys generated in a temporary directory, so the suite runs from
an installed wheel with no research tooling and no oracle: every receipt is replayed through the Python
reference kernel. The research verifier's replay through the Lean oracle is held to this one in
`test_core_evidence.py`."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

import prismpath  # noqa: E402
from prismpath import cli  # noqa: E402
from prismpath.kernel import canon2  # noqa: E402
from prismpath.ledgers import core_evidence, root_statement  # noqa: E402

CASES = Path(__file__).resolve().parent / "fixtures" / "core_evidence" / "cases.jsonl"
MERKLE = "the root statement does not verify: its root is not the receipts' Merkle root"


@pytest.fixture(scope="module")
def produced(tmp_path_factory):
    base = tmp_path_factory.mktemp("evidence_verify")
    manifest = core_evidence.produce(CASES, base / "run", base / "keys")
    return base, manifest


def _copy(produced, tmp_path, name="copy"):
    base, _manifest = produced
    copy = tmp_path / name
    shutil.copytree(base / "run", copy)
    return copy


def _pins(produced):
    base, _manifest = produced
    return {"pin_authority": base / "keys" / "authority.pub", "pin_instance": base / "keys" / "instance.pub"}


def _receipts(run):
    return (run / "receipts.jsonl").read_bytes().split(b"\n")[:-1]


def test_the_fixture_run_holds_every_kind_of_case(produced):
    """The cases give routes, refusals, and each reason a case is outside the core."""
    base, manifest = produced
    decisions = {canon2.loads(line)["decision"] for line in _receipts(base / "run")}
    assert decisions == {"route", "refuse"}
    assert {row["why"] for row in manifest["excluded"]} == {"engine-counter", "unrenderable", "inferred-path"}
    assert manifest["cases"] == 60 and manifest["receipts"] > 100


def test_a_good_run_verifies_with_every_receipt_replayed(produced):
    base, manifest = produced
    summary = core_evidence.verify(base / "run", sample=None, **_pins(produced))
    assert summary["root_statement"] == "signed" and summary["against"] == "the reference kernel"
    assert summary["replayed"] == summary["receipts"] == summary["agree"] == manifest["receipts"]
    assert summary["disagree"] == 0 and summary["excluded"] == len(manifest["excluded"])


def test_unpinned_keys_are_an_escape_hatch(produced, monkeypatch):
    """Without both keys pinned every check runs and a production build refuses the pass with dist:hatch-refused
    (spec-policy-distribution.md, D1). Only a dev build reports signed-unpinned."""
    base, _manifest = produced
    one_pin = {"pin_authority": _pins(produced)["pin_authority"]}
    for pins in ({}, one_pin):
        with pytest.raises(core_evidence.Bad, match="dist:hatch-refused"):
            core_evidence.verify(base / "run", sample=5, **pins)
    from prismpath.distribution import devbuild
    monkeypatch.setattr(devbuild, "is_dev_build", lambda package_dir=None: True)
    assert core_evidence.verify(base / "run", sample=5)["root_statement"] == "signed-unpinned"
    assert core_evidence.verify(base / "run", sample=5, **one_pin)["root_statement"] == "signed-unpinned"


def test_a_sample_replay_agrees(produced):
    base, _manifest = produced
    first = core_evidence.verify(base / "run", sample=25, seed=3, **_pins(produced))
    again = core_evidence.verify(base / "run", sample=25, seed=3, **_pins(produced))
    assert first["replayed"] == first["agree"] == 25 and first["disagree"] == 0
    assert first == again


def test_a_tampered_receipt_is_refused_by_the_merkle_root(produced, tmp_path):
    copy = _copy(produced, tmp_path)
    lines = _receipts(copy)
    at = next(number for number, line in enumerate(lines) if b'"decision":"route"' in line)
    receipt = canon2.loads(lines[at])
    receipt["target"] = receipt["target"] + "x"
    lines[at] = canon2.dumps(receipt)
    (copy / "receipts.jsonl").write_bytes(b"".join(line + b"\n" for line in lines))
    with pytest.raises(core_evidence.Bad, match=MERKLE.replace("'", ".")):
        core_evidence.verify(copy, sample=None, **_pins(produced))


def test_a_dropped_receipt_is_refused_by_the_merkle_root(produced, tmp_path):
    copy = _copy(produced, tmp_path)
    (copy / "receipts.jsonl").write_bytes(b"".join(line + b"\n" for line in _receipts(copy)[:-1]))
    with pytest.raises(core_evidence.Bad, match="its root is not the receipts. Merkle root"):
        core_evidence.verify(copy, sample=5)


def _rewrite_manifest(run, **change):
    manifest = canon2.loads((run / "run.json").read_bytes().rstrip(b"\n"))
    manifest.update(change)
    (run / "run.json").write_bytes(canon2.dumps(manifest) + b"\n")


def test_a_tampered_run_json_is_refused_for_the_keys(produced, tmp_path):
    copy = _copy(produced, tmp_path)
    _rewrite_manifest(copy, authority_key_id="0" * 64)
    with pytest.raises(core_evidence.Bad, match="run.json names other keys than the run carries"):
        core_evidence.verify(copy, sample=5)


def test_a_run_json_change_the_root_statement_does_not_bind_is_refused(produced, tmp_path):
    copy = _copy(produced, tmp_path)
    _rewrite_manifest(copy, decider="someone-else")
    with pytest.raises(core_evidence.Bad, match="the root statement does not bind this run.json"):
        core_evidence.verify(copy, sample=5)


def test_a_run_json_that_is_not_canon2_is_refused(produced, tmp_path):
    copy = _copy(produced, tmp_path)
    (copy / "run.json").write_bytes((copy / "run.json").read_bytes().replace(b'","', b'", "', 1))
    with pytest.raises(core_evidence.Bad, match="run.json is not a canon/2 document"):
        core_evidence.verify(copy, sample=5)


def test_a_wrong_pinned_key_is_refused(produced, tmp_path):
    other = tmp_path / "other-keys"
    core_evidence.ensure_keys(other)
    with pytest.raises(core_evidence.Bad, match="the run's authority key is not the pinned authority key"):
        core_evidence.verify(produced[0] / "run", sample=5, pin_authority=other / "authority.pub",
                             pin_instance=_pins(produced)["pin_instance"])
    with pytest.raises(core_evidence.Bad, match="the run's instance key is not the pinned instance key"):
        core_evidence.verify(produced[0] / "run", sample=5, pin_authority=_pins(produced)["pin_authority"],
                             pin_instance=other / "instance.pub")


def test_a_swapped_instance_key_is_refused(produced, tmp_path):
    """Another instance key put in the run is not the one run.json names, nor the root statement's."""
    other = tmp_path / "other-keys"
    core_evidence.ensure_keys(other)
    copy = _copy(produced, tmp_path)
    shutil.copy(other / "instance.pub", copy / "instance.pub")
    with pytest.raises(core_evidence.Bad, match="run.json names other keys"):
        core_evidence.verify(copy, sample=5)


def _flip_signature(data: bytes) -> bytes:
    at = data.index(b'"sig":"') + len(b'"sig":"')
    return data[:at] + (b"1" if data[at:at + 1] == b"0" else b"0") + data[at + 1:]


def test_a_tampered_root_statement_signature_is_refused(produced, tmp_path):
    copy = _copy(produced, tmp_path)
    path = copy / "receipts.roots.jsonl"
    path.write_bytes(_flip_signature(path.read_bytes()))
    with pytest.raises(core_evidence.Bad, match="the root statement's signature does not verify"):
        core_evidence.verify(copy, sample=5)


def test_a_tampered_image_attestation_is_refused(produced, tmp_path):
    """images.jsonl is bound by run.json, so a changed signature is refused as a changed file."""
    copy = _copy(produced, tmp_path)
    path = copy / "images.jsonl"
    path.write_bytes(_flip_signature(path.read_bytes()))
    with pytest.raises(core_evidence.Bad, match="images.jsonl is not the file run.json names"):
        core_evidence.verify(copy, sample=5)


def _resign(produced, copy, lines):
    base, _manifest = produced
    (copy / "receipts.jsonl").write_bytes(b"".join(line + b"\n" for line in lines))
    leaves = [core_evidence.sha256_hex(line) for line in lines]
    instance = root_statement.InstanceKey.load(str(base / "keys" / "instance.key"))
    statement = core_evidence.make_root_statement(instance, root_statement.merkle_root(leaves), len(leaves),
                                                  (copy / "run.json").read_bytes().rstrip(b"\n"))
    (copy / "receipts.roots.jsonl").write_bytes(canon2.dumps(statement) + b"\n")


def test_a_false_receipt_resigned_with_the_instance_key_fails_the_replay(produced, tmp_path):
    """Whoever holds the instance key can sign anything, so the signatures alone do not make a decision
    true: the replay through the reference kernel refuses a signed false receipt."""
    copy = _copy(produced, tmp_path)
    lines = _receipts(copy)
    at = next(number for number, line in enumerate(lines) if b'"decision":"route"' in line)
    receipt = canon2.loads(lines[at])
    receipt["target"] = receipt["target"] + "x"
    lines[at] = canon2.dumps(receipt)
    _resign(produced, copy, lines)
    with pytest.raises(core_evidence.Bad, match="1 replayed decisions differ from the reference kernel"):
        core_evidence.verify(copy, sample=None, **_pins(produced))


# ----------------------------------------------------------------- the stored flow is the signed image's rendering
def _reseal_cases(produced, copy, change):
    """`change` applied to cases.jsonl's rows, and the run sealed again around it as an honest producer holding
    the instance key would: run.json names the new file and the root statement is signed again. Only the
    flow check is left to notice."""
    rows = [canon2.loads(line) for line in (copy / "cases.jsonl").read_bytes().split(b"\n")[:-1]]
    change(rows)
    (copy / "cases.jsonl").write_bytes(b"".join(canon2.dumps(row) + b"\n" for row in rows))
    _rewrite_manifest(copy, cases_sha256=core_evidence.sha256_hex((copy / "cases.jsonl").read_bytes()))
    _resign(produced, copy, _receipts(copy))


def _first_with_flow(rows, needle="-> "):
    return next(row for row in rows if row["flow"] is not None and needle in row["flow"])


def test_a_run_whose_stored_flow_was_edited_is_refused(produced, tmp_path):
    """The reference decides from the flow, so a flow edited away from the signed image would have it decide
    a policy the authority never signed while every hash and signature still holds."""
    copy = _copy(produced, tmp_path)
    edited = {}

    def edit(rows):
        row = _first_with_flow(rows, "when ")
        row["flow"] = row["flow"].replace("when ", "when not ", 1)
        edited["case"] = row["case"]
    _reseal_cases(produced, copy, edit)
    with pytest.raises(core_evidence.Bad, match=f"case {edited['case']}: the stored flow is not the rendering of the "
                                                f"signed image"):
        core_evidence.verify(copy, sample=None, **_pins(produced))


def test_a_flow_given_to_an_image_with_no_rendering_is_refused(produced, tmp_path):
    copy = _copy(produced, tmp_path)

    def edit(rows):
        donor = _first_with_flow(rows)
        next(row for row in rows if row["flow"] is None)["flow"] = donor["flow"]
    _reseal_cases(produced, copy, edit)
    with pytest.raises(core_evidence.Bad, match="the stored flow renders no image"):
        core_evidence.verify(copy, sample=5)


def test_a_flow_withheld_from_an_image_that_renders_is_refused(produced, tmp_path):
    """Dropping a flow would move a case outside the core (`unrenderable`) and take its decisions off the record."""
    copy = _copy(produced, tmp_path)
    _reseal_cases(produced, copy, lambda rows: _first_with_flow(rows).update(flow=None))
    with pytest.raises(core_evidence.Bad, match="the stored flow is not the rendering of the signed image"):
        core_evidence.verify(copy, sample=5)


def test_the_stored_flows_are_the_canonical_renderings(produced):
    from prismpath.kernel import core_render
    base, _manifest = produced
    for case in core_evidence.read_cases(base / "run" / "cases.jsonl"):
        assert case["flow"] == core_render.flow_of(case["image"])[0]
        assert core_evidence.flow_problem(case) is None


def test_produce_refuses_cases_whose_flow_is_not_the_rendering(produced, tmp_path):
    rows = [canon2.loads(line) for line in CASES.read_bytes().split(b"\n")[:-1]]
    row = _first_with_flow(rows, "when ")
    row["flow"] = row["flow"].replace("when ", "when not ", 1)
    edited = tmp_path / "cases.jsonl"
    edited.write_bytes(b"".join(canon2.dumps(item) + b"\n" for item in rows))
    with pytest.raises(RuntimeError, match="the stored flow is not the rendering of the signed image"):
        core_evidence.produce(edited, tmp_path / "run", produced[0] / "keys")


# ----------------------------------------------------------------- the retired Merkle tree
def _retired_root(leaves):
    """The root the retired tree gave: no domain prefixes, the last node of an odd layer paired with itself."""
    import hashlib
    layer = [bytes.fromhex(leaf) for leaf in leaves]
    while len(layer) > 1:
        layer = layer + layer[-1:] if len(layer) % 2 else layer
        layer = [hashlib.sha256(layer[i] + layer[i + 1]).digest() for i in range(0, len(layer), 2)]
    return layer[0].hex()


def test_a_run_rooted_in_the_retired_tree_is_refused_as_old_scheme(produced, tmp_path):
    """A run produced before the RFC 6962 tree: its root statement is `prismpath.core-run-root/1`, signed over
    the retired tree's root. It is refused by name, never checked under the new tree."""
    base, _manifest = produced
    copy = _copy(produced, tmp_path)
    leaves = [core_evidence.sha256_hex(line) for line in _receipts(copy)]
    instance = root_statement.InstanceKey.load(str(base / "keys" / "instance.key"))
    statement = canon2.loads((copy / "receipts.roots.jsonl").read_bytes().rstrip(b"\n"))
    statement.update(format="prismpath.core-run-root/1", root=_retired_root(leaves))
    del statement["sig"]
    statement["sig"] = instance.sign(b"prismpath.core-run-root/1\x00" + canon2.dumps(statement)).hex()
    (copy / "receipts.roots.jsonl").write_bytes(canon2.dumps(statement) + b"\n")
    with pytest.raises(core_evidence.Bad, match="prismpath.core-run-root/1, whose root is of the retired Merkle tree"):
        core_evidence.verify(copy, sample=5, **_pins(produced))


def test_the_new_root_is_not_the_retired_one(produced):
    base, _manifest = produced
    leaves = [core_evidence.sha256_hex(line) for line in _receipts(base / "run")]
    statement = canon2.loads((base / "run" / "receipts.roots.jsonl").read_bytes().rstrip(b"\n"))
    assert statement["format"] == core_evidence.ROOT_FORMAT == "prismpath.core-run-root/2"
    assert statement["root"] == root_statement.merkle_root(leaves) != _retired_root(leaves)


# ----------------------------------------------------------------- the command line
def _cli(capsys, *argv):
    code = cli.main(["evidence", "verify", *map(str, argv)])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_the_command_verifies_a_good_run(produced, capsys):
    base, manifest = produced
    pins = _pins(produced)
    code, out, _err = _cli(capsys, base / "run", "--sample", "all", "--pin-authority", pins["pin_authority"],
                           "--pin-instance", pins["pin_instance"])
    assert code == 0, out
    assert out.startswith(f"prismpath evidence: verified {base / 'run'}: decider python, {manifest['receipts']} receipts")
    assert "root statement signed," in out and "through the reference kernel" in out and " 0 disagree" in out
    code, out, _err = _cli(capsys, base / "run", "--sample", "10")
    assert code == 1 and "dist:hatch-refused" in out, out                 # owner decision 8: unpinned is exit 1


def test_the_command_refuses_a_tampered_run(produced, tmp_path, capsys):
    copy = _copy(produced, tmp_path)
    (copy / "receipts.jsonl").write_bytes(b"".join(line + b"\n" for line in _receipts(copy)[:-1]))
    code, out, _err = _cli(capsys, copy)
    assert code == 1
    assert out.strip() == f"prismpath evidence: REFUSED {copy}: {MERKLE}"
    code, out, _err = _cli(capsys, copy, "--json")
    report = json.loads(out)
    assert code == 1 and report == {"ok": False, "run": str(copy), "refused": MERKLE}


def test_the_command_json_report(produced, capsys):
    base, manifest = produced
    pins = _pins(produced)
    code, out, _err = _cli(capsys, base / "run", "--sample", "7", "--json", "--pin-authority", str(pins["pin_authority"]),
                           "--pin-instance", str(pins["pin_instance"]))
    report = json.loads(out)
    assert code == 0 and report["ok"] is True and report["replayed"] == report["agree"] == 7
    assert report["root_statement"] == "signed" and report["receipts"] == manifest["receipts"]


def test_the_command_refuses_its_inputs_with_exit_2(produced, tmp_path, capsys):
    code, _out, err = _cli(capsys, tmp_path / "absent")
    assert code == 2 and "is not a directory" in err
    code, _out, err = _cli(capsys, produced[0] / "run", "--pin-authority", tmp_path / "absent.pub")
    assert code == 2 and "absent.pub" in err
    with pytest.raises(SystemExit) as exited:
        cli.main(["evidence", "verify", str(produced[0] / "run"), "--sample", "some"])
    assert exited.value.code == 2


def test_the_verifier_needs_no_numpy(produced):
    """Offline packs install no numpy: the verifier and its command import and run with numpy unimportable."""
    base, _manifest = produced
    program = (
        "import importlib.abc, sys\n"
        "class Block(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path, target=None):\n"
        "        if name == 'numpy' or name.startswith('numpy.'):\n"
        "            raise ImportError('numpy is blocked for this test')\n"
        "sys.meta_path.insert(0, Block())\n"
        "from prismpath import cli\n"
        f"code = cli.main(['evidence', 'verify', {str(base / 'run')!r}, '--sample', 'all', '--pin-authority', "
        f"{str(_pins(produced)['pin_authority'])!r}, '--pin-instance', {str(_pins(produced)['pin_instance'])!r}])\n"
        "assert 'numpy' not in sys.modules\n"
        "sys.exit(code)\n")
    package_parent = str(Path(prismpath.__file__).resolve().parents[1])
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [package_parent, os.environ.get("PYTHONPATH")]))}
    result = subprocess.run([sys.executable, "-c", program], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "verified" in result.stdout and " 0 disagree" in result.stdout, result.stdout
