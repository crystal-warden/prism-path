# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Every scripted scenario, every check true, and each population verified end to end; then a verified
population altered in each way that matters, and the verifier refusing each alteration."""
import json
import os
import shutil
from pathlib import Path

import pytest

from integrations.governed_population import evidence, lineage, scenarios
from integrations.governed_population import policy as pp
from integrations.governed_population.simulate import World, version
from integrations.governed_population.limits import RIGHTS
from prismpath.kernel import canon2


def _oracle():
    path = os.environ.get("PRISMPATH_CORE_ORACLE") or str(Path(__file__).resolve().parents[3] / "formal" / ".lake"
                                                          / "build" / "bin" / "core-oracle")
    return path if Path(path).exists() else None


@pytest.mark.parametrize("name", sorted(scenarios.SCENARIOS))
def test_scenario(name, tmp_path):
    result = scenarios.SCENARIOS[name](tmp_path / name, _oracle())
    failed = [check for check, ok in result["checks"].items() if not ok]
    assert failed == [], (failed, result["decisions"])


def test_no_member_ever_holds_a_private_key_but_its_own(tmp_path):
    scenarios.runaway(tmp_path / "p", None)
    agents = tmp_path / "p" / "population" / "agents"
    for keys in agents.glob("*/keys"):
        assert sorted(p.name for p in keys.iterdir()) == ["authority.pub", "instance.key", "instance.pub"]
    controller = tmp_path / "p" / "population" / "controller" / "keys"
    assert sorted(p.name for p in controller.iterdir()) == ["authority.pub", "instance.key", "instance.pub"]


def test_a_decision_that_cannot_be_made_does_nothing(tmp_path, monkeypatch):
    world = World(tmp_path / "w", root_version=version("v1", "idle"))
    ctl, root = world.controller, world.root.agent

    def broken(raw):
        raise RuntimeError("the kernel failed")
    monkeypatch.setattr(ctl.admission, "decide", broken)
    out = ctl.submit(root.request("replicate", count=1, rights=list(RIGHTS), child_key="instance",
                                  policy_ref=root.version.policy_ref))
    assert out.kind == "none" and out.receipt is None and len(ctl.members) == 1 and not ctl.pending
    assert not any(p.name != "a0" for p in (tmp_path / "w" / "population" / "agents").iterdir())
    monkeypatch.undo()
    # a stop does not wait for a decision: it is carried out, and the missing decision is a fault
    monkeypatch.setattr(ctl.admission, "decide", broken)
    stop = ctl.operator_stop(world.operator.stop("a0"))
    assert stop.kind == "allow" and ctl.members["a0"].state == "stopped" and ctl.faults


# ----------------------------------------------------------------- a verified population, altered
@pytest.fixture(scope="module")
def sealed(tmp_path_factory):
    base = tmp_path_factory.mktemp("sealed")
    world = World(base / "w", root_version=version("v1", "worker"))
    ctl, root = world.controller, world.root.agent
    made = ctl.submit(root.request("replicate", count=2, rights=["write", "exec"], child_key="instance",
                                   policy_ref=root.version.policy_ref))
    ctl.round()
    ctl.submit(root.request("evolve", version=version("v2", "worker", system_message="v2").doc()))
    ctl.operator_stop(world.operator.stop(made.detail["children"][1]))
    result = world.close_and_verify()
    assert result["lineage"]["members"] == 3 and result["lineage"]["version_changes"] == 3
    return base / "w"


def _copy(sealed, tmp_path):
    shutil.copytree(sealed, tmp_path / "w", symlinks=True)
    return tmp_path / "w"


def _verify(root):
    return lineage.verify_population(root / "population", root / "operator" / "authority.pub",
                                     root / "population" / "controller" / "keys" / "instance.pub")


def _rewrite(path, change):
    rows = [canon2.loads(line) for line in path.read_bytes().split(b"\n") if line]
    rows = change(rows)
    path.write_bytes(b"".join(canon2.dumps(row) + b"\n" for row in rows))


def test_the_unaltered_population_verifies(sealed, tmp_path):
    assert _verify(_copy(sealed, tmp_path))["survivors"] == 2


def test_an_altered_admission_receipt_is_caught(sealed, tmp_path):
    root = _copy(sealed, tmp_path)
    path = root / "population" / "controller" / "admission" / "receipts.jsonl"
    before = path.read_bytes()
    path.write_bytes(before.replace(b'"target":"allow"', b'"target":"escalate_122"', 1))
    assert path.read_bytes() != before
    with pytest.raises(lineage.Bad, match="admission run does not verify"):
        _verify(root)


def test_a_member_with_no_receipt_is_caught(sealed, tmp_path):
    root = _copy(sealed, tmp_path)

    def add(rows):
        fake = {**rows[1], "id": "a0.99", "admission": {"receipt": 0, "batch": ["a0.99"]}}
        return rows + [fake]
    _rewrite(root / "population" / "members.jsonl", add)
    with pytest.raises(lineage.Bad):
        _verify(root)


def test_a_member_whose_rights_grew_is_caught(sealed, tmp_path):
    root = _copy(sealed, tmp_path)
    _rewrite(root / "population" / "members.jsonl",
             lambda rows: [rows[0]] + [{**row, "rights": sorted(RIGHTS)} for row in rows[1:]])
    with pytest.raises(lineage.Bad, match="rights"):
        _verify(root)


def test_a_member_holding_the_authority_key_is_caught(sealed, tmp_path):
    root = _copy(sealed, tmp_path)
    shutil.copy(root / "operator" / "authority.key", root / "population" / "agents" / "a0.1" / "keys" / "authority.key")
    with pytest.raises(lineage.Bad, match="key other than its own"):
        _verify(root)


def test_a_member_whose_key_is_another_members_is_caught(sealed, tmp_path):
    root = _copy(sealed, tmp_path)
    _rewrite(root / "population" / "members.jsonl",
             lambda rows: rows[:2] + [{**rows[2], "instance_key_id": rows[1]["instance_key_id"],
                                       "instance_public_key": rows[1]["instance_public_key"]}])
    with pytest.raises(lineage.Bad, match="holds the key of"):
        _verify(root)


def test_an_image_signed_by_a_member_is_caught(sealed, tmp_path):
    """A member re-signs its run's image attestation with its own key: the pinned authority refuses it."""
    root = _copy(sealed, tmp_path)
    from prismpath.ledgers import core_evidence, root_statement
    member = root / "population" / "agents" / "a0.1"
    key = root_statement.InstanceKey.load(str(member / "keys" / "instance.key"))
    images = member / "run" / "images.jsonl"
    row = canon2.loads(images.read_bytes().rstrip(b"\n"))
    image = bytes.fromhex(canon2.loads((member / "run" / "cases.jsonl").read_bytes().rstrip(b"\n"))["image"])
    row["sig"] = key.sign(core_evidence.IMAGE_DOMAIN + image).hex()
    images.write_bytes(canon2.dumps(row) + b"\n")
    with pytest.raises(lineage.Bad, match="harness run does not verify"):
        _verify(root)


def test_a_version_change_without_its_evaluation_is_caught(sealed, tmp_path):
    root = _copy(sealed, tmp_path)
    for run in (root / "population" / "evaluations").glob("*/evaluation/receipts.jsonl"):
        run.write_bytes(run.read_bytes().replace(b'"target":"allow"', b'"target":"refuse_120"'))
    with pytest.raises(lineage.Bad, match="version change"):
        _verify(root)


def test_a_survivor_under_a_stopped_ancestor_is_caught(sealed, tmp_path):
    root = _copy(sealed, tmp_path)
    _rewrite(root / "population" / "stops.jsonl", lambda rows: rows + [{**rows[0], "member": "a0", "target": "a0"}])
    with pytest.raises(lineage.Bad):
        _verify(root)


def test_another_controller_key_is_refused(sealed, tmp_path):
    root = _copy(sealed, tmp_path)
    with pytest.raises(lineage.Bad, match="admission run does not verify"):
        lineage.verify_population(root / "population", root / "operator" / "authority.pub",
                                  root / "population" / "agents" / "a0.1" / "keys" / "instance.pub")
