"""RC4 and OP2, OP3 in the core run verifier (prismpath/ledgers/core_evidence.py): a cFS run with a floor case, a
fallback `would` line, a floor case with no set to ask (`asked` false) and an operator case verifies, and an operator
case is refused when its answer is bound to another PEP, its receipt is not the answer, a second answer names the
escalation the first one closed, or the answer was never in force while its escalation was open. An operator case not
enacted, an answer the PEP applied but whose command it could not send, verifies."""
import json
import shutil

import pytest

from integrations.cfs.ground import answer as ground_answer
from integrations.cfs.tests.test_cfs_dist import (ALLOW_3, _body, _cfs_floor, _dist, _floor_point, _reading,  # noqa
                                                  _resign, env, table)
from prismpath.kernel import canon2
from prismpath.ledgers import core_evidence as ce


def _run(tmp_path, *, pep=None, opened=None, enacted=True, second=None):
    """A sealed run whose operator answer names `pep`, the run's own PEP id unless given, for an escalation opened at
    `opened` (the answer's own start unless given), its operator case `enacted` or not, and with `second` ("refuse" or
    "allow") a second answer to the same escalation and a second operator case; (run dir, keys, pins)."""
    from prismpath.distribution import install
    point = _floor_point(tmp_path)
    first = _cfs_floor(point, ALLOW_3, rate={"allows": 3, "window": 60})
    fallback = point.install_set("install.fallback", {"cfs.table": _body(2)}, 1, widens=True)
    eid = lambda pairs: env.envelope_id(env.unseal(pairs[0][0])[0])          # noqa: E731
    floor_policy = point.policy_of(ALLOW_3)
    escalation = canon2.dumps({"case": "v1", "cause_code": 166, "decider": "python",
                               "format": "prismpath.cfs-escalation/1", "n": 4, "policy_sha256": floor_policy,
                               "reading_sha256": ce.sha256_hex(_reading(3, 9)),
                               "time": _dist.NOW if opened is None else opened})
    keys = tmp_path / "keys"
    ce.ensure_keys(keys)
    own = ce.hashlib.sha256((keys / "instance.pub").read_bytes()).digest()[:16].hex()
    sealed, body = ground_answer.seal_answer(_dist.GEN.test_key("O1"), pep=pep or own,
                                             receipt=ce.sha256_hex(escalation), policy=floor_policy, answer="allow",
                                             now=_dist.NOW, stream=_dist.STREAM)
    core = table.core_of
    cases = [{"id": "floor-1", "image": core(ALLOW_3), "readings": [_reading(3)], "basis": "floor",
              "install": eid(first)},
             {"id": "would", "image": core(_body(2)), "enacted": False, "readings": [_reading(3)],
              "basis": "fallback", "install": eid(fallback)},
             {"id": "alone", "image": core(ALLOW_3), "readings": [_reading(3, 7)], "basis": "floor", "asked": False,
              "install": eid(first)},
             {"id": "op", "image": core(ALLOW_3), "readings": [_reading(3, 9)], "basis": "operator",
              "install": eid(first), "answer": env.envelope_id(env.unseal(sealed)[0]), "enacted": enacted}]
    answers, decided = [(sealed, body)], {"op": {"decision": "route", "target": "allow"}}
    if second is not None:
        again, again_body = ground_answer.seal_answer(_dist.GEN.test_key("O1"), pep=pep or own,
                                                      receipt=ce.sha256_hex(escalation), policy=floor_policy,
                                                      answer=second, now=_dist.NOW + 1, stream=_dist.STREAM)
        answers.append((again, again_body))
        cases.append({"id": "op2", "image": core(ALLOW_3), "readings": [_reading(3, 9)], "basis": "operator",
                      "install": eid(first), "answer": env.envelope_id(env.unseal(again)[0])})
        decided["op2"] = {"decision": "route", "target": "allow"} if second == "allow" else {
            "decision": "refuse", "cause": "dist:floor-rate", "cause_code": 166}
    cases_path = tmp_path / "cases.jsonl"
    ce.write_cases(cases, cases_path)
    pin = tmp_path / "install.json"
    pin.write_text(json.dumps(install.anchor_part([_dist.public(n) for n in ("N1", "N2", "N3")], threshold=2,
                                                  operators=[_dist.public("O1")], domain="0" * 64)))
    ce.produce(cases_path, tmp_path / "run", keys, install=[*first, *fallback, *answers], rates=[], time_us=1,
               escalations=[escalation], operator=decided)
    pins = {"pin_authority": keys / "authority.pub", "pin_instance": keys / "instance.pub", "pin_install": pin}
    return tmp_path / "run", keys, pins


def test_a_run_with_floor_fallback_would_and_operator_cases_verifies(tmp_path):
    run, _keys, pins = _run(tmp_path)
    summary = ce.verify(run, sample=None, **pins)
    assert summary["disagree"] == 0 and summary["receipts"] == 4 and summary["replayed"] == 3


def test_an_operator_answer_bound_to_another_pep_is_refused(tmp_path):
    run, _keys, pins = _run(tmp_path, pep="ab" * 16)
    with pytest.raises(ce.Bad) as refused:
        ce.verify(run, sample=None, **pins)
    assert "bound to another PEP" in str(refused.value)


def test_an_operator_receipt_that_is_not_the_answer_is_refused(tmp_path):
    run, keys, pins = _run(tmp_path)
    bad = tmp_path / "bad"
    shutil.copytree(run, bad)
    receipts = [canon2.loads(line) for line in ce._lines(bad / "receipts.jsonl")]
    receipts[-1] = {**{k: v for k, v in receipts[-1].items() if k != "target"}, "decision": "refuse",
                    "cause": "dist:floor-rate", "cause_code": 166}
    _resign(bad, keys, receipts=[canon2.dumps(r) for r in receipts])
    with pytest.raises(ce.Bad) as refused:
        ce.verify(bad, sample=None, **pins)
    assert "not the operator's answer" in str(refused.value)


def test_an_operator_case_not_enacted_verifies_with_the_answer_as_its_receipt(tmp_path):
    run, _keys, pins = _run(tmp_path, enacted=False)
    summary = ce.verify(run, sample=None, **pins)
    assert summary["disagree"] == 0 and summary["receipts"] == 4


@pytest.mark.parametrize("second", ["refuse", "allow"])
def test_a_second_answer_to_an_escalation_its_first_answer_closed_is_refused(tmp_path, second):
    run, _keys, pins = _run(tmp_path, second=second)
    with pytest.raises(ce.Bad) as refused:
        ce.verify(run, sample=None, **pins)
    assert "second answer to an escalation" in str(refused.value)


@pytest.mark.parametrize("opened", [_dist.NOW - ce.ANSWER_LIFE - 1, _dist.NOW + ce.ANSWER_LIFE + 1])
def test_an_answer_never_in_force_while_its_escalation_was_open_is_refused(tmp_path, opened):
    run, _keys, pins = _run(tmp_path, opened=opened)
    with pytest.raises(ce.Bad) as refused:
        ce.verify(run, sample=None, **pins)
    assert "never in force" in str(refused.value)


def test_an_answer_in_force_at_the_last_second_of_its_escalation_verifies(tmp_path):
    run, _keys, pins = _run(tmp_path, opened=_dist.NOW - ce.ANSWER_LIFE)
    assert ce.verify(run, sample=None, **pins)["disagree"] == 0
