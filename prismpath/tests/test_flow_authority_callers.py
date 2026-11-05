# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The authorization check as a library call, and every place that loads a flow to make decisions.

`flow_authority.authorize_flow` is what `run` and `resume` use; here it is pinned for the callers that
had no check before 0.1.3: a program that loads a flow itself, `checkpoint.run_durable` and `resume`,
the timeout scheduler, `compose` (the library harness and the command) and the ledgered loop (Mission Control's
sprint has its own file, `test_flow_authority_console.py`). Each honours PRISMPATH_REQUIRE_AUTHORIZATION and the
authority keys exactly as `run` does, and each refuses with the registry causes and runs nothing."""
import json
import os

import pytest

pytest.importorskip("cryptography")

from prismpath import cli  # noqa: E402
from prismpath.hotswap import flow_authority as fa, policy_pack  # noqa: E402
from prismpath.kernel import causes  # noqa: E402
from prismpath.kernel.parser import parse_file  # noqa: E402
from prismpath.ledgers import checkpoint, root_statement as rs  # noqa: E402
from prismpath.workers import composer, scheduler  # noqa: E402

FLOW = """---
name: triage
start: a
---

## a
Do the thing.
-> b: when tests_pass

## b
Done.
"""

PARENT = """---
name: parent
start: dispatch
---

## dispatch
@spawn(child=child.md, over=files, item_id=path, join=all_done)
-> aggregate: on event all_done

## aggregate
Combine.
"""

CHILD = """---
name: child
start: review
---

## review
Review one file.
-> done: always

## done
Finish.
"""

WAITING = """---
name: order
start: place
---
## place
-> await_payment: when always
## await_payment
-> fulfilled: on event payment_confirmed
-> cancelled: on timeout
## fulfilled
## cancelled
"""


@pytest.fixture(autouse=True)
def _no_ambient_settings(monkeypatch):
    for name in (rs.INSTANCE_KEY_ENV, fa.REQUIRE_ENV, fa.AUTHORITY_PUB_ENV, fa.STATE_DIR_ENV, "SPRINT_FLOW"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def setup(tmp_path):
    authority = policy_pack.keygen(str(tmp_path / "keys"))
    instance = rs.keygen(str(tmp_path / "keys"))
    flow = tmp_path / "flow.md"
    flow.write_text(FLOW)
    return {"authority": authority, "instance": instance, "flow": str(flow), "tmp": tmp_path,
            "state": str(tmp_path / "state")}


def _required(setup):
    return fa.AuthorizationPolicy(required=True, authority_pubs=[setup["authority"]["public"]], state_dir=setup["state"])


def _sign(setup, path=None, version=1):
    keys = setup["authority"]
    return fa.sign_flow(path or setup["flow"], version, keys["private"], keys["public"])


def _env_required(setup, monkeypatch):
    monkeypatch.setenv(fa.REQUIRE_ENV, "1")
    monkeypatch.setenv(fa.AUTHORITY_PUB_ENV, setup["authority"]["public"])
    monkeypatch.setenv(fa.STATE_DIR_ENV, setup["state"])


def _main(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


# ------------------------------------------------------------------ the library call

def test_nothing_is_asked_of_a_flow_with_no_manifest_when_authorization_is_not_required(setup):
    result = fa.authorize_flow(setup["flow"])
    assert result.status == fa.NONE and not result.ok and result.record == fa.UNAUTHORIZED


def test_a_manifest_with_no_authority_key_is_reported_as_unchecked(setup):
    _sign(setup)
    result = fa.authorize_flow(setup["flow"])
    assert result.status == fa.UNCHECKED and result.manifest["version"] == 1 and result.record == fa.UNAUTHORIZED


def test_a_valid_manifest_verifies_and_names_the_authorization(setup):
    manifest = _sign(setup, version=3)
    policy = fa.AuthorizationPolicy(authority_pubs=[setup["authority"]["public"]], state_dir=setup["state"])
    result = fa.authorize_flow(setup["flow"], policy)
    assert result.status == fa.VERIFIED and result.ok and not result.required
    assert result.record == {"manifest_sha256": fa.manifest_sha256(manifest), "key_id": setup["authority"]["key_id"], "version": 3}
    assert not os.path.exists(os.path.join(setup["state"], fa.FLOOR_FILE))      # not required: the floor does not move


def test_a_failed_check_is_returned_not_raised_when_authorization_is_not_required(setup):
    _sign(setup)
    with open(setup["flow"], "a") as handle:
        handle.write(" ")
    policy = fa.AuthorizationPolicy(authority_pubs=[setup["authority"]["public"]], state_dir=setup["state"])
    result = fa.authorize_flow(setup["flow"], policy)
    assert result.status == fa.FAILED and result.reasons == ["flow:sha256-mismatch"] and result.record == fa.UNAUTHORIZED


def test_a_required_flow_without_authorization_raises_with_the_registry_cause(setup):
    with pytest.raises(fa.FlowNotAuthorized) as refused:
        fa.authorize_flow(setup["flow"], _required(setup))
    assert refused.value.causes == ["sig:missing"] and causes.code("sig:missing") == 1
    assert "sig:missing" in str(refused.value)


def test_a_required_flow_that_verifies_raises_the_floor(setup):
    _sign(setup, version=2)
    result = fa.authorize_flow(setup["flow"], _required(setup))
    assert result.ok and result.required
    assert json.load(open(os.path.join(setup["state"], fa.FLOOR_FILE)))["triage"]["version"] == 2
    _sign(setup, version=1)
    with pytest.raises(fa.FlowNotAuthorized) as refused:
        fa.authorize_flow(setup["flow"], _required(setup))
    assert refused.value.causes == ["flow:version-replay"]


def test_required_with_no_authority_key_is_a_configuration_error(setup):
    with pytest.raises(fa.AuthorizationConfigError, match="no trusted authority key"):
        fa.authorize_flow(setup["flow"], fa.AuthorizationPolicy(required=True))


def test_the_environment_supplies_what_the_policy_leaves_out(setup, monkeypatch):
    _env_required(setup, monkeypatch)
    with pytest.raises(fa.FlowNotAuthorized):
        fa.authorize_flow(setup["flow"])
    _sign(setup)
    assert fa.authorize_flow(setup["flow"]).ok
    revoked = fa.AuthorizationPolicy(revoked=[setup["authority"]["key_id"]])
    with pytest.raises(fa.FlowNotAuthorized) as refused:
        fa.authorize_flow(setup["flow"], revoked)
    assert refused.value.causes == ["sig:revoked-key"]


def test_an_instance_key_is_refused_as_the_authority_and_never_authorizes(setup):
    instance = rs.InstanceKey.load(setup["instance"]["private"])
    fa.sign_flow(setup["flow"], 1, setup["instance"]["private"], setup["instance"]["public"])
    policy = fa.AuthorizationPolicy(required=True, authority_pubs=[setup["instance"]["public"]], state_dir=setup["state"])
    with pytest.raises(fa.AuthorizationConfigError, match="also a policy authority key"):
        fa.authorize_flow(setup["flow"], policy, instance)


def test_load_authorized_gives_the_graph_and_the_authorization(setup):
    _sign(setup)
    graph, authorization = fa.load_authorized(setup["flow"], _required(setup))
    assert graph.name == "triage" and authorization.ok
    with open(setup["flow"], "a") as handle:
        handle.write(" ")
    with pytest.raises(fa.FlowNotAuthorized):
        fa.load_authorized(setup["flow"], _required(setup))


# ------------------------------------------------------------------ durable runs and the scheduler

def test_run_durable_refuses_an_unauthorized_flow_before_running_anything(setup, monkeypatch):
    _env_required(setup, monkeypatch)
    ran = []
    ckpt = str(setup["tmp"] / "x.json")
    with pytest.raises(fa.FlowNotAuthorized):
        checkpoint.run_durable(setup["flow"], lambda node, instruction, state: ran.append(node) or {"tests_pass": True}, ckpt)
    assert ran == [] and not os.path.exists(ckpt)
    _sign(setup)
    result = checkpoint.run_durable(setup["flow"], lambda node, instruction, state: {"tests_pass": True}, ckpt)
    assert result.stopped == "terminal"


def test_resume_refuses_a_flow_that_lost_its_authorization_while_suspended(setup, monkeypatch):
    _sign(setup)
    ckpt = str(setup["tmp"] / "s.json")
    checkpoint.run_durable(setup["flow"], lambda node, instruction, state: {"needs_human": True}, ckpt)
    _env_required(setup, monkeypatch)
    os.remove(fa.manifest_paths(setup["flow"])[0])
    ran = []
    with pytest.raises(fa.FlowNotAuthorized) as refused:
        checkpoint.resume(ckpt, lambda node, instruction, state: ran.append(node) or {}, choose="b")
    assert refused.value.causes == ["sig:missing"] and ran == []


def test_the_scheduler_skips_a_refused_flow_and_keeps_scanning(setup, monkeypatch):
    flow = setup["tmp"] / "order.md"
    flow.write_text(WAITING)
    qdir = setup["tmp"] / "queue"
    qdir.mkdir()
    agent = lambda node, instruction, state: ({"wait": True, "timeout_s": 10} if node == "await_payment" else {"always": True})
    ckpt = str(qdir / "r1.json")
    assert checkpoint.run_durable(str(flow), agent, ckpt).stopped == "waiting"
    _env_required(setup, monkeypatch)
    saved = checkpoint.load_checkpoint(ckpt)["saved_at"]
    fired = scheduler.fire_due_timeouts(agent, qdir=str(qdir), now=saved + 100)
    assert len(fired) == 1 and fired[0]["refused"] == ["sig:missing"] and "result" not in fired[0]
    assert checkpoint.load_checkpoint(ckpt)["stopped"] == "waiting"
    _sign(setup, str(flow))
    fired = scheduler.fire_due_timeouts(agent, qdir=str(qdir), now=saved + 100)
    assert fired[0]["result"].stopped == "terminal"


# ------------------------------------------------------------------ compose

def _fanout(setup):
    tmp = setup["tmp"]
    (tmp / "parent.md").write_text(PARENT)
    (tmp / "child.md").write_text(CHILD)
    qdir = tmp / "queue"
    qdir.mkdir()
    files = [{"path": "a.py"}, {"path": "b.py"}]

    def agent(node, instruction, state):
        if node == "dispatch":
            state["files"] = files
            return {"wait": True, "timeout_s": 600, "spawn": {"child": "child.md", "over": "files", "item_id": "path",
                                                                "join": "all_done", "items": files}}
        return {"always": True}

    assert checkpoint.run_durable(str(tmp / "parent.md"), agent, str(qdir / "parent.json")).stopped == "waiting"
    return qdir, agent


def test_compose_refuses_an_unauthorized_child_flow_and_spawns_nothing(setup, monkeypatch):
    qdir, agent = _fanout(setup)
    _env_required(setup, monkeypatch)
    _sign(setup, str(setup["tmp"] / "parent.md"))                    # the parent is authorized, the child is not
    records = composer.advance_fanouts(agent, qdir=str(qdir))
    assert len(records) == 1 and records[0]["refused"] == ["sig:missing"] and records[0]["spawned"] == 0
    assert records[0]["flow"].endswith("child.md") and "not authorized" in records[0]["error"]
    assert not (qdir / "parent.children").exists()
    assert checkpoint.load_checkpoint(str(qdir / "parent.json"))["stopped"] == "waiting"


def test_compose_runs_when_both_flows_are_authorized(setup, monkeypatch):
    qdir, agent = _fanout(setup)
    _env_required(setup, monkeypatch)
    _sign(setup, str(setup["tmp"] / "parent.md"))
    _sign(setup, str(setup["tmp"] / "child.md"))
    records = composer.advance_fanouts(agent, qdir=str(qdir))
    assert records[0]["joined"] is True and records[0]["spawned"] == 2 and "refused" not in records[0]


def test_the_compose_command_names_the_refusal_and_exits_2(setup, capsys):
    qdir, _agent = _fanout(setup)
    code, out, _err = _main(capsys, "compose", "--queue", str(qdir), "--require-authorization", "--authority-pub",
                            setup["authority"]["public"], "--state-dir", setup["state"])
    assert code == 2
    assert "refused:" in out and "parent.md is not authorized: sig:missing (cause 1)" in out and "refused 1" in out
    _sign(setup, str(setup["tmp"] / "parent.md"))
    _sign(setup, str(setup["tmp"] / "child.md"))
    code, out, _err = _main(capsys, "compose", "--queue", str(qdir), "--require-authorization", "--authority-pub",
                            setup["authority"]["public"], "--state-dir", setup["state"])
    assert code == 0 and "joined (all_done)" in out and "refused" not in out


def test_the_compose_command_needs_the_authority_key_when_it_is_required(setup, capsys):
    qdir, _agent = _fanout(setup)
    code, _out, err = _main(capsys, "compose", "--queue", str(qdir), "--require-authorization")
    assert code == 2 and "needs the trusted authority key" in err


# ------------------------------------------------------------------ the ledgered loop

def test_the_ledgered_loop_checks_its_flow_first(setup):
    from prismpath.ledgers.ledger_runner import run_ledgered_loop
    flow = setup["tmp"] / "queue.md"
    flow.write_text("---\nname: q\nstart: fetch\n---\n## fetch\n@checkpoint(unit=item_id)\n-> done: when always\n## done\n")
    calls = []
    with pytest.raises(fa.FlowNotAuthorized) as refused:
        run_ledgered_loop(str(flow), lambda *a: calls.append(a) or {}, ledger=object(), policy=_required(setup))
    assert refused.value.causes == ["sig:missing"] and calls == []
