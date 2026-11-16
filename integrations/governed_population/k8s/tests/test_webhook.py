# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The admission webhook without a cluster: every fixture's answer, cause, request and receipt; every
receipt agreeing with the second reading of the rules (owner_rules), the population's invariants and (when
built) the Lean oracle; the readings equal to the simulation controller's for the same requests; and every
error path a deny with no allow receipt, except an operator's stop, which is never refused."""
import json
import os
import ssl
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

from integrations.governed_population import evidence, exhaustive, owner_rules
from integrations.governed_population import policy as pp
from integrations.governed_population.agent import Version
from integrations.governed_population.k8s import operator_tool, webhook
from integrations.governed_population.k8s.classify import Config
from integrations.governed_population.limits import CAP, LINE_REFUSALS, RIGHTS
from integrations.governed_population import identity as ident
from integrations.governed_harness.policy import Policy as HarnessPolicy
from prismpath.kernel import canon2
from prismpath.ledgers import core_evidence

from . import fixtures as fx

HERE = Path(__file__).resolve().parent
K8S = HERE.parent
REPO = K8S.parents[2]


def _oracle():
    path = os.environ.get("PRISMPATH_CORE_ORACLE") or str(exhaustive.DEFAULT_ORACLE)
    return path if Path(path).exists() else None


class Registry:
    def __init__(self, items=()):
        self.items_list, self.fail = list(items), False

    def items(self):
        if self.fail:
            raise ConnectionError("the API server is unreachable")
        return list(self.items_list)


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    out = tmp_path_factory.mktemp("operator") / "keys"
    operator_tool.init(out)
    return out


def config():
    return Config(harness_sha256=ident.sha256_hex(HarnessPolicy.load().image))


def make_evaluation(keys: Path, store: Path, ref: str, version_doc, cases: int = 51) -> Path:
    """A sealed evaluation run as `canary.evaluate` leaves it, without running the 51 cases: one decision of
    the evaluation image under the evaluator's key."""
    version = Version.from_doc(version_doc)
    policy = pp.evaluation()
    attestations = json.loads((keys / "attestations.json").read_text())
    run = evidence.DecisionRun(store / ref, "evaluation", policy.image, attestations["evaluation"],
                               ident.InstanceIdentity(keys / "evaluator"), (keys / "operator" / "authority.pub").read_bytes())
    raw = policy.reading_bytes(pp.evaluation_reading(cases=cases, out_of_policy=0, wrong_cause=0, unverified=0,
                                                     benign_failed=0, subject=version.sha256))
    run.record(raw, policy.decide(raw).verdict)
    run.close()
    return store / ref


def decider(keys, data, registry, **kw):
    store = webhook.EvaluationStore(data.parent / "evaluations", keys / "operator" / "authority.pub",
                                    [keys / "evaluator" / "instance.pub"], pp.evaluation().image)
    return webhook.Decider(data, keys / "webhook", keys / "operator" / "authority.pub",
                           json.loads((keys / "attestations.json").read_text()), config(), registry, store,
                           out=open(os.devnull, "w"), **kw)


def setup_case(keys, tmp, case):
    (tmp / "evaluations").mkdir(parents=True, exist_ok=True)
    if case["evaluation"]:
        ev = case["evaluation"]
        make_evaluation(keys, tmp / "evaluations", ev["ref"], ev["version"], ev["cases"])
    d = decider(keys, tmp / "data", Registry(case["registry"]))
    state = case["state"]
    d.state.tombstones.update(state.get("tombstones", ()))
    d.state.line_refusals.update(state.get("line_refusals", {}))
    for name, line in state.get("pending", {}).items():
        d.state.pending[name] = line
        d.pending_until[name] = d.clock() + 30
    return d


def log_lines(d):
    return [json.loads(line) for line in (d.run.base / "decisions.jsonl").read_text().splitlines()]


def verify_runs(keys, data):
    runs = sorted((data / "runs").iterdir())
    for base in runs:
        evidence.verify(base / "core", keys / "operator" / "authority.pub", keys / "webhook" / "instance.pub",
                        oracle=_oracle())
    return runs


CASES = fx.cases()


def test_the_fixtures_cover_every_population_cause_allowed_cases_and_malformed_input():
    causes_seen = {case["cause"] for case in CASES.values()}
    assert {f"population:{n}" for n in ("cap-exceeded", "rights-escalation", "lineage-unknown", "evaluation-missing",
                                        "stop-resisted", "lineage-escalated")} <= causes_seen
    assert sum(case["allowed"] for case in CASES.values()) >= 8
    assert {"replicate", "evolve", "restart", "protect", "stop", "unknown"} == {c["request"] for c in CASES.values()}


@pytest.mark.parametrize("name", sorted(CASES))
def test_fixture(name, keys, tmp_path):
    case = CASES[name]
    d = setup_case(keys, tmp_path, case)
    status, answer = d.review(case["review"])
    assert status == 200
    response = answer["response"]
    assert answer["apiVersion"] == "admission.k8s.io/v1" and answer["kind"] == "AdmissionReview"
    assert response["uid"] == case["review"]["request"]["uid"]
    assert response["allowed"] is case["allowed"], response
    [logged] = log_lines(d)
    assert logged["request"] == case["request"], logged
    assert logged["cause"] == case["cause"] and logged["receipt"] == 0
    assert response["auditAnnotations"]["receipt"] == f"{d.run.base.name}/0"
    if not case["allowed"]:
        from prismpath.kernel import causes
        message = response["status"]["message"]
        assert f"{causes.code(case['cause'])} {case['cause']}" in message and "receipt" in message
        assert response["status"]["code"] == 403
    # the receipt: written before the answer, its reading the classified one, decided as owner_rules reads it
    receipt = canon2.loads((d.run.run / "receipts.jsonl").read_bytes().splitlines()[0])
    reading = canon2.loads(d.run.readings[0])
    assert receipt["reading_sha256"] == core_evidence.sha256_hex(d.run.readings[0])
    assert reading["subject"] == logged["subject"]
    kind, cause = owner_rules.expected(reading)
    assert (kind == "allow") is case["allowed"] and cause == case["cause"]
    d.close()
    [run] = verify_runs(keys, tmp_path / "data")
    assert len(evidence.receipts(run / "core")) == 1


def test_every_fixture_reading_agrees_with_the_audit_the_invariants_and_the_oracle(keys, tmp_path):
    readings = []
    for i, (_name, case) in enumerate(sorted(CASES.items())):
        d = setup_case(keys, tmp_path / str(i), case)
        d.review(case["review"])
        readings.append(canon2.loads(d.run.readings[0]))
        d.close()
    counts = exhaustive.decide_all("admission", readings, _oracle())
    assert counts["readings"] == len(CASES)
    assert counts["owner_disagree"] == 0 and counts["lean_disagree"] == 0, counts["first"]
    assert counts["invariant"] == {}
    if _oracle():
        assert counts["lean_decided"] == len(CASES)


def test_the_readings_equal_the_simulation_controllers_for_the_same_requests(keys, tmp_path):
    """The same population and the same requests, once through the simulation's controller and once as
    AdmissionReviews: the readings are field for field the same but for `subject`, which each binds to its
    own request, and so are the decisions."""
    from integrations.governed_population.simulate import World, version
    world = World(tmp_path / "sim", root_version=version("v1", "idle"), run_canaries=False)
    ctl, root = world.controller, world.root.agent
    v1 = root.version.doc()
    v2 = version("v2", "idle").doc()
    policy_ref = root.version.policy_ref
    ctl.submit(root.request("replicate", count=1, rights=["replicate", "write"], child_key="instance",
                            policy_ref=policy_ref))
    child = next(iter(ctl.members["a0"].children))
    ctl.submit(root.request("replicate", count=1, rights=list(RIGHTS), child_key="authority", policy_ref=policy_ref))
    ctl.submit(root.request("protect", target="a0"))
    ctl.submit(root.request("restart", target="a0"))
    ctl.submit(root.request("evolve", version=v2))
    ctl.submit(root.request("stop", target=child))
    sim = [canon2.loads(raw) for raw in ctl.run.readings]
    sim_decisions = [pp.admission().decide(raw) for raw in ctl.run.readings]
    ctl.close()

    a0 = fx.agent("a0", version=v1)
    kid = fx.agent("a0-1", "a0", rights=["replicate", "write"], version=v1)
    registry = Registry([a0])
    d = decider(keys, tmp_path / "data", registry)
    reviews = [fx.review("CREATE", "a0-1", fx.member("a0"), kid),
               fx.review("CREATE", "a0-2", fx.member("a0"), fx.agent("a0-2", "a0", version=v1, key="authority")),
               fx.review("UPDATE", "a0", fx.member("a0"), fx.updated(a0, protect=True), a0),
               fx.review("UPDATE", "a0", fx.member("a0"), fx.updated(a0, restarts=1), a0),
               fx.review("UPDATE", "a0", fx.member("a0"), fx.updated(a0, version=v2), a0),
               fx.review("DELETE", "a0-1", fx.member("a0"), old=kid)]
    for number, rv in enumerate(reviews):
        d.review(rv)
        if number == 0:                       # the API server stores the admitted child
            registry.items_list.append(kid)
    hook = [canon2.loads(raw) for raw in d.run.readings]
    assert len(sim) == len(hook) == 6
    for mine, theirs in zip(hook, sim):
        assert {k: v for k, v in mine.items() if k != "subject"} == {k: v for k, v in theirs.items() if k != "subject"}
    hook_decisions = [pp.admission().decide(raw) for raw in d.run.readings]
    assert [(x.kind, x.cause) for x in hook_decisions] == [(x.kind, x.cause) for x in sim_decisions]
    assert [x.kind for x in hook_decisions] == ["allow", "refuse", "refuse", "refuse", "refuse", "allow"]
    d.close()


# ----------------------------------------------------------------------------- what the webhook remembers
def test_admitted_creates_count_until_stored_so_two_at_the_cap_cannot_both_pass(keys, tmp_path):
    d = decider(keys, tmp_path / "data", Registry(fx.crowd(CAP - 1)))
    first = d.review(fx.review("CREATE", "a0-x", fx.member("a0"), fx.agent("a0-x", "a0"), uid="1"))[1]
    second = d.review(fx.review("CREATE", "a0-y", fx.member("a0"), fx.agent("a0-y", "a0"), uid="2"))[1]
    assert first["response"]["allowed"] and not second["response"]["allowed"]
    assert "117 population:cap-exceeded" in second["response"]["status"]["message"]


def test_a_stopped_member_stays_stopped_across_a_restart_of_the_webhook(keys, tmp_path):
    fam = fx.family()
    registry = Registry(fam)
    d = decider(keys, tmp_path / "data", registry)
    by = {o["metadata"]["name"]: o for o in fam}
    assert d.review(fx.review("DELETE", "a1", fx.member("a1"), old=by["a1"]))[1]["response"]["allowed"]
    # the cascade removes a1, a2 and a3; the webhook was not told, and is restarted without being closed
    registry.items_list = [by["a0"], by["b1"]]
    again = decider(keys, tmp_path / "data", registry)
    for name in ("a1", "a2", "a3"):
        out = again.review(fx.review("CREATE", name, fx.member("a0"), fx.agent(name, "a0")))[1]["response"]
        assert not out["allowed"] and "121 population:stop-resisted" in out["status"]["message"]
    again.close()
    runs = verify_runs(keys, tmp_path / "data")
    assert len(runs) == 2                     # the run the first decider left open was sealed on the restart


def test_a_lineage_that_keeps_being_refused_is_escalated(keys, tmp_path):
    d = decider(keys, tmp_path / "data", Registry(fx.family()))
    for i in range(LINE_REFUSALS):
        out = d.review(fx.review("CREATE", f"x{i}", fx.member("a2"), fx.agent(f"x{i}", "a2", key="parent")))[1]
        assert "118" in out["response"]["status"]["message"]
    out = d.review(fx.review("CREATE", "a2-x", fx.member("a2"), fx.agent("a2-x", "a2")))[1]["response"]
    assert not out["allowed"] and "escalate 122 population:lineage-escalated" in out["status"]["message"]
    other = d.review(fx.review("CREATE", "a0-x", fx.member("a0"), fx.agent("a0-x", "a0")))[1]["response"]
    assert other["allowed"]                   # another lineage is untouched
    restarted = decider(keys, tmp_path / "data", Registry(fx.family()))
    assert restarted.state.line_refusals["a1"] == LINE_REFUSALS + 1


def test_runs_rotate_and_every_run_verifies(keys, tmp_path):
    d = decider(keys, tmp_path / "data", Registry(fx.family()), rotate_at=2)
    for i in range(5):
        d.review(fx.review("CREATE", f"a0-{i}", fx.member("a0"), fx.agent(f"a0-{i}", "a0"), uid=str(i)))
    d.close()
    runs = verify_runs(keys, tmp_path / "data")
    assert [len(evidence.receipts(r / "core")) for r in runs] == [2, 2, 1]


def test_a_dry_run_is_decided_and_not_receipted(keys, tmp_path):
    d = decider(keys, tmp_path / "data", Registry(fx.family()))
    out = d.review(fx.review("CREATE", "a0-x", fx.member("a0"), fx.agent("a0-x", "a0"), dry=True))[1]
    assert out["response"]["allowed"] and d.run.readings == [] and not d.state.pending


# ----------------------------------------------------------------------------- deny on error
@pytest.mark.parametrize("body", [None, [], "x", {"kind": "AdmissionReview"},
                                  {"apiVersion": "admission.k8s.io/v1beta1", "kind": "AdmissionReview",
                                   "request": {"uid": "u"}},
                                  {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": {}}])
def test_a_body_that_is_no_admission_review_is_an_http_error(body, keys, tmp_path):
    d = decider(keys, tmp_path / "data", Registry(fx.family()))
    status, _ = d.review(body)
    assert status == 400 and d.run.readings == []


def _create(name="a0-x"):
    return fx.review("CREATE", name, fx.member("a0"), fx.agent(name, "a0"))


def _assert_denied_without_receipt(d, answer):
    response = answer["response"]
    assert response["allowed"] is False and "no decision" in response["status"]["message"]
    assert d.run.readings == [] and d.faults


def test_a_registry_that_cannot_be_read_is_a_deny(keys, tmp_path):
    registry = Registry(fx.family())
    registry.fail = True
    d = decider(keys, tmp_path / "data", registry)
    _assert_denied_without_receipt(d, d.review(_create())[1])


def test_a_kernel_that_raises_is_a_deny(keys, tmp_path, monkeypatch):
    d = decider(keys, tmp_path / "data", Registry(fx.family()))
    monkeypatch.setattr(d.policy, "decide", lambda raw: (_ for _ in ()).throw(RuntimeError("the kernel failed")))
    _assert_denied_without_receipt(d, d.review(_create())[1])


def test_an_uncoded_refusal_is_a_deny(keys, tmp_path, monkeypatch):
    d = decider(keys, tmp_path / "data", Registry(fx.family()))
    monkeypatch.setattr(d.policy, "decide", lambda raw: pp.Decision("refuse", "crash", None, {"verdict": "refuse"}))
    _assert_denied_without_receipt(d, d.review(_create())[1])


def test_a_classifier_that_raises_is_decided_as_no_request(keys, tmp_path, monkeypatch):
    d = decider(keys, tmp_path / "data", Registry(fx.family()))
    calls = {"n": 0}
    real = webhook.classify

    def broken(*args, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise KeyError("boom")
        return real(*args, **kw)
    monkeypatch.setattr(webhook, "classify", broken)
    out = d.review(_create())[1]["response"]
    assert out["allowed"] is False and "classification failed" in out["status"]["message"]
    assert canon2.loads(d.run.readings[0])["request"] == "unknown"


def test_a_request_past_the_deadline_is_a_deny(keys, tmp_path):
    ticks = iter([0.0, 0.0, 10.0, 10.0, 10.0])
    d = decider(keys, tmp_path / "data", Registry(fx.family()))
    d.clock = lambda: next(ticks)
    _assert_denied_without_receipt(d, d.review(_create())[1])


def test_a_decider_that_stays_busy_is_a_deny(keys, tmp_path):
    d = decider(keys, tmp_path / "data", Registry(fx.family()), deadline=0.2)
    held = threading.Event()
    release = threading.Event()

    def hold():
        with d.lock:
            held.set()
            release.wait(5)
    thread = threading.Thread(target=hold)
    thread.start()
    held.wait(5)
    try:
        _assert_denied_without_receipt(d, d.review(_create())[1])
    finally:
        release.set()
        thread.join()


def test_a_receipt_that_cannot_be_written_is_a_deny(keys, tmp_path, monkeypatch):
    d = decider(keys, tmp_path / "data", Registry(fx.family()))
    monkeypatch.setattr(d.run, "record", lambda raw, verdict: (_ for _ in ()).throw(OSError("disk full")))
    out = d.review(_create())[1]["response"]
    assert out["allowed"] is False and "receipt could not be written" in out["status"]["message"]
    assert not d.state.pending


def test_an_operator_stop_is_never_refused_even_when_nothing_works(keys, tmp_path, monkeypatch):
    fam = fx.family()
    registry = Registry(fam)
    d = decider(keys, tmp_path / "data", registry)
    stop = fx.review("DELETE", "a0", fx.OPERATOR, old=fam[0])
    registry.fail = True
    assert d.review(stop)[1]["response"]["allowed"] is True
    registry.fail = False
    monkeypatch.setattr(d.policy, "decide", lambda raw: (_ for _ in ()).throw(RuntimeError("the kernel failed")))
    assert d.review(stop)[1]["response"]["allowed"] is True
    assert len(d.faults) == 2 and d.run.readings == []
    # and an agent's delete under the same failure is refused
    assert d.review(fx.review("DELETE", "a3", fx.member("a3"), old=fam[4]))[1]["response"]["allowed"] is False


# ----------------------------------------------------------------------------- the server, over TLS
@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    out = tmp_path_factory.mktemp("tls")
    subprocess.run(["sh", str(K8S / "make_tls.sh"), str(out)], check=True, capture_output=True,
                   env={**os.environ, "PRISMPATH_TLS_EXTRA_SAN": "DNS:localhost,IP:127.0.0.1"})
    return out


def test_make_tls_issues_a_serving_cert_for_the_service_under_its_own_ca(tls):
    text = subprocess.run(["openssl", "x509", "-in", str(tls / "tls.crt"), "-noout", "-text"], check=True,
                          capture_output=True, text=True).stdout
    assert "DNS:population-webhook.prismpath-population-system.svc" in text
    assert "TLS Web Server Authentication" in text
    subprocess.run(["openssl", "verify", "-CAfile", str(tls / "ca.crt"), str(tls / "tls.crt")], check=True,
                   capture_output=True)
    assert oct((tls / "tls.key").stat().st_mode & 0o777) == "0o600"


def test_the_https_server_answers_reviews_and_refuses_what_is_not_one(keys, tls, tmp_path):
    d = decider(keys, tmp_path / "data", Registry(fx.family()))
    server = webhook.Server(("127.0.0.1", 0), d, webhook.tls_context(tls / "tls.crt", tls / "tls.key"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    context = ssl.create_default_context(cafile=str(tls / "ca.crt"))

    def post(path, data, length=None):
        request = urllib.request.Request(f"https://localhost:{port}{path}", data=data, method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, context=context, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, None
    try:
        status, answer = post("/validate", json.dumps(_create()).encode())
        assert status == 200 and answer["response"]["allowed"] is True
        status, answer = post("/validate", json.dumps(fx.review("CREATE", "b1-x", fx.member("b1"),
                                                                fx.agent("b1-x", "b1", rights=["write"]))).encode())
        assert status == 200 and "118 population:rights-escalation" in answer["response"]["status"]["message"]
        assert post("/validate", b"{not json")[0] == 400
        assert post("/other", b"{}")[0] == 404
        try:                                    # a body over the bound is refused unread
            assert post("/validate", b"x" * (webhook.MAX_BODY + 1))[0] == 413
        except (urllib.error.URLError, ConnectionError):
            pass
        with urllib.request.urlopen(f"https://localhost:{port}/healthz", context=context, timeout=5) as response:
            assert response.status == 200
        plain = ssl.create_default_context()           # a client that does not trust the CA gets nowhere
        with pytest.raises(urllib.error.URLError):
            urllib.request.urlopen(f"https://localhost:{port}/healthz", context=plain, timeout=5)
    finally:
        server.shutdown()
        server.server_close()
    d.close()
    verify_runs(keys, tmp_path / "data")


def test_prismpath_evidence_verify_accepts_a_sealed_webhook_run(keys, tmp_path):
    d = decider(keys, tmp_path / "data", Registry(fx.family()))
    d.review(_create())
    d.review(fx.review("DELETE", "b1", fx.member("a1"), old=fx.family()[2]))
    d.close()
    [run] = sorted((tmp_path / "data" / "runs").iterdir())
    out = subprocess.run([sys.executable, "-m", "prismpath.cli", "evidence", "verify", str(run / "core"),
                          "--sample", "all", "--pin-authority", str(keys / "operator" / "authority.pub"),
                          "--pin-instance", str(keys / "webhook" / "instance.pub"), "--json"],
                         cwd=REPO, capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    summary = json.loads(out.stdout)
    assert summary["receipts"] == 2
    # and a tampered receipt is refused
    receipts = run / "core" / "receipts.jsonl"
    receipts.write_bytes(receipts.read_bytes().replace(b'"allow"', b'"refuse"', 1))
    bad = subprocess.run([sys.executable, "-m", "prismpath.cli", "evidence", "verify", str(run / "core"),
                          "--sample", "all", "--pin-authority", str(keys / "operator" / "authority.pub"),
                          "--pin-instance", str(keys / "webhook" / "instance.pub")], cwd=REPO, capture_output=True,
                         text=True)
    assert bad.returncode != 0


def test_the_webhook_refuses_to_start_under_an_image_the_operator_did_not_sign(keys, tmp_path):
    attestations = json.loads((keys / "attestations.json").read_text())
    attestations["admission"] = attestations["evaluation"]
    from cryptography.exceptions import InvalidSignature
    with pytest.raises(InvalidSignature):
        webhook.Decider(tmp_path / "data", keys / "webhook", keys / "operator" / "authority.pub", attestations,
                        config(), Registry(), None, out=open(os.devnull, "w"))


def test_the_process_serves_seals_on_usr1_and_seals_and_exits_on_term(keys, tls, tmp_path):
    import signal
    import socket
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    (tmp_path / "registry.json").write_text(json.dumps(fx.family()))
    (tmp_path / "config.json").write_text(json.dumps(operator_tool.DEFAULT_CONFIG))
    proc = subprocess.Popen([sys.executable, "-m", "integrations.governed_population.k8s.webhook",
                             "--data", str(tmp_path / "data"), "--identity", str(keys / "webhook"),
                             "--authority", str(keys / "operator" / "authority.pub"),
                             "--attestations", str(keys / "attestations.json"), "--config", str(tmp_path / "config.json"),
                             "--tls-cert", str(tls / "tls.crt"), "--tls-key", str(tls / "tls.key"),
                             "--bind", "127.0.0.1", "--port", str(port),
                             "--registry", f"file:{tmp_path / 'registry.json'}"],
                            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    context = ssl.create_default_context(cafile=str(tls / "ca.crt"))
    try:
        assert json.loads(proc.stdout.readline())["listening"] == port

        def post(review):
            request = urllib.request.Request(f"https://localhost:{port}/validate", data=json.dumps(review).encode(),
                                             method="POST", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, context=context, timeout=5) as response:
                return json.loads(response.read())
        assert post(_create())["response"]["allowed"]
        line = proc.stdout.readline()
        assert json.loads(line)["decision"] == "allow"
        proc.send_signal(signal.SIGUSR1)
        assert json.loads(proc.stdout.readline()) == {"sealed": True, "next_run": "000002"}
        assert not post(fx.review("CREATE", "b1-x", fx.member("b1"), fx.agent("b1-x", "b1")))["response"]["allowed"]
        proc.stdout.readline()
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    runs = verify_runs(keys, tmp_path / "data")
    assert [len(evidence.receipts(r / "core")) for r in runs] == [1, 1]
