# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Flow execution, resumption, fan-out composition, and audit trail commands."""
import argparse
import os

from prismpath.cli.common import CliError, cause_code, named_causes, parse_flow, require_file
from prismpath.kernel.engine import run


def _add_authorization_args(parser) -> None:
    """The flags `run` and `resume` share for requiring an authorized flow."""
    parser.add_argument('--require-authorization', dest='require_authorization', action='store_true',
                        help='refuse a flow whose flow manifest is missing, edited after signing, signed by an unknown '
                             'or revoked authority key, or older than a version already accepted (exit 2); also '
                             'PRISMPATH_REQUIRE_AUTHORIZATION=1')
    parser.add_argument('--authority-pub', dest='authority_pub', nargs='+', default=None, metavar='PUB',
                        help='trusted authority public key(s) (`swap keygen`); default: PRISMPATH_AUTHORITY_PUB, '
                             'paths separated by the platform path separator')
    parser.add_argument('--revoked', default=None, help='revocation list JSON of authority key ids')
    parser.add_argument('--state-dir', dest='state_dir', default=None, metavar='DIR',
                        help='where the accepted flow versions are kept (default: PRISMPATH_STATE_DIR, else ./.prismpath)')


def _add_receipt_args(parser) -> None:
    """The flags `run` and `resume` share for writing signed receipts."""
    parser.add_argument('--audit-log', dest='audit_log', default=None, metavar='PATH',
                        help='append one receipt per decision to this audit log (JSONL, Merkle rooted; '
                             '`prismpath trail` reads it)')
    parser.add_argument('--instance-key', dest='instance_key', default=None, metavar='KEY',
                        help='the deployment\'s instance private key (`prismpath ledger keygen`): sign a root '
                             'statement over the audit log at the end of the run (default: '
                             '$PRISMPATH_INSTANCE_KEY, else the deployment\'s own key in the state directory; '
                             'without one the receipts are written unsigned)')


def register(subparsers) -> None:
    run_parser = subparsers.add_parser('run', help='Parse the flow and run it (mock worker by default; '
                                                   '--worker ollama:MODEL for a real local model)')
    run_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    run_parser.add_argument('--type-gate', action='store_true',
                            help='validate each worker output against the derived contract (contract.py)')
    # The dictionary's word for whatever produces a node's outcome is worker, so that is the flag a
    # reader meets. The dest keeps the older spelling on purpose: the hidden alias below has to land on
    # the same attribute, and nothing downstream of the parser should move for a surface rename.
    run_parser.add_argument('--worker', dest='agent', default=None, metavar='SPEC',
                            help='real worker instead of the mock: `ollama:llama3.2` (local Ollama) '
                                 'or `openai:MODEL@BASE` (any OpenAI-compatible endpoint - vLLM, '
                                 'LM Studio, llama.cpp). JSON replies feed `when` predicates; '
                                 'failures ride the flow\'s `on error` edges')
    run_parser.add_argument('--agent', dest='agent', default=None, metavar='SPEC',
                            help=argparse.SUPPRESS)
    _add_receipt_args(run_parser)
    _add_authorization_args(run_parser)
    run_parser.set_defaults(func=run_flow)

    resume_parser = subparsers.add_parser(
        'resume', help='Resume a suspended/crashed run from a JSON checkpoint (mock agent); like run, it checks '
                      'authorization and writes signed receipts with --audit-log')
    resume_parser.add_argument('checkpoint', type=str, help='Path to the checkpoint JSON')
    resume_parser.add_argument('--choose', default=None,
                               help='the edge target a human picks (for a needs_human suspension)')
    _add_receipt_args(resume_parser)
    _add_authorization_args(resume_parser)
    resume_parser.set_defaults(func=resume_flow)

    compose_parser = subparsers.add_parser(
        'compose', help='Advance pending fan-out/composition runs in the queue: spawn children, '
                        'join, resume parents (the out-of-band harness tick - item #4); a flow without its '
                        'authorization is refused when authorization is required')
    compose_parser.add_argument('--queue', default=None,
                                help='queue dir to scan (default: the prismpath queue dir)')
    _add_authorization_args(compose_parser)
    compose_parser.set_defaults(func=compose_cmd)

    from prismpath import trail as _trail
    _trail.add_parser(subparsers)


def _require_runnable(graph, path: str) -> None:
    """Refuse to run a flow whose start or edge targets name nodes it does not define; the engine
    would otherwise stop on a bare KeyError. `prismpath validate` reports the same findings."""
    if not graph.nodes:
        raise CliError(f"{path} defines no nodes (a node is a `## name` heading); "
                       f"see `prismpath validate {path}`")
    problems = []
    if graph.start not in graph.nodes:
        problems.append(f"start node {graph.start!r} is not defined")
    for name, node_obj in graph.nodes.items():
        for target, _condition in node_obj.edges:
            if target not in graph.nodes:
                problems.append(f"[{name}] edge -> {target!r} points at an undefined node")
    if problems:
        more = f" (and {len(problems) - 1} more)" if len(problems) > 1 else ""
        raise CliError(f"{path} cannot run: {problems[0]}{more}; see `prismpath validate {path}`")


def _mock_agent(node, instruction, state):
    return {'text': node, 'tests_pass': True, 'always': True}


def _instance_key_for(args):
    """The instance key `run` signs with: --instance-key, else $PRISMPATH_INSTANCE_KEY, else the deployment's
    own key in the state directory (`<state dir>/instance.key`, ./.prismpath by default), else None. The key
    found in the state directory is named on stdout, so signing by default is never silent."""
    from prismpath.ledgers import root_statement
    path = getattr(args, "instance_key", None) or os.environ.get(root_statement.INSTANCE_KEY_ENV, "").strip()
    if not path:
        default = os.path.join(_state_dir(args), root_statement.DEFAULT_KEY_NAME + ".key")
        if not os.path.exists(default):
            return None
        key = root_statement.InstanceKey.load(default)
        print(f"Signing with the deployment's instance key {key.fingerprint}, found at {default}")
        return key
    require_file(path)
    return root_statement.InstanceKey.load(path)


def _receipts_of(result, graph, run_id: str, policy: dict, skip: int = 0, extra: dict = None) -> list:
    """One receipt per decision the run made: each routed step with cause 0, and the stop itself when
    the run refused, parked or escalated, with the registry cause the engine set. `skip` leaves out the
    first steps, the ones a resumed run took before it was suspended and already has receipts for; `seq`
    stays the step's position in the whole run. `extra` fields ride on every receipt."""
    receipts = []
    for seq, step in enumerate(result.steps):
        if seq < skip:
            continue
        receipts.append({"run": run_id, "seq": seq, "node": step.node, "target": step.target,
                         "how": step.info.get("used"), "rule": step.info.get("cond"), "outcome": step.target,
                         "cause": 0, "policy": policy, **(extra or {})})
    if result.cause:
        receipts.append({"run": run_id, "seq": len(result.steps), "node": result.path[-1], "target": None,
                         "how": result.stopped, "rule": None, "outcome": result.stopped,
                         "cause": int(result.cause), "policy": policy, **(extra or {})})
    return receipts


def _authority_pubs(args) -> list:
    from prismpath.hotswap import flow_authority
    pubs = list(getattr(args, "authority_pub", None) or [])
    if not pubs:
        pubs = [path for path in os.environ.get(flow_authority.AUTHORITY_PUB_ENV, "").split(os.pathsep) if path.strip()]
    for path in pubs:
        require_file(path)
    return pubs


def _authorization_required(args) -> bool:
    from prismpath.hotswap import flow_authority
    return bool(getattr(args, "require_authorization", False)) or \
        os.environ.get(flow_authority.REQUIRE_ENV, "").strip().lower() in ("1", "true", "yes")


def _state_dir(args) -> str:
    from prismpath.hotswap import flow_authority
    return (getattr(args, "state_dir", None) or os.environ.get(flow_authority.STATE_DIR_ENV, "").strip()
            or flow_authority.DEFAULT_STATE_DIR)


class _Refused(Exception):
    """The flow is not authorized and authorization is required; `causes` are registry names."""

    def __init__(self, causes_named, manifest):
        super().__init__(",".join(causes_named))
        self.causes = list(causes_named)
        self.manifest = manifest


def _policy_of(args):
    """The authorization policy these flags and the environment name, as the library check takes it.
    Required without an authority key to check against is a mistake in the command, said once here."""
    from prismpath.hotswap import flow_authority
    policy = flow_authority.AuthorizationPolicy(
        required=_authorization_required(args), authority_pubs=_authority_pubs(args),
        revoked=getattr(args, "revoked", None), state_dir=_state_dir(args))
    if policy.required and not policy.authority_pubs:
        raise CliError("--require-authorization needs the trusted authority key: pass --authority-pub PUB "
                       "or set PRISMPATH_AUTHORITY_PUB")
    return policy


def _check_authorization(args, flow_path: str, instance_key=None):
    """Decide whether this flow may run. Returns what the receipts and the root statement record as the
    authorization in force, and prints one line saying what was checked. Raises _Refused when
    authorization is required and the flow does not have it; when it is not required, a flow manifest
    that is present is still verified (given authority keys) and the result reported, never ignored.
    The check itself is `flow_authority.authorize_flow`, the one library callers use."""
    from prismpath.hotswap import flow_authority
    policy = _policy_of(args)
    try:
        authorization = flow_authority.authorize_flow(flow_path, policy, instance_key)
    except flow_authority.AuthorizationConfigError as same_key:
        raise CliError(f"refused: {same_key}") from same_key
    except flow_authority.FlowNotAuthorized as refused:
        raise _Refused(refused.causes, refused.manifest) from refused
    manifest = authorization.manifest
    if authorization.status == flow_authority.UNCHECKED:
        print(f"Authorization: a flow manifest is present (version {(manifest or {}).get('version')}, authority key "
              f"{str((manifest or {}).get('key_id'))[:16]}), not checked: pass --authority-pub to verify it")
    elif authorization.status == flow_authority.FAILED:
        print(f"Authorization: NOT verified: {named_causes(authorization.reasons)}; not required, so the run proceeds unauthorized")
    elif authorization.status == flow_authority.VERIFIED:
        print(f"Authorization: verified, {manifest['flow']} version {manifest['version']} by authority key "
              f"{manifest['key_id'][:16]} (flow manifest {flow_authority.manifest_sha256(manifest)[:16]})")
    return authorization.record


def _flow_policy_identity(path: str, graph, authorization) -> dict:
    from prismpath.hotswap import flow_authority
    return {"flow": graph.name, "flow_sha256": flow_authority.flow_sha256(path), "authorization": authorization}


def run_flow(args) -> int:
    graph = parse_flow(args.flow_md)
    _require_runnable(graph, args.flow_md)
    audit_path = getattr(args, "audit_log", None)
    if not audit_path and getattr(args, "instance_key", None):
        raise CliError("--instance-key signs the run's receipts; pass --audit-log PATH as well")
    instance_key = _instance_key_for(args) if audit_path else None
    try:
        authorization = _check_authorization(args, args.flow_md, instance_key)
    except _Refused as refused:
        policy = _flow_policy_identity(args.flow_md, graph, "unauthorized")
        if audit_path:
            _write_refusal(audit_path, instance_key, graph, policy, refused.causes)
        raise CliError(f"refused: the flow is not authorized: {named_causes(refused.causes)}") from refused
    policy = _flow_policy_identity(args.flow_md, graph, authorization)
    agent = _mock_agent
    if getattr(args, "agent", None):
        from prismpath.workers.chat_agent import chat_agent
        try:
            agent = chat_agent(args.agent)
        except ValueError as exc:
            print(f"✗ {exc}")
            return 2
    result = run(graph, agent, type_gate=getattr(args, "type_gate", False))
    print(f"Path: {result.path}")
    print(f"Stopped Reason: {result.stopped}")
    if result.stopped == "contract_violation" and result.pending:
        for violation in result.pending.get("violations", []):
            print(f"  ✗ [{result.pending['node']}] {violation}")
    if audit_path:
        _write_receipts(audit_path, instance_key, result, graph, policy)
    elif os.environ.get("PRISMPATH_INSTANCE_KEY", "").strip():
        print("Not signed: no receipts were written (PRISMPATH_INSTANCE_KEY is set; pass --audit-log PATH)")
    return 1 if result.stopped == "contract_violation" else 0


def _write_refusal(audit_path: str, instance_key, graph, policy: dict, refusal_causes, node: str = None,
                   extra: dict = None) -> None:
    """A refusal to run is a decision too: one receipt with the first registry cause, signed like any."""
    import uuid
    from prismpath.ledgers.audit_log import AuditLog
    log = AuditLog(audit_path, instance_key=instance_key)
    first = refusal_causes[0]
    log.append("engine", "decision", {"run": uuid.uuid4().hex[:12], "seq": 0, "node": node or graph.start, "target": None,
                                      "how": "authorization", "rule": None, "outcome": "refused",
                                      "cause": cause_code(first) or 0,
                                      "refusal": list(refusal_causes), "policy": policy, **(extra or {})})
    statement = log.checkpoint("run-refused", policy)
    print(f"Receipts: the refusal appended to {audit_path}"
          + (f", signed in root statement {statement['seq']}" if statement else ", not signed (no instance key)"))


def _write_receipts(audit_path: str, instance_key, result, graph, policy: dict, skip: int = 0,
                    trigger: str = "run-end", extra: dict = None) -> None:
    import uuid
    from prismpath.ledgers.audit_log import AuditLog
    log = AuditLog(audit_path, instance_key=instance_key)
    receipts = _receipts_of(result, graph, uuid.uuid4().hex[:12], policy, skip=skip, extra=extra)
    for receipt in receipts:
        log.append("engine", "decision", receipt)
    print(f"Receipts: {len(receipts)} appended to {audit_path} ({len(log.events)} in the log), "
          f"root {log.current_root()[:16] or '(empty)'}")
    statement = log.checkpoint(trigger, policy)
    if statement is not None:
        print(f"Signed: root statement {statement['seq']} over {statement['leaves']} events by instance key "
              f"{instance_key.fingerprint}, in {log.statements_path}")
    elif instance_key is None:
        print("Not signed: no instance key (pass --instance-key KEY, set PRISMPATH_INSTANCE_KEY, or create the "
              "deployment's own with `prismpath ledger keygen --out .prismpath`); "
              "the receipts carry a Merkle root and no signature")


def resume_flow(args) -> int:
    """Resume a suspended run. Like `run`, it checks the flow's authorization, writes a receipt per decision
    it takes (and a refusal receipt when the flow is not authorized), and signs the root at the end with the
    instance key. The receipts are the steps taken since the suspension; `seq` continues from the steps
    before it and each carries `resumed`, so a reader can tell where the earlier receipts end."""
    from prismpath.ledgers import checkpoint
    audit_path = getattr(args, "audit_log", None)
    if not audit_path and getattr(args, "instance_key", None):
        raise CliError("--instance-key signs the run's receipts; pass --audit-log PATH as well")
    try:
        saved = checkpoint.load_checkpoint(args.checkpoint)
        flow_path = saved["flow_path"]
    except checkpoint.CheckpointError as exc:
        print(f"cannot resume: {exc}")
        return 1
    instance_key = _instance_key_for(args) if audit_path else None
    graph = parse_flow(flow_path) if audit_path else None
    skip = len(saved.get("steps", []))
    marker = {"resumed": True, "prior_steps": skip}
    try:
        authorization = _check_authorization(args, flow_path, instance_key)
    except _Refused as refused:
        if audit_path:
            _write_refusal(audit_path, instance_key, graph, _flow_policy_identity(flow_path, graph, "unauthorized"),
                           refused.causes, node=saved.get("pending_node"), extra=marker)
        raise CliError(f"refused: the flow is not authorized: {named_causes(refused.causes)}") from refused
    try:
        result = checkpoint.resume(args.checkpoint, _mock_agent, choose=args.choose, policy=_policy_of(args))
    except checkpoint.CheckpointError as exc:
        print(f"cannot resume: {exc}")
        return 1
    print(f"Path: {result.path}")
    print(f"Stopped Reason: {result.stopped}")
    if result.pending:
        cands = [cand.get('target') for cand in result.pending.get('candidates', [])]
        print(f"Awaiting human - candidates: {cands}  (resume with --choose <edge>)")
    if audit_path:
        _write_receipts(audit_path, instance_key, result, graph, _flow_policy_identity(flow_path, graph, authorization),
                        skip=skip, trigger="resume-end", extra=marker)
    elif os.environ.get("PRISMPATH_INSTANCE_KEY", "").strip():
        print("Not signed: no receipts were written (PRISMPATH_INSTANCE_KEY is set; pass --audit-log PATH)")
    return 0


def compose_cmd(args) -> int:
    """Advance every pending fan-out in the queue by one tick: spawn/poll children and, where a join is
    ready, aggregate + resume the parent. The out-of-band harness a deployment runs on a schedule
    (mirrors the timeout scanner). Uses the mock agent, like `run`/`resume`. Each fan-out's parent flow
    and child flow are checked for authorization before anything is spawned or resumed (the flags and
    environment `run` takes); a fan-out whose flow is refused is left as it was, named, and the exit
    code is 2."""
    from prismpath.workers import composer
    recs = composer.advance_fanouts(_mock_agent, qdir=args.queue, policy=_policy_of(args))
    refused = 0
    for record in recs:
        if record.get("refused"):
            refused += 1
            print(f"  ✗ {record['path']}: refused: {record['flow']} is not authorized: {named_causes(record['refused'])}")
        elif record.get("error"):
            print(f"  ✗ {record['path']}: {record['error']}")
        elif record.get("joined"):
            print(f"  [{record.get('node')}] {record.get('done', 0)}/{record.get('spawned', 0)} children done "
                  f"-> joined ({record.get('event')}), parent resumed")
        else:
            print(f"  [{record.get('node')}] {record.get('done', 0)}/{record.get('spawned', 0)} children done "
                  f"-> still waiting")
    print(f"advanced {len(recs) - refused} fan-out(s)" + (f", refused {refused}" if refused else ""))
    return 2 if refused else 0
