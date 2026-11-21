# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath gateway`: serve the reverse proxy in front of a resource, record its attested policy, verify its run.

    prismpath gateway init   [--home DIR] [--policy FILE]        keys, and the policy recorded and attested
    prismpath gateway        --upstream URL --listen ADDR ...    serve (the default action)
    prismpath gateway verify [--home DIR]                        seal and verify every run, every receipt replayed
    prismpath gateway rules  [--home DIR]                        the rules with their hit counts, from the receipts

The home holds what `prismpath agent init` makes (`authority` and `instance` keys, `policy.core.json`, its
attestation under the authority key, `runs/`), under `<config>/prismpath/gateway` unless `--home` names another.
`init --policy` takes a compiled `.core.json` image or a `.rules.md` source (compiled here); without it the shipped
demo policy is recorded.
"""
from __future__ import annotations

import json
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional

HERE = Path(__file__).resolve().parent
DEMO_POLICY = HERE / "policy" / "demo.core.json"
DEMO_ROUTES = HERE / "policy" / "demo.routes.json"


def add_parser(subparsers) -> None:
    gateway = subparsers.add_parser(
        'gateway', help='Protect a resource: an HTTP reverse proxy that has the core decide every request under an '
                        'attested policy and receipts the decision, whoever the client is (serve, init, verify, rules)')
    gateway.add_argument('action', nargs='?', choices=('serve', 'init', 'verify', 'rules'), default='serve',
                         help='serve (the default), init, verify or rules')
    gateway.add_argument('--home', default=None, help='the gateway home (default <config>/prismpath/gateway)')
    gateway.add_argument('--upstream', default=None, metavar='URL', help='serve: the one service, http://HOST[:PORT]')
    gateway.add_argument('--listen', default='127.0.0.1:8080', metavar='ADDR', help='serve: HOST:PORT (default 127.0.0.1:8080)')
    gateway.add_argument('--routes', default=None, metavar='FILE',
                         help='serve: the route table (default: none, every path is `other`)')
    gateway.add_argument('--session', default=None, help='serve: the id of the run (default a fresh one)')
    gateway.add_argument('--forward-header', action='append', default=[], metavar='NAME',
                         help='serve: also pass this request header to the service (repeatable)')
    gateway.add_argument('--timeout', type=float, default=10.0, help='serve: seconds a client may be silent')
    gateway.add_argument('--deadline', type=float, default=30.0, help='serve: seconds a connection may stay open')
    gateway.add_argument('--upstream-timeout', type=float, default=10.0, help='serve: seconds the service has to answer')
    gateway.add_argument('--max-response', type=int, default=8 * 1024 * 1024, help='serve: bytes of the service\'s answer held')
    gateway.add_argument('--max-connections', type=int, default=64, help='serve: connections served at once')
    gateway.add_argument('--policy', default=None, metavar='FILE', help='init: the policy to record (.core.json or .rules.md; default the demo)')
    gateway.add_argument('--json', action='store_true', help='machine readable output')
    gateway.set_defaults(func=gateway_cmd)


def _home(args) -> Path:
    from prismpath.gateway.proxy import gateway_home
    return Path(args.home) if args.home else gateway_home()


def init(home: Path, policy: Optional[str], out=None) -> int:
    from prismpath.agent import commands
    from prismpath.agent.policy import Policy
    from prismpath.kernel import policy_source
    out = out or sys.stdout
    path = Path(policy) if policy else DEMO_POLICY
    if path.name.endswith(".rules.md"):
        image = policy_source.compile_source(path.read_text(encoding="utf-8"))
    else:
        image = path.read_bytes()
    image = image[:-1] if image.endswith(b"\n") else image
    from prismpath.gateway import reading
    checked = Policy(image)
    if sorted(checked.fields) != sorted(reading.FIELDS):
        raise commands.AgentError(f"{path} defines the fields {checked.fields}, not the gateway reading's {sorted(reading.FIELDS)}")
    commands._make_dir(home)
    keys = {role: commands._ensure_key(home, role) for role in commands.KEY_ROLES}
    for name, data in ((commands.POLICY_FILE, image), (commands.ATTESTATION_FILE,
                                                       commands._attestation(home, image, "gateway"))):
        tmp = home / (name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, home / name)
    commands.load_checked(home)
    print(f"gateway home {home}: keys {keys}, policy sha256 {commands._sha256_hex(image)} recorded, attested by the "
          f"authority key", file=out)
    return 0


def serve(args) -> int:
    from prismpath.gateway.proxy import Gateway, make_server
    from prismpath.gateway.reading import Routes
    if not args.upstream:
        raise SystemExit("prismpath gateway: name the service with --upstream URL")
    host, _, port = args.listen.rpartition(":")
    routes = Routes.load(Path(args.routes)) if args.routes else Routes()
    gateway = Gateway(args.upstream, routes, _home(args), args.session, args.forward_header, args.timeout,
                      args.deadline, args.upstream_timeout, args.max_response, args.max_connections)
    if gateway.failure:
        sys.stderr.write(f"prismpath gateway: every request will be refused: {gateway.failure}\n")
    server = make_server(gateway, host or "127.0.0.1", int(port))
    sys.stderr.write(f"prismpath gateway: listening on {server.server_address[0]}:{server.server_address[1]} "
                     f"session {gateway.session} upstream {args.upstream}\n")
    sys.stderr.flush()
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stop.wait()
    server.shutdown()
    server.server_close()
    gateway.seal()
    return 0


def verify(home: Path, as_json: bool, out=None) -> int:
    from prismpath.agent import commands
    from prismpath.agent.run import RunStore
    out = out or sys.stdout
    commands._require_keys(home)
    rows = []
    for run in RunStore(home / commands.RUNS_DIR).runs():
        row: Dict[str, Any] = {"session": run.session}
        try:
            summary = run.summary()
            if summary["receipts"] == 0:
                row.update(receipts=0, verified=True)
            else:
                result = run.verify(home, seal=summary["seal"] != "diverged")
                row.update(receipts=result["receipts"], replayed=result["replayed"], disagree=result["disagree"],
                           root_statement=result["root_statement"],
                           verified=result["disagree"] == 0 and result["root_statement"] == "signed")
        except Exception as exc:   # noqa: BLE001 - one bad run does not stop the others
            row.update(verified=False, error=commands._detail(exc))
        rows.append(row)
    ok = all(r["verified"] for r in rows)
    if as_json:
        print(json.dumps({"home": str(home), "runs": rows, "verified": ok}, indent=2), file=out)
    else:
        for r in rows:
            if r.get("error"):
                print(f"{r['session']}: REFUSED ({r['error']})", file=out)
            elif not r["receipts"]:
                print(f"{r['session']}: no receipts yet", file=out)
            else:
                print(f"{r['session']}: {r['receipts']} receipts, {r['replayed']} replayed through the reference kernel, "
                      f"{r['disagree']} disagree, root statement {r['root_statement']}{'' if r['verified'] else ' REFUSED'}",
                      file=out)
    return 0 if ok else 1


def rules(home: Path, as_json: bool, out=None) -> int:
    from prismpath.agent import commands, rules as agent_rules
    out = out or sys.stdout
    commands._require_keys(home)
    policy, _store = commands.load_checked(home)
    data = agent_rules.report(home, policy, "custom", None, None)
    out.write(json.dumps(data, indent=2) + "\n" if as_json else agent_rules.render(data))
    return 0


def gateway_cmd(args) -> int:
    from prismpath.agent import commands
    try:
        if args.action == 'init':
            return init(_home(args), args.policy)
        if args.action == 'verify':
            return verify(_home(args), args.json)
        if args.action == 'rules':
            return rules(_home(args), args.json)
        return serve(args)
    except commands.AgentError as exc:
        print(f"prismpath gateway: {exc}", file=sys.stderr)
        return 2
