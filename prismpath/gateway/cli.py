# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath gateway`: serve the reverse proxy in front of a resource, record its attested policy, verify its run.

    prismpath gateway init   [--home DIR] [--policy FILE]        keys, and the policy recorded and attested
    prismpath gateway        --upstream URL --listen ADDR ...    serve (the default action)
    prismpath gateway verify [--home DIR]                        seal and verify every run, every receipt replayed
    prismpath gateway rules  [--home DIR]                        the rules with their hit counts, from the receipts
    prismpath gateway identity-bundle --domain TD=PEM ... --out FILE    the body of an identity.bundle
    prismpath gateway identity-map --map FILE --out FILE                the body of an identity.map

The two identity bodies are sealed like any artifact, `prismpath dist seal --artifact identity.bundle --body FILE
--target gateway ...`, where the authority key is (spec-policy-distribution.md, section 13.1). A home that holds
its own policy takes them at `serve` with `--identity-bundle` and `--identity-map`.

The home holds what `prismpath agent init` makes (`authority` and `instance` keys, `policy.core.json`, its
attestation under the authority key, `runs/`), under `<config>/prismpath/gateway` unless `--home` names another.
`init --policy` takes a compiled `.core.json` image or a `.rules.md` source (compiled here); without it the shipped
demo policy is recorded.

A home that follows a stream (a PEP of kind `gateway`, `prismpath dist pep --kind gateway`) holds its instance key
and no authority key. Its policy and route table are the release its PEP committed, so `serve` refuses `--routes`
there, `init` refuses to record a policy in it, a grant for it is issued where the authority key is (`grant
--stream`), and a grant is revoked through the signed revocation list (`prismpath dist revoke`), not `revoke`.
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
                        'attested policy and receipts the decision, whoever the client is (serve, init, verify, rules, grant, revoke)')
    gateway.add_argument('action', nargs='?', choices=('serve', 'init', 'verify', 'rules', 'grant', 'revoke',
                                                       'identity-bundle', 'identity-map'),
                         default='serve', help='serve (the default), init, verify, rules, grant, revoke, identity-bundle '
                                               'or identity-map')
    gateway.add_argument('--home', default=None, help='the gateway home (default <config>/prismpath/gateway)')
    gateway.add_argument('--upstream', default=None, metavar='URL', help='serve: the one service, http://HOST[:PORT]')
    gateway.add_argument('--listen', default='127.0.0.1:8080', metavar='ADDR', help='serve: HOST:PORT (default 127.0.0.1:8080)')
    gateway.add_argument('--routes', default=None, metavar='FILE',
                         help='serve: the route table, required unless the home follows a stream, where it is the committed '
                              'gateway.routes and refused here (the demo one is prismpath/gateway/policy/demo.routes.json)')
    gateway.add_argument('--session', default=None, help='serve: the id of the run (default a fresh one)')
    gateway.add_argument('--forward-header', action='append', default=[], metavar='NAME',
                         help='serve: also pass this request header to the service (repeatable)')
    gateway.add_argument('--timeout', type=float, default=10.0, help='serve: seconds a client may be silent')
    gateway.add_argument('--deadline', type=float, default=30.0, help='serve: seconds a connection may stay open')
    gateway.add_argument('--upstream-timeout', type=float, default=10.0, help='serve: seconds the service has to answer')
    gateway.add_argument('--max-response', type=int, default=8 * 1024 * 1024, help='serve: bytes of the service\'s answer held')
    gateway.add_argument('--max-connections', type=int, default=64, help='serve: connections served at once')
    gateway.add_argument('--policy', default=None, metavar='FILE', help='init: the policy to record (.core.json or .rules.md; default the demo)')
    gateway.add_argument('--path-class', action='append', default=[], metavar='CLASS',
                         help='grant: a route class the grant covers (repeat for more)')
    gateway.add_argument('--method-class', action='append', default=[], metavar='CLASS',
                         help='grant: a method class the grant covers, read, write, delete or other (repeat for more)')
    gateway.add_argument('--ttl', type=int, default=3600, help='grant: seconds the grant lasts (default 3600)')
    gateway.add_argument('--stream', default=None, metavar='NAME',
                         help='grant: the stream of the gateway the grant is for (default this home\'s own)')
    gateway.add_argument('--grant-id', default=None, metavar='ID', help='revoke: the id of the grant to revoke')
    gateway.add_argument('--client-cert-header', default=None, metavar='NAME',
                         help='serve: the header the front proxy passes the client certificate chain in, percent '
                              'encoded PEM, leaf first (read only under a policy that reads workload)')
    gateway.add_argument('--front-proxy', action='append', default=[], metavar='ADDR',
                         help='serve: an IP address of the front proxy, the only peer the certificate header is read '
                              'from (repeatable)')
    gateway.add_argument('--identity-bundle', default=None, metavar='FILE',
                         help='serve: the identity.bundle body, in a home that holds its own policy')
    gateway.add_argument('--identity-map', default=None, metavar='FILE',
                         help='serve: the identity.map body, in a home that holds its own policy')
    gateway.add_argument('--domain', action='append', default=[], metavar='TD=PEM',
                         help='identity-bundle: a trust domain and a PEM file of its CA certificates (repeatable)')
    gateway.add_argument('--map', default=None, metavar='FILE',
                         help='identity-map: a JSON file {"entries": [{"match": "spiffe://td/path/*", "class": NAME}]}')
    gateway.add_argument('--out', default=None, metavar='FILE', help='identity-bundle, identity-map: where the body goes')
    gateway.add_argument('--json', action='store_true', help='machine readable output')
    gateway.set_defaults(func=gateway_cmd)


def _home(args) -> Path:
    from prismpath.gateway.proxy import gateway_home
    return Path(args.home) if args.home else gateway_home()


def _distributed(home: Path) -> bool:
    from prismpath.onion import home as onion_home
    return onion_home.is_distributed(home)


def _load(home: Path):
    """(policy, run store) of the home: the committed release of a home that follows a stream, else the recorded,
    attested policy, each the policy a gateway home decides with (`home.policy_of`)."""
    from prismpath.agent.run import RunStore
    from prismpath.onion import home as onion_home
    if _distributed(home):
        policy, _bodies = onion_home.load_distributed(Path(home), kind="gateway")
    else:
        policy = onion_home.load_checked(home, kind="gateway")
    return policy, RunStore(Path(home) / onion_home.RUNS_DIR)


def init(home: Path, policy: Optional[str], out=None) -> int:
    from prismpath.kernel import policy_source
    from prismpath.onion import home as onion_home
    out = out or sys.stdout
    if _distributed(home):
        raise onion_home.AgentError(f"{home} follows a stream, so its policy is the release its PEP commits and none is "
                                  f"recorded here")
    path = Path(policy) if policy else DEMO_POLICY
    if path.name.endswith(".rules.md"):
        image = policy_source.compile_source(path.read_text(encoding="utf-8"))
    else:
        image = path.read_bytes()
    image = image[:-1] if image.endswith(b"\n") else image
    from prismpath.gateway import reading
    checked = onion_home.policy_of("gateway", image)
    if not reading.fields_ok(checked.fields):
        raise onion_home.AgentError(f"{path} defines the fields {checked.fields}, not the gateway reading's "
                                  f"{sorted(reading.FIELDS)}, with or without {reading.WORKLOAD}")
    onion_home.make_dir(home)
    keys = {role: onion_home.ensure_key(home, role) for role in onion_home.KEY_ROLES}
    for name, data in ((onion_home.POLICY_FILE, image), (onion_home.ATTESTATION_FILE,
                                                       onion_home.attestation(home, image, "gateway"))):
        tmp = home / (name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, home / name)
    onion_home.load_checked(home, kind="gateway")
    print(f"gateway home {home}: keys {keys}, policy sha256 {onion_home.sha256_hex(image)} recorded, attested by the "
          f"authority key", file=out)
    return 0


def serve(args) -> int:
    from prismpath.gateway.proxy import Gateway, make_server
    from prismpath.gateway.reading import Routes
    if not args.upstream:
        raise SystemExit("prismpath gateway: name the service with --upstream URL")
    host, _, port = args.listen.rpartition(":")
    home = _home(args)
    if _distributed(home):
        if args.routes:
            raise SystemExit("prismpath gateway: this home follows a stream, so its route table is the committed "
                             "gateway.routes; --routes is refused here, and a new table is released on the stream")
        routes = None
    elif not args.routes:
        raise SystemExit("prismpath gateway: name the route table with --routes FILE; without one every path reads `other` "
                         f"and a policy that allows `other` would allow all of them (the demo table is {DEMO_ROUTES})")
    else:
        routes = Routes.load(Path(args.routes))
    from prismpath.gateway import identity
    if _distributed(home) and (args.identity_bundle or args.identity_map):
        raise SystemExit("prismpath gateway: this home follows a stream, so its identity bundle and map are the "
                         "committed identity.bundle and identity.map; --identity-bundle and --identity-map are refused here")
    if bool(args.identity_bundle) != bool(args.identity_map):
        raise SystemExit("prismpath gateway: --identity-bundle and --identity-map are given together")
    bodies = ((Path(args.identity_bundle).read_bytes(), Path(args.identity_map).read_bytes())
              if args.identity_bundle else None)
    try:
        setting = identity.Setting.of(args.client_cert_header, args.front_proxy)
    except identity.IdentityError as exc:
        raise SystemExit(f"prismpath gateway: {exc}")
    gateway = Gateway(args.upstream, routes, home, args.session, args.forward_header, args.timeout,
                      args.deadline, args.upstream_timeout, args.max_response, args.max_connections,
                      identity_setting=setting, identity_bodies=bodies)
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
    from prismpath.agent.run import RunStore
    from prismpath.onion import home as onion_home
    out = out or sys.stdout
    onion_home.require_keys(home)
    rows = []
    for run in RunStore(home / onion_home.RUNS_DIR).runs():
        row: Dict[str, Any] = {"session": run.session}
        try:
            summary = run.summary()
            if summary["receipts"] == 0:
                row.update(receipts=0, verified=True)
            else:
                result = run.verify(home, seal=summary["seal"] != "diverged")
                row.update(receipts=result["receipts"], replayed=result["replayed"], disagree=result["disagree"],
                           root_statement=result["root_statement"],
                           routes_sha256=result["bound"]["routes_sha256"],
                           verified=result["disagree"] == 0 and result["root_statement"] == "signed")
        except Exception as exc:   # noqa: BLE001 - one bad run does not stop the others
            row.update(verified=False, error=onion_home.detail(exc))
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
                      f"{r['disagree']} disagree, root statement {r['root_statement']}{'' if r['verified'] else ' REFUSED'}; "
                      f"route table sha256 {', '.join(r['routes_sha256']) or 'not recorded'} (kept on the journal lines, "
                      f"outside the signed root)", file=out)
    return 0 if ok else 1


def rules(home: Path, as_json: bool, out=None) -> int:
    from prismpath.agent import rules as agent_rules
    from prismpath.onion import home as onion_home
    out = out or sys.stdout
    if not _distributed(home):
        onion_home.require_keys(home)
    policy, _store = _load(home)
    data = agent_rules.report(home, policy, "custom", None, None)
    out.write(json.dumps(data, indent=2) + "\n" if as_json else agent_rules.render(data))
    return 0


def grant(home: Path, path_classes, method_classes, ttl: int, as_json: bool, out=None, stream: Optional[str] = None) -> int:
    """Seal a grant envelope under the recorded policy for the gateway on `stream` (this home's own by default) and
    print the header value a client sends."""
    from prismpath.gateway import grants
    from prismpath.onion import home as onion_home
    out = out or sys.stdout
    if _distributed(home):
        raise onion_home.AgentError(f"{home} follows a stream and holds no authority key; issue the grant where the "
                                  f"authority key is, with --stream naming this gateway's stream")
    policy = onion_home.load_checked(home, kind="gateway")
    try:
        value, doc = grants.issue(home, onion_home.sha256_hex(policy.image), path_classes, method_classes, ttl,
                                  stream=stream or grants.LOCAL_STREAM)
    except grants.GrantError as exc:
        raise onion_home.AgentError(str(exc))
    if as_json:
        print(json.dumps({"header": grants_header(), "value": value, "grant": doc}, sort_keys=True), file=out)
    else:
        print(f"grant {doc['grant_id']}: {', '.join(doc['method_classes'])} on {', '.join(doc['path_classes'])} until "
              f"{doc['expires']} (Unix seconds)", file=sys.stderr)
        print(value, file=out)
    return 0


def grants_header() -> str:
    from prismpath.gateway import reading
    return reading.GRANT_HEADER


def revoke(home: Path, grant_id: Optional[str], out=None) -> int:
    from prismpath.onion import home as onion_home
    from prismpath.gateway import grants
    out = out or sys.stdout
    if not grant_id:
        raise onion_home.AgentError("name the grant with --grant-id ID")
    try:
        added = grants.revoke(home, grant_id)
    except grants.GrantError as exc:
        raise onion_home.AgentError(str(exc))
    print(f"grant {grant_id} {'revoked' if added else 'was already revoked'}; the next request that presents it is refused", file=out)
    return 0


def identity_bundle(domains, out_path: Optional[str], out=None) -> int:
    """Write the `identity.bundle` body of these `TD=PEM` pairs, each PEM file holding CA certificates."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from prismpath.onion import home as onion_home
    from prismpath.gateway import identity
    out = out or sys.stdout
    if not domains or not out_path:
        raise onion_home.AgentError("name each trust domain with --domain TD=PEM and the body with --out FILE")
    pairs: Dict[str, list] = {}
    for item in domains:
        domain, mark, pem = item.partition("=")
        if not mark or not pem:
            raise onion_home.AgentError(f"{item!r} is not TD=PEM")
        try:
            certs = x509.load_pem_x509_certificates(Path(pem).read_bytes())
        except (OSError, ValueError) as exc:
            raise onion_home.AgentError(f"{pem} holds no PEM certificates ({exc})")
        pairs.setdefault(domain, []).extend(cert.public_bytes(serialization.Encoding.DER) for cert in certs)
    try:
        body = identity.bundle_body(pairs)
    except identity.IdentityError as exc:
        raise onion_home.AgentError(str(exc))
    return _write_body(out_path, body, "identity.bundle", out)


def identity_map(map_path: Optional[str], out_path: Optional[str], out=None) -> int:
    """Write the `identity.map` body of the entries in a JSON file, in their order."""
    from prismpath.onion import home as onion_home
    from prismpath.gateway import identity
    out = out or sys.stdout
    if not map_path or not out_path:
        raise onion_home.AgentError("name the entries with --map FILE and the body with --out FILE")
    try:
        doc = json.loads(Path(map_path).read_text(encoding="utf-8"))
        rows = doc["entries"] if isinstance(doc, dict) and set(doc) == {"entries"} else None
        if not isinstance(rows, list) or not all(isinstance(row, dict) and set(row) == {"match", "class"}
                                                 for row in rows):
            raise ValueError('the map file is {"entries": [{"match": ..., "class": ...}, ...]}')
        body = identity.map_body(rows)
    except (OSError, ValueError) as exc:
        raise onion_home.AgentError(f"{map_path}: {exc}")
    return _write_body(out_path, body, "identity.map", out)


def _write_body(path: str, body: bytes, artifact: str, out) -> int:
    import hashlib
    Path(path).write_bytes(body)
    print(f"{artifact} body {path}: sha256 {hashlib.sha256(body).hexdigest()}; seal it with prismpath dist seal "
          f"--artifact {artifact} --body {path} --target gateway", file=out)
    return 0


def gateway_cmd(args) -> int:
    from prismpath.onion import home as onion_home
    try:
        if args.action == 'init':
            return init(_home(args), args.policy)
        if args.action == 'verify':
            return verify(_home(args), args.json)
        if args.action == 'rules':
            return rules(_home(args), args.json)
        if args.action == 'grant':
            return grant(_home(args), args.path_class, args.method_class, args.ttl, args.json, stream=args.stream)
        if args.action == 'revoke':
            return revoke(_home(args), args.grant_id)
        if args.action == 'identity-bundle':
            return identity_bundle(args.domain, args.out)
        if args.action == 'identity-map':
            return identity_map(args.map, args.out)
        return serve(args)
    except onion_home.AgentError as exc:
        print(f"prismpath gateway: {exc}", file=sys.stderr)
        return 2
