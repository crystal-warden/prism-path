# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Policy authoring, manifest check, authorization, canonicalization, hot-swap, gateway, and distribution commands."""
import json
import sys

from prismpath.cli.common import CliError, cause_code, require_file


def register(subparsers) -> None:
    from prismpath.kernel import policy_source
    policy_actions = policy_source.add_parser(subparsers)
    from prismpath.distribution import manifest_cli
    manifest_cli.add_parser(policy_actions)

    from prismpath.gateway import cli as gateway_cli
    gateway_cli.add_parser(subparsers)

    from prismpath.distribution import cli as dist_cli
    dist_cli.add_parser(subparsers)

    authorize_parser = subparsers.add_parser(
        'authorize', help='Sign a Markdown flow with the policy authority key, or verify that signature: '
                          'the authorization `run --require-authorization` checks')
    authorize_parser.add_argument('action', choices=['sign', 'verify'], help='sign | verify')
    authorize_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    authorize_parser.add_argument('--priv', help='authority private key (sign)')
    authorize_parser.add_argument('--pub', nargs='+', help='authority public key (sign: the signer\'s; verify: the trusted keys)')
    authorize_parser.add_argument('--version', type=int, default=None,
                                  help='sign: the monotonic version of this authorization (1, 2, ...)')
    authorize_parser.add_argument('--revoked', default=None, help='verify: revocation list JSON of key ids')
    authorize_parser.add_argument('--state-dir', dest='state_dir', default=None, metavar='DIR',
                                  help='verify: also check the version against the floor accepted in DIR')
    authorize_parser.set_defaults(func=authorize_cmd)

    canonicalize_parser = subparsers.add_parser(
        'canonicalize', help='Write a canon/2 document a person wrote (any spacing, member order or escapes) '
                             'as its exact canonical bytes, the only spelling a reader of a hashed or signed '
                             'document or of a reading accepts')
    canonicalize_parser.add_argument('document', type=str, help='the document to canonicalize, or - for standard input')
    canonicalize_mode = canonicalize_parser.add_mutually_exclusive_group()
    canonicalize_mode.add_argument('--out', default=None, metavar='PATH',
                                   help='write the canonical bytes and a line feed here (default: standard output)')
    canonicalize_mode.add_argument('--in-place', dest='in_place', action='store_true',
                                   help='replace the document with its canonical bytes and a line feed')
    canonicalize_mode.add_argument('--check', action='store_true',
                                   help='write nothing; exit 1 when the document is not already its canonical bytes')
    canonicalize_parser.set_defaults(func=canonicalize_cmd)

    swap_parser = subparsers.add_parser(
        'swap', help='Secure policy hot-swap: signed packs, envelope check, attested swap '
                     '(spec-secure-hotswap)')
    swap_parser.add_argument('action', choices=[
        'keygen', 'pack', 'verify', 'envelope', 'swap', 'attest'],
        help='keygen | pack | verify | envelope | swap | attest')
    swap_parser.add_argument('--ppt', help='the .ppt image (pack/verify/swap)')
    swap_parser.add_argument('--priv', help='authority private key (keygen writes it; pack/envelope use it)')
    swap_parser.add_argument('--pub', nargs='+', help='authority public key(s) (verify/swap/attest)')
    swap_parser.add_argument('--out', help='output dir (keygen/envelope) or state dir (swap/attest)')
    swap_parser.add_argument('--name', default='authority', help='keygen key name (default authority)')
    swap_parser.add_argument('--fields', help='comma list name:kind (pack/envelope), e.g. temp:int,rule:str')
    swap_parser.add_argument('--flow', help='the flow the image was compiled from (pack/envelope): a flow that '
                             'defines its fields supplies the signed field dictionary, and pack records its hash')
    swap_parser.add_argument('--version', type=int, default=1, help='monotonic pack version (pack)')
    swap_parser.add_argument('--envelope-id', dest='envelope_id', default='env1',
                             help='envelope id the pack targets / the envelope defines')
    swap_parser.add_argument('--envelope', help='envelope base path without .json/.sig (swap/attest)')
    swap_parser.add_argument('--caps', help='comma list k=v envelope caps (envelope), e.g. atoms=1024,nodes=256')
    swap_parser.add_argument('--revoked', help='revocation list JSON of key_ids (verify/swap)')
    swap_parser.add_argument('--overlay-of', dest='overlay_of', default=None,
                             help='pack: name the policy of record this pack temporarily overrides; attest shows it as overlay_of')
    swap_parser.add_argument('--allow-unsigned', dest='allow_unsigned', action='store_true',
                             help='demo escape hatch: swap an unsigned image, stamped in the audit log')
    swap_parser.set_defaults(func=swap_cmd)


def canonicalize_cmd(args) -> int:
    """`prismpath canonicalize`: the writer's step for text a person wrote. Every reader of a hashed or
    signed document and of a reading accepts only the exact canonical canon/2 bytes and refuses any other
    spelling (`document:not-canonical`, `reading:not-canonical`); this command reads the document by every
    other canon/2 rule (a float, a duplicate key, an integer beyond plus or minus 2^53 minus 1, a lone
    surrogate and nesting past 128 are still refused, exit 2) and writes its canonical bytes and one line
    feed. `--check` writes nothing and exits 1 when the document is not already those bytes."""
    from prismpath import canon
    if args.document == "-":
        raw = sys.stdin.buffer.read()
    else:
        require_file(args.document)
        with open(args.document, "rb") as handle:
            raw = handle.read()
    try:
        canonical = canon.canonicalize_document(raw) + b"\n"
    except canon.CanonicalError as error:
        raise CliError(f"{args.document} has no canon/2 form: {error}") from error
    if args.check:
        if raw in (canonical, canonical[:-1]):     # the line feed that ends a file is the reader's terminator
            return 0
        print(f"prismpath canonicalize: {args.document} is not its canonical canon/2 bytes "
              f"(document:not-canonical); run `prismpath canonicalize --in-place {args.document}`", file=sys.stderr)
        return 1
    if args.in_place:
        if args.document == "-":
            raise CliError("--in-place needs a file, not standard input")
        canon.atomic_write_bytes(args.document, canonical)
    elif args.out:
        canon.atomic_write_bytes(args.out, canonical)
    else:
        sys.stdout.buffer.write(canonical)
        sys.stdout.flush()
    return 0


def _read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _parse_fields(spec):
    return dict(part.split(":", 1) for part in spec.split(",")) if spec else {}


def authorize_cmd(args) -> int:
    """Sign a flow with the authority key, or verify that signature (prismpath.hotswap.flow_authority)."""
    from prismpath.hotswap import flow_authority, policy_pack
    from prismpath.ledgers import root_statement
    require_file(args.flow_md)
    if args.action == 'sign':
        if not (args.priv and args.pub and args.version is not None):
            raise CliError("sign needs --priv and --pub (the authority key) and --version N")
        instance = root_statement.key_from_env()
        if instance is not None:
            with open(args.pub[0], "rb") as handle:
                if policy_pack.sha256_hex(handle.read()) == instance.key_id:
                    raise CliError("refused: that is the instance key (PRISMPATH_INSTANCE_KEY); a flow is authorized "
                                   "by the policy authority key, `swap keygen`")
        try:
            manifest = flow_authority.sign_flow(args.flow_md, args.version, args.priv, args.pub[0])
        except ValueError as refusal:
            raise CliError(f"sign: refused: {refusal}") from refusal
        print(json.dumps({**manifest, "manifest_sha256": flow_authority.manifest_sha256(manifest),
                          "files": list(flow_authority.manifest_paths(args.flow_md))}, indent=1))
        return 0
    if not args.pub:
        raise CliError("verify needs --pub (the trusted authority key or keys)")
    for path in args.pub:
        require_file(path)
    floor = flow_authority.VersionFloor.in_state_dir(args.state_dir) if args.state_dir else None
    ok, reasons, manifest = flow_authority.verify_flow(args.flow_md, args.pub, policy_pack.load_revoked(args.revoked),
                                                       floor=floor)
    out = {"ok": ok, "reasons": reasons, "causes": [cause_code(reason) for reason in reasons]}
    if manifest:
        out.update({"flow": manifest.get("flow"), "version": manifest.get("version"), "key_id": manifest.get("key_id"),
                    "manifest_sha256": flow_authority.manifest_sha256(manifest)})
    print(json.dumps(out, indent=1))
    return 0 if ok else 1


def swap_cmd(args):
    """Secure policy hot-swap CLI (spec-secure-hotswap). Loud absence: a missing `cryptography`
    surfaces the install message and exits non-zero, never a silent pass."""
    import json as _json
    try:
        from prismpath.hotswap import policy_pack
        from prismpath.hotswap import policy_host
    except Exception as exc:                                  # pragma: no cover
        print(str(exc), file=sys.stderr)
        return 2
    action = args.action
    try:
        if action == 'keygen':
            print(_json.dumps(policy_pack.keygen(args.out or '.', args.name), indent=1))
            return 0
        if action == 'pack':
            if not (args.ppt and args.priv and args.pub):
                print('pack needs --ppt --priv --pub', file=sys.stderr)
                return 2
            flow_text = _read_text(args.flow) if args.flow else None
            # L1: the pack is a sealed `policy.ppt` envelope, `<ppt>.sealed`, on the stream `local` with a lifetime of
            # ten years; the flags mean what they meant for the older manifest
            manifest = policy_pack.seal_pack(args.ppt, _parse_fields(args.fields), args.version,
                                             args.envelope_id, args.priv, args.pub[0], overlay_of=args.overlay_of,
                                             flow_text=flow_text)
            print(_json.dumps({**manifest, "sealed": args.ppt + policy_pack.SEALED}, indent=1))
            return 0
        if action == 'verify':
            if not (args.ppt and args.pub):
                print('verify needs --ppt --pub', file=sys.stderr)
                return 2
            ok, reasons, _manifest = policy_pack.verify_pack(args.ppt, args.pub, policy_pack.load_revoked(args.revoked))
            print(_json.dumps({'ok': ok, 'reasons': reasons}, indent=1))
            return 0 if ok else 1
        if action == 'envelope':
            if not (args.priv and args.pub and args.out):
                print('envelope needs --priv --pub --out', file=sys.stderr)
                return 2
            caps = ({key: int(val) for key, val in (kv.split("=", 1) for kv in args.caps.split(","))}
                    if args.caps else None)
            fields = (policy_pack.field_dictionary_of(_read_text(args.flow)) if args.flow
                      else _parse_fields(args.fields))
            env = policy_pack.build_envelope(args.envelope_id, fields, caps,
                                             args.priv, args.pub[0], args.out)
            print(_json.dumps(env, indent=1))
            return 0
        if action in ('swap', 'attest'):
            if not (args.out and args.pub and args.envelope):
                print(f'{action} needs --out (state dir) --pub --envelope', file=sys.stderr)
                return 2
            env, reasons = policy_pack.load_envelope(args.envelope, args.pub)
            if env is None:
                print(_json.dumps({'ok': False, 'reasons': reasons}, indent=1))
                return 1
            host = policy_host.PolicyHost(args.out, args.pub, env, revoked=policy_pack.load_revoked(args.revoked))
            print(f"audit log {host.audit.path}: root statements signed by instance key "
                  f"{host.audit.instance_key.fingerprint}" if host.audit.signing else
                  f"audit log {host.audit.path}: not signed (no instance key; set PRISMPATH_INSTANCE_KEY)",
                  file=sys.stderr)
            if action == 'attest':
                print(_json.dumps(host.attest(), indent=1))
                return 0
            if not args.ppt:
                print('swap needs --ppt', file=sys.stderr)
                return 2
            res = host.swap(args.ppt, allow_unsigned=args.allow_unsigned)
            print(_json.dumps(res, indent=1))
            return 0 if res.get('ok') else 1
    except RuntimeError as exc:                               # loud absence (no cryptography)
        print(str(exc), file=sys.stderr)
        return 2
    except ValueError as refusal:                             # a flow, image or dictionary refused
        print(f"swap {action}: refused: {refusal}", file=sys.stderr)
        return 1
    return 2
