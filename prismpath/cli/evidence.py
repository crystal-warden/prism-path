# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Assessor commands: ledger anchoring, core evidence verification, and Facet telemetry."""
import argparse
import json
import os
import sys

from prismpath.cli.common import CliError, parse_flow, require_file, require_program

LOG_ANCHOR_RECORD = "log_{label}.json"


def _sample_arg(text: str):
    """`--sample`: a count of receipts to replay, or `all` (None)."""
    if text == 'all':
        return None
    try:
        count = int(text)
    except ValueError:
        count = -1
    if count < 0:
        raise argparse.ArgumentTypeError(f"expected a nonnegative count or all, not {text!r}")
    return count


def register(subparsers) -> None:
    ledger_parser = subparsers.add_parser(
        'ledger', help='Evidence: the instance key, OTS anchor/upgrade/verify of roots and root statements, '
                       'and the air-gap tier (#36/#53)')
    ledger_parser.add_argument('action', choices=[
        'keygen', 'anchor', 'upgrade', 'verify', 'export-request', 'relay-stamp', 'import-proofs', 'rfc3161'],
        help='ledger action: keygen writes the instance key that signs root statements; the rest anchor and verify')
    ledger_parser.add_argument('--name', default='instance',
                               help='keygen key name (default instance; never the policy authority key)')
    ledger_parser.add_argument('--repo', help='ledger git repo (anchor: enumerate Output-Hash trailers)')
    ledger_parser.add_argument('--statements', default=None, metavar='PATH',
                               help='anchor: the hashes of the signed root statements in this file (or the ones '
                                    'beside this audit log), so the timestamp covers the signatures')
    ledger_parser.add_argument('--log', default=None, metavar='PATH',
                               help='anchor: timestamp this audit log (the hash of its latest root statement when it '
                                    'has any, else its Merkle root; the output says which). verify: check the log '
                                    'still holds what was anchored under --out/--label, and the timestamp proof')
    ledger_parser.add_argument('--pub', nargs='+', default=None, metavar='INSTANCE_PUB',
                               help='verify --log: pin the deployment\'s instance public key(s), as `trail --pub`')
    ledger_parser.add_argument('--out', help='output dir (anchor/upgrade/verify) or bundle path (air-gap)')
    ledger_parser.add_argument('--label', default='v1', help='anchor label (default v1)')
    ledger_parser.add_argument('--leaf', help='leaf hash hex (verify)')
    ledger_parser.add_argument('--root', help='root file (rfc3161 / export-request)')
    ledger_parser.add_argument('--request', help='stamp-request bundle (relay-stamp)')
    ledger_parser.add_argument('--proofs', help='proof bundle (import-proofs)')
    ledger_parser.add_argument('--dir', help='roots dir (import-proofs)')
    ledger_parser.add_argument('--cafile', help='TSA CA cert (rfc3161 verify)')
    ledger_parser.add_argument('--tsr', help='RFC-3161 response file to verify')
    ledger_parser.add_argument('--policy-hash', dest='policy_hash', default=None,
                               help='C1: bind the flow-definition hash to the anchored record')
    ledger_parser.add_argument('--gate-id', dest='gate_id', default=None,
                               help='C1: bind the gate identity that produced the record')
    ledger_parser.add_argument('--ots', action='store_true',
                               help='accepted and ignored: verify always walks the Merkle path and then the OTS proof')
    ledger_parser.set_defaults(func=ledger_cmd)

    evidence_parser = subparsers.add_parser(
        'evidence', help='Verify a signed core run: its keys, root statement, Merkle root, image signatures and '
                         'receipts, every decision or a sample replayed through the reference kernel')
    evidence_parser.add_argument('action', choices=['verify'],
                                 help='evidence action: verify checks a core run directory and exits 0 when it '
                                      'verifies with both keys pinned and 1 when refused; without both pins every '
                                      'check runs and the pass is refused with dist:hatch-refused outside a dev build')
    evidence_parser.add_argument('run', help='the core run directory (run.json, cases.jsonl, images.jsonl, '
                                             'receipts.jsonl, receipts.roots.jsonl, authority.pub, instance.pub)')
    evidence_parser.add_argument('--sample', default='200', type=_sample_arg, metavar='N|all',
                                 help='how many receipts to replay through the reference kernel, or all (default 200)')
    evidence_parser.add_argument('--seed', type=int, default=0, help='the seed that chooses the sample (default 0)')
    evidence_parser.add_argument('--pin-authority', dest='pin_authority', default=None, metavar='PUB',
                                 help="your own copy of the authority public key (raw 32 bytes, as `swap keygen` "
                                      "writes it); with --pin-instance the root statement is signed, and without "
                                      "both the verify is refused outside a dev build")
    evidence_parser.add_argument('--pin-instance', dest='pin_instance', default=None, metavar='PUB',
                                 help="your own copy of the instance public key (raw 32 bytes, as `ledger keygen` "
                                      "writes it)")
    evidence_parser.add_argument('--pin-install', dest='pin_install', default=None, metavar='JSON',
                                 help="for a cFS run with an action floor or a fallback policy, your own copy of the "
                                      "install key set its PEP started from, the `install` part of its anchor (RC4)")
    evidence_parser.add_argument('--json', action='store_true', help='machine readable output')
    evidence_parser.set_defaults(func=evidence_cmd)

    facet_parser = subparsers.add_parser(
        'facet', help='Facet telemetry: decision-preserving quantization, wire encoding, and stream decoding')
    facet_parser.add_argument('action', choices=['quantize', 'encode', 'decode'],
                              help='facet action: quantize | encode | decode')
    facet_parser.add_argument('flow_md', type=str, help='Path to the flow markdown file')
    facet_parser.add_argument('payload', type=str, help='JSON reading or HEX string')
    facet_parser.set_defaults(func=facet_cmd)


def _statement_hashes(path: str) -> list:
    """The content hash of every root statement in `path`, or in the statements file beside the audit
    log `path` names. Each hash covers the statement's signature, so anchoring them timestamps the
    signed roots and not only the roots."""
    from prismpath.ledgers import root_statement
    if not path.endswith(".roots.jsonl") and os.path.exists(root_statement.statements_path_for(path)):
        path = root_statement.statements_path_for(path)
    require_file(path)
    statements, _findings = root_statement.read_statements(path)
    return [root_statement.statement_hash(statement) for statement in statements if statement]


def _anchor_log(args) -> int:
    """`ledger anchor --log`: stamp the latest signed root statement's hash (the Merkle root when the log
    has no statements), say which, and keep a record beside the proof for `ledger verify --log`."""
    import json as _json
    from prismpath.ledgers import ledger_ots as ots
    from prismpath.ledgers.audit_log import AnchorRefused, AuditLog
    if args.repo or args.statements:
        raise CliError("--log anchors an audit log by itself: drop --repo and --statements")
    require_file(args.log)
    log = AuditLog(args.log)
    try:
        target = log.anchor_target()
    except AnchorRefused as refused:
        raise CliError(f"not anchoring {args.log}: {refused}", code=1) from refused
    if target["kind"] == "root-statement":
        said = (f"anchoring root statement {target['statement']} (sha256 {target['hash'][:16]}), signed by instance key "
                f"{target['key']}, which covers {target['leaves']} of the log's {target['log_leaves']} events")
        if target["unsigned_tail"]:
            said += (f"; the {target['unsigned_tail']} later events are not covered by it, and a timestamp on it says "
                     f"nothing about them until a later statement is anchored")
    else:
        said = (f"anchoring the Merkle root (sha256 {target['hash'][:16]}) over the log's {target['leaves']} events: the "
                f"log has no root statements, so this timestamps the events and not who recorded them "
                f"(`prismpath ledger keygen` makes the instance key that signs them)")
    print(said, file=sys.stderr)
    out_dir = args.out or '.'
    res = ots.anchor([target["hash"]], out_dir, args.label)
    res["anchored"] = {**target, "log": os.path.abspath(args.log), "label": args.label, "says": said}
    if res.get('stamped'):
        with open(os.path.join(out_dir, LOG_ANCHOR_RECORD.format(label=args.label)), "w", encoding="utf-8") as handle:
            _json.dump(res["anchored"], handle, indent=1, sort_keys=True)
            handle.write("\n")
    print(_json.dumps(res, indent=1))
    return 0 if res.get('stamped') else 1


def _verify_log_anchor(args) -> int:
    """`ledger verify --log`: does the log still hold what `ledger anchor --log` stamped, does it verify,
    and does the timestamp proof verify. The last needs Bitcoin block data."""
    import json as _json
    from prismpath.ledgers import ledger_ots as ots, root_statement
    from prismpath.ledgers.audit_log import AuditLog
    require_file(args.log)
    out_dir = args.out or '.'
    record_path = os.path.join(out_dir, LOG_ANCHOR_RECORD.format(label=args.label))
    if not os.path.exists(record_path):
        raise CliError(f"no log anchor record {record_path}: anchor the log with `ledger anchor --log` "
                       f"(same --out and --label), or check a single hash with `ledger verify --leaf`")
    with open(record_path, encoding="utf-8") as handle:
        record = _json.load(handle)
    pinned = [root_statement.load_public(path) for path in (args.pub or [])]
    log = AuditLog(args.log)
    signing = log.verify_statements(pinned or None)
    in_log = log.holds_anchor(record)
    proof = ots.verify_unit(record["hash"], out_dir, args.label)
    ok = (log.verify_log() and signing["status"] != root_statement.INVALID and in_log
          and bool(proof.get("merkle_ok")) and bool(proof.get("ots_ok")))
    print(_json.dumps({"ok": ok, "log": args.log, "log_verifies": log.verify_log(), "signing": signing["status"],
                       "findings": signing["findings"], "anchored": {key: record.get(key) for key in
                       ("kind", "hash", "statement", "leaves", "says")},
                       "log_holds_anchor": in_log, "proof": proof}, indent=1))
    return 0 if ok else 1


def ledger_cmd(args):
    """Flow-Ledger attestation CLI (#36 connected OTS + #53 air-gap tier)."""
    import json as _json
    from prismpath.ledgers import ledger_ots as ots
    from prismpath.ledgers import ledger_airgap as airgap
    action = args.action
    if action == 'keygen':
        from prismpath.ledgers import root_statement
        try:
            print(_json.dumps(root_statement.keygen(args.out or '.', args.name), indent=1))
        except FileExistsError as exists:
            raise CliError(f"keygen: {exists.filename} exists; {exists.strerror}") from exists
        return 0
    # The OpenTimestamps client and OpenSSL are external programs, checked before shelling out.
    if action in ('anchor', 'upgrade', 'verify', 'relay-stamp'):
        require_program('ots', 'the OpenTimestamps client: pip install opentimestamps-client', action)
    if action == 'anchor' and args.repo:
        require_program('git', 'install git from https://git-scm.com', 'anchor --repo')
    if action == 'rfc3161':
        require_program('openssl', "install OpenSSL with your system's package manager", action)
    if action == 'anchor' and args.log:
        return _anchor_log(args)
    if action == 'verify' and args.log:
        return _verify_log_anchor(args)
    if action == 'anchor':
        if args.statements:
            hashes = _statement_hashes(args.statements)
            if not hashes:
                print(f'no root statements in {args.statements} (a run signs them with --instance-key)')
                return 1
        else:
            hashes = ots.from_ledger(args.repo) if args.repo else []
        if not hashes:
            print('no Output-Hash values found in ledger (need --repo with PrismPath-Output-Hash trailers, '
                  'or --statements with signed root statements)')
            return 1
        res = ots.anchor(hashes, args.out or '.', args.label)
        print(_json.dumps(res, indent=1))
        return 0 if res.get('stamped') else 1
    if action == 'upgrade':
        res = ots.upgrade(args.out or '.', args.label)
        print(_json.dumps(res, indent=1))
        return 0 if res.get('ots_rc') == 0 else 1
    if action == 'verify':
        if not args.leaf:
            print('--leaf <hex> required for verify')
            return 2
        res = ots.verify_unit(args.leaf, args.out or '.', args.label)
        print(_json.dumps(res, indent=1))
        return 0 if res.get('merkle_ok') and res.get('ots_ok') else 1
    if action == 'export-request':
        if not (args.root and args.out):
            print('--root and --out required for export-request')
            return 2
        res = airgap.export_stamp_request([(args.root, args.label)], args.out,
                                      policy_hash=args.policy_hash, gate_id=args.gate_id)
        print(_json.dumps(res, indent=1))
        return 0
    if action == 'relay-stamp':
        if not (args.request and args.out):
            print('--request and --out required for relay-stamp')
            return 2
        print(_json.dumps(airgap.relay_stamp(args.request, args.out), indent=1))
        return 0
    if action == 'import-proofs':
        if not args.proofs:
            print('--proofs required for import-proofs')
            return 2
        print(_json.dumps(airgap.import_proofs(args.proofs, args.dir or '.'), indent=1))
        return 0
    if action == 'rfc3161':
        if not args.root:
            print('--root required for rfc3161')
            return 2
        if args.tsr and args.cafile:
            res = airgap.rfc3161_verify(args.root, args.tsr, args.cafile)
            print(_json.dumps(res, indent=1))
            return 0 if res.get('verified') else 1
        print(_json.dumps(airgap.rfc3161_query(args.root), indent=1))
        return 0
    print('unknown ledger action: ' + str(action))
    return 2


def _load_telemetry():
    """The Facet codec ships in the package (prismpath.telemetry); PROTOCOL.md is its specification."""
    from prismpath.telemetry import packed, quantizer, wire, zeckendorf
    return quantizer, zeckendorf, wire, packed


def evidence_cmd(args) -> int:
    """`evidence verify RUN`: every check of a signed core run, its receipts replayed through the reference
    kernel; 0 when it verifies, 1 when it is refused, with the first failed check."""
    from prismpath.ledgers import core_evidence
    if not os.path.isdir(args.run):
        raise CliError(f"{args.run} is not a directory (a core run is a directory)")
    pin_install = getattr(args, "pin_install", None)
    for pin in (args.pin_authority, args.pin_instance, pin_install):
        if pin is not None:
            require_file(pin)
    try:
        summary = core_evidence.verify(args.run, sample=args.sample, seed=args.seed,
                                       pin_authority=args.pin_authority, pin_instance=args.pin_instance,
                                       pin_install=pin_install)
    except core_evidence.Bad as bad:
        if args.json:
            print(json.dumps({"ok": False, "run": args.run, "refused": str(bad)}, indent=1))
        else:
            print(f"prismpath evidence: REFUSED {args.run}: {bad}")
        return 1
    if args.json:
        print(json.dumps({"ok": True, **summary}, indent=1, default=str))
    else:
        print(f"prismpath evidence: verified {args.run}: decider {summary['decider']}, {summary['receipts']} receipts, "
              f"{summary['images']} image attestations, root statement {summary['root_statement']}, "
              f"{summary['replayed']} replayed through {summary['against']}: {summary['agree']} agree, "
              f"{summary['disagree']} disagree")
    return 0


def facet_cmd(args) -> int:
    quantizer, zeckendorf, wire, packed = _load_telemetry()
    graph = parse_flow(args.flow_md)
    try:
        parts = quantizer.build_partitions(graph)
    except ValueError as refusal:
        print(f"facet: the codec cannot carry this flow: {refusal}", file=sys.stderr)
        return 2
    action = args.action

    if action in ('quantize', 'encode'):
        if os.path.exists(args.payload):
            with open(args.payload, "r", encoding="utf-8") as fh:
                reading = json.load(fh)
        else:
            reading = json.loads(args.payload)

        order = sorted(parts.keys())
        # The one acceptance rule: a missing field or a refused value is reported with the field and
        # the reason, and a defined field that allows absence encodes its absent cell.
        try:
            syms = quantizer.checked_quantize(parts, reading)
        except quantizer.InputRefused as refusal:
            print(f"facet: refused {refusal.field}: {refusal.reason} ({refusal.value!r})", file=sys.stderr)
            return 2

        if action == 'quantize':
            symbol_tuple = tuple(syms[field_name] for field_name in order)
            print(symbol_tuple)
            return 0
        elif action == 'encode':
            bits = wire.encode_reading(parts, reading)
            raw_bytes = packed.pack(bits, 8)
            print(raw_bytes.hex())
            return 0

    elif action == 'decode':
        try:
            raw_bytes = bytes.fromhex(args.payload)
            recon_reading = wire.decode_reading(parts, packed.unpack(raw_bytes))
        except ValueError as refusal:
            print(f"facet: not a frame this flow's codebook decodes: {refusal}", file=sys.stderr)
            return 2

        start_node = graph.start
        route = None
        cause = None

        if start_node in graph.nodes:
            from prismpath.kernel import predicates
            for target, cond in graph.nodes[start_node].edges:
                if predicates.is_deterministic(cond) and predicates.eval_condition(cond, recon_reading):
                    route = target
                    cause = cond
                    break

        print(f"Next node: {route}")
        print(f"Cause: {cause}")
        return 0

    return 2
