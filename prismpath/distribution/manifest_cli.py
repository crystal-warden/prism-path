# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath policy manifest check FILE --pub KEY...`: the release check of a policy manifest (SPEC.md section 10).

The grammar and the check are the kernel's (`kernel/policy_manifest.py`). This surface does what the kernel may not:
it reads the manifest and the files it names (each confined to the manifest's directory), verifies the signature
with the flow authority, and prints what `policy_manifest.check` found. `add_parser` takes the `<action>` group of
`prismpath policy`, so the command is registered in one place (`cli.py` calls it right after `policy_source`).

Exit 0 when the manifest holds, 1 when the check found something wrong, 2 when the manifest does not read or a
needed file cannot be read at all.
"""
from __future__ import annotations

import json
import os
import sys
from typing import List, Optional

from prismpath.distribution import kinds
from prismpath.kernel import policy_manifest


def add_parser(actions) -> None:
    """`prismpath policy manifest check`, under the `policy` command's action group."""
    manifest_parser = actions.add_parser('manifest', help='the signed policy manifest (<name>.policy.md) that names a '
                                                          'release\'s rules, image and side inputs')
    manifest_actions = manifest_parser.add_subparsers(dest='manifest_action', metavar='<action>', required=True)
    check_parser = manifest_actions.add_parser(
        'check', help='check a manifest: its signature, that its rules compile to its image byte for byte, both '
                      'hashes, and the hash of every side input it names; exit 1 when anything is wrong')
    check_parser.add_argument('manifest', metavar='FILE', help='the manifest (<name>.policy.md)')
    check_parser.add_argument('--pub', nargs='+', required=True, metavar='PUB',
                              help='the trusted authority public key(s) that may have signed it (`swap keygen`)')
    check_parser.add_argument('--revoked', default=None, help='revocation list JSON of authority key ids')
    check_parser.add_argument('--state-dir', dest='state_dir', default=None, metavar='DIR',
                              help='refuse a manifest signed at a version below the one this directory accepted')
    check_parser.add_argument('--json', action='store_true', help='print JSON')
    check_parser.set_defaults(func=manifest_cmd)


def _reader(directory: str):
    """The bytes of a file the manifest names, or None when there is none. A path that resolves outside the
    manifest's directory (a link) reads as absent, so the check never hashes a file the signer did not place."""
    root = os.path.realpath(directory)

    def read(path: str) -> Optional[bytes]:
        full = os.path.realpath(os.path.join(root, path))
        if os.path.commonpath([root, full]) != root or not os.path.isfile(full):
            return None
        with open(full, "rb") as handle:
            return handle.read()
    return read


def manifest_cmd(args) -> int:
    from prismpath.hotswap import flow_authority, policy_pack

    def refuse(lines: List[str]) -> int:
        for text in lines:
            print(f"prismpath policy manifest check: {text}", file=sys.stderr)
        return 2

    try:
        with open(args.manifest, "rb") as handle:
            raw = handle.read()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return refuse([f"{args.manifest}: {getattr(error, 'strerror', None) or error}"])
    try:
        manifest = policy_manifest.parse(text, args.manifest)
    except policy_manifest.ManifestError as error:
        return refuse(error.lines())
    try:
        for path in args.pub:
            if not os.path.isfile(path):
                return refuse([f"{path}: no such public key"])
        floor = flow_authority.VersionFloor.in_state_dir(args.state_dir) if args.state_dir else None
        ok, reasons, _signed = flow_authority.verify_flow(args.manifest, args.pub, policy_pack.load_revoked(args.revoked),
                                                          floor=floor)
    except (OSError, ValueError) as error:
        return refuse([f"{error}"])
    signature = policy_manifest.Signature(ok, tuple(reasons))
    found = policy_manifest.check(manifest, signature, _reader(os.path.dirname(os.path.abspath(args.manifest))),
                                  known_targets=kinds.TARGET_KINDS)
    if args.json:
        print(json.dumps({"ok": not found, "manifest": args.manifest, "manifest_sha256": manifest.sha256,
                          "id": manifest.id, "stream": manifest.stream, "seq": manifest.seq,
                          "targets": list(manifest.targets), "rules_sha256": manifest.rules_sha256,
                          "image_sha256": manifest.image_sha256,
                          "findings": [{"code": f.code, "line": f.line, "message": f.message} for f in found]}, indent=1))
    elif found:
        for finding in found:
            print(finding.render(args.manifest), file=sys.stderr)
    else:
        print(f"{args.manifest} holds: {manifest.id} seq {manifest.seq} on stream {manifest.stream} for "
              f"{', '.join(manifest.targets)}, rules sha256 {manifest.rules_sha256}, image sha256 {manifest.image_sha256}, "
              f"{len(manifest.files)} side input(s) checked")
    return 1 if found else 0
