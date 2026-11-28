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
import stat
import sys
import time
from datetime import datetime, timezone
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
    check_parser.add_argument('--pub', action='append', required=True, metavar='PUB',
                              help='a trusted authority public key that may have signed it (`swap keygen`); repeat the flag '
                                   'for more than one, and write FILE before the flags or after a flag\'s value')
    check_parser.add_argument('--revoked', default=None, help='revocation list JSON of authority key ids')
    check_parser.add_argument('--state-dir', dest='state_dir', default=None, metavar='DIR',
                              help='refuse a manifest signed at a version below the one this directory accepted')
    check_parser.add_argument('--json', action='store_true', help='print JSON')
    check_parser.set_defaults(func=manifest_cmd)


MAX_FILE = 16 * 1024 * 1024        # the most a side file may hold; a larger one is a finding, not a read


def _point_findings(image, points):
    """What is wrong with the evidence fields of an image, given the information points the manifest names."""
    from prismpath.agent import target
    return target.evidence_findings(image, points)


def _reader(directory: str):
    """The bytes of a file the manifest names, or None when there is none. A path that resolves outside the
    manifest's directory (a link) reads as absent, so the check never hashes a file the signer did not place. The
    file is opened without following a link at its last part and is the same file (device and inode) the confined
    path named, so a link swapped in after the check is not followed. A file over MAX_FILE is a ValueError."""
    root = os.path.realpath(directory)

    def read(path: str) -> Optional[bytes]:
        full = os.path.realpath(os.path.join(root, path))
        if os.path.commonpath([root, full]) != root or not os.path.isfile(full):
            return None
        try:
            descriptor = os.open(full, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return None
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                return None
            try:
                named = os.stat(full)
            except OSError:
                return None
            if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                return None
            if opened.st_size > MAX_FILE:
                raise ValueError(f"is {opened.st_size} bytes, more than the {MAX_FILE} a side input may hold")
            data = handle.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise ValueError(f"is more than the {MAX_FILE} bytes a side input may hold")
            return data
    return read


def _created(manifest) -> Optional[int]:
    """Unix seconds of the flow manifest's signed `created`, or None when it is not a time."""
    try:
        moment = datetime.fromisoformat(str((manifest or {}).get("created")))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


def manifest_cmd(args) -> int:
    from prismpath.hotswap import flow_authority, policy_pack

    def refuse(lines: List[str]) -> int:
        for text in lines:
            print(f"prismpath policy manifest check: {text}", file=sys.stderr)
        return 2

    for path in [*args.pub, *([args.revoked] if args.revoked else [])]:
        if not os.path.isfile(path):
            return refuse([f"{path}: no such file"])
    try:
        with open(args.manifest, "rb") as handle:
            raw = handle.read()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return refuse([f"{args.manifest}: {getattr(error, 'strerror', None) or error}"])
    # The signature is verified first, and the text parsed is the buffer read above: `check` requires its hash to be the
    # `flow_sha256` the signature covers, so a file swapped between the two reads fails.
    try:
        floor = flow_authority.VersionFloor.in_state_dir(args.state_dir) if args.state_dir else None
        ok, reasons, signed = flow_authority.verify_flow(args.manifest, args.pub, policy_pack.load_revoked(args.revoked),
                                                         floor=floor)
    except (OSError, ValueError) as error:
        return refuse([f"{error}"])
    signature = policy_manifest.Signature(ok, tuple(reasons), (signed or {}).get("flow_sha256", "") if ok else "",
                                          _created(signed) if ok else None)
    try:
        manifest = policy_manifest.parse(text, args.manifest)
    except policy_manifest.ManifestError as error:
        if not ok:
            print(policy_manifest.check_signature_only(signature).render(args.manifest), file=sys.stderr)
            return 1
        return refuse(error.lines())
    found = policy_manifest.check(manifest, signature, _reader(os.path.dirname(os.path.abspath(args.manifest))),
                                  known_targets=kinds.TARGET_KINDS, now=int(time.time()),
                                  point_findings=_point_findings)
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
