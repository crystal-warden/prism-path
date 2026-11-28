# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath policy manifest check FILE --pub KEY...`: the release check of a policy manifest (SPEC.md section 10).

The grammar and the check are the kernel's (`kernel/policy_manifest.py`). This surface does what the kernel may not:
it reads the manifest and the files it names (each confined to the manifest's directory), verifies the signature
with the flow authority, and prints what `policy_manifest.check` found. `examine` is that read and check as a call,
and `dist seal --manifest` seals from the `Release` it returns, so the seal reads nothing the check did not verify.
A manifest's targets are held to the kinds that registered a `derive` (`kinds.sealable`). `add_parser` takes the
`<action>` group of `prismpath policy`, so the command is registered in one place (`cli.py` calls it right after `policy_source`).

Exit 0 when the manifest holds, 1 when the check found something wrong, 2 when the manifest does not read or a
needed file cannot be read at all.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import time
from dataclasses import dataclass
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


class Unreadable(Exception):
    """The manifest or a key file it is checked with cannot be read at all (exit 2). `lines` say why."""

    def __init__(self, lines: List[str]):
        super().__init__("\n".join(lines))
        self.lines = lines


@dataclass(frozen=True)
class Examined:
    """What reading and verifying a manifest found: the parsed manifest (None when the signature failed and the text
    does not read either), the findings, the `Release` when there are none, and the verified flow manifest."""
    manifest: Optional[policy_manifest.Manifest]
    findings: List[policy_manifest.Finding]
    release: Optional[policy_manifest.Release]
    signed: Optional[dict]


def sealable_targets() -> frozenset:
    """The target kinds a manifest can be sealed for in this process: every kind that registered a `derive`."""
    from prismpath import kinds_builtin
    kinds_builtin.load()
    return kinds.sealable()


def examine(path: str, pubs: List[str], *, revoked: Optional[str] = None, state_dir: Optional[str] = None,
            now: Optional[int] = None) -> Examined:
    """Read the manifest at `path` once, verify its signature with the flow authority against `pubs` (and the version
    floor in `state_dir` when it is named), parse the same bytes, and check it against the files beside it, each
    confined to its directory. `Unreadable` when the manifest or a key file cannot be read at all, or the manifest's
    signature holds and its text does not read. The floor is read, never raised: raising it is the sealing tool's,
    once a release is written (`dist seal --manifest --state-dir`)."""
    from prismpath.hotswap import flow_authority, policy_pack
    now = int(time.time()) if now is None else now
    for one in [*pubs, *([revoked] if revoked else [])]:
        if not os.path.isfile(one):
            raise Unreadable([f"{one}: no such file"])
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise Unreadable([f"{path}: {getattr(error, 'strerror', None) or error}"]) from None
    # The signature is verified first, and the text parsed is the buffer read above: `check` requires its hash to be the
    # `flow_sha256` the signature covers, so a file swapped between the two reads fails.
    try:
        floor = flow_authority.VersionFloor.in_state_dir(state_dir) if state_dir else None
        ok, reasons, signed = flow_authority.verify_flow(path, pubs, policy_pack.load_revoked(revoked), floor=floor)
    except (OSError, ValueError) as error:
        raise Unreadable([f"{error}"]) from None
    signed = signed if ok else None
    version = (signed or {}).get("version")
    signature = policy_manifest.Signature(ok, tuple(reasons), (signed or {}).get("flow_sha256", ""), _created(signed)
                                          if ok else None, version if isinstance(version, int) else None,
                                          str((signed or {}).get("key_id", "")))
    try:
        manifest = policy_manifest.parse(text, path)
    except policy_manifest.ManifestError as error:
        if not ok:
            return Examined(None, [policy_manifest.check_signature_only(signature)], None, None)
        raise Unreadable(error.lines()) from None
    found, release = policy_manifest.verify(manifest, signature, _reader(os.path.dirname(os.path.abspath(path))),
                                            known_targets=sealable_targets(), now=now)
    return Examined(manifest, found, release, signed)


def manifest_cmd(args) -> int:
    def refuse(lines: List[str]) -> int:
        for text in lines:
            print(f"prismpath policy manifest check: {text}", file=sys.stderr)
        return 2

    try:
        done = examine(args.manifest, args.pub, revoked=args.revoked, state_dir=args.state_dir)
    except Unreadable as error:
        return refuse(error.lines)
    manifest, found = done.manifest, done.findings
    if manifest is None:
        print(found[0].render(args.manifest), file=sys.stderr)
        return 1
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
