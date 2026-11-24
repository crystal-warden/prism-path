# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`prismpath dist`, the command line of policy distribution (spec-policy-distribution.md and
docs/guides/policy-distribution.md).

The owner's commands run where the authority key is and never on the controller (F1): `anchor` writes the
trust anchor of a stream from the authority public keys, `seal` signs an
envelope, `revoke` and `rotate` seal the trust statements, and `rekey` runs rotate, release, commit and
revoke in that order, so the active release never stands on a key that is already revoked (R5). `seal`
and `revoke` refuse a revocation list that drops an entry no floor has passed (R8), against the controller
directory given with `--held`.

The controller's commands work on its directory, which is its whole state, so they may run beside
`serve`: `serve` listens, `enroll` adds a PEP and the anchor of its stream, `offer`, `commit` and `abort`
drive a group's rollout, and `fleet` prints the fleet view. A sealed envelope and its body dropped in the
directory's `inbox/` as `<name>.sealed` and `<name>.body` are verified and stored at the next request or
command (F1). `verify` runs the one verifier on a sealed envelope and its body.

`pep` runs a host PEP over its state directory: `provision` takes the trust anchor and prints its
fingerprint, and again with `--confirm` takes that fingerprint (P2), `poll` pulls from a controller,
`status` prints the PEP's state and `rollback` returns to the release kept before the active one (RB1).

The engineer's commands run where the install keys are (section 21): `anchor` with `--install-pub` writes the
install part of a `/2` anchor, `install` seals a fallback policy or a ceiling, compared with the set it follows
(IS12) and held to the ceiling (CL3), and `install-trust` seals an install trust statement against the engineer's
list of retired key ids (IS11, K4). `seal --ceiling` refuses a release above the ceiling (CL2). Before it signs a
ceiling, `install` shows its lapse preview from the controller state `--held` names, or says the fleet is unknown,
warns where no release inside the ceiling reaches a machine that lapses, and signs only on the engineer's yes (CL5,
CL6). `--staged` writes the unsigned rollout option that has the controller offer it to a canary group first (CL7).

Exit 0 when the command did what it was asked, 1 when it was refused, with the cause on stderr, and 2 for a
usage error.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import List, Optional

from prismpath import canon
from prismpath.distribution import envelope as env
from prismpath.distribution import kinds, state_record
from prismpath.distribution.kinds import Refused

DEFAULT_LISTEN = "127.0.0.1:8471"
ROLLOUT_SUFFIX = ".rollout.json"                     # CL7: an unsigned rollout option in the inbox


def add_parser(subparsers) -> None:
    dist = subparsers.add_parser(
        'dist', help='Policy distribution: seal and verify signed releases, run the reference controller, and run a '
                     'host enforcement point that pulls from it (seal, verify, serve, enroll, offer, commit, abort, '
                     'pep, fleet, revoke, rotate, rekey, anchor, install, install-trust, acknowledge)')
    commands = dist.add_subparsers(dest='dist_command', metavar='<action>')
    commands.required = True

    seal = commands.add_parser('seal', help='sign a distribution envelope for a body (the owner, where the key is)')
    seal.add_argument('--artifact', required=True, help='the artifact kind, such as policy.ppt')
    seal.add_argument('--body', required=True, metavar='FILE')
    _release_args(seal)
    seal.add_argument('--release', default=None, help='the release id (default the release of this one artifact)')
    seal.add_argument('--policy', default=None, metavar='SHA256', help='the policy hash (default the body\'s own)')
    seal.add_argument('--replaces', default=None, metavar='SHA256',
                      help='the policy hash this release replaces (default, with --held, the latest release stored '
                           'on the stream below this seq, else none)')
    seal.add_argument('--widens', action='store_true',
                      help='say the release allows more than the one it replaces; set as well unless the release is '
                           'compared with the one --held holds for replaces and is not larger (W7)')
    seal.add_argument('--yes', action='store_true',
                      help='sign the change statement for a table the comparator finds allows nothing more, without '
                           'asking (W9, W11)')
    seal.add_argument('--meta', default=None, metavar='FILE', help='the meta object, JSON')
    seal.add_argument('--qualification', default=None, metavar='FILE',
                      help='for policy.ppt, fill meta from the image and this qualification envelope')
    seal.add_argument('--ceiling', default=None, metavar='DIR',
                      help='the ceiling the stream\'s PEPs hold, as `dist install` wrote it; a release above it is '
                           'refused before it is sealed (CL2)')
    seal.set_defaults(func=seal_cmd)

    widen = commands.add_parser('widen', help='sign the widening statement a release that allows more needs (W4)')
    widen.add_argument('--sealed', required=True, metavar='FILE', help='the sealed release it is for')
    widen.add_argument('--from', dest='froms', action='append', default=[], metavar='SHA256',
                       help='a policy hash the release may replace (repeatable); none means any, and no policy')
    widen.add_argument('--key', action='append', required=True, metavar='PEM', help='an authority private key')
    widen.add_argument('--out', required=True, metavar='FILE', help='the sealed statement; the body goes beside it')
    widen.set_defaults(func=widen_cmd)

    anchor = commands.add_parser('anchor', help='write the trust anchor of a stream from authority public keys')
    anchor.add_argument('--pub', action='append', required=True, metavar='FILE',
                        help='an authority public key, 32 raw bytes (`swap keygen`), repeatable')
    anchor.add_argument('--target', required=True, help='the target kind of the stream\'s PEPs')
    anchor.add_argument('--stream', required=True)
    anchor.add_argument('--controller', default=None, metavar='FILE',
                        help='the controller\'s instance public key, 32 raw bytes; writes a prismpath.dist-trust/2 '
                             'anchor that names it as the first controller key (K6, P4)')
    anchor.add_argument('--fresh', type=int, default=0, metavar='SECONDS',
                        help='with --controller, the longest lifetime of a fresh statement; 0 leaves freshness off (H16)')
    anchor.add_argument('--install-pub', action='append', default=[], metavar='FILE',
                        help='an install public key, 32 raw bytes, repeatable; writes the anchor\'s install part (P4)')
    anchor.add_argument('--install-threshold', type=int, default=1, help='the install threshold (IS2)')
    anchor.add_argument('--operator-pub', action='append', default=[], metavar='FILE',
                        help='an operator public key, 32 raw bytes, repeatable (OP1)')
    anchor.add_argument('--install-seq', type=int, default=0, help='the install trust sequence the keys stand at')
    anchor.add_argument('--domain', default=None, metavar='SHA256',
                        help='the hash of the reading domain the PEP was built with (P4, CL4); default the one this '
                             'build gives the target kind')
    anchor.add_argument('--out', required=True, metavar='FILE')
    anchor.set_defaults(func=anchor_cmd)

    inst = commands.add_parser('install', help='seal an install set: an action floor, a fallback policy or a ceiling '
                                               '(section 21)')
    inst.add_argument('--kind', required=True, choices=('floor', 'fallback', 'ceiling'),
                      help='the install kind; this version builds the fallback policy and the ceiling')
    inst.add_argument('--set', dest='bodies', action='append', default=[], metavar='AS=FILE',
                      help='an artifact of the set and its body, repeatable, such as policy.ppt=table.ppt')
    inst.add_argument('--list', dest='tables', action='append', default=[], metavar='FILE',
                      help='for a ceiling of a kind that cannot decide, a table the list holds, repeatable (CL1)')
    inst.add_argument('--empty', action='store_true', help='the empty set, which withdraws the held one (IS6)')
    inst.add_argument('--stream', required=True)
    inst.add_argument('--seq', type=int, required=True, help='the install sequence of this kind on the stream')
    inst.add_argument('--target', required=True, help='the one target kind of the set (IS1)')
    inst.add_argument('--key', action='append', required=True, metavar='PEM', help='an install private key')
    inst.add_argument('--not-before', type=int, default=None, help='Unix seconds (default now)')
    inst.add_argument('--qualification', default=None, metavar='FILE',
                      help='for a policy.ppt, fill its meta from the image and this qualification envelope')
    inst.add_argument('--follows', default=None, metavar='DIR',
                      help='the set this one follows, as this command wrote it; sets replaces and is compared (IS12)')
    inst.add_argument('--ceiling', default=None, metavar='DIR', help='the held ceiling, as this command wrote it (CL3)')
    inst.add_argument('--widens', action='store_true', help='say the set allows more than the one it follows')
    inst.add_argument('--yes', action='store_true',
                      help='sign the install change statement for a floor or fallback table the comparator finds '
                           'allows nothing more, and a ceiling after its lapse preview, without asking at the '
                           'terminal (IS15, CL5)')
    inst.add_argument('--held', default=None, metavar='DIR',
                      help='a controller directory, read and never written: a ceiling\'s lapse preview names the '
                           'releases it is above and the machines that run each (CL5, CL6)')
    inst.add_argument('--staged', action='store_true',
                      help='a ceiling for a planned change: the controller offers it to the canary group first and to '
                           'the rest once the canary reports it applied with no unexpected lapse (CL7)')
    inst.add_argument('--canary', default='canary', metavar='GROUP',
                      help='with --staged, the controller group offered the ceiling first (default canary)')
    inst.add_argument('--rate', default=None, metavar='ALLOWS/WINDOW', help="a floor's signed rate of overrides (AF8)")
    inst.add_argument('--answer-rate', default=None, metavar='ALLOWS/WINDOW',
                      help="a floor's signed rate of operator allows (OP4)")
    inst.add_argument('--layout', default=None, metavar='FILE', help="a table floor's layout document (AF10)")
    inst.add_argument('--command', type=int, default=None, help="a table floor's command register (AF9)")
    inst.add_argument('--out', required=True, metavar='DIR', help='where each <as>.sealed and <as>.body is written')
    inst.set_defaults(func=install_cmd)

    itrust = commands.add_parser('install-trust', help='seal an install trust statement (IS11)')
    itrust.add_argument('--current-pub', action='append', required=True, metavar='FILE',
                        help='an install public key as the PEP holds it now, repeatable')
    itrust.add_argument('--current-threshold', type=int, required=True)
    itrust.add_argument('--current-operator', action='append', default=[], metavar='FILE')
    itrust.add_argument('--install-pub', action='append', required=True, metavar='FILE', help='a key of the new set')
    itrust.add_argument('--operator-pub', action='append', default=[], metavar='FILE')
    itrust.add_argument('--threshold', type=int, required=True)
    itrust.add_argument('--retired', required=True, metavar='FILE',
                        help='the engineer\'s list of every retired key id, one per line, kept here and appended to '
                             '(K4): a key once retired is never added again')
    itrust.add_argument('--stream', required=True)
    itrust.add_argument('--seq', type=int, required=True, help='the install trust sequence, the held one plus one')
    itrust.add_argument('--target', required=True)
    itrust.add_argument('--key', action='append', required=True, metavar='PEM',
                        help='a signer: the current install keys at the threshold and every key the statement adds')
    itrust.add_argument('--not-before', type=int, default=None, help='Unix seconds (default now)')
    itrust.add_argument('--out', required=True, metavar='FILE', help='the sealed statement; the body goes beside it')
    itrust.set_defaults(func=install_trust_cmd)

    verify = commands.add_parser('verify', help='run the verifier on a sealed envelope and its body')
    verify.add_argument('--sealed', required=True, metavar='FILE')
    verify.add_argument('--body', required=True, metavar='FILE')
    verify.add_argument('--anchor', required=True, metavar='FILE', help='the trust anchor the PEP holds')
    verify.add_argument('--qualification', default=None, metavar='FILE', help='a host PEP\'s qualification envelope')
    verify.add_argument('--now', type=int, default=None, help='the PEP\'s time, Unix seconds (default now)')
    verify.set_defaults(func=verify_cmd)

    serve = commands.add_parser('serve', help='run the reference controller\'s HTTP listener on its directory')
    _controller_args(serve)
    serve.add_argument('--listen', default=DEFAULT_LISTEN, metavar='HOST:PORT')
    serve.set_defaults(func=serve_cmd)

    enroll = commands.add_parser('enroll', help='enrol a PEP by its instance public key, and serve its stream')
    _controller_args(enroll)
    enroll.add_argument('--pub', required=True, metavar='FILE', help='the PEP\'s instance public key, 32 raw bytes')
    enroll.add_argument('--anchor', required=True, metavar='FILE', help='the trust anchor of its stream')
    enroll.add_argument('--qualification', default=None, metavar='FILE', help='a host stream\'s qualification envelope')
    enroll.add_argument('--group', default='default')
    enroll.add_argument('--rule', choices=('each', 'all'), default='each')
    enroll.add_argument('--install', action='append', default=None, metavar='ENVELOPE_ID',
                        help='the envelope id of an install statement the PEP printed beside the anchor, repeatable; '
                             'enrolls its install id, which acknowledges a first set it came with (P2 step 5, H13)')
    enroll.add_argument('--layout', default=None, metavar='FILE',
                        help='for a table kind, the layout document its action floors are checked against (AF10)')
    enroll.set_defaults(func=enroll_cmd)

    ack = commands.add_parser('acknowledge', help='acknowledge a held install set or install trust statement by the '
                                                  'envelope ids of its statements, so the controller offers it (H13)')
    _controller_args(ack)
    ack.add_argument('--envelope', action='append', required=True, metavar='ENVELOPE_ID',
                     help='an envelope id of the set, repeatable; name every statement of it, never a release id')
    ack.add_argument('--by', default=None, help='the acknowledger, by default the login running this command')
    ack.set_defaults(func=acknowledge_cmd)

    for name, text in (('offer', 'offer a stored release to a group'),
                       ('commit', 'send commit to the members of a group\'s rollout that staged'),
                       ('abort', 'end a group\'s rollout and send abort to its members')):
        command = commands.add_parser(name, help=text)
        _controller_args(command)
        command.add_argument('--group', default='default')
        if name == 'offer':
            command.add_argument('--stream', required=True)
            command.add_argument('--seq', type=int, required=True)
            command.add_argument('--delay', type=int, default=0, metavar='MS', help='the flip delay of B8')
        command.set_defaults(func=rollout_cmd, action=name)

    fleet = commands.add_parser('fleet', help='print the fleet view (F4)')
    _controller_args(fleet)
    fleet.set_defaults(func=fleet_cmd)

    revoke = commands.add_parser('revoke', help='seal the next revocation list (the owner, where the key is)')
    revoke.add_argument('--entry', action='append', default=[], metavar='KIND=VALUE',
                        help='add envelope=<id>, policy=<hash> or key=<key id> (repeatable)')
    revoke.add_argument('--drop', action='append', default=[], metavar='KIND=VALUE',
                        help='leave out an envelope or a policy a floor has passed (repeatable)')
    revoke.add_argument('--floor', action='append', default=[], metavar='STREAM=SEQ', help='raise a floor (repeatable)')
    _trust_args(revoke)
    revoke.set_defaults(func=revoke_cmd)

    rotate = commands.add_parser('rotate', help='seal a key rotation, signed by a trusted key and the new one')
    rotate.add_argument('--new', required=True, metavar='PEM', help='the new authority private key')
    rotate.add_argument('--retire', default='', metavar='KEY_ID', help='a trusted key id to retire')
    _trust_args(rotate)
    rotate.set_defaults(func=rotate_cmd)

    rekey = commands.add_parser('rekey', help='rotate, release under the new key, commit, then revoke the old key')
    _controller_args(rekey)
    rekey.add_argument('--old', required=True, metavar='PEM', help='the authority key in use')
    rekey.add_argument('--new', required=True, metavar='PEM', help='the authority key that replaces it')
    rekey.add_argument('--body', required=True, metavar='FILE', help='the policy to release under the new key')
    rekey.add_argument('--qualification', default=None, metavar='FILE')
    rekey.add_argument('--group', default='default')
    rekey.add_argument('--stream', required=True)
    rekey.add_argument('--seq', type=int, required=True, help='the release\'s seq')
    rekey.add_argument('--target', action='append', required=True, help='a target kind (repeatable)')
    rekey.add_argument('--not-before', type=int, default=None)
    rekey.add_argument('--expires', type=int, required=True)
    rekey.add_argument('--timeout', type=float, default=600.0, help='seconds to wait for the commit')
    rekey.add_argument('--widens', action='store_true',
                       help='the release may allow more than the table it replaces; without it a table the comparator '
                            'finds larger is refused (W9)')
    rekey.add_argument('--yes', action='store_true',
                       help='sign the change statement for a table the comparator finds allows nothing more (W11)')
    rekey.set_defaults(func=rekey_cmd)

    pep = commands.add_parser('pep', help='run a host enforcement point (provision, poll, status, rollback)')
    pep.add_argument('pep_command', choices=('provision', 'poll', 'status', 'rollback'))
    pep.add_argument('--state', required=True, metavar='DIR', help='the PEP\'s state directory')
    pep.add_argument('--kind', choices=('host', 'agent', 'gateway'), default='host',
                     help='host (a policy host), agent (an agent home that `prismpath agent init --follow` made) or '
                          'gateway (a gateway home holding its instance key and no authority key)')
    pep.add_argument('--key', required=True, metavar='FILE', help='the PEP\'s instance key (`ledger keygen`)')
    pep.add_argument('--anchor', default=None, metavar='FILE', help='provision: the trust anchor')
    pep.add_argument('--qualification', default=None, metavar='FILE', help='provision: the qualification envelope')
    pep.add_argument('--confirm', default=None, metavar='FINGERPRINT', help='provision: the anchor\'s fingerprint')
    pep.add_argument('--url', default=None, help='poll: the controller, http://host:port')
    pep.add_argument('--once', action='store_true', help='poll: one round, then exit')
    pep.add_argument('--interval', type=float, default=30.0, help='poll: seconds between rounds (B3)')
    pep.add_argument('--wait', type=float, default=0.0, help='poll: hold each request open up to this long')
    pep.set_defaults(func=pep_cmd)


def _release_args(parser) -> None:
    parser.add_argument('--stream', required=True)
    parser.add_argument('--seq', type=int, required=True)
    parser.add_argument('--target', action='append', required=True, help='a target kind (repeatable)')
    parser.add_argument('--not-before', type=int, default=None, help='Unix seconds (default now)')
    parser.add_argument('--expires', type=int, default=0, help='Unix seconds; 0 only for a trust kind')
    parser.add_argument('--key', action='append', required=True, metavar='PEM', help='an authority private key (repeatable)')
    parser.add_argument('--held', default=None, metavar='DIR', help='a controller directory, for R8')
    parser.add_argument('--out', required=True, metavar='FILE', help='where the sealed envelope is written')


def _trust_args(parser) -> None:
    parser.add_argument('--seq', type=int, default=None, help='the trust sequence (default the held one plus one)')
    parser.add_argument('--target', action='append', default=None, help='a target kind (default every served kind)')
    parser.add_argument('--key', action='append', required=True, metavar='PEM', help='a trusted authority private key')
    parser.add_argument('--held', required=True, metavar='DIR', help='the controller directory (R1, R8)')
    parser.add_argument('--not-before', type=int, default=None, help='Unix seconds (default now)')
    parser.add_argument('--out', required=True, metavar='FILE', help='the sealed statement; the body goes beside it')


def _controller_args(parser) -> None:
    parser.add_argument('--dir', required=True, metavar='DIR', help='the controller\'s directory')
    parser.add_argument('--key', required=True, metavar='FILE', help='the controller\'s instance key')


# ------------------------------------------------------------------ helpers

def _fail(cause: str, detail: str = "") -> int:
    print(f"refused: {cause}" + (f": {detail}" if detail else ""), file=sys.stderr)
    return 1


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _json(path: Optional[str]) -> Optional[dict]:
    return None if path is None else json.loads(_read(path).decode("utf-8"))


def _authority(paths: List[str]) -> list:
    from prismpath.hotswap import policy_pack
    return [policy_pack._load_private(path) for path in paths]


def _instance(path: str):
    from prismpath.ledgers.root_statement import InstanceKey
    return InstanceKey.load(path)


def _write(path: str, data: bytes) -> None:
    canon.atomic_write_bytes(path, data)


def _print(doc) -> None:
    print(json.dumps(doc, indent=1, sort_keys=True))


def policy_meta(body: bytes, qualification: dict) -> dict:
    """The `meta` of a `policy.ppt` envelope, from the image and the qualification envelope a host holds."""
    from prismpath.hotswap import policy_pack
    header = policy_pack.read_ppt_header(body)
    return {"counts": {key: header[key] for key in sorted(kinds.COUNT_MEMBERS)},
            "fields": dict(qualification["fields"]), "qualification": qualification["envelope_id"],
            "wcet_cycles": policy_pack.wcet_cycles(body)}


def build_sealed(artifact: str, body: bytes, *, stream: str, seq: int, targets: List[str], signers: list,
                 not_before: int, expires: int, meta: Optional[dict] = None, release: Optional[str] = None,
                 policy: Optional[str] = None, replaces: str = "", widens: bool = False,
                 held: Optional[str] = None) -> bytes:
    """The sealing tool. A revocation list is checked against the controller directory `held` first (R8)."""
    trust_kind = artifact in kinds.ON_TRUST_STREAM
    if artifact == "trust.revocation":
        if held is None:
            raise Refused("dist:trust-replay", "a revocation list is sealed against the controller's directory (R8)")
        _check_drops(body, held)
    envelope_bytes = env.build(
        artifact, body, stream=env.TRUST_STREAM if trust_kind else stream, seq=seq, targets=targets,
        not_before=not_before, expires=0 if trust_kind else expires, meta=meta or {}, replaces=replaces, widens=widens,
        policy_sha256=env.ZERO_HASH if trust_kind else (policy or canon.sha256_hex(body)),
        release=env.ZERO_HASH if trust_kind else (release or env.release_id([(artifact, canon.sha256_hex(body))])))
    return env.seal(envelope_bytes, signers)


def _held(directory: str):
    """The controller state in `directory`, read and never written, for the sealing tool."""
    from prismpath.distribution.controller import Controller
    return Controller.reader(directory)


def _check_drops(body: bytes, directory: str) -> None:
    from prismpath.distribution.trust import check_drops
    controller = _held(directory)
    earlier = [controller.blob(controller.stored[one]["body_sha256"]) for one in controller.chain
               if controller.stored[one]["artifact"] == "trust.revocation"]
    check_drops(body, earlier, controller.held_envelopes())


def _controller(args):
    from prismpath.distribution.controller import Controller
    return Controller(args.dir, _instance(args.key))


def ingest(controller) -> list:
    """Store every `<name>.sealed` with its `<name>.body` in the directory's inbox (F1). A stored pair is
    removed, a refused one is renamed `.refused` with its cause beside it."""
    inbox = os.path.join(controller.dir, "inbox")
    if not os.path.isdir(inbox):
        return []
    from prismpath.distribution.controller_install import ROLLOUT_FORMAT
    done = []
    for name in sorted(os.listdir(inbox)):            # CL7: a rollout option first, so no PEP sees the set before it
        if not name.endswith(ROLLOUT_SUFFIX):
            continue
        path = os.path.join(inbox, name)
        try:
            doc = json.loads(_read(path).decode("utf-8"))
            if not isinstance(doc, dict) or doc.get("format") != ROLLOUT_FORMAT or doc.get("staged") is not True:
                raise ValueError("not a rollout option of a staged ceiling")
            done.append(controller.pace(doc.get("set_id"), doc.get("canary")))
            os.remove(path)
        except (ValueError, UnicodeDecodeError) as error:
            done.append({"refused": name, "cause": str(error)})
            os.replace(path, path + ".refused")
    for name in sorted(os.listdir(inbox)):
        if not name.endswith(".sealed"):
            continue
        stem = os.path.join(inbox, name[:-len(".sealed")])
        if not os.path.exists(stem + ".body"):
            continue
        try:
            envelope = controller.put(_read(stem + ".sealed"), _read(stem + ".body"))
            done.append({"stored": envelope.envelope_id, "artifact": envelope.artifact, "seq": envelope.seq})
            os.remove(stem + ".sealed")
            os.remove(stem + ".body")
        except Refused as refused:
            done.append({"refused": name, "cause": refused.cause})
            os.replace(stem + ".sealed", stem + ".sealed.refused")
            _write(stem + ".cause", f"{refused.cause}: {refused}\n".encode("utf-8"))
    return done


# ------------------------------------------------------------------ the owner's commands

def replaced(directory: Optional[str], artifact: str, stream: str, seq: int, policy: Optional[str] = None):
    """The (policy hash, body) of the release a new one at `seq` replaces: the latest one the controller in
    `directory` stores on `stream` below `seq`, with its `artifact` body, or the latest whose policy hash is
    `policy` when one is named. ("", None) when there is none, and (`policy`, None) when none is held for it."""
    if directory is None or artifact in kinds.TRUST_ARTIFACTS:
        return policy or "", None
    return _replaced_in(_held(directory), artifact, stream, seq, policy)


def _replaced_in(controller, artifact: str, stream: str, seq: int, policy: Optional[str] = None):
    below = _below(controller, artifact, stream, seq, policy)
    if not below and policy is not None:
        return policy, None
    if not below:
        return "", None
    latest = max(below, key=lambda info: info["seq"])
    return latest["policy"], controller.blob(latest["body_sha256"])


def _below(controller, artifact: str, stream: str, seq: int, policy: Optional[str]) -> list:
    return [dict(info, envelope_id=one) for one, info in controller.stored.items()
            if info["stream"] == stream and info["artifact"] == artifact and info["seq"] < seq
            and (policy is None or info["policy"] == policy)]


def _replaced_fields(controller, stream: str, seq: int, policy: Optional[str]) -> Optional[dict]:
    """The signed field dictionary of the `policy.ppt` envelope `_replaced_in` holds the new one to (W8)."""
    from prismpath.distribution import table_compare
    below = _below(controller, "policy.ppt", stream, seq, policy)
    if not below:
        return None
    latest = max(below, key=lambda info: info["seq"])
    return table_compare.table_fields(env.read(env.unseal(controller.sealed(latest["envelope_id"]))[0]))


def table_comparison(controller, body: bytes, meta: Optional[dict], stream: str, seq: int, policy: Optional[str],
                     previous: Optional[bytes]):
    """W8 at the sealing tool: the table comparator's answer for a `policy.ppt` body against the table it
    replaces, which `controller` holds, or None when it holds none."""
    from prismpath.distribution import table_compare
    if previous is None:
        return None
    fields = (meta or {}).get("fields")
    return table_compare.compare_tables(previous, body, active_fields=_replaced_fields(controller, stream, seq, policy),
                                        staged_fields=dict(fields) if isinstance(fields, dict) else None)


def scope_mark(artifact: str, previous: Optional[bytes], body: bytes, comparison) -> str:
    """F4 at the sealing tool, as the controller marks a rollout: a widening for a release that replaces nothing
    held, that a comparator with an order finds larger, or a table W8 finds larger or cannot decide, a change, not
    larger, for one that differs and allows nothing more, and empty for a renewal."""
    from prismpath.distribution import widening
    from prismpath.distribution.controller import CHANGE_NOT_LARGER, WIDENING
    if previous is None:
        return WIDENING
    if bytes(previous) == bytes(body):
        return ""
    if widening.compare_artifact(artifact, previous, body) == widening.NOT_LARGER:
        return CHANGE_NOT_LARGER
    if artifact == "policy.ppt" and comparison is not None and comparison.answer == widening.NOT_LARGER:
        return CHANGE_NOT_LARGER
    return WIDENING


def _confirmed(args, comparison, replaces: str, *, keys: str = "the release's keys") -> bool:
    """W9, IS15: the owner or the engineer is shown what W8 found before a change statement is signed, and says yes,
    at the terminal or with `--yes` for a script."""
    shown = {"comparison": comparison.document(), "replaces": replaces,
             "change": "this table allows nothing more than the one it replaces, by the table comparator (W8)"}
    print(json.dumps(shown, indent=2, sort_keys=True), file=sys.stderr)
    return _said_yes(args, f"sign a change statement that says so, with {keys}? [y/N] ")


def _said_yes(args, question: str) -> bool:
    """`--yes`, or a yes typed at the terminal. No terminal and no `--yes` is a no."""
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(question)
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def change_sealed(release_sealed: bytes, signers: list) -> tuple:
    """The sealed change statement for the release in `release_sealed` and its body (W10): the same stream, seq,
    policy hash, release id, targets, `replaces` and `widens` (E7), `from` the policy hash it replaces and `basis`
    the table comparator its claim rests on."""
    release = env.read(env.unseal(release_sealed)[0])
    if release.artifact in kinds.TRUST_ARTIFACTS or release.widens or not release.replaces:
        raise Refused(kinds.BAD_FORMAT, "a change statement is for a release that replaces one and does not widen")
    body = canon.canon2_bytes({"basis": kinds.CHANGE_BASIS, canon.ENCODING_KEY: canon.CANON2,
                               "format": kinds.CHANGE_FORMAT, "from": release.replaces})
    kinds.read_change(body)
    envelope_bytes = env.build("trust.change", body, stream=release.stream, seq=release.seq,
                               targets=list(release.targets), not_before=release.not_before, expires=0,
                               policy_sha256=release.policy_sha256, release=release.release,
                               replaces=release.replaces, widens=False)
    return env.seal(envelope_bytes, signers), body


NOT_CONFIRMED = ("the table allows nothing more than the one it replaces, and a change statement is signed only when "
                 "the owner says yes; run again at a terminal or with --yes, or with --widens to release it as a "
                 "widening")


def seal_cmd(args) -> int:
    from prismpath.distribution import widening
    from prismpath.distribution.controller import WIDENING
    body = _read(args.body)
    meta = _json(args.meta)
    if meta is None and args.artifact == "policy.ppt" and args.qualification:
        meta = policy_meta(body, _json(args.qualification))
    if args.ceiling:
        from prismpath.distribution import install
        held = read_set_dir(args.ceiling)
        if not install.inside(args.target[0], held, {args.artifact: body}, whole=False):
            return _fail(install.ABOVE_CEILING, "the release is above the ceiling (CL2)")
    replaces, previous = replaced(args.held, args.artifact, args.stream, args.seq, args.replaces)
    # W7: `widens` is false only when the release is compared with the one it replaces and is not larger, so
    # a release that replaces nothing, or one the directory holds nothing for, widens
    widens = args.widens or args.artifact not in kinds.TRUST_ARTIFACTS and (
        previous is None or widening.compare_artifact(args.artifact, previous, body) != widening.NOT_LARGER)
    comparison = None
    if args.artifact == "policy.ppt" and args.held is not None and previous is not None:
        comparison = table_comparison(_held(args.held), body, meta, args.stream, args.seq, args.replaces, previous)
    mark = scope_mark(args.artifact, previous, body, comparison) if args.artifact not in kinds.TRUST_ARTIFACTS else ""
    change = (widens and not args.widens and comparison is not None and comparison.answer == widening.NOT_LARGER
              and replaces != "")
    if change:
        if not _confirmed(args, comparison, replaces):
            return _fail(widening.UNSIGNED, NOT_CONFIRMED)
        widens = False                                   # W11: it allows nothing more, so it does not widen
    try:
        sealed = build_sealed(args.artifact, body, stream=args.stream, seq=args.seq, targets=args.target,
                              signers=_authority(args.key), not_before=args.not_before or int(time.time()),
                              expires=args.expires, meta=meta, release=args.release, policy=args.policy,
                              replaces=replaces, widens=widens, held=args.held)
        statement = change_sealed(sealed, _authority(args.key)) if change else None
    except Refused as refused:
        return _fail(refused.cause, str(refused))
    _write(args.out, sealed)
    printed = {"sealed": args.out, "envelope_id": env.envelope_id(env.unseal(sealed)[0]),
               "body_sha256": canon.sha256_hex(body), "sealed_size": len(sealed), "replaces": replaces,
               "widens": widens, "scope": mark}
    if comparison is not None:
        printed["comparison"] = comparison.document()
    if statement is not None:
        stem = os.path.splitext(args.out)[0] + ".change"
        _write(stem + ".sealed", statement[0])
        _write(stem + ".body", statement[1])
        printed["change"] = {"sealed": stem + ".sealed", "body": stem + ".body", "from": replaces,
                             "basis": kinds.CHANGE_BASIS}
    elif widens and mark == WIDENING:
        printed["next"] = "this release allows more than the one it replaces; sign its widening statement with widen"
    elif widens:
        printed["next"] = "this release says it widens; sign its widening statement with widen"
    _print(printed)
    return 0


def widening_sealed(release_sealed: bytes, froms: List[str], signers: list) -> tuple:
    """The sealed widening statement for the release in `release_sealed` and its body: the same stream, seq,
    policy hash, release id, targets, `replaces` and `widens` (W4, E7), and `from` sorted. Only `widen` and a
    `rekey` the owner passes `--widens` sign one, never the tool on its own (W9)."""
    release = env.read(env.unseal(release_sealed)[0])
    if release.artifact in kinds.TRUST_ARTIFACTS:
        raise Refused(kinds.BAD_FORMAT, "a widening statement is for a release, not a trust statement")
    body = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.WIDENING_FORMAT,
                               "from": sorted(set(froms))})
    kinds.read_widening(body)
    envelope_bytes = env.build("trust.widening", body, stream=release.stream, seq=release.seq,
                               targets=list(release.targets), not_before=release.not_before, expires=0,
                               policy_sha256=release.policy_sha256, release=release.release,
                               replaces=release.replaces, widens=release.widens)
    return env.seal(envelope_bytes, signers), body


def widen_cmd(args) -> int:
    try:
        sealed, body = widening_sealed(_read(args.sealed), args.froms, _authority(args.key))
    except Refused as refused:
        return _fail(refused.cause, str(refused))
    _write(args.out, sealed)
    body_path = os.path.splitext(args.out)[0] + ".body"
    _write(body_path, body)
    _print({"sealed": args.out, "body": body_path, "from": sorted(set(args.froms)),
            "envelope_id": env.envelope_id(env.unseal(sealed)[0])})
    return 0


def _trust_statement(args, artifact: str, body: bytes, signers: list) -> int:
    controller = _held(args.held)
    if artifact == "trust.revocation" and set(kinds.read_revocation(body)["keys"]) & controller.install_key_ids():
        return _fail("dist:rotation-invalid", "a revocation list never names an install or an operator key id (IS7)")
    if artifact == "trust.rotation":
        added = env.key_id(bytes.fromhex(kinds.read_rotation(body)["add"]))
        if added in controller.retired_authority() | controller.install_key_ids():
            return _fail("dist:rotation-invalid", "the rotation adds a key that was retired or is held in another "
                                                  "role (K4)")
    targets = args.target or sorted({anchor["target"] for anchor in controller.anchors.values()})
    if not targets:
        return _fail("dist:target-mismatch", "the controller serves no stream, so name --target")
    seq = args.seq if args.seq is not None else controller.trust_seq() + 1
    try:
        sealed = build_sealed(artifact, body, stream=env.TRUST_STREAM, seq=seq, targets=targets, signers=signers,
                              not_before=args.not_before or int(time.time()), expires=0, held=args.held)
    except Refused as refused:
        return _fail(refused.cause, str(refused))
    _write(args.out, sealed)
    body_path = os.path.splitext(args.out)[0] + ".body"
    _write(body_path, body)
    _print({"sealed": args.out, "body": body_path, "seq": seq, "envelope_id": env.envelope_id(env.unseal(sealed)[0])})
    return 0


def revocation_body(directory: str, entries: List[str], drops: List[str], floors: List[str]) -> bytes:
    """The next revocation list: the latest one stored in the controller directory, with `entries` added,
    `drops` left out and `floors` raised. A list is cumulative (section 10)."""
    controller = _held(directory)
    latest = {"envelopes": [], "keys": [], "policies": [], "floors": {}}
    for one in controller.chain:
        if controller.stored[one]["artifact"] == "trust.revocation":
            latest = kinds.read_revocation(controller.blob(controller.stored[one]["body_sha256"]))
    lists = {name: set(latest[name]) for name in ("envelopes", "keys", "policies")}
    raised = dict(latest["floors"])
    column = {"envelope": "envelopes", "policy": "policies", "key": "keys"}
    for entry in entries:
        kind, _, value = entry.partition("=")
        if kind not in column or not kinds.is_hex64(value):
            raise ValueError(f"{entry!r} is not envelope=, policy= or key= with 64 hex digits")
        lists[column[kind]].add(value)
    for entry in drops:
        kind, _, value = entry.partition("=")
        if kind not in ("envelope", "policy"):
            raise ValueError("only an envelope or a policy is ever dropped, never a key (R6)")
        lists[column[kind]].discard(value)
    for entry in floors:
        stream, _, seq = entry.partition("=")
        if not kinds.is_stream(stream) or not seq.isdigit():
            raise ValueError(f"{entry!r} is not STREAM=SEQ")
        raised[stream] = max(raised.get(stream, 0), int(seq))
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.REVOCATION_FORMAT,
                               "envelopes": sorted(lists["envelopes"]), "keys": sorted(lists["keys"]),
                               "policies": sorted(lists["policies"]), "floors": raised})


def revoke_cmd(args) -> int:
    try:
        body = revocation_body(args.held, args.entry, args.drop, args.floor)
        kinds.read_revocation(body)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    except Refused as refused:
        return _fail(refused.cause, str(refused))
    return _trust_statement(args, "trust.revocation", body, _authority(args.key))


def rotation_body(new_private, retire: str = "") -> bytes:
    from prismpath.hotswap import policy_pack
    _priv, _pub, ser, _invalid = policy_pack._ed25519()
    public = new_private.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.ROTATION_FORMAT,
                               "add": public.hex(), "retire": retire})


def rotate_cmd(args) -> int:
    new = _authority([args.new])[0]
    return _trust_statement(args, "trust.rotation", rotation_body(new, args.retire), _authority(args.key) + [new])


def rekey_cmd(args) -> int:
    """Rotate to the new key retiring the old one, release under the new key, wait for the group to commit, then
    revoke the old key (R5's order of work). A release that is not the one it replaces goes with a widening
    statement from that one when the owner passes `--widens` (W3, W7), and with a change statement when the table
    comparator finds it allows nothing more and the owner says yes, at the terminal or with `--yes` (W9, W11).
    Otherwise it is refused before anything is stored. Each statement is stored in the controller directory, which the running
    `serve` offers."""
    from prismpath.distribution import widening
    from prismpath.hotswap import policy_pack
    controller = _controller(args)
    old, new = _authority([args.old])[0], _authority([args.new])[0]
    _priv, _pub, ser, _invalid = policy_pack._ed25519()
    old_id = env.key_id(old.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw))
    targets = sorted({anchor["target"] for anchor in controller.anchors.values()})
    now = int(time.time())
    try:
        with controller.locked():
            body = _read(args.body)
            meta = policy_meta(body, _json(args.qualification)) if args.qualification else {}
            replaces, previous = _replaced_in(controller, "policy.ppt", args.stream, args.seq)
            widens = previous is None or widening.compare_artifact("policy.ppt", previous, body) != widening.NOT_LARGER
            comparison = table_comparison(controller, body, meta, args.stream, args.seq, None, previous)
            change = (widens and not args.widens and comparison is not None
                      and comparison.answer == widening.NOT_LARGER and replaces != "")
            if widens and not args.widens and not change:
                # W9: a release that allows more is an act the owner takes on purpose, never signed in passing
                raise Refused(widening.UNSIGNED, "the table allows more than the one it replaces "
                              f"({(comparison.document() if comparison else {'reason': 'no table before it'})}); "
                              "pass --widens to release it with a widening statement")
            if change and not _confirmed(args, comparison, replaces):
                raise Refused(widening.UNSIGNED, NOT_CONFIRMED)
            widens = widens and not change
            rotation = rotation_body(new, old_id)
            controller.put(build_sealed("trust.rotation", rotation, stream=env.TRUST_STREAM,
                                        seq=controller.trust_seq() + 1, targets=targets, signers=[old, new],
                                        not_before=now, expires=0), rotation)
            release = build_sealed("policy.ppt", body, stream=args.stream, seq=args.seq, targets=args.target,
                                   signers=[new], not_before=args.not_before or now, expires=args.expires,
                                   meta=meta, replaces=replaces, widens=widens)
            if change:                                   # W11: the owner said yes to what W8 found
                statement, statement_body = change_sealed(release, [new])
                controller.put(statement, statement_body)
            elif widens:                                 # W3: the owner's --widens, from the release it replaces alone
                statement, statement_body = widening_sealed(release, [replaces] if replaces else [], [new])
                controller.put(statement, statement_body)
            controller.put(release, body)
            controller.offer(args.group, args.stream, args.seq)
        deadline = time.monotonic() + args.timeout
        while True:
            with controller.locked():
                controller.tick()
                state = [one for one in controller.rollouts if (one.group, one.stream, one.seq)
                         == (args.group, args.stream, args.seq)][-1].state
            if state == "committed":
                break
            if state == "aborted" or time.monotonic() > deadline:
                print(f"the release is {state}, so the old key is not revoked; run rekey's last step with "
                      f"`prismpath dist revoke --entry key={old_id}` once it commits", file=sys.stderr)
                return 1
            time.sleep(1.0)
        with controller.locked():
            revocation = revocation_body(args.dir, [f"key={old_id}"], [], [])
            controller.put(build_sealed("trust.revocation", revocation, stream=env.TRUST_STREAM,
                                        seq=controller.trust_seq() + 1, targets=targets, signers=[new],
                                        not_before=int(time.time()), expires=0, held=args.dir), revocation)
    except Refused as refused:
        return _fail(refused.cause, str(refused))
    _print({"rotated": old_id, "released": args.seq, "revoked": old_id})
    return 0


def default_domain(target: str) -> str:
    """P4: the domain hash this build gives a PEP of `target` built with its defaults (`install.domain_sha256`). A
    `host` PEP's domain is its qualification envelope's fields, so name it with --domain there."""
    from prismpath.distribution import install
    from prismpath.distribution.adapters import Adapter
    if target == "host":
        raise Refused(kinds.BAD_FORMAT, "a host PEP's domain is its qualification envelope's fields; name --domain")
    probe = Adapter()
    probe.kind = target
    if target == "cfs":
        from integrations.cfs import dist_kind
        probe.layout = dist_kind.built_layout()
    return install.domain_sha256(probe)


def anchor_cmd(args) -> int:
    from prismpath.distribution.trust import anchor_bytes, read_anchor
    try:
        if args.fresh and not args.controller:
            return _fail("dist:bad-format", "freshness needs a controller key to sign it (--controller)")
        part = None
        if args.install_pub:
            from prismpath.distribution import install
            if not args.controller:
                return _fail("dist:bad-format", "an install part is on a prismpath.dist-trust/2 anchor (--controller)")
            domain = args.domain or default_domain(args.target)
            part = install.anchor_part([_read(path) for path in args.install_pub], threshold=args.install_threshold,
                                       operators=[_read(path) for path in args.operator_pub], seq=args.install_seq,
                                       domain=domain)
        raw = anchor_bytes([_read(path) for path in args.pub], target=args.target, stream=args.stream,
                           controller=_read(args.controller) if args.controller else None, fresh=args.fresh,
                           install=part)
    except Refused as refused:
        return _fail(refused.cause, str(refused))
    _write(args.out, raw)
    _print({"anchor": args.out, "fingerprint": read_anchor(raw).fingerprint, "target": args.target,
            "stream": args.stream})
    return 0


def read_set_dir(directory: str):
    """The install set `dist install` wrote to `directory`, as a held set, each statement checked against its body."""
    from prismpath.distribution import install
    statements, envelopes, bodies = {}, {}, {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".sealed"):
            continue
        sealed = _read(os.path.join(directory, name))
        body = _read(os.path.join(directory, name[:-len(".sealed")] + ".body"))
        envelope = env.read(env.unseal(sealed)[0])
        if envelope.artifact == install.CHANGE and envelope.body_sha256 == canon.sha256_hex(body):
            continue                                 # IS14: the change statement written beside the set
        if envelope.body_sha256 != canon.sha256_hex(body) or envelope.artifact not in install.SET_KINDS:
            raise Refused("dist:body-mismatch", f"{name} is not an install statement with its body")
        named = envelope.meta["as"]
        statements[named] = (envelope.envelope_id, canon.sha256_hex(sealed), envelope.body_sha256)
        envelopes[named], bodies[named] = envelope, body
    if not envelopes:
        raise Refused(kinds.BAD_FORMAT, f"{directory} holds no install set")
    first = next(iter(envelopes.values()))
    return install.HeldSet(first.artifact, first.seq, env.set_id(one[0] for one in statements.values()),
                           first.policy_sha256, first.release, first.replaces, first.widens, statements, envelopes,
                           bodies)


def _rate(text: Optional[str]):
    """AF8, OP4: `ALLOWS/WINDOW` as a signed rate, None when not given."""
    if text is None:
        return None
    allows, _, window = text.partition("/")
    rate = {"allows": int(allows), "window": int(window)}
    if not kinds.FORMS["rate"](rate):
        raise Refused(kinds.BAD_FORMAT, f"a rate is 1 to 65535 allows in 1 to 86400 seconds, not {text}")
    return rate


def _rated(kind: str, rates) -> Optional[dict]:
    """The statements of a floor as IS12 compares their rates: one whose `meta` holds the rates given."""
    from types import SimpleNamespace
    from prismpath.distribution import install
    if kind != install.FLOOR:
        return None
    return {"set": SimpleNamespace(meta={name: value for name, value in rates.items() if value is not None})}


INSTALL_NOT_CONFIRMED = ("the table allows nothing more than the one it follows, and an install change statement is "
                         "signed only when the engineer says yes; run again at a terminal or with --yes, or with "
                         "--widens to seal it as a widening")


def _install_comparison(target: str, kind: str, follows, bodies: dict, metas: dict):
    """W8 at the sealing tool for an action floor or a fallback policy on `host` and `mesh`: the table comparator's
    answer for the set's `policy.ppt` against the one of the set it follows, or None when there is nothing to compare."""
    from prismpath.distribution import table_compare
    if (target not in ("host", "mesh") or kind not in kinds.CHANGES_SETS or follows is None or follows.empty
            or "policy.ppt" not in bodies or "policy.ppt" not in follows.bodies):
        return None
    fields = (metas.get("policy.ppt") or {}).get("fields")
    return table_compare.compare_tables(
        follows.bodies["policy.ppt"], bodies["policy.ppt"],
        active_fields=table_compare.table_fields(follows.envelopes.get("policy.ppt")),
        staged_fields=dict(fields) if isinstance(fields, dict) else None)


def _as_sealed(kind: str, rates, metas: dict, layout: Optional[bytes]) -> dict:
    """The statements of a set as IS12 and IS15 compare them beside their tables: one whose `meta` holds the rates, and
    on a table floor its `layout` hash and `command` register."""
    from types import SimpleNamespace
    from prismpath.distribution import install
    meta = {}
    if kind == install.FLOOR:
        meta = {name: value for name, value in rates.items() if value is not None}
        if layout is not None:
            meta["layout"] = canon.sha256_hex(layout)
        command = (metas.get("policy.ppt") or {}).get("command")
        if command is not None:
            meta["command"] = command
    return {"set": SimpleNamespace(meta=meta)}


CEILING_NOT_CONFIRMED = ("not signed: a ceiling is signed only when the engineer says yes after its lapse preview; "
                         "run again at a terminal or with --yes (CL5)")


def ceiling_preview(held: Optional[str], stream: str, target: str, bodies: dict) -> dict:
    """CL5: the lapse preview of a new ceiling, from the controller state in `held`, read and never written. With no
    state, or one that does not read, the fleet is unknown, which is never taken as nothing lapsing."""
    if not held:
        return {"fleet": "unknown", "reason": "no controller state was given (--held), so which releases this ceiling "
                                              "lapses is not known"}
    try:
        controller = _held(held)
    except (ValueError, OSError, Refused) as error:
        return {"fleet": "unknown", "reason": f"the controller state in {held} does not read ({error}), so which "
                                              "releases this ceiling lapses is not known"}
    return controller.ceiling_preview(stream, target, bodies)


def _show_preview(preview: dict, args) -> None:
    """CL5, CL6: the preview on stderr, its counts in plain words and each retirement warning, before the yes."""
    print(json.dumps({"ceiling preview": preview}, indent=2, sort_keys=True), file=sys.stderr)
    if preview["fleet"] != "known":
        print(f"fleet unknown: {preview['reason']}. This is not the same as nothing lapsing.", file=sys.stderr)
    else:
        print(f"this ceiling lapses {preview['lapsing']} of {preview['machines']} machine(s) of {preview['target']} "
              f"on {preview['stream']}, in {len(preview['lapses'])} release(s)", file=sys.stderr)
        for entry in preview["lapses"]:
            print(f"  seq {entry['seq']} release {entry['release'][:16]}: {entry['machines']} machine(s)",
                  file=sys.stderr)
        for warning in preview["warnings"]:
            print(f"warning: {warning}", file=sys.stderr)
    print(f"the controller offers it to the group {args.canary} first (--staged)" if args.staged
          else "the controller offers it to every machine at once", file=sys.stderr)


def install_cmd(args) -> int:
    """The sealing tool's install set (section 21). It compares the set with the one it follows and refuses one it
    computes as larger whose `widens` is false, on a `cfs` table by the core image inside it (IS12, H13), and holds
    a fallback policy to the held ceiling (CL3). On `host` and `mesh` it compares an action floor's or a fallback
    policy's table by W8, shows the engineer the answer, and for a table that allows nothing more signs an install
    change statement beside a set whose `widens` is false only on the engineer's yes, at the terminal or with `--yes`
    (IS15). It never signs one for a table W8 finds larger or cannot decide. A ceiling is signed only after its lapse
    preview and the engineer's yes, and `--staged` writes its unsigned rollout option beside it (CL5 to CL7)."""
    from prismpath.distribution import floor, install, widening
    kind = {"floor": install.FLOOR, "fallback": install.FALLBACK, "ceiling": install.CEILING}[args.kind]
    try:
        if args.empty:
            bodies = {kinds.NONE: b""}
        elif args.tables:
            bodies = {kinds.POLICY_LIST: install.ceiling_body(_read(path) for path in args.tables)}
        else:
            bodies = {}
            for item in args.bodies:
                named, _, path = item.partition("=")
                bodies[named] = _read(path)
        if not bodies:
            return _fail(kinds.BAD_FORMAT, "a set holds at least one artifact (--set, --list or --empty)")
        follows = read_set_dir(args.follows) if args.follows else None
        ceiling = read_set_dir(args.ceiling) if args.ceiling else None
        real = {name: body for name, body in bodies.items() if name != kinds.NONE}
        if kind != install.CEILING and real and not install.inside(args.target, ceiling, real,
                                                                  whole=kind != install.FLOOR):
            return _fail(install.ABOVE_CEILING, "the set is above the held ceiling (CL3)")
        rates = {name: _rate(getattr(args, name)) for name in ("rate", "answer_rate")}
        layout = _read(args.layout) if args.layout else None
        if kind == install.FLOOR and layout is not None:
            floor.read_layout(layout)                 # AF10: a staleness bound of 0 is refused here
        metas = {}
        if "policy.ppt" in bodies and args.qualification:
            metas["policy.ppt"] = policy_meta(bodies["policy.ppt"], _json(args.qualification))
        for name in ("policy.ppt", "cfs.table"):
            if kind == install.FLOOR and name in bodies and args.command is not None:
                metas.setdefault(name, {})["command"] = args.command
        larger = install.set_larger(args.target, kind, follows, bodies, _rated(kind, rates))
        if larger is None:                          # H13: a cfs table, by the core image inside it
            larger = widening.compare_release(dict(follows.bodies), real) != widening.NOT_LARGER
        comparison = _install_comparison(args.target, kind, follows, bodies, metas)
        change = (larger and not args.widens and comparison is not None and comparison.answer == widening.NOT_LARGER
                  and not install.set_larger(args.target, kind, follows, bodies,
                                             _as_sealed(kind, rates, metas, layout), change=True))
        if comparison is not None:
            print(json.dumps({"comparison": comparison.document()}, indent=2, sort_keys=True), file=sys.stderr)
        if change and not _confirmed(args, comparison, follows.policy_sha256, keys="the install keys"):
            return _fail(install.UNSIGNED, INSTALL_NOT_CONFIRMED)
        if larger and not args.widens and not change:
            return _fail(install.UNSIGNED, "the set allows more than the one it follows; seal it with --widens")
        if args.staged and kind != install.CEILING:
            print("--staged paces a ceiling only (CL7)", file=sys.stderr)
            return 2
        if kind == install.CEILING:
            preview = ceiling_preview(args.held, args.stream, args.target, bodies)
            _show_preview(preview, args)
            if not _said_yes(args, "sign this ceiling with the install keys? [y/N] "):
                print(CEILING_NOT_CONFIRMED, file=sys.stderr)
                return 1
        pairs = install.seal_set(kind, bodies, stream=args.stream, seq=args.seq, target=args.target,
                                 signers=_authority(args.key),
                                 replaces=follows.policy_sha256 if follows and not follows.empty else "",
                                 widens=bool(args.widens), metas=metas,
                                 not_before=args.not_before or int(time.time()), layout=layout, **rates)
        statement = install.seal_change(pairs[0][0], _authority(args.key)) if change else None
    except Refused as refused:
        return _fail(refused.cause, str(refused))
    os.makedirs(args.out, exist_ok=True)
    out = []
    for sealed, body in pairs:
        named = env.read(env.unseal(sealed)[0]).meta["as"]
        _write(os.path.join(args.out, f"{named}.sealed"), sealed)
        _write(os.path.join(args.out, f"{named}.body"), body)
        out.append({"as": named, "envelope_id": env.envelope_id(env.unseal(sealed)[0])})
    printed = {"set": args.out, "kind": kind, "seq": args.seq, "statements": out, "widens": bool(args.widens)}
    if comparison is not None:
        printed["comparison"] = comparison.document()
        printed["scope"] = "widening" if larger and not change else "change, not larger"
    if kind == install.CEILING:
        printed["preview"] = preview
    if args.staged:                                 # CL7: unsigned, for the controller's inbox beside the set
        from prismpath.distribution.controller_install import ROLLOUT_FILE, ROLLOUT_FORMAT
        set_id = env.set_id(one["envelope_id"] for one in out)
        _write(os.path.join(args.out, ROLLOUT_FILE), json.dumps(
            {"canary": args.canary, "format": ROLLOUT_FORMAT, "set_id": set_id, "staged": True},
            sort_keys=True).encode("utf-8"))
        printed["rollout"] = {"staged": True, "canary": args.canary, "set_id": set_id,
                              "file": os.path.join(args.out, ROLLOUT_FILE)}
    if statement is not None:                       # IS15: handed to the controller before the set it carries
        _write(os.path.join(args.out, f"{install.CHANGE}.sealed"), statement[0])
        _write(os.path.join(args.out, f"{install.CHANGE}.body"), statement[1])
        printed["change"] = {"sealed": os.path.join(args.out, f"{install.CHANGE}.sealed"),
                             "envelope_id": env.envelope_id(env.unseal(statement[0])[0]),
                             "from": follows.policy_sha256, "basis": kinds.CHANGE_BASIS}
    _print(printed)
    return 0


def install_trust_cmd(args) -> int:
    """IS11, K4: the sealing tool's install trust statement. It keeps every retired id in `--retired`, so a key the
    PEP has forgotten is still never added again, and refuses a statement that needs more than four signatures."""
    from prismpath.distribution import install
    try:
        current = [_read(path) for path in args.current_pub]
        operators = [_read(path) for path in args.current_operator]
        retired = []
        if os.path.exists(args.retired):
            retired = [line.strip() for line in _read(args.retired).decode("ascii").splitlines() if line.strip()]
        record = install.Record(keys={env.key_id(one): one for one in current}, threshold=args.current_threshold,
                                operators={env.key_id(one): one for one in operators})
        body = install.trust_body([_read(path) for path in args.install_pub], threshold=args.threshold,
                                  operators=[_read(path) for path in args.operator_pub])
        sealed = install.seal_trust(record, body, stream=args.stream, seq=args.seq, targets=[args.target],
                                    signers=_authority(args.key), not_before=args.not_before or int(time.time()),
                                    retired=retired)
    except Refused as refused:
        return _fail(refused.cause, str(refused))
    doc = kinds.read_install_trust(body)
    kept = {env.key_id(bytes.fromhex(one)) for one in doc["keys"] + doc["operators"]}
    dropped = sorted((set(record.keys) | set(record.operators)) - kept)
    _write(args.retired, "".join(line + "\n" for line in retired + [one for one in dropped if one not in retired])
           .encode("ascii"))
    _write(args.out, sealed)
    body_path = os.path.splitext(args.out)[0] + ".body"
    _write(body_path, body)
    _print({"sealed": args.out, "body": body_path, "seq": args.seq, "retired": dropped,
            "envelope_id": env.envelope_id(env.unseal(sealed)[0])})
    return 0


def verify_cmd(args) -> int:
    from prismpath.distribution.trust import read_anchor
    from prismpath.distribution.verify import PepView, verify
    anchor = read_anchor(_read(args.anchor))
    view = PepView(kind=anchor.target, stream=anchor.stream, qualification=_json(args.qualification))
    verdict = verify(_read(args.sealed), _read(args.body), trust=anchor.store(), pep=view,
                     now=args.now if args.now is not None else int(time.time()))
    _print({"ok": verdict.ok, "cause": verdict.cause,
            "envelope_id": verdict.envelope.envelope_id if verdict.envelope else None})
    return 0 if verdict.ok else 1


# ------------------------------------------------------------------ the controller's commands

def serve_cmd(args) -> int:
    from prismpath.distribution import http
    controller = _controller(args)
    host, _, port = args.listen.rpartition(":")
    server = http.serve(_Ingesting(controller), (host or "127.0.0.1", int(port)))
    print(f"serving {args.dir} on http://{host}:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


class _Ingesting:
    """The controller as `serve` hands it to the listener: each request first stores what the inbox holds."""

    def __init__(self, controller):
        self.controller = controller

    def locked(self):
        from contextlib import contextmanager

        @contextmanager
        def held():
            with self.controller.locked() as controller:
                ingest(controller)
                yield controller
        return held()


def enroll_cmd(args) -> int:
    from prismpath.distribution.trust import read_anchor
    controller = _controller(args)
    raw = _read(args.anchor)
    anchor = read_anchor(raw)
    try:
        with controller.locked():
            if anchor.fingerprint not in controller.anchors:
                controller.add_anchor(raw, _json(args.qualification),
                                      layout=_read(args.layout) if getattr(args, "layout", None) else None)
            ingest(controller)
            pep = controller.enroll(_read(args.pub), anchor.target, anchor.stream, args.group, args.rule,
                                    install_envelopes=getattr(args, "install", None))
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    _print({"enrolled": pep, "kind": anchor.target, "stream": anchor.stream, "group": args.group})
    return 0


def acknowledge_cmd(args) -> int:
    """H13: the acknowledger's command. It signs nothing and holds no key of the spec; the controller lets the login
    that runs it acknowledge, and the acknowledgement goes to its audit log. A PEP never reads it: this is detection,
    and a PEP applies a well signed set from any sender."""
    import getpass
    controller = _controller(args)
    try:
        with controller.locked():
            ingest(controller)
            done = controller.acknowledge(args.envelope, by=args.by or getpass.getuser())
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    _print(done)
    return 0


def rollout_cmd(args) -> int:
    controller = _controller(args)
    try:
        with controller.locked():
            stored = ingest(controller)
            if args.action == "offer":
                rollout = controller.offer(args.group, args.stream, args.seq, args.delay)
            elif args.action == "commit":
                rollout = controller.commit(args.group)
            else:
                rollout = controller.abort(args.group)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    _print({"stored": stored, "rollout": rollout.document()})
    return 0


def fleet_cmd(args) -> int:
    controller = _controller(args)
    with controller.locked():
        ingest(controller)
        _print(controller.fleet())
    return 0


# ------------------------------------------------------------------ a host PEP

def _host_pep(args):
    from prismpath.distribution.adapters.host import HostAdapter
    from prismpath.distribution.pep import Pep
    from prismpath.hotswap.policy_host import PolicyHost
    key = _instance(args.key)
    if getattr(args, "kind", "host") == "agent":
        from prismpath.distribution.adapters.agent_home import AgentHomeAdapter
        return Pep(args.state, AgentHomeAdapter(args.state), key, time.time)
    if getattr(args, "kind", "host") == "gateway":
        from prismpath.distribution.adapters.gateway import GatewayHomeAdapter
        return Pep(args.state, GatewayHomeAdapter(args.state), key, time.time)
    saved = os.path.join(args.state, "dist-qualification.json")
    if args.qualification:
        os.makedirs(args.state, exist_ok=True)
        _write(saved, _read(args.qualification))
    if not os.path.exists(saved):
        raise ValueError("a host PEP is provisioned with --qualification first")
    host = PolicyHost(args.state, [], _json(saved), instance_key=key)
    return Pep(args.state, HostAdapter(host), key, time.time)


def _status(pep) -> dict:
    record = state_record.read(pep.record("beat"), pep.instance_key.public_raw)
    return {"state": record.state, "stream": pep.stream, "active_seq": record.active_seq,
            "active_policy": pep.active.policy_sha256 if pep.active else None, "floor": record.floor,
            "staged_seq": record.staged_seq if record.staged else None, "trust_seq": record.trust_seq,
            "held": record.held, "pep_id": record.pep_id.hex(), "refusal": pep.refusal()}


def pep_cmd(args) -> int:
    from prismpath.distribution.pep import PepRefused
    try:
        pep = _host_pep(args)
        if args.pep_command == "provision":
            if args.confirm:
                pep.confirm(args.confirm)
                _print(_status(pep))
                return 0
            if not args.anchor:
                print("provision needs --anchor, then --confirm with the fingerprint it prints", file=sys.stderr)
                return 2
            _print({"fingerprint": pep.provision(_read(args.anchor)),
                    "next": "compare it with the owner's, then run provision again with --confirm"})
            return 0
        if args.pep_command == "status":
            _print(_status(pep))
            return 0
        if args.pep_command == "rollback":
            record = state_record.read(pep.rollback(), pep.instance_key.public_raw)
            _print({"event": record.event, "cause": record.cause, **_status(pep)})
            return 0 if record.event == "rolled-back" else 1
        return _poll(pep, args)
    except (PepRefused, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


def _poll(pep, args) -> int:
    from prismpath.distribution.http import HttpTransport, PullClient
    if not args.url:
        print("poll needs --url", file=sys.stderr)
        return 2
    client = PullClient(pep, HttpTransport(args.url))
    while True:
        client.poll(wait=args.wait)
        for where, why in client.failures:
            print(f"{where}: {why}", file=sys.stderr)
        client.failures.clear()
        if args.once:
            _print(_status(pep))
            return 0
        time.sleep(args.interval)
