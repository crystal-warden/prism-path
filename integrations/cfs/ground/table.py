#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The policy table file on the ground: its layout, its version, its signatures and its distribution envelope.

    python -m integrations.cfs.ground.table sign TBL --keys KEYS --seq N [--stream S] [--version V]
                                              [--replaces HASH] [--active TBL] [-o OUT]

A cFE table file (`pp_app_policy.tbl`, written by cFS's elf2cfetbl) is a 64 byte cFE file header, a 52 byte
table header (big endian: reserved, offset, byte count, table name) and the table's bytes, here the C struct
`PP_PolicyTable_t` (fsw/inc/prismpath_app_kernel.h) in the target's own byte order, little endian. The struct
has no padding, so its layout is the offsets below, which tests/test_cfs_run.py holds to the C compiler's.

The cFS app admits a table by its distribution envelope (docs/design/spec-policy-distribution.md, the `cfs` kind): a
`cfs.table` whose body is the struct's bytes before `ImageSig` and whose policy hash is the SHA-256 of the core image
inside it, sealed with the authority key and offered on the software bus in the frames of section 8.3 (`frames`,
`commit_frame`). `sign` writes the signed table file and, beside it, the sealed envelope and its body as a statement
file (`OUT.pps`), with the widening statement a table that allows more needs (`OUT.w.pps`, W3, W4). It sets
`widens` as the controller would (W7): false only when the table's core image allows nothing more than the active
one's (`dist_kind.compare_cfs_tables`), and a first table always widens.

The authority still signs two things into the struct, both Ed25519 with the authority key:

  ImageSig  over b"prismpath.core-image/1\\0" and the core image bytes: the core run's own image attestation
            (`prismpath.ledgers.core_evidence.IMAGE_DOMAIN`), which the app copies to images.jsonl. It travels with
            the commit frame, since the body before it does not hold it, and it no longer admits a table;
  TableSig  over b"prismpath.cfs-table/1\\0" and the SHA-256 of every struct byte before ImageSig, which a framework
            with no distribution envelope admits a table by (integrations/fprime). The cFS app does not read it.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path
from typing import Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from prismpath.ledgers import core_evidence  # noqa: E402

IMAGE_MAX, RULES_MAX, CORE_MAX, FLOW_MAX = 1024, 16, 2048, 1536
TABLE_DOMAIN = b"prismpath.cfs-table/1\x00"
# offsets of PP_PolicyTable_t's members (natural alignment, no padding)
OFF = {
    "LayoutHash": 0, "ImageLen": 4, "RuleCount": 6, "ContractCause": 8, "NoMatchCause": 10, "Version": 12,
    "CoreLen": 16, "FlowJsonLen": 18, "Rules": 20,
}
OFF["Image"] = OFF["Rules"] + 4 * RULES_MAX
OFF["Core"] = OFF["Image"] + IMAGE_MAX
OFF["FlowJson"] = OFF["Core"] + CORE_MAX
OFF["ImageSig"] = OFF["FlowJson"] + FLOW_MAX
OFF["TableSig"] = OFF["ImageSig"] + 64
SIZE = OFF["TableSig"] + 64
HEADERS = 64 + 52          # the cFE file header and the table header


# AF9, AF10: what each field of a layout is, by the labels of fsw/inc/prismpath_app_layout.h
ROLES = ("command", "parameter", "independent", "proposer")
COMMAND, PARAMETER, INDEPENDENT, PROPOSER = range(4)


def layout_document(fields) -> bytes:
    """The layout document of AF10: a canon/2 list of each field's register, role, bounds and staleness bound, from
    (register, role, min, max, stale) rows. Its SHA-256 is `layout` in the `meta` of a table floor. An independent
    field has a staleness bound of at least one second and no other field has one, so a layout that would read a
    reading of the world as never stale is refused here, before any floor is sealed for it."""
    from prismpath.kernel import canon2
    rows = []
    for reg, role, low, high, stale in sorted(fields):
        if role not in range(len(ROLES)) or not low <= high:
            raise ValueError(f"register {reg}: role {role} with bounds {low} to {high} is not a layout field")
        if (role == INDEPENDENT) != (stale > 0) or stale < 0:
            raise ValueError(f"register {reg}: an independent field takes a staleness bound of 1 second or more, and "
                             f"no other field takes one (AF10), not {stale}")
        rows.append({"max": high, "min": low, "reg": reg, "role": ROLES[role], "stale": stale})
    if [row["reg"] for row in rows] != list(range(len(rows))) or sum(row["role"] == "command" for row in rows) > 1:
        raise ValueError("a layout labels each register once, in order, and at most one command field")
    return canon2.dumps(rows)


def pack(built: dict) -> bytearray:
    """The unsigned struct bytes of a table from `gen_image.build`'s result: what the C initializer in
    fsw/tables/prismpath_app_policy_tbl.c holds, byte for byte."""
    data = bytearray(SIZE)
    struct.pack_into("<IHHHHIHH", data, 0, built["layout_hash"], len(built["image"]), len(built["rules"]),
                     built["contract_cause"], built["nomatch_cause"], built["version"], len(built["core"]),
                     len(built["flow_json"]))
    for index, (kind, cause) in enumerate(built["rules"]):
        struct.pack_into("<BBH", data, OFF["Rules"] + 4 * index, kind, 0, cause)
    for name, blob in (("Image", built["image"]), ("Core", built["core"]), ("FlowJson", built["flow_json"])):
        data[OFF[name]:OFF[name] + len(blob)] = blob
    return data


def split(tbl: bytes) -> Tuple[bytes, bytearray]:
    """(headers, the struct bytes) of a table file, checking the table header's byte count."""
    if len(tbl) != HEADERS + SIZE:
        raise ValueError(f"a policy table file is {HEADERS + SIZE} bytes, not {len(tbl)}")
    _reserved, offset, count = struct.unpack(">III", tbl[64:76])
    if offset != 0 or count != SIZE:
        raise ValueError(f"the table header says offset {offset}, {count} bytes; this layout is offset 0, {SIZE} bytes")
    return tbl[:HEADERS], bytearray(tbl[HEADERS:])


def u16(data: bytes, name: str) -> int:
    return struct.unpack_from("<H", data, OFF[name])[0]


def u32(data: bytes, name: str) -> int:
    return struct.unpack_from("<I", data, OFF[name])[0]


def core_of(data: bytes) -> bytes:
    return bytes(data[OFF["Core"]:OFF["Core"] + u16(data, "CoreLen")])


def digest(data: bytes) -> bytes:
    """The SHA-256 the table signature covers: every struct byte before ImageSig."""
    return hashlib.sha256(bytes(data[:OFF["ImageSig"]])).digest()


def set_version(data: bytearray, version: int) -> None:
    struct.pack_into("<I", data, OFF["Version"], version)


def sign(data: bytearray, authority_key: Path) -> None:
    """Fill in both signatures with the authority key (PKCS8 PEM, as `prismpath swap keygen` writes it)."""
    from prismpath.hotswap import policy_pack
    signer = policy_pack._load_private(str(authority_key))
    data[OFF["ImageSig"]:OFF["ImageSig"] + 64] = signer.sign(core_evidence.IMAGE_DOMAIN + core_of(data))
    data[OFF["TableSig"]:OFF["TableSig"] + 64] = signer.sign(TABLE_DOMAIN + digest(data))


def signed_file(tbl: bytes, authority_key: Path, version: int = None) -> bytes:
    headers, data = split(tbl)
    if version is not None:
        set_version(data, version)
    sign(data, authority_key)
    return headers + bytes(data)


# ----------------------------------------------------------------- the distribution envelope
STREAM = "cfs/vehicle"
FRAME_LIMIT = 250          # PRISMPATH_APP_FRAME_MAX, the frame limit of the link (section 8.3)


def body_of(data: bytes) -> bytes:
    """A cfs.table body: the struct's bytes before ImageSig."""
    return bytes(data[:OFF["ImageSig"]])


def policy_of(data: bytes) -> str:
    """The policy hash of a cfs.table: the SHA-256 of its core image (section 3)."""
    return hashlib.sha256(core_of(data)).hexdigest()


def widens_from(data: bytes, active: bytes = None) -> bool:
    """W7 as the sealing tool applies it for a target that cannot decide: a first table widens, and so does one whose
    core image allows more than the active one's, or that differs from it in anything but a narrower core image."""
    if active is None:
        return True
    from integrations.cfs import dist_kind
    from prismpath.distribution import widening
    return dist_kind.compare_cfs_tables(body_of(active), body_of(data)) != widening.NOT_LARGER


def seal_table(data: bytes, signers, *, seq: int, stream: str = STREAM, not_before: int, expires: int,
               replaces: str = "", widens: bool = True, froms=None, artifact: str = "cfs.table", meta=None):
    """The sealed envelope of a table and its body, and when it widens its widening statement and body, whose `from`
    is `froms`, or `replaces` alone, or empty (any) for a first table: [(sealed, body), ...], the statement first."""
    from prismpath import canon
    from prismpath.distribution import envelope as env
    from prismpath.distribution import kinds
    body = body_of(data)
    policy = policy_of(data)
    release = env.release_id([("cfs.table", canon.sha256_hex(body))])        # a set's is over [as, body] alike (IS1)
    envelope = env.build(artifact, body, stream=stream, seq=seq, targets=["cfs"], not_before=not_before,
                         expires=expires, meta=meta or {}, replaces=replaces, widens=widens, policy_sha256=policy,
                         release=release)
    out = [(env.seal(envelope, signers), body)]
    if widens and artifact == "cfs.table":
        statement = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": kinds.WIDENING_FORMAT,
                                        "from": sorted(set(froms if froms is not None else ([replaces] if replaces else [])))})
        widening = env.build("trust.widening", statement, stream=stream, seq=seq, targets=["cfs"],
                             not_before=not_before, expires=0, policy_sha256=policy, release=release,
                             replaces=replaces, widens=True)
        out.insert(0, (env.seal(widening, signers), statement))
    return out


def frames(sealed: bytes, body: bytes, transfer: int, limit: int = FRAME_LIMIT):
    """The offer and chunk frames of one sealed envelope and its body (frames.frames_for)."""
    from prismpath.distribution import frames as frame_binding
    return list(frame_binding.frames_for(transfer, sealed, body, limit))


def commit_frame(transfer: int, stream: str, seq: int, policy: str, delay_ms: int = 0) -> bytes:
    from prismpath.distribution import frames as frame_binding
    return frame_binding.encode(frame_binding.commit_for(transfer, stream, seq, policy, delay_ms), FRAME_LIMIT)


def abort_frame(transfer: int, stream: str, seq: int, policy: str) -> bytes:
    from prismpath.distribution import frames as frame_binding
    return frame_binding.encode(frame_binding.abort_for(transfer, stream, seq, policy), FRAME_LIMIT)


def image_sig(data: bytes) -> bytes:
    return bytes(data[OFF["ImageSig"]:OFF["ImageSig"] + 64])


def statement_file(sealed: bytes, body: bytes, sig: bytes = None) -> bytes:
    """A sealed envelope and its body as the app reads one from its file system (prismpath_app_dist.c,
    PP_AppDist_ReadStatement): "PPST", the sealed length and bytes, the body length and bytes, and the image
    attestation of a release's table when it is one."""
    out = b"PPST" + struct.pack("<I", len(sealed)) + bytes(sealed) + struct.pack("<I", len(body)) + bytes(body)
    return out + (b"\x01" + bytes(sig) if sig is not None else b"\x00")


def main(argv=None) -> int:
    import time
    parser = argparse.ArgumentParser(description="sign a PrismPath cFS policy table file and seal its distribution "
                                                 "envelope with the authority key")
    parser.add_argument("action", choices=["sign"])
    parser.add_argument("tbl", type=Path)
    parser.add_argument("--keys", type=Path, required=True, help="the directory holding authority.key")
    parser.add_argument("--version", type=int, default=None, help="set the image version before signing")
    parser.add_argument("--seq", type=int, default=None, help="the distribution seq; without it no envelope is sealed")
    parser.add_argument("--stream", default=STREAM)
    parser.add_argument("--active", type=Path, default=None, help="the table file the vehicle has active, if any")
    parser.add_argument("--days", type=int, default=30, help="the envelope's lifetime from now")
    parser.add_argument("-o", "--out", type=Path, default=None, help="write here (default: in place)")
    args = parser.parse_args(argv)
    out = signed_file(args.tbl.read_bytes(), args.keys / "authority.key", args.version)
    target = args.out or args.tbl
    target.write_bytes(out)
    print(f"signed {target}: version {u32(split(out)[1], 'Version')}")
    if args.seq is not None:
        from prismpath.hotswap import policy_pack
        data = split(out)[1]
        active = split(args.active.read_bytes())[1] if args.active else None
        widens = widens_from(data, active)
        now = int(time.time())
        sealed = seal_table(data, [policy_pack._load_private(str(args.keys / "authority.key"))], seq=args.seq,
                            stream=args.stream, not_before=now, expires=now + 86400 * args.days,
                            replaces=policy_of(active) if active is not None else "", widens=widens)
        target.with_suffix(".pps").write_bytes(statement_file(*sealed[-1], image_sig(data)))
        if widens:
            target.with_suffix(".w.pps").write_bytes(statement_file(*sealed[0]))
        print(f"sealed seq {args.seq} on {args.stream}: widens {str(widens).lower()}, policy {policy_of(data)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
