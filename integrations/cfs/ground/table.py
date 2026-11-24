#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The policy table file on the ground: its layout, its version, and the authority's two signatures.

    python -m integrations.cfs.ground.table sign TBL --keys KEYS [--version N] [-o OUT]

A cFE table file (`pp_app_policy.tbl`, written by cFS's elf2cfetbl) is a 64 byte cFE file header, a 52 byte
table header (big endian: reserved, offset, byte count, table name) and the table's bytes, here the C struct
`PP_PolicyTable_t` (fsw/inc/prismpath_app_kernel.h) in the target's own byte order, little endian. The struct
has no padding, so its layout is the offsets below, which tests/test_cfs_run.py holds to the C compiler's.

The authority signs two things, both Ed25519 with the authority key (`authority.key`, the key that says which
policy may run):

  ImageSig  over b"prismpath.core-image/1\\0" and the core image bytes: the core run's own image attestation
            (`prismpath.ledgers.core_evidence.IMAGE_DOMAIN`), which the app copies to images.jsonl;
  TableSig  over b"prismpath.cfs-table/1\\0" and the SHA-256 of every struct byte before ImageSig: it binds the
            version, the compiled PPT image, the rules, the causes and the core image to each other.

The app checks both against the authority key it holds, so a table the authority did not sign never decides, and
the version (which only TableSig covers) cannot be raised past the floor without the authority.
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="sign a PrismPath cFS policy table file with the authority key")
    parser.add_argument("action", choices=["sign"])
    parser.add_argument("tbl", type=Path)
    parser.add_argument("--keys", type=Path, required=True, help="the directory holding authority.key")
    parser.add_argument("--version", type=int, default=None, help="set the image version before signing")
    parser.add_argument("-o", "--out", type=Path, default=None, help="write here (default: in place)")
    args = parser.parse_args(argv)
    out = signed_file(args.tbl.read_bytes(), args.keys / "authority.key", args.version)
    (args.out or args.tbl).write_bytes(out)
    print(f"signed {args.out or args.tbl}: version {u32(split(out)[1], 'Version')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
