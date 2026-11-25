#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Provision a staged cFS build with the app's keys, its trust anchor and a boot release.

    python -m integrations.cfs.ground.provision --exe-dir <cFS>/build-native_std/exe/cpu1 --keys KEYS

It makes (when absent) the test keys a core run and a distribution stream name, with the repository's own
generators (`prismpath.ledgers.core_evidence.ensure_keys`, `root_statement.keygen`): the authority key, which says
which policy may run, the instance key, which signs what the app recorded and every state record it sends, and the
controller key the anchor names (K6). Into the build's `cf/` it writes

  pp_authority.pub   the authority's raw 32 byte public key, the key the core run's image attestations are under
  pp_instance.key    the instance key's raw 32 byte Ed25519 seed
  pp_trust.anchor    the trust anchor of P2 step 3, `prismpath.dist-trust/2` (`anchor_document`): the authority key,
                     the controller key, `fresh` 0, the target kind `cfs` and the stream, and with install keys the
                     `install` member, whose domain is the SHA-256 of the app's layout document (CL4, AF10)
  pp_boot0.pps,      the boot release: the example table's widening statement and its sealed envelope with the
  pp_boot1.pps       table's image attestation, which the app stages and commits as if offered when it starts with
                     no release active (a first start, or after a lost record under MINIMUM; a power on reset of a
                     provisioned app keeps its files and loses the store, which is a lost record, Q5)

and signs `cf/pp_app_policy.tbl` in place (integrations/cfs/ground/table.py), which the app no longer loads at start.
The ground keeps `KEYS`, and pins its `authority.pub` and `instance.pub` when it verifies a downlinked run.

These are test keys in a file system the flight software can read. A mission builds the anchor into its boot image
and provisions the instance key per vehicle in protected storage; nothing here is a deployment's key.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from integrations.cfs.ground import table  # noqa: E402
from prismpath.ledgers import core_evidence  # noqa: E402


def instance_seed(instance_key: Path) -> bytes:
    """The raw 32 byte seed of an instance key (PKCS8 PEM), the form Monocypher signs with."""
    from cryptography.hazmat.primitives import serialization as ser
    private = ser.load_pem_private_key(Path(instance_key).read_bytes(), password=None)
    return private.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())


ANCHOR_FORMAT = "prismpath.dist-trust/2"


def anchor_document(authority_publics, *, controller_public: bytes, stream: str, target: str = "cfs",
                    install_publics=(), threshold: int = 2, operator_publics=(), seq: int = 0,
                    domain: str = "") -> bytes:
    """The trust anchor of P4, `prismpath.dist-trust/2`, in canon/2: the authority keys (every entry in the role
    `authority`), the threshold of S6, the controller key (K6), `fresh` 0, the PEP's target kind and stream, and,
    when install keys are given, the `install` member with those keys, their threshold, the operator keys, the
    install trust sequence and the hash of the reading domain the PEP was built with (CL4)."""
    from prismpath import canon
    keys = {canon.sha256_hex(bytes(raw)): {"public": bytes(raw).hex(), "role": "authority"} for raw in authority_publics}
    doc = {"controller": bytes(controller_public).hex(), "encoding": "canon/2", "format": ANCHOR_FORMAT, "fresh": 0,
           "keys": keys, "stream": stream, "target": target, "threshold": 1}
    if install_publics:
        if not 1 <= threshold <= len(install_publics) <= 4 or len(operator_publics) > 4 or len(domain) != 64:
            raise ValueError("an install member holds 1 to 4 install keys at a threshold from 1 to their number, at "
                             "most 4 operator keys and the SHA-256 of the domain (P4, IS11)")
        doc["install"] = {"domain": domain, "keys": sorted(bytes(raw).hex() for raw in install_publics),
                          "operators": sorted(bytes(raw).hex() for raw in operator_publics), "seq": seq,
                          "threshold": threshold}
    roles = [canon.sha256_hex(bytes(raw)) for raw in (*authority_publics, controller_public, *install_publics,
                                                       *operator_publics)]
    if len(set(roles)) != len(roles):
        raise ValueError("no key is held in two roles (K4)")
    return canon.canon2_bytes(doc)


def app_layout(monitor_stale: int = 0) -> list:
    """The app's layout labels as (register, role, min, max, stale) rows, from its layout header, the monitor's field
    independent with the build's staleness bound and the proposer's in a build with no monitor (AF10)."""
    from integrations.cfs.prismpath_app.policy import gen_image
    roles = {"COMMAND": table.COMMAND, "PARAMETER": table.PARAMETER, "INDEPENDENT": table.INDEPENDENT,
             "PROPOSER": table.PROPOSER}
    rows = []
    for reg, _name, _kind, _off, _width, low, high, role in gen_image.layout_rows():
        role = roles[role]
        if role == table.INDEPENDENT and monitor_stale == 0:
            role = table.PROPOSER
        rows.append((reg, role, low, high, monitor_stale if role == table.INDEPENDENT else 0))
    return rows


def domain(monitor_stale: int = 0) -> str:
    """CL4 on cfs: the domain the app was built for is its layout, so the anchor names its layout document's hash."""
    import hashlib
    return hashlib.sha256(table.layout_document(app_layout(monitor_stale))).hexdigest()


def public_raw(private) -> bytes:
    from cryptography.hazmat.primitives import serialization as ser
    return private.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def boot_release(data: bytes, authority_key: Path, *, seq: int = 1, stream: str = table.STREAM, now: int = None,
                 days: int = 365) -> list:
    """The statement files of a first release of the table `data`: its widening statement, then its envelope with the
    table's image attestation. Its `not_before` is 0, so a vehicle whose clock has not been set yet (a cFE that
    counts from its epoch) still admits it, and it expires `days` after the ground's `now`."""
    import time
    from prismpath.hotswap import policy_pack
    now = int(time.time()) if now is None else now
    sealed = table.seal_table(data, [policy_pack._load_private(str(authority_key))], seq=seq, stream=stream,
                              not_before=0, expires=now + 86400 * days, widens=True, froms=[])
    return [table.statement_file(*sealed[0]), table.statement_file(*sealed[1], table.image_sig(data))]


def provision(exe_dir: Path, keys: Path, *, stream: str = table.STREAM, monitor_stale: int = 0,
              install_publics=(), install_threshold: int = 2, operator_publics=(), boot: bool = True,
              now: int = None) -> dict:
    from prismpath.ledgers import root_statement
    keys = Path(keys)
    authority_key, authority_pub, instance_key, _instance_pub = core_evidence.ensure_keys(keys)
    if not (keys / "controller.pub").exists():
        root_statement.keygen(str(keys), "controller")
    cf = Path(exe_dir) / "cf"
    (cf / "pp_authority.pub").write_bytes(authority_pub.read_bytes())
    seed = cf / "pp_instance.key"
    seed.write_bytes(instance_seed(instance_key))
    seed.chmod(0o600)
    anchor = anchor_document([authority_pub.read_bytes()], controller_public=(keys / "controller.pub").read_bytes(),
                             stream=stream, install_publics=install_publics, threshold=install_threshold,
                             operator_publics=operator_publics, domain=domain(monitor_stale))
    (cf / "pp_trust.anchor").write_bytes(anchor)
    tbl = cf / "pp_app_policy.tbl"
    tbl.write_bytes(table.signed_file(tbl.read_bytes(), authority_key))
    for k in range(2):
        (cf / f"pp_boot{k}.pps").unlink(missing_ok=True)
    if boot:
        for k, data in enumerate(boot_release(table.split(tbl.read_bytes())[1], authority_key, stream=stream, now=now)):
            (cf / f"pp_boot{k}.pps").write_bytes(data)
    return {"authority": str(cf / "pp_authority.pub"), "instance": str(seed), "table": str(tbl),
            "anchor": str(cf / "pp_trust.anchor")}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--exe-dir", type=Path, required=True, help="the staged cpu1 directory (holds core-cpu1)")
    parser.add_argument("--keys", type=Path, required=True, help="the ground's key directory (made when absent)")
    args = parser.parse_args(argv)
    for name, path in provision(args.exe_dir, args.keys).items():
        print(f"{name}: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
