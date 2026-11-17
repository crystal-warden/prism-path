#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Provision a staged cFS build with the app's keys and a signed policy table.

    python -m integrations.cfs.ground.provision --exe-dir <cFS>/build-native_std/exe/cpu1 --keys KEYS

It makes (when absent) the two test keys a core run names, with the repository's own generators
(`prismpath.ledgers.core_evidence.ensure_keys`): the authority key, which says which policy may run, and the
instance key, which signs what the app recorded. Into the build's `cf/` it writes

  pp_authority.pub   the authority's raw 32 byte public key, which the app checks every table against
  pp_instance.key    the instance key's raw 32 byte Ed25519 seed, which the app signs root statements with

and signs `cf/pp_app_policy.tbl` in place (integrations/cfs/ground/table.py). The ground keeps `KEYS`, and pins
its `authority.pub` and `instance.pub` when it verifies a downlinked run.

These are test keys in a file system the flight software can read. A mission builds the authority key into its
boot image and provisions the instance key per vehicle in protected storage; nothing here is a deployment's key.
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


def provision(exe_dir: Path, keys: Path) -> dict:
    authority_key, authority_pub, instance_key, _instance_pub = core_evidence.ensure_keys(Path(keys))
    cf = Path(exe_dir) / "cf"
    (cf / "pp_authority.pub").write_bytes(authority_pub.read_bytes())
    seed = cf / "pp_instance.key"
    seed.write_bytes(instance_seed(instance_key))
    seed.chmod(0o600)
    tbl = cf / "pp_app_policy.tbl"
    tbl.write_bytes(table.signed_file(tbl.read_bytes(), authority_key))
    return {"authority": str(cf / "pp_authority.pub"), "instance": str(seed), "table": str(tbl)}


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
