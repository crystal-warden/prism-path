#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Provision the F Prime guard with its keys and a signed policy table.

    python -m integrations.fprime.ground.provision --onboard DIR --keys KEYS

It makes (when absent) the two test keys a core run names, with the repository's own generators
(`prismpath.ledgers.core_evidence.ensure_keys`): the authority key, which says which policy may run, and the
instance key, which signs what the guard recorded. The policy table is the cFS app's, byte for byte: the example
policy compiled by `integrations/cfs/prismpath_app/policy/gen_image.py`, as the raw bytes of `PP_PolicyTable_t`,
signed with the authority key by `integrations/cfs/ground/table.py`. Into the onboard directory DIR it writes

  pp_authority.pub          the authority's raw 32 byte public key
  pp_instance.key           the instance key's raw 32 byte Ed25519 seed
  pp_policy.tbl             the signed policy table (version 2)
  pp_policy_tampered.tbl    the same table with one threshold changed and not signed again (refused as sig:invalid)

Point the guard's parameters at it: POLICY_FILE at pp_policy.tbl, KEYS_DIR at DIR and RUN_DIR at a directory for the
run. These are test keys in a file system the flight software can read; nothing here is a deployment's key.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from integrations.cfs.ground import provision as cfs_provision, table  # noqa: E402
from integrations.cfs.prismpath_app.policy import gen_image  # noqa: E402
from prismpath.ledgers import core_evidence  # noqa: E402


def provision(onboard: Path, keys: Path) -> dict:
    onboard, keys = Path(onboard), Path(keys)
    onboard.mkdir(parents=True, exist_ok=True)
    authority_key, authority_pub, instance_key, _instance_pub = core_evidence.ensure_keys(keys)
    (onboard / "pp_authority.pub").write_bytes(authority_pub.read_bytes())
    seed = onboard / "pp_instance.key"
    seed.write_bytes(cfs_provision.instance_seed(instance_key))
    seed.chmod(0o600)
    data = table.pack(gen_image.build(gen_image.CORE.read_bytes().rstrip(b"\n")))
    table.sign(data, authority_key)
    (onboard / "pp_policy.tbl").write_bytes(bytes(data))
    data[table.OFF["Image"] + 56] ^= 0x01          # one threshold of the image, the signatures left as they were
    (onboard / "pp_policy_tampered.tbl").write_bytes(bytes(data))
    return {name: str(onboard / name) for name in
            ("pp_authority.pub", "pp_instance.key", "pp_policy.tbl", "pp_policy_tampered.tbl")}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--onboard", type=Path, required=True, help="the directory the guard reads its files from")
    parser.add_argument("--keys", type=Path, required=True, help="the ground's key directory (made when absent)")
    args = parser.parse_args(argv)
    for name, path in provision(args.onboard, args.keys).items():
        print(f"{name}: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
