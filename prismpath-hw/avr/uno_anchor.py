# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Write uno_anchor.eep, the EEPROM image ppt_uno_dist.c reads at its first start: first key provisioning (section 14)
for the Uno of the board validation pass. It holds the Uno's instance key seed, the authority public key of the mesh
harness (prismpath-hw/mesh/gen_mesh_tables.py, the same key the ESP32 nodes are built with) and the stream.

The instance seed lives beside this file in `uno_instance.key`, gitignored and made on first run, so the harness can
read the Uno's state records under its public key. No authority private key is written to the board.

    python uno_anchor.py [--out uno_anchor.eep]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HW = HERE.parent
for path in (str(HW / "mesh"), str(HW.parent)):
    if path not in sys.path:
        sys.path.insert(0, path)

import gen_mesh_tables as tables  # noqa: E402

INSTANCE = HERE / "uno_instance.key"
STREAM_ROOM = 65        # PP_STREAM_MAX + 1, the stream and its zero byte (EE_STREAM in ppt_uno_dist.c)


def instance():
    """The Uno's instance key, made on first run."""
    return tables.load_or_make(INSTANCE)[0]


def image(seed: bytes, authority_public: bytes, stream: str = tables.STREAM) -> bytes:
    """The EEPROM bytes from offset 0: the magic, the seed, the anchor key and the stream (ppt_uno_dist.c)."""
    name = stream.encode("ascii")
    if len(seed) != 32 or len(authority_public) != 32 or not 1 <= len(name) < STREAM_ROOM:
        raise ValueError("a seed and a key of 32 bytes and a stream of 1 to 64 characters")
    return b"PPU1" + seed + authority_public + name + bytes(STREAM_ROOM - len(name))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(HERE / "uno_anchor.eep"))
    args = parser.parse_args(argv)
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    seed = instance().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    authority = tables.public_raw(tables.load_or_make(tables.KEYS["authority"])[0])
    Path(args.out).write_bytes(image(seed, authority))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
