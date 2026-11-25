# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The mesh's trust anchor, its layout and its policies, and the signer of its distribution releases.

The nodes carry no policy in their firmware. They carry the trust anchor (spec-policy-distribution.md P2, P4: the
authority's public key, the controller key, `fresh` and the stream they follow, and the install member when the
engineer gives the node install keys), the layout they decide over (AF10) and the hash of the reading domain they
were built with (CL4), in `main/tables.h`, which this script writes. They take every policy as a sealed
distribution envelope over ESP-NOW.

The layout has three fields. Register 0 is `command`, the command field (COMMAND), register 1 is `level`, its one
parameter (PARAMETER), and register 2 is `clear`, a reading the node takes itself (INDEPENDENT, stale after 5
seconds), so a narrow action floor (AF9, AF10) can be written for it. Policy A (permissive) and B (tightened) both
decide `command` 1 by `level`, and on the fixed test input they disagree, so a commit shows as every node's answer
changing at once.

The layout document and the domain document are this script's own reading of AF10 and CL4, whose forms the spec
names but does not fix for `mesh`: the layout is a canon/2 list of each field's register, role, bounds and
staleness bound in register order, and the domain a canon/2 object of each field's name and bounds. Their SHA-256
are what the node is built with.

The keys live beside this file, each a raw 32 byte seed and gitignored, made on first run: `authority_ed25519.key`
and `controller_ed25519.key`. Only their public keys are baked into the firmware. `Signer` seals releases, trust
statements, install statements and controller statements with them for the harness and the simulated mesh.

    python gen_mesh_tables.py [--fresh SECONDS] [--install-key HEX ...] [--threshold N]   # -> main/tables.h
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Optional, Sequence

HERE = Path(__file__).resolve().parent
HW = HERE.parent
REPO = HW.parent
for path in (str(HW), str(REPO)):
    if path not in sys.path:
        sys.path.insert(0, path)

from prismpath import canon  # noqa: E402
from prismpath.distribution import envelope as env  # noqa: E402
from prismpath.distribution import state_record  # noqa: E402
from prismpath.distribution import statement as statements  # noqa: E402
from prismpath.hotswap import policy_pack  # noqa: E402
from prismpath.kernel import ppt_compile as pc  # noqa: E402

COMMAND, PARAMETER, INDEPENDENT, PROPOSER = range(4)
ROLES = {COMMAND: "command", PARAMETER: "parameter", INDEPENDENT: "independent", PROPOSER: "proposer"}
# AF10: (name, register, role, min, max, staleness bound in seconds)
LAYOUT = [("command", 0, COMMAND, 0, 15, 0), ("level", 1, PARAMETER, 0, 1000, 0), ("clear", 2, INDEPENDENT, 0, 1, 5)]

# The core answers allow when an edge of the table's start node holds, and refuses otherwise (pp_pep_ask), so each
# policy is one predicate.
POLICY_A = "when command == 1 and level < 300"
POLICY_B = "when command == 1 and level < 200"
# a narrow floor: command 2 with its level in [10, 20], and only while the node's own reading says clear
FLOOR = "when command == 2 and level >= 10 and level <= 20 and clear == 1"
TEST_INPUT = {"command": 1, "level": 250, "clear": 1}   # A allows it, B refuses it
STREAM = "mesh/demo"
NOT_BEFORE = 1_800_000_000
DAY = 86400
KEYS = {"authority": HERE / "authority_ed25519.key", "controller": HERE / "controller_ed25519.key"}
INT = 2


def compile_policy(text: str) -> bytes:
    """The table of one predicate over the layout's fields. The compiler numbers fields in the order they first
    appear, so a table whose numbering is not the layout's would read another field than it names, and is refused."""
    compiled = pc.compile_predicate(text)
    registers = {name: reg for name, reg, *_rest in LAYOUT}
    if any(registers.get(name) != reg for name, reg in compiled.fields.items()):
        raise ValueError(f"the fields {compiled.fields} are not numbered as the layout numbers them: name them in "
                         f"register order")
    return compiled.serialize()


def tables():
    """The compiled tables of policies A and B."""
    return compile_policy(POLICY_A), compile_policy(POLICY_B)


def floor_table() -> bytes:
    return compile_policy(FLOOR)


def regs(command: int, level: int, clear: int) -> bytes:
    """The register file the core reads: a 4 byte prefix, then 8 bytes per field, its type and its value."""
    out = b"\x00" * 4
    for value in (command, level, clear):
        out += INT.to_bytes(4, "little") + value.to_bytes(4, "little", signed=True)
    return out


def layout_document() -> bytes:
    return canon.canon2_bytes([{"max": high, "min": low, "register": reg, "role": ROLES[role], "stale": stale}
                               for _name, reg, role, low, high, stale in LAYOUT])


def layout_sha256() -> str:
    return canon.sha256_hex(layout_document())


def domain_sha256() -> str:
    return canon.sha256_hex(canon.canon2_bytes({name: {"max": high, "min": low}
                                                for name, _reg, _role, low, high, _stale in LAYOUT}))


def load_or_make(path: Path):
    """The key at `path`, made on first run, and whether it was made now."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(path.read_bytes()), False
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    path.chmod(0o600)
    return key, True


def public_raw(key) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def image_meta(body: bytes) -> dict:
    """`meta` of a `policy.ppt` release (section 3). A mesh node bounds it and skips it (E9)."""
    header = policy_pack.read_ppt_header(body)
    return {"counts": {name: header[name] for name in ("atoms", "nodes", "edges", "prog_words", "max_steps", "max_stack")},
            "fields": {name: "int" for name, *_rest in LAYOUT}, "qualification": "mesh-demo",
            "wcet_cycles": policy_pack.wcet_cycles(body)}


class Signer:
    """The authority's, the controller's and the engineer's writers for one mesh stream. Keys are Ed25519 private
    keys of `cryptography`, the files beside this script unless given."""

    def __init__(self, authority=None, controller=None, install: Sequence = (), stream: str = STREAM):
        self.authority = authority or load_or_make(KEYS["authority"])[0]
        self.controller = controller or load_or_make(KEYS["controller"])[0]
        self.install = list(install)
        self.stream = stream

    def release(self, body: bytes, seq: int, *, not_before: int = NOT_BEFORE, expires: int = NOT_BEFORE + 30 * DAY,
                replaces: str = "", widens: bool = False) -> bytes:
        policy = canon.sha256_hex(body)
        envelope_bytes = env.build("policy.ppt", body, stream=self.stream, seq=seq, policy_sha256=policy,
                                   release=env.release_id([("policy.ppt", policy)]), targets=["mesh"],
                                   not_before=not_before, expires=expires, replaces=replaces, widens=widens,
                                   meta=image_meta(body))
        return env.seal(envelope_bytes, [self.authority])

    def widening(self, body: bytes, seq: int, *, replaces: str = "", froms=(), not_before: int = NOT_BEFORE) -> tuple:
        """The owner's widening statement (W3, W4) for the release of `body` at `seq` that says it widens: every
        member it shares with that release (E7) and `from`, the policy hashes it may replace (any when empty)."""
        policy = canon.sha256_hex(body)
        statement = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-widening/1",
                                        "from": sorted(froms)})
        envelope_bytes = env.build("trust.widening", statement, stream=self.stream, seq=seq, policy_sha256=policy,
                                   release=env.release_id([("policy.ppt", policy)]), targets=["mesh"],
                                   not_before=not_before, expires=0, replaces=replaces, widens=True)
        return env.seal(envelope_bytes, [self.authority]), statement

    def release_with_statement(self, body: bytes, seq: int, *, replaces: str = "", **args) -> list:
        """(sealed, body) of a release of `body` that widens, its widening statement first: a mesh node cannot
        decide which of two tables is larger, so every new table is larger (W2) and needs one."""
        widening = self.widening(body, seq, replaces=replaces, not_before=args.get("not_before", NOT_BEFORE))
        return [widening, (self.release(body, seq, replaces=replaces, widens=True, **args), body)]

    def _trust(self, artifact: str, body: bytes, seq: int) -> tuple:
        envelope_bytes = env.build(artifact, body, stream=env.TRUST_STREAM, seq=seq, policy_sha256=env.ZERO_HASH,
                                   release=env.ZERO_HASH, targets=["mesh"], not_before=NOT_BEFORE, expires=0)
        return env.seal(envelope_bytes, [self.authority]), body

    def revocation(self, seq: int, *, envelopes=(), keys=(), policies=(), floors=None) -> tuple:
        body = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-revocation/1",
                                   "envelopes": sorted(envelopes), "keys": sorted(keys), "policies": sorted(policies),
                                   "floors": dict(floors or {})})
        return self._trust("trust.revocation", body, seq)

    def controller_key(self, seq: int, public: bytes) -> tuple:
        """A `trust.controller` naming `public` as the controller key (K7)."""
        body = canon.canon2_bytes({canon.ENCODING_KEY: canon.CANON2, "format": "prismpath.dist-controller/1",
                                   "key": public.hex()})
        return self._trust("trust.controller", body, seq)

    def statement(self, epoch: int, *, key_seq: int = 0, fresh: bool = False, trust_seq: int = 0,
                  stream_seq: int = 0, expires: int = 0, key=None, stream: Optional[str] = None) -> bytes:
        """A controller statement (H9, H16), signed by the controller key unless `key` is given."""
        read = statements.Statement(key_seq=key_seq, stream=state_record.stream_prefix(stream or self.stream),
                                    epoch=epoch, fresh=fresh, trust_seq=trust_seq, stream_seq=stream_seq,
                                    expires=expires)
        return statements.build(read, key or self.controller)

    def floor(self, body: bytes, seq: int = 1, rate: Optional[dict] = None) -> tuple:
        """An action floor of the table `body` (section 21, IS1), signed by every install key the signer holds, with
        the signed `rate` of AF8 when one is given."""
        policy = canon.sha256_hex(body)
        meta = {"as": "policy.ppt", "command": 0, "layout": layout_sha256(), **({"rate": rate} if rate else {})}
        # written as a document here, since the Python envelope writer does not take the install kinds yet
        envelope_bytes = canon.canon2_bytes({
            "artifact": "install.floor", "body_sha256": policy, "body_size": len(body), canon.ENCODING_KEY: canon.CANON2,
            "expires": 0, "format": env.FORMAT, "meta": meta,
            "not_before": NOT_BEFORE, "policy_sha256": policy, "release": env.release_id([("policy.ppt", policy)]),
            "replaces": "", "seq": seq, "stream": self.stream, "targets": ["mesh"], "widens": True})
        return env.seal(envelope_bytes, self.install), body


def _carray(data: bytes) -> str:
    return "{ " + ", ".join(f"0x{byte:02x}" for byte in data) + " }"


def anchor_fingerprint(authority: bytes, controller: bytes, fresh: int, install: Sequence[bytes], threshold: int) -> str:
    """IS10: the install trust id a provisioning starts, the SHA-256 of the anchor as this script bakes it."""
    return canon.sha256_hex(canon.canon2_bytes({
        "authority": [authority.hex()], "controller": controller.hex(), "fresh": fresh, "stream": STREAM,
        "install": {"keys": sorted(key.hex() for key in install), "threshold": threshold}}))


def header(authority: bytes, controller: bytes, fresh: int = 0, install: Sequence[bytes] = (), threshold: int = 2) -> str:
    """The text of main/tables.h."""
    lines = [
        "/* generated by gen_mesh_tables.py: the mesh's trust anchor, layout and domain (do not edit) */",
        "#ifndef TABLES_H", "#define TABLES_H", "#include \"mesh_node.h\"", "",
        f"/* AF10: the layout the node is built with, its hash {layout_sha256()} */",
        "static const pp_layout MESH_LAYOUT = {",
        f"    {_carray(bytes.fromhex(layout_sha256()))},",
        f"    {len(LAYOUT)},",
        "    { " + ", ".join(f"{{{reg}, {role}, {low}, {high}, {stale}}}" for _n, reg, role, low, high, stale in LAYOUT) + " }",
        "};",
        "/* P4, CL4: the reading domain it is built with */",
        f"static const uint8_t MESH_DOMAIN[32] = {_carray(bytes.fromhex(domain_sha256()))};",
    ]
    if install:
        if not 1 <= threshold <= len(install) <= 4:
            raise SystemExit("an install member has 1 to 4 keys and a threshold of 1 to their number (IS2)")
        keys = ", ".join(_carray(key) for key in install)
        lines += [
            "/* section 21: the install member of the anchor */",
            "static const pp_install_anchor MESH_INSTALL = {",
            f"    .present = 1, .keys = {{ {keys} }}, .n_keys = {len(install)}, .threshold = {threshold}, .seq = 0,",
            f"    .domain = {_carray(bytes.fromhex(domain_sha256()))},",
            f"    .fingerprint = {_carray(bytes.fromhex(anchor_fingerprint(authority, controller, fresh, install, threshold)))},",
            "};",
        ]
    lines += [
        "/* P2, P4: the anchor a node trusts from its first boot */",
        "static const mesh_anchor MESH_ANCHOR = {",
        f"    .n_authorities = 1, .authorities = {{ {_carray(authority)} }},",
        f"    .has_controller = 1, .controller = {_carray(controller)},",
        f"    .fresh = {fresh}, .stream = \"{STREAM}\", .install = {'&MESH_INSTALL' if install else 'NULL'},",
        "};", "#endif", "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fresh", type=int, default=0, help="H16: the longest lifetime of a fresh statement, 0 for off")
    parser.add_argument("--install-key", action="append", default=[], help="an install key's public key, 64 hex digits")
    parser.add_argument("--threshold", type=int, default=2)
    args = parser.parse_args(argv)
    made = []
    keys = {}
    for name, path in KEYS.items():
        keys[name], created = load_or_make(path)
        if created:
            made.append(path.name)
    install = [bytes.fromhex(key) for key in args.install_key]
    text = header(public_raw(keys["authority"]), public_raw(keys["controller"]), args.fresh, install,
                  args.threshold if install else 0)
    (HERE / "main" / "tables.h").write_text(text, encoding="utf-8")
    for name in made:
        print(f"created {name} (gitignored)")
    table_a, table_b = tables()
    print(f"anchor key id {hashlib.sha256(public_raw(keys['authority'])).hexdigest()} on stream {STREAM}, layout "
          f"{layout_sha256()[:16]}; policy A {len(table_a)} bytes, policy B {len(table_b)} bytes, floor "
          f"{len(floor_table())} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
