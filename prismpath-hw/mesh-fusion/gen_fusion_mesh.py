"""Compile the 3-field distributed-fusion policy to a .ppt and emit it, with the node role map, as a
C header for the ESP-NOW fusion mesh.

Three physically separate ESP32 nodes each sense one channel and project it to a small band:
  slot 0  tof_a  = a VL53L0X rangefinder  (band 0=contact .. 3=far, closer is lower)
  slot 1  tof_b  = a second VL53L0X       (same bands)
  slot 2  arm    = a potentiometer        (band 0=low .. 3=high, the arming/sensitivity knob)

Every node broadcasts its own band over ESP-NOW and hears the other two, so each holds all three and
runs the SAME baked Level M table over them. The winning edge is the fused posture. CRITICAL needs
BOTH rangefinders close AND the knob armed, a region no single node reaches alone.

Two pre-vetted fusion policies are baked so the fleet can coordinate-swap the fusion RULE itself (the
two-phase commit from mesh/, one layer up): policy A arms at knob band >= 2, policy B tightens that to
>= 3. Each gets a 32-bit FNV-1a id; a node stages a pushed table only if it re-hashes to its announced
id and that id is on the baked allowlist {A, B}. (An Ed25519 signature is the named follow-on, same
shape.) With the sensors held in an A-CRITICAL state, a swap to B re-fuses the fleet to WARN, so the
rule change is visible without touching a sensor.

    python gen_fusion_mesh.py     # -> main/fusion_mesh_table.h
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HW = HERE.parent                                     # prismpath-hw
REPO = HW.parent
sys.path.insert(0, str(HW))
sys.path.insert(0, str(REPO))

import ppt_compile as pc
from prismpath.parser import parse

# The fused posture, fail-operational. Field order follows first appearance: tof_a -> 0, tof_b -> 1,
# arm -> 2, which must line up with the node slots below. A live sensor reads band 0..3 (lower ToF =
# closer, higher arm = more armed); a slot the mesh has NOT heard within the freshness window reads the
# STALE sentinel 8. A dark sensor is a signal, not silence: while the system is armed (or a live
# rangefinder is at contact) a dark sensor escalates to TAMPER (possible defeat); otherwise it drops to
# DEGRADED and the fleet keeps deciding on whatever remains. Never serial, never blank. The `arm <= 3`
# bounds keep the sentinel (8) from reading as "armed" in the threshold rules; ToF `<= n` rules exclude
# it naturally. {ARM} is the arming threshold the two policies differ on (A=2 permissive, B=3 tightened).
FUSE_FLOW = """---
name: fusion_mesh
start: fuse
---
## fuse
Two rangefinders and an arming knob fused into one posture, resilient to a node going dark. A live
sensor reads a band 0..3; an unheard sensor reads the STALE sentinel 8. Critical needs BOTH rangefinders
close AND the system armed. A dark sensor escalates to tamper while armed or while a live rangefinder is
at contact, and degrades otherwise, so the decision never goes silent. Everything is a decided band.
-> critical: when tof_a <= 1 and tof_b <= 1 and arm >= {ARM} and arm <= 3
-> tamper: when tof_a == 8 and arm >= {ARM} and arm <= 3
-> tamper: when tof_b == 8 and arm >= {ARM} and arm <= 3
-> tamper: when arm == 8 and tof_a <= 0
-> tamper: when arm == 8 and tof_b <= 0
-> degraded: when tof_a == 8 or tof_b == 8 or arm == 8
-> warn: when tof_a <= 0 or tof_b <= 0
-> warn: when tof_a <= 1 and arm >= 1 and arm <= 3
-> warn: when tof_b <= 1 and arm >= 1 and arm <= 3
-> ok: else
## critical
-> end: when always
## tamper
-> end: when always
## degraded
-> end: when always
## warn
-> end: when always
## ok
-> end: when always
## end
done
"""

# fuse-node edge index -> posture name (same edge structure for both policies)
VERDICTS = ["CRITICAL", "TAMPER", "TAMPER", "TAMPER", "TAMPER", "DEGRADED", "WARN", "WARN", "WARN", "OK"]
EXPECT_FIELDS = {"tof_a": 0, "tof_b": 1, "arm": 2}

# Node roles: MAC (from `esptool read_mac`) -> (slot, kind, label). Slot must match the field index the
# flow assigns that channel. KIND_TOF=0 KIND_POT=1.
ROLES = [
    ("68:09:47:df:d5:90", 0, 0, "tof-A"),      # ttyUSB0
    ("58:2a:bd:76:6a:bc", 1, 0, "tof-B"),      # ttyUSB1
    ("68:09:47:e0:38:00", 2, 1, "arm"),        # ttyUSB2  (pot on GPIO35 / ADC1_CH7)
]


def fnv1a32(b: bytes) -> int:
    h = 0x811C9DC5
    for x in b:
        h = ((h ^ x) * 0x01000193) & 0xFFFFFFFF
    return h


def carr(name, blob):
    hexb = ",\n  ".join(", ".join(f"0x{c:02x}" for c in blob[i:i + 12]) for i in range(0, len(blob), 12))
    return f"static const uint8_t {name}[] = {{\n  {hexb}\n}};"


def compile_policy(arm_threshold):
    comp = pc.compile_flow(parse(FUSE_FLOW.replace("{ARM}", str(arm_threshold))), 25)
    got = {k: comp.fields[k] for k in EXPECT_FIELDS if k in comp.fields}
    if got != EXPECT_FIELDS:
        print(f"FATAL: field slots {comp.fields} != expected {EXPECT_FIELDS}", file=sys.stderr)
        sys.exit(1)
    return comp.serialize()


def mac_bytes(mac):
    return "{" + ", ".join(f"0x{int(x, 16):02x}" for x in mac.split(":")) + "}"


def main() -> int:
    a = compile_policy(2)          # policy A: arm >= 2 (permissive)
    b = compile_policy(3)          # policy B: arm >= 3 (tightened)
    ida, idb = fnv1a32(a), fnv1a32(b)

    roles_c = ",\n  ".join(
        f"{{ {mac_bytes(mac)}, {slot}, {kind}, \"{label}\" }}" for mac, slot, kind, label in ROLES)
    verd_c = ", ".join(f'"{v}"' for v in VERDICTS)
    out = [
        "/* generated by gen_fusion_mesh.py — two pre-vetted 3-field fusion policies + node roles (do not edit) */",
        "#ifndef FUSION_MESH_TABLE_H",
        "#define FUSION_MESH_TABLE_H",
        "#include <stdint.h>",
        "",
        "enum { KIND_TOF = 0, KIND_POT = 1 };",
        "#define N_SLOTS 3",
        "",
        "/* policy A (permissive): CRITICAL arms at knob band >= 2 */",
        carr("FUSE_TABLE_A", a),
        f"static const uint16_t FUSE_TABLE_A_LEN = {len(a)};",
        f"static const uint32_t POLICY_ID_A = 0x{ida:08x}u;",
        "",
        "/* policy B (tightened): CRITICAL arms at knob band >= 3 */",
        carr("FUSE_TABLE_B", b),
        f"static const uint16_t FUSE_TABLE_B_LEN = {len(b)};",
        f"static const uint32_t POLICY_ID_B = 0x{idb:08x}u;",
        "",
        "/* fuse-node winning edge index -> posture name (shared by both policies) */",
        f"static const char *const VERDICTS[] = {{ {verd_c} }};",
        f"static const int VERDICTS_N = {len(VERDICTS)};",
        "",
        "/* MAC (esptool read_mac) -> slot + sensor kind; one binary, each board self-selects its role */",
        "typedef struct { uint8_t mac[6]; uint8_t slot; uint8_t kind; const char *label; } role_t;",
        f"static const role_t ROLES[] = {{\n  {roles_c}\n}};",
        f"static const int ROLES_N = {len(ROLES)};",
        "#endif",
        "",
    ]
    (HERE / "main").mkdir(parents=True, exist_ok=True)
    (HERE / "main" / "fusion_mesh_table.h").write_text("\n".join(out))
    print(f"wrote fusion_mesh_table.h: A={len(a)}B id_A=0x{ida:08x} (arm>=2) | B={len(b)}B id_B=0x{idb:08x} (arm>=3)")
    for mac, slot, kind, label in ROLES:
        print(f"  slot {slot} {'TOF' if kind == 0 else 'POT'} {label:6} {mac}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
