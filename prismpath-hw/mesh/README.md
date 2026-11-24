# mesh: ESP32 nodes as policy distribution enforcement points

Three ESP32 boards are enforcement points of kind `mesh` (`docs/design/spec-policy-distribution.md`). Each takes
every policy as a sealed distribution envelope over ESP-NOW, verifies it before it reads the body, stages it,
flips with the group on a commit, applies revocations, rotations and controller key statements, takes the
controller's epoch statements, decides every request under the C core in `prismpath-hw/dist/`, and signs a state
record for every transition with its own instance key. The firmware carries only its trust anchor, its layout and
the hash of its reading domain.

## What's here

| File | What it holds |
|---|---|
| `main/mesh_node.c`, `main/mesh_node.h` | The node's logic with no ESP-IDF in it: the durable parts in a store under their own names, the install parts on two media (IS10), frames into calls of the core, each state record out as a frame of type 3 |
| `main/ppt_mesh.c` | The board: NVS on two partitions, ESP-NOW, UART0 and `esp_timer` around `mesh_node.c` |
| `main/tables.h` | Written by `gen_mesh_tables.py`: the anchor (authority key, controller key, `fresh`, stream, an install member when given), the layout and the domain |
| `main/Kconfig.projbuild` | `CONFIG_PPT_MESH_EXPIRY_HOLD`, the expiry response (X6). Off is REFUSE |
| `gen_mesh_tables.py` | The anchor, the layout, policies A and B and an action floor, and `Signer`, which seals releases, widening statements, trust statements, controller statements and install floors |
| `mesh_checks.py` | The seven checks, written once over a fleet of nodes |
| `host/mesh_sim.c`, `host/sim_fleet.py` | `mesh_node.c` built for the host: three simulated nodes, each with two in-memory NVS media, on one in-memory radio, and their Python driver |
| `board_run.py` | The seven checks on the boards, called by `../fleet/run.py` |
| `partitions.csv` | `nvs` of 128 kB and `nvs_copy` of 64 kB for the durable state |

## The layout and the policies

Register 0 is `command` (COMMAND), register 1 is `level`, its parameter (PARAMETER), and register 2 is `clear`, a
reading the node takes itself (INDEPENDENT, stale after 5 seconds). The core answers allow when an edge of a table's
start node holds. Policy A allows command 1 below level 300 and policy B below level 200, so at the test input
(command 1, level 250, clear 1) A allows and B refuses. The action floor allows command 2 at a level from 10 to 20
while `clear` is 1 and fresh (AF9, AF10). `gen_mesh_tables.py` refuses a table whose fields the compiler numbers
otherwise than the layout.

## The checks

`mesh_checks.run_checks` runs the seven checks of the plan's PR 17 on any fleet: one build on every node, each with
its own instance key; release B staged and committed on all three, which flip together; a bad signature refused
with `sig:invalid`; a replay of A refused with `dist:seq-replay` before and after a reset; A after B without a
widening statement refused with `dist:widening-unsigned`; a revocation applied and the revoked release refused;
and an expired release refused by default while a node built with HOLD keeps deciding with the hold bit set and
drops to no policy on the revocation.

`prismpath/tests/test_mesh_firmware.py` runs them on the simulated mesh, with no board and no ESP-IDF, and adds
controller statements in frames of type 6 with freshness, an action floor over the radio, the install parts read
from their second copy, the NVS partitions against the largest durable state the core allows, and the build
settings. The boards run the same checks in the board validation pass.

## Build and run on the boards

```bash
python gen_mesh_tables.py               # main/tables.h, and the keys on first run (gitignored)
. ~/cwprojects/esp-idf/export.sh
idf.py set-target esp32 && idf.py build
cd .. && python -m fleet.run            # build, flash every board by path and MAC, run the checks, write the report
```

One build runs on every ESP32 classic board: `sdkconfig.defaults` sets `CONFIG_XTAL_FREQ_AUTO`, and `fleet/run.py`
fails a build whose sdkconfig does not hold it. The firmware owns UART0, whose lines `main/ppt_mesh.c` lists, so
`idf.py monitor` shows nothing useful. Read the nodes with `board_run.py`.

## The NVS partitions

At the bounds of `pp_dist.h` the durable parts take 69,930 bytes on `nvs` with the instance key's seed, and the
install parts 28,484 bytes on `nvs_copy`. A part is always written whole, so NVS needs room to write the largest
part again before it erases the old one, and it keeps one page free. `nvs` then needs 22 pages of 4 kB with PHY
calibration and has 32, and `nvs_copy` needs 11 and has 16. The default partition of 24 kB holds neither.

The demo this directory held before, a two phase commit over a baked allowlist (evidence #100) and its Ed25519
version (#87, #88), is in its history, with `orchestrate.py` and `recert.py`.
