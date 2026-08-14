# mesh: coordinated fleet policy swap over ESP-NOW

Three ESP32 nodes swap a signed policy **together**: one table is broadcast, verified again on every
node before it is staged (refuse, don't downgrade), committed only after a quorum ACKs, and applied
at a shared tick so the whole fleet flips within ~1 ms. The multi node analogue of the single node
signed hot swap (evidence #87/#88); see evidence **#100**.

## What's here

- `gen_mesh_tables.py`: compiles two `.ppt` images with the **untouched** PrismPath compiler and
  emits `main/tables.h`: **policy A** (`level < 300`, permissive) and **policy B** (`level < 200`,
  tightened), each tagged with its FNV-1a-32 id. Regenerate them if you change the policies.
- `main/ppt_mesh.c`: the node firmware. Byte exact evaluator (identical to `interp.c`), ESP-NOW
  gossip plus a two phase commit (PREPARE → verify+stage+ACK → quorum → COMMIT@tick).
- `orchestrate.py`: the host driver that opens all three nodes, pokes one, and timestamps the
  coordinated flip.

## The contract

At the test field `level = 250`: policy A → **ALLOW**, policy B → **DENY**. On PREPARE each follower
recomputes `fnv1a32(received_table)`, checks it equals the announced id **and** that the id is in its
baked allowlist `{A, B}`; only then does it stage and ACK. A table that fails either check is
**refused, not swapped**. COMMIT carries a fixed `FLIP_DELAY` (120 ms); each node applies the staged
table at *its own* `local_now + FLIP_DELAY`, so the fleet flips together without a shared clock.
The FNV-1a id/allowlist is a fast integrity plus prevetting stand in for a real signature;
**Ed25519 on the mesh is the named follow on**.

## Build, flash, run

```bash
# 1. (re)generate the tables
python gen_mesh_tables.py

# 2. build + flash each of the three boards (ESP-IDF v5.4, target esp32)
idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash        # repeat for /dev/ttyUSB2, /dev/ttyUSB3

# 3. drive the fleet: baseline, poke node A, watch all three flip together
python orchestrate.py               # defaults to ttyUSB0/2/3, or pass ports explicitly
```

Expected: all three start `active=A verdict=ALLOW epoch=0`; after one poke you see
`PREPARE → ACK → ACK → COMMIT → FLIP` and all three settle on `active=B verdict=DENY epoch=1`, with a
sub millisecond spread across nodes as observed from the host.

The firmware owns UART0 (console disabled in `sdkconfig.defaults`) for a clean binary status/command
channel, so `idf.py monitor` shows nothing useful; read the nodes with `orchestrate.py` instead.
