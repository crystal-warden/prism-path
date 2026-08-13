# PrismPath PPT eBPF/XDP Spike

This directory contains the proof-of-shape eBPF/XDP implementation for compiling and executing PrismPath "PPT" (Level M) decidable match-action tables directly inside the Linux kernel network stack.

---

## 1. Architectural Overview & Semantics Parity

A PrismPath flow compiles into a compact binary table image (`.ppt` format, documented in [`../prismpath-hw/TABLE_FORMAT.md`](../prismpath-hw/TABLE_FORMAT.md)). The reference interpreter [`../prismpath-hw/interp.c`](../prismpath-hw/interp.c) defines the exact execution semantics.

The eBPF implementation in [`ppt_xdp.bpf.c`](./ppt_xdp.bpf.c) mirrors `interp.c`'s core three evaluation tiers:
1. **`eval_atom`**: Evaluates single predicates (`field OP constant`) over a register file context adhering strictly to Level M totality rules.
2. **`eval_prog`**: Runs a stack machine over per-edge program words to evaluate boolean combinations (`NOT`, `AND`, `OR`, `TRUE`, `FALSE`).
3. **`evaluate`**: Priority encoder — evaluates node edges sequentially; the first matching edge wins.

---

## 2. Mapping Tables

### PPT Image Section → BPF Map

| PPT Image Section | BPF Map Name | Map Type | Key Type | Value Type | Max Entries | Description |
|---|---|---|---|---|---|---|
| Header Metadata | `config_map` | `BPF_MAP_TYPE_ARRAY` | `__u32` | `struct ppt_config` | 1 | Stores flow configuration (`n_fields`, `n_nodes`, `start_node`, etc.) |
| `atoms` ($n_{atoms} \times 8\text{B}$) | `atoms_map` | `BPF_MAP_TYPE_ARRAY` | `__u32` | `struct ppt_atom` | 1024 | Flow-wide deduplicated atomic field comparators |
| `nodes` ($n_{nodes} \times 4\text{B}$) | `nodes_map` | `BPF_MAP_TYPE_ARRAY` | `__u32` | `struct ppt_node` | 256 | Graph node edge offsets and edge counts |
| `edges` ($n_{edges} \times 6\text{B}$) | `edges_map` | `BPF_MAP_TYPE_ARRAY` | `__u32` | `struct ppt_edge` | 1024 | Ordered edge targets, program offsets, and lengths |
| `prog` ($prog\_len \times 2\text{B}$) | `prog_map` | `BPF_MAP_TYPE_ARRAY` | `__u32` | `__u16` | 4096 | Per-edge stack machine boolean opcodes and atom indices |
| Result Output | `result_map` | `BPF_MAP_TYPE_ARRAY` | `__u32` | `struct ppt_result` | 1 | Output verdict (`matched_edge`, `target_node`, metrics) |

### `interp.c` Function → eBPF Function

| `interp.c` Function | `ppt_xdp.bpf.c` Function | Semantics & eBPF Adaptation |
|---|---|---|
| `eval_atom(a, regs)` | `eval_atom(a, regs, n_fields)` | Exact parity for totality: non-numeric ordering returns 0 (unsatisfied); missing fields return `TY_NONE`; `TRUTHY` checks `val != 0`. Context bounds checked. |
| `eval_prog(im, e, regs)` | `eval_prog` + `prog_word_cb` | RPN stack machine (`OPC_NOT/AND/OR/TRUE/FALSE`) run as a `bpf_loop` callback (verified once); fixed-depth constant-indexed operand stack. See §4. |
| `evaluate(im, node, regs)` | `evaluate` + `edge_loop_cb` | Priority encoder; edge iteration via `bpf_loop` (verified once), first true edge wins. `evaluate` is `__noinline` (own stack frame). |
| `mode_eval` / `main` | `ppt_xdp_prog(ctx)` | XDP entry point (`SEC("xdp")`). Parses on-wire register file, executes `evaluate`, writes verdict to `result_map`, returns `XDP_PASS`. |

---

## 3. On-Wire Packet Layout

The XDP program inspects incoming packets for a PrismPath context payload. It supports both **raw packet payloads** (for lightweight testing) and **standard Ethernet + IPv4 + UDP encapsulated frames**.

### Packet Payload Structure

```
+-------------------------------------------------------------+
| Header: struct ppt_packet_hdr (12 bytes)                   |
|   - __u32 magic     : 0x4D545050 ("PPTM")                  |
|   - __u32 node_idx  : Graph node index to evaluate        |
|   - __u32 n_fields  : Number of register pairs following   |
+-------------------------------------------------------------+
| Registers: struct ppt_reg[n_fields] (n_fields * 8 bytes)   |
|   - __s32 ty       : Type tag (0=NONE, 1=BOOL, 2=INT, 3=STR) |
|   - __s32 val      : Value or intern string ID              |
+-------------------------------------------------------------+
```

When an XDP frame arrives:
1. The parser verifies bounds against `ctx->data_end`.
2. It checks for `PPT_MAGIC` (0x4D545050) either directly at payload start or following UDP header (port 9999).
3. Up to `MAX_FIELDS_PER_PKT` (8) registers are copied into bounded local stack storage for high-speed evaluation.

---

## 4. eBPF Verifier Analysis — what actually works, and the road to it

A data-driven table interpreter (nested `evaluate × eval_prog` loops running a stack machine over
runtime table/packet data) is a genuinely hard case for the verifier. Getting it to load took several
distinct techniques; the failed attempts are documented here because they are the useful part — they
show *why* the final design is the way it is. All numbers are from kernel **6.17** (aarch64), libbpf
1.3, SKB/generic XDP.

### 4.1 The core problem: the verifier explores STATES, not just instructions

The verifier symbolically walks every reachable path. A stack machine indexed by a runtime stack
pointer (`stack[sp]`), nested inside an edge loop, makes the reachable-state space blow up. Two hard
ceilings bite: `BPF_COMPLEXITY_LIMIT_JMP_SEQ` (8192 jumps in a path) and the 1,000,000
processed-instruction limit.

### 4.2 What did NOT work (and why)

| Attempt | Result |
|---|---|
| `#pragma unroll` the loops | Clang **refuses** — the loops have a data-dependent `break` and a nested call across a function boundary. They stay real loops. |
| Bounds tuning (64→16→8) | The state count is **insensitive** to the loop bounds — it plateaus at ~43k–47k regardless. 64×64 hit the 8192-jump limit; 16×16 processed exactly 1,000,001 insns (1 over); 8×8 *unrolled* was **worse** (68k states). |
| Constant-indexed stack alone | Removing `stack[sp]` (see 4.4) helped — the log shrank from 259k to ~10k lines — but states still plateaued ~47k. Necessary, not sufficient. |

The lesson: the cost is the **interaction** of the whole per-packet interpreter, and no single bound
moves it. The only thing that collapses it is making each loop verified **once**.

### 4.3 What works: nested `bpf_loop` (verify each loop body ONCE)

`bpf_loop(nr, cb, ctx, 0)` verifies the callback a single time regardless of iteration count. Both
interpreter loops are `bpf_loop` callbacks:
* **`edge_loop_cb`** — the priority encoder over a node's edges (the routing loop).
* **`prog_word_cb`** — the RPN stack machine, one program word per call; the operand stack (`st[]`) is
  carried in a `struct prog_ctx` and mutated across words. Nested inside `edge_loop_cb`.

The register file is NOT in either ctx — it lives in a per-CPU map (see 4.5), so the ctxs stay tiny.
Because neither loop is re-explored per-iteration, the state count collapses and the program loads.
Requires kernel ≥ 5.17.

### 4.4 Constant-indexed operand stack (no `stack[sp]`)

The stack is a fixed-depth array accessed **only** through `st_get`/`st_put`, which `switch` on the
index so every `st[]` reference is a compile-time-constant slot. This avoids the specific verifier
penalty for a runtime-variable stack offset. Depth is `STACK_MAX`.

### 4.5 Register file in a per-CPU map — and the resulting full-capacity bounds

The per-packet register file is ONE per-CPU map value (`struct ppt_regfile`), not stack-resident and
not embedded in any ctx. This does two things: it keeps the bpf-to-bpf call chain far under the
512-byte stack budget regardless of field count (embedding `regs[]` in each ctx overran it —
"combined stack size ... Too large"), and it lets the field-load be a single map lookup + a call-free
unrolled fill loop (a per-field lookup was a helper call × N that re-exploded the state count).

With that in place the bounds run at **full original capacity** — the numbers that overran the verifier
before the rewrite now load with headroom (processed ~150k of the 1M-insn budget):
* `MAX_FIELDS_PER_PKT = 32`, `MAX_EDGES_PER_NODE = 64`, `MAX_PROG_PER_EDGE = 64` — edges and prog are
  `bpf_loop` dimensions (O(1) to the verifier); fields are a once-verified unrolled fill.
* The one genuine **declared-subset** limit is `STACK_MAX = 4` — the max operand-stack depth of a
  supported predicate. Level M expressions fold left-associatively, so a flat AND/OR chain (including
  `in`-lists) stays at depth 2; 4 covers real nesting. It is a `switch` depth (constant-indexed), not
  an array size, so it is deliberately small; a predicate deeper than this is outside the subset.

### 4.6 Standard safety properties (all retained)

* **Map lookups NULL-checked**; keys bitwise-masked to power-of-two map capacities
  (`& (MAX_ATOMS-1)`, `& (MAX_PROG_WORDS-1)`, …) so range analysis sees `[0, cap-1]`.
* **512-byte stack budget**: `evaluate` is `__noinline` (own frame), and the register file lives in a
  map (4.5) rather than any ctx, so the call chain stays well under 512 B at any field count.
* **Loop-counter aliasing**: never pass the loop induction variable's address (`&i`) to a helper — the
  verifier then can't prove `i` increments and rejects with "infinite loop detected". Use a copy.
* **Totality**: out-of-range field → `TY_NONE`; non-numeric ordering → unsatisfied; stack under/overflow
  guarded — exact parity with `interp.c`.

---

## 5. Verification & Execution Status — PROVEN end-to-end at full bounds

Run on kernel 6.17 (aarch64), clang 18, libbpf 1.3, via `sudo make smoke` (which captures `smoke.out`):

1. **`interp.c` reference** — compiled; `regs1.bin → match 0 1`, `regs2.bin → match 2 2`.
2. **Host semantics parity** — `loader.c`'s host evaluator matches `interp.c` on the sample table.
3. **eBPF compile** — `clang -target bpf` produces a valid `ppt_xdp.bpf.o` (`xdp` section).
4. **Kernel verifier — PASSED at 32/64/64.** `bpf_object__load` succeeds at the full bounds that overran
   the verifier three ways before the rewrite (8192-jump limit; 1M-insn un-unrolled; 1M-insn unrolled) —
   now processing ~150k of the 1M-insn budget. A PrismPath Level M / PPT table interpreter is accepted
   by the Linux verifier.
5. **XDP attach + in-kernel EXECUTION verified.** The program attaches to `veth-ppt-a` (SKB mode); a
   crafted PPT packet is injected; smoke Step 4 reads `result_map` back and confirms the **in-kernel
   verdict byte-matches `interp.c`** for that packet (`matched_edge=0, target_node=1, eval_status=1,
   pkt_count=1`). `sudo make smoke` exits **0**.

Full chain proven: **compile → verify → load → attach → execute in-kernel → correct output**, matching
the C reference on a real packet, at full table bounds.

---

## 6. How to Run

### Build Binaries
```bash
make clean
make
```

### Run Smoke Test (Host Parity & Non-Root Check)
```bash
./smoke.sh
```

### Run Full Kernel XDP Test (Requires Root / CAP_BPF)
```bash
sudo ./smoke.sh
```

---

## 7. Conformance & flow execution — the loader's `certify` / `run` / `runbatch` modes

Beyond the single-packet smoke test, the loader drives the actual XDP program in-kernel via
`BPF_PROG_TEST_RUN` (no NIC needed) so the eBPF target can be certified against the same frozen corpus
every other kernel uses, and can execute whole flows.

- **`sudo ./loader <ppt> certify <packets.bin>`** — runs a table-per-vector conformance corpus. Each
  record carries its own compiled PPT table + a crafted packet; the maps are repopulated per vector.
  Built by `cert_corpus.py`, which frames every in-subset vector of
  `../prismpath/portable/conformance/predicates.json` and cross-checks each against `interp.c` first.
  The declared subset uses the **same filter as `prismpath-hw`'s C-target cert** (in-fragment condition
  + the fields it *reads* representable on the i32 table): **124/1079** (corpus v2, negative-integer
  literals included), of which the eBPF target passes
  **124/124 in-kernel, byte-matching the reference — re-certified 2026-08-12 on both aarch64 and
  x86_64 with the hardened loader.** The other 955 are excluded and itemized: 943 whose
  condition is not a match-action table (field-vs-field, arithmetic, string-ordering, `is`, non-literal
  collections, constant-only, …) plus 12 float / 11 non-scalar whose *read* field can't be represented on
  an i32 table. **No exclusion is an eBPF limit** — operand-stack depth stays well under `STACK_MAX=4`.
- **`sudo ./loader <ppt> run <regs.bin> [names.txt]`** — drives one flow hop-by-hop: start at the flow's
  start node, evaluate it in-kernel, follow the matched target, repeat to a terminal. Prints the
  in-kernel path and the host-reference path and checks they match. `run_flow_demo.py` / `run_incident_demo.py`
  build the inputs.
- **`sudo ./loader <ppt> runbatch <records.bin> [names.txt]`** — the same, batched: one BPF load, many
  register files (e.g. one per real alert), each traced to a terminal and checked against the reference.

**Real-flow evidence.** The 12-node Level M SOC flow `adapters/soc/flows/wazuh_triage.md` has been run
through the eBPF router in-kernel on a **live Wazuh alert stream** (`run_stream_demo.py` classifies each
real alert with the live LLM, builds the routing register file, no synthetic values): 27/27 real alerts
routed identically in-kernel and by the reference, branching correctly (`benign` vs `stage_containment`)
on real verdicts.

### Conformance framing (don't say "declared subset")

Report the **Level M / match-action corpus** as the *cross-substrate standard* — the vectors that
produce identical verdicts on Python, the portable JS/Rust/Go kernels, the FPGA C-table, and eBPF. Name
each richer tier (P1 locked-semantic, P2/semantic) separately; never as a lump "+X above." The eBPF
target certifies **100% of the in-fragment corpus**, with every exclusion itemized as a language feature
that isn't a decidable table.

## 8. Real-packet classification on live traffic (`ppt_net`) + measured latency

`ppt_net.bpf.c` is the same verified eval back-end with a **real-packet front-end**: it parses live
Ethernet/IPv4/TCP-UDP into a fixed canonical register file — `0 src_ip · 1 dst_ip · 2 src_port ·
3 dst_port · 4 protocol · 5 pkt_len · 6 tcp_flags · 7 ttl` — and evaluates a Level M table per packet.
**Observe-only (always `XDP_PASS`)**, built for a mirror attach where it cannot affect production traffic.
`net_compile.py` compiles a triage flow (`net_triage.md`) with that schema pre-seeded so field indices
line up with the parser's slots.

Loader modes: `netattach <ppt> <iface>` (populate table + attach XDP in SKB mode + pin the histogram),
`netstats [names]` (read the per-target histogram), `netdetach <iface>`, `netbench <ppt>` (per-packet
latency via `BPF_PROG_TEST_RUN`), `netupdate <new.ppt> <iface>` (live policy hot-swap — below).

- **Live traffic:** attached observe-only on `span0` (the gretap mirroring all home traffic), the
  `net_triage` table (ssh/dns/http/https/icmp/jumbo/other) classified **7,491 real packets in-kernel**
  with a sensible TLS-dominant distribution; the `(no-match)` bucket was 0 (the table is exhaustive over
  real traffic). Zeek/AF_PACKET still see every packet — `XDP_PASS` doesn't disturb existing capture.
- **Latency (kernel-measured, `BPF_PROG_TEST_RUN` × 1e6):** **132–182 ns/packet** for parse + Level M
  eval, **~5.5–7.6 Mpps on one core** (aarch64, generic/SKB XDP). Sub-microsecond — measured, not asserted.
- **Live policy hot-swap (`netupdate`):** the program holds no policy — it lives entirely in the maps.
  Edit the `.md` flow → recompile → `netupdate <new.ppt> <iface>` reaches the running program via its
  map-IDs and repopulates the table **in place, no detach, no reload**. Demonstrated on live `span0`:
  swapped a 7-class table for an 8-class one (splitting `quic`=UDP/443 from `https`=TCP/443) while the
  program kept classifying — `result_map.pkt_count` climbed straight through the swap, proving one
  uninterrupted instance. This is the FPGA "swap the map, change the policy, no reprogram" property on
  the kernel substrate: alter in-kernel line-rate behavior by editing Markdown. **Fixed without a
  reload:** the 8-field packet ABI and the table bounds; any in-bounds Level M table hot-swaps.
  **Atomic (double-buffered):** the four table maps hold two banks; a packet reads a single `__u32`
  bank selector once (an aligned load, atomic against the loader's aligned store) and evaluates
  entirely within it. `netupdate` writes the *inactive* bank in full, then flips the selector in ONE
  update — so a packet sees the old table whole or the new table whole, never a torn mix, and a
  failed write is never committed. Proven by `loader netstorm <a> <b>`: **200,000 evaluations under
  ~500k concurrent bank flips, zero torn reads, on both aarch64 and x86_64** (evidence #93). The
  conformance program `ppt_xdp` stays single-bank — its 124/124 cert is unaffected.
- **Secure hot-swap (trusted pre-loader, `net_swap.py`):** bare `netupdate` loads any
  structurally-valid image. `net_swap.py` puts the authorization + envelope gates in front of it —
  it verifies the signed policy pack against its signed envelope and monotonic-version floor
  **on the host**, and execs `netupdate` only on success, so a tampered or replayed policy never
  reaches a map. Privilege-free up to the loader exec (tested without root by injecting the loader
  call). This is the eBPF layer of the secure-hot-swap composition; the full four-property mechanism
  (authorized / envelope-bounded / attested / audited-atomic) and its software reference tier are
  specified in [`../docs/design/spec-secure-hotswap.md`](../docs/design/spec-secure-hotswap.md).
- **Loader-side hardenings (staged, pending a privileged recert):** three `loader.c` fixes are built
  but held until a root live-smoke passes (substrate-retest discipline) — a `MAX_*` capacity check in
  `parse_image_buf` (an oversized image previously partial-populated instead of being rejected),
  checked `bpf_map_update_elem` returns (a partial populate aborts loudly instead of leaving a torn
  table), and **preserving `drop_mask` across a swap**. That last one fixes a real bug: `netupdate`
  rebuilds `config_map[0]` with a designated initializer that zeroes the enforcement mask, so a
  hot-swap silently drops an enforcing program back to observe-only. It is **latent today** because
  enforcement is observe-only anyway (§9), but it must land before inline `DROP` does.

## 9. Honest status — what is and isn't proven

- **Proven:** compile → verifier-accepted → in-kernel execution; 124/124 declared-subset conformance
  (the same 124/1079 subset the FPGA C-target certifies; re-certified 2026-08-12, aarch64 + x86_64);
  real multi-node flows + a live alert stream routed correctly in-kernel; **real on-wire packets parsed
  and classified on live home traffic; sub-microsecond per-packet latency measured.**
- **Caveats / not yet done:** the latency figure is program **compute cost** (`BPF_PROG_TEST_RUN`), not
  end-to-end wire latency, on **generic/SKB** XDP (native-driver XDP would likely be faster);
  enforcement is **observe-only** (no inline `DROP`/`REDIRECT` yet); a first-class
  `prismpath compile --target ebpf` flag is still a packaging nicety (the `.ppt` comes from
  `../prismpath-hw/ppt_compile.py`). The inline deployment on the Protectli/Proxmox firewall (its Linux
  side — never OPNsense/FreeBSD) is the follow-on.
