# Decision-delta demo runbook

The three-axis decision object, live across three machines: the value axis (signed predicates), the
state axis (a resident FSM posture), and the time axis (send-on-delta with a **signed** timestamp).
The dev station emits raw events; the signed `posture_selector` on the Protectli decides (the
certified eBPF resident FSM of ledger row #119); only posture **changes** are forwarded to the FPGA,
each carrying the kernel receipt's `seq` + `t_ns`; the board renders the posture on LD4/LD5. Holds
transmit nothing - the LED's hold-time is the time-delta made physical.

## Topology

```
  gx10 (dev station)          Protectli (delivery)              Arty Z7-20 (target)
  drive_scenario.py  --UDP--> sel_forward_receipts  --UDP-->    led_listen.py
  events 1/2/0        :9500   signed selector decides  :9410    renders LD4/LD5
                              drains signed receipts             + logs render trail
                              + logs receipt trail
```

Access (see the fpga-board-access + protectli notes): gx10 reaches the Protectli at
`adminlocal@192.168.4.2` (key auth, passwordless sudo); the board sits behind it on a point-to-point
link, reached with `ssh -J adminlocal@192.168.4.2 xilinx@10.10.10.2`. The board's `10.10.10.2` and the
Protectli's `10.10.10.1` are the demo's data link; gx10 talks to the Protectli over the LAN.

## Precondition: a clean PL (wedge safety)

`led_listen.py` loads `ppt_pathb.bit` directly and does **NOT** probe any hardcoded AXI address first
(that hangs the Zynq bus if a different design is resident - only a power cycle recovers). Before the
run, get the PL to a clean state: **power-cycle the board**, then load directly with no probing. On a
fresh boot this is safe. Do not reprogram the PL while a prior auto-mode design is actively mastering
the bus.

## Build (on the Protectli, once)

`sel_forward_receipts.c` builds against the selector sources. Copy it next to them and build:

```bash
# from gx10:
rsync -a prismpath-ebpf/decision-delta-demo/sel_forward_receipts.c adminlocal@192.168.4.2:~/prismpath-sel/
ssh adminlocal@192.168.4.2 'cd ~/prismpath-sel && \
  clang -O2 -target bpf -I. -c ppt_select.bpf.c -o ppt_select.bpf.o && \
  gcc -O2 -Wno-unused-function -I. sel_forward_receipts.c -o sel_forward_receipts \
      -lcrypto $(pkg-config --libs libbpf)'
```

`led_listen.py` needs no build; copy it to the board:

```bash
scp -o ProxyJump=adminlocal@192.168.4.2 prismpath-ebpf/decision-delta-demo/led_listen.py xilinx@10.10.10.2:/home/xilinx/
```

## Run (drop-proof: nohup + output files on each node)

1. **Board** - start the render listener (self-exits after the duration, parks green):

```bash
ssh -J adminlocal@192.168.4.2 xilinx@10.10.10.2 \
  "sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh; source /etc/profile.d/boardname.sh; cd /home/xilinx; nohup python3 led_listen.py 90 /home/xilinx/led_render.log > /home/xilinx/led_listen.out 2>&1 & echo started pid \$!'"
```

2. **Protectli** - start the forwarder (signed selector + receipt drain):

```bash
ssh adminlocal@192.168.4.2 \
  "cd ~/prismpath-sel && nohup sudo ./sel_forward_receipts selector_corpus.bin ppt_select.bpf.o 10.10.10.2 9410 9500 90 receipt_trail.log > sel_forward.out 2>&1 & echo started pid \$!"
```

3. **gx10** - drive the scenario (watch the LEDs walk):

```bash
python3 prismpath-ebpf/decision-delta-demo/drive_scenario.py --host 192.168.4.2 --port 9500 --gap 2.0
# or --slow for long, eye-visible holds
```

## Collect + freeze the evidence

Two trails prove it end to end: the Protectli **receipt trail** (signed decisions + `t_ns`) and the
board **render trail** (what the LEDs actually showed, with the upstream `seq`/`t_ns` echoed).

```bash
mkdir -p prismpath-ebpf/decision-delta-demo/evidence
scp adminlocal@192.168.4.2:~/prismpath-sel/receipt_trail.log            prismpath-ebpf/decision-delta-demo/evidence/
scp -o ProxyJump=adminlocal@192.168.4.2 xilinx@10.10.10.2:/home/xilinx/led_render.log prismpath-ebpf/decision-delta-demo/evidence/
cd prismpath-ebpf/decision-delta-demo/evidence && sha256sum receipt_trail.log led_render.log > decision_delta.SHA256SUMS
```

## Check (decision-exact)

- Every `SENT` row in `receipt_trail.log` has a matching `DELTA` row in `led_render.log`, same order,
  same posture, same upstream `seq`/`t_ns`.
- `held` rows have `prev == next` and produced **no** board render (holds suppressed).
- `t_ns` is monotonic across the receipt trail; `deltas_sent + holds_suppressed == events`.
- The forwarder prints the session Merkle root over the receipts - the per-session anchor (OTS is the
  held-for-publish step, owner-gated), the same anchor object as row #119.
