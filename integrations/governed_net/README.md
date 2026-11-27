# governed_net

This is phase 2 of the governed agent harness. The tool calls go over a real network, and the kernel
decides each one with XDP before the tool server sees it. The harness loop runs on a client (the owner's
Mac) and asks the model over the normal network. Each call it makes becomes one UDP datagram to an
enforcement host. There, an XDP program reads the datagram strictly, decides it against the signed policy's
table with the repository's shared evaluator, and reports the decision through a ring buffer. The program
passes the datagram to the tool server only on `allow`. The server re-derives the request and decides it
again with the Python kernel, and it runs the call in bubblewrap only when both decisions say `allow`. A
userspace logger writes every XDP decision as a signed core receipt that `formal/diff/core_evidence.py`
verifies.

Two deployments (SETUP.md). The **LAN edge layout** (the owner's choice) puts the program on the Proxmox
host's own LAN NIC, which the whole household crosses; it matches only the configured tool-server address
and the agent port, so everything else, every other host, port, IPv6, ARP, VLAN tag and fragment, passes
untouched, and it keeps per-verdict counters so coexistence is measurable. Because the program guards only
that NIC, the client pins its socket to the LAN interface (a mesh VPN would otherwise bypass it) and the
server refuses any source outside the LAN as a backstop. The **dedicated wire layout** is the alternative:
a cable to a passed-through port on a small VM, isolating the agent path. The decision, the receipts and
the verification are the same in both.

```
model reply -> client -> datagram (header = the call, typed integers) -> wire
   -> XDP on the port: strict read -> policy table (shared evaluator) -> ring buffer event -> PASS | DROP
   -> tool server: strict read, re-derive (own handle table), decide again (Python kernel), receipt
   -> both allow: run in bwrap | any disagreement: a recorded finding, never run
   ring buffer -> receipt logger -> canon/2 core receipts + signed root (decider "xdp")
```

The protocol and the reasoning behind it are in [`PROTOCOL.md`](PROTOCOL.md). The owner's steps for the
enforcement host are in [`SETUP.md`](SETUP.md), and what was run and what it shows is in
[`RESULTS.md`](RESULTS.md).

| File | What it is |
|------|------------|
| `protocol.py` | the datagram, its encoder, and its strict reader |
| `policy/net_rules.rules.md`, `.core.json` | the readable rules and the signed `prismpath.core/1` image they compile to, over the protocol's seven fields |
| `policy.py` | the image decided by the Python kernel (`governed_harness.policy`) and compiled to the XDP program's table and action file |
| `owner_rules.py` | the rules read a second time in plain Python |
| `../../prismpath-ebpf/gnet/gn_xdp.h` | the frame parse, the strict reading, the register fill and the action: one text for the kernel and its test path |
| `../../prismpath-ebpf/gnet/gn_xdp.bpf.c` | the XDP program (its maps, its ring buffer, its entry) |
| `../../prismpath-ebpf/gnet/gn_batch.c` | the same text run natively over a shim of the BPF maps, `bpf_loop` and the ring buffer |
| `../../prismpath-ebpf/gnet/gn_loader.c` | load, fill, attach, stream the ring buffer, detach, and `BPF_PROG_TEST_RUN` a corpus (privileged, libbpf host; SETUP.md) |
| `../../prismpath-ebpf/gnet/gn_xdp.pin.bpf.c` | the same program with every map pinned by name, for the no-install host |
| `../../prismpath-ebpf/gnet/gn_loader.py` | the no-install loader: fill the pinned maps, read the counters, drain the ring buffer, attach/detach via iproute2 (stdlib only; `--self-test`) |
| `../../prismpath-ebpf/gnet/coexist.sh` | ping RTTs plus the counters, to compare the LAN detached and attached |
| `frame.py`, `xdp_userspace.py`, `differential.py` | the Python decision of a frame (with the match target and household traffic), the userspace path, and the differential |
| `receipt_logger.py` | ring buffer events to per-client receipts, the signed root, and the status port |
| `server.py` | the tool server: handles, re-derivation, re-decision, the source-prefix backstop, per-client findings, and confined execution |
| `gate.py` | the userspace path in front of the server on loopback, one back socket per client. **It is not the kernel** |
| `client.py` | the Mac client: a standard-library-only network backend with interface pinning, and a one-episode command |
| `adversary_net.py` | the adapted adversary set, the lying client probes, the end-to-end run, and the two-client run |

## Run it (no privileges)

```sh
export PRISMPATH_CORE_ORACLE=/path/to/core-oracle          # or: cd formal && lake build core-oracle
python -m pytest -q integrations/governed_net/tests
python -m integrations.governed_net.differential --random 200000 --seed 777 --out /tmp/gn-diff   # + household + counters
python -m integrations.governed_net.adversary_net probes --out /tmp/gn-probes
python -m integrations.governed_net.adversary_net two-client --out /tmp/gn-two
python -m integrations.governed_net.adversary_net live --out /tmp/gn-live --concurrency 4   # against the model
python prismpath-ebpf/gnet/gn_loader.py --self-test        # the no-install loader's non-privileged checks
make -C prismpath-ebpf gnet                                 # gn_xdp.bpf.o, the pinned gn_xdp.pin.bpf.o, loader, test path
```
