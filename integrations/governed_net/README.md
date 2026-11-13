# governed_net

This is phase 2 of the governed agent harness. The tool calls go over a real network wire, and the
kernel decides each one with XDP before the tool server sees it. The harness loop runs on a client (the
owner's Mac) and asks the model over the normal network. Each call it makes becomes one UDP datagram on a
dedicated cable to an enforcement host. There, an XDP program on that port reads the datagram strictly,
decides it against the signed policy's table with the repository's shared evaluator, and reports the
decision through a ring buffer. The program passes the datagram to the tool server only on `allow`. The
server re-derives the request and decides it again with the Python kernel, and it runs the call in
bubblewrap only when both decisions say `allow`. A userspace logger writes every XDP decision as a signed
core receipt that `formal/diff/core_evidence.py` verifies.

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
| `policy/net_rules.src.json`, `.core.json` | the signed `prismpath.core/1` image over the protocol's seven fields |
| `policy.py` | the image decided by the Python kernel (`governed_harness.policy`) and compiled to the XDP program's table and action file |
| `owner_rules.py` | the rules read a second time in plain Python |
| `../../prismpath-ebpf/gnet/gn_xdp.h` | the frame parse, the strict reading, the register fill and the action: one text for the kernel and its test path |
| `../../prismpath-ebpf/gnet/gn_xdp.bpf.c` | the XDP program (its maps, its ring buffer, its entry) |
| `../../prismpath-ebpf/gnet/gn_batch.c` | the same text run natively over a shim of the BPF maps, `bpf_loop` and the ring buffer |
| `../../prismpath-ebpf/gnet/gn_loader.c` | load, fill, attach, stream the ring buffer, detach, and `BPF_PROG_TEST_RUN` a corpus (privileged; SETUP.md) |
| `frame.py`, `xdp_userspace.py`, `differential.py` | the Python decision of a frame, the userspace path, and the differential of the two |
| `receipt_logger.py` | ring buffer events to receipts, the signed root, and the status port |
| `server.py` | the tool server: handles, re-derivation, re-decision, findings, and confined execution |
| `gate.py` | the userspace path in front of the server on loopback. **It is not the kernel** |
| `client.py` | the network tool backend for the harness loop, and a one-episode command for the Mac |
| `adversary_net.py` | the adapted adversary set, seven lying client probes, the end-to-end run, and the scores |

## Run it (no privileges)

```sh
export PRISMPATH_CORE_ORACLE=/path/to/core-oracle          # or: cd formal && lake build core-oracle
python -m pytest -q integrations/governed_net/tests
python -m integrations.governed_net.differential --random 200000 --seed 20261113 --out /tmp/gn-diff
python -m integrations.governed_net.adversary_net probes --out /tmp/gn-probes
python -m integrations.governed_net.adversary_net live --out /tmp/gn-live --concurrency 4   # against the model
make -C prismpath-ebpf gnet                                 # the XDP object, its loader, its test path
```
