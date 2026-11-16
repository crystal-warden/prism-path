# prismpath-collector

The collector is the privileged reader of [the Mission Control plan's section 3.1](../../docs/design/mission-control-plan.md) (work package WP9). It is the one component that holds `CAP_BPF`. It opens an eBPF enforcer's pinned ring buffer and, for the governed net edge, its counter and configuration maps, drains the decisions the program reports, makes each one a leaf of an RFC 6962 tree it seals as it goes, and serves what it read as newline delimited canon/2 records on a Unix socket and, when asked, a loopback TCP port. It takes in one subscription line per client and nothing else. It never loads, attaches, updates or deletes anything in the kernel.

It reads the two enforcers in this directory that report through a ring buffer.

| `--source` | program | ring buffer pin | record |
|---|---|---|---|
| `gnet` | the governed net edge, [`gnet/gn_xdp.pin.bpf.c`](../gnet/gn_xdp.pin.bpf.c) | `/sys/fs/bpf/tc/globals/gn_events`, with `gn_config_map` and `gn_counts_map` beside it | `struct gn_event`, 56 bytes ([`gnet/gn_common.h`](../gnet/gn_common.h)) |
| `selector` | the stateful selector, [`ppt_select.bpf.c`](../ppt_select.bpf.c), deployed by `loader selattach` | `/sys/fs/bpf/ppt_sel_receipts` | `struct ppt_receipt`, 40 bytes ([`ppt_common.h`](../ppt_common.h)) |

The console is the reader of the feed. WP6 (operating) shows it live and WP4 (auditing) keeps it as evidence. The last section says what they consume.

**Where it ships.** The collector is held in research with the kernel target it reads. `tools/export_clean.py` holds `prismpath-ebpf/` back, the product carries no eBPF enforcer whose pins the collector could open, and the console in the product reads the feed only where a collector runs. So it is its own Cargo workspace with its own lockfile, like `prismpath-reflect-bindings`, and the root workspace, which the product carries byte for byte, does not name it. When an enforcer ships, the collector ships with it as one manifest change.

## Running it

```sh
cargo build --release --manifest-path prismpath-ebpf/collector/Cargo.toml
prismpath-collector --source gnet --maps-dir /sys/fs/bpf/tc/globals \
    --socket /run/prismpath-collector/feed.sock --socket-group prismpath-feed --allow-uid 1000
```

| option | default | meaning |
|---|---|---|
| `--source gnet\|selector` | required | which enforcer's record layout |
| `--maps-dir DIR` | `/sys/fs/bpf/tc/globals` for `gnet` | the governed net pins: `gn_events`, and `gn_config_map` and `gn_counts_map` read for `status` records |
| `--ring PIN` | `/sys/fs/bpf/ppt_sel_receipts` for `selector` | a ring buffer pin, with no counter maps |
| `--recorded FILE` | none | a recorded ring buffer instead of the kernel (below); needs no privilege |
| `--socket PATH` | required | the feed's Unix socket, created mode 0660 |
| `--socket-group NAME\|GID` | the collector's group | the socket's group |
| `--allow-uid UID`, `--allow-gid GID` | the collector's own uid | the Unix peers allowed, by user id or primary group id; repeatable |
| `--tcp ADDRESS:PORT` | off | also serve on this loopback address; anything else is refused at start |
| `--seal-interval-ms N` | 1000 | a seal at least this often while leaves arrive, and a `status` record this often regardless |
| `--seal-count N` | 1024 | a seal after this many leaves, whatever the interval |
| `--proof-window N` | 65536 | leaf hashes kept for consistency proofs (32 bytes each, so 2 MiB); at least `--seal-count`, at most 16,777,216 |
| `--queue N` | 4096 | records queued per client before one is dropped for that client |
| `--max-clients N` | 16 | clients served at once |
| `--write-timeout-ms N` | 5000 | a client whose socket takes nothing for this long is disconnected |
| `--exit-when-drained` | off | with `--recorded`, stop when the recording is read |

It exits 0 on SIGTERM or SIGINT (after draining what the ring holds, a final seal and a last `status`), 2 when it cannot start, 3 when the ring buffer's headers stop making sense, and 4 if a session ever reaches 2^53 - 1 leaves.

**One reader per ring buffer.** A BPF ring buffer has one consumer position, so the collector is the consumer of the pin it opens. It takes the place of `gn_loader.py events` on the governed net pins, and the two must not run at once. (`gn_loader run` and the selector harnesses load their own unpinned objects with their own ring buffers, so they are not affected.) A decision the collector drains is no longer in the ring for any other reader. Each `decision` record carries the event's bytes (`frame`), so a consumer that wants the logger's input (`receipt_logger.py` reads the same 56 bytes as hex) can take it from the feed.

## The feed

A client connects, sends exactly one of

```
{"op":"subscribe","protocol":"prismpath.collector/2"}
{"count":N,"op":"subscribe","protocol":"prismpath.collector/2","session":"<32 hex>"}
```

and a newline, and from then on only reads. The second is a resume: a client that was connected to the
session `session` before, and last verified a seal of `count` leaves in it, asks for its join seal to be
proved from that count (below). Each must be the exact canonical canon/2 bytes, `count` an integer from 0
to 2^53 - 1 and `session` 32 lowercase hex characters; anything else is refused. A resume that names
another session is served as a plain subscription (a new session is a new tree).

The protocol is `prismpath.collector/2`. Version 1 had no consistency proofs and no resume; a `/1`
subscription is refused (`not-a-subscription`) and the console reads only `/2`. Every line it is sent is the canonical canon/2 bytes of one JSON object and a newline, at most 8,192 bytes. Hashes are lowercase hex. A value the kernel holds as a 64 bit unsigned integer (a request id, a time, a sequence number, a counter) is a decimal string, since canon/2 integers stop at 2^53 - 1. The collector's own counts are integers. Every record has `kind`.

| `kind` | when | members besides `kind` |
|---|---|---|
| `hello` | first, once | `protocol`, `source`, `ring`, `session` (16 random bytes, the tree's name), `max_record`, `queue`, `seal_interval_ms`, `seal_count`, `proof_window`, `leaf` (`"sha256(frame)"`) |
| `seal` | second (`trigger` `join`), then on the interval, on the count and at the end (`interval`, `count`, `final`) | `source`, `session`, `trigger`, `count`, `root` (absent for no leaves), `peaks` (tallest first), `malformed`, and `consistency` on every seal after the first this connection was sent and on a resumed join seal (below) |
| `decision` | a governed net event | `source`, `index`, `leaf`, `frame`, `request_id`, `t_ns`, `image_index`, `edge`, `cause`, `cause_name` and `cause_class` (when registered), `outcome` and `outcome_name`, `reason`, `reading` (the seven decided fields), `handle`, `src_ip`, `src_port` |
| `receipt` | a selector receipt | `source`, `index`, `leaf`, `frame`, `seq`, `t_ns`, `policy_hash`, `prev_node`, `event`, `next_node`, `migration`, `cause`, `cause_name` and `cause_class` (when registered), `facet` (the receipt stream profile frame, when the fields fit it) |
| `malformed` | a committed record that is not its source's struct | `source`, `index`, `leaf`, `length`, `reason` (`length` or `oversized`), `frame` (when 256 bytes or fewer) |
| `gap` | in place of records this client's queue had no room for | `source`, `dropped` (records of any kind, seals and statuses among them; the next leaf's `index` or seal's `count` says which leaves) |
| `status` | every seal interval, and last | `source`, `session`, `count`, `discarded` (records the producer gave back), `feed` (clients, accepted, refused, slow, extra_input, dropped), `enforcer` (governed net only: `loaded`, `start_node`, `image_index`, `n_rules`, `counters`) |
| `error` | the ring buffer is corrupt, before the final seal | `source`, `session`, `reason` |
| `refused` | instead of `hello`, then the connection ends | `reason`: `oversized`, `extra-input`, `not-canon2`, `not-a-subscription`, `timeout`, `peer-not-allowed`, `busy` |

Every record that stands for something drained (`decision`, `receipt`, `malformed`) is a leaf. `index` is its place in the session's tree and `leaf` is SHA-256 of the record's bytes, the leaf [`merkle.h`](../merkle.h) gives a receipt, so the tree over a selector session's receipts has the root `seal_receipts` computes over the same receipts as a journal. A `seal`'s `peaks` with its `count` are the accumulator's whole state, one hash per set bit of the count, so a client that joins mid session can check every later seal from the leaves it receives and the `join` seal alone (`prismpath_rs::merkle::Accumulator::from_peaks`, and the Python `root_statement.MerkleAccumulator` keeps its peaks in the same order).

**Consistency proofs.** A seal's `consistency` says that its tree holds an older one unchanged. The old size is exactly this: on every seal but a join, the `count` of the last seal this connection was sent (queued for it, so the last it receives before this one, whatever a `gap` dropped between); on a resumed join seal, the `count` the resume named. A plain join seal has none: it is the connection's first and there is nothing on it to prove from. The member is one of

| `consistency` | meaning |
|---|---|
| `{"from": m, "proof": [hex, ...]}` | the RFC 6962 consistency proof (section 2.1.2, PROOF(m, D[count])) from m leaves to this seal's `count`: verify it as RFC 9162 section 2.1.4.2 says, against the root the client holds for m leaves and this seal's `root` (`root_statement.verify_consistency`, `prismpath_rs::merkle::verify_consistency`). Empty when m is `count`, where the roots are equal, and when m is 0, since every tree extends the empty one (RFC 9162 defines no proof from 0). |
| `{"from": m, "missing": "window"}` | m leaves is further back than the collector keeps leaves for (`proof_window`, in `hello`): the collector cannot prove it and says so. |
| `{"from": m, "missing": "ahead"}` | a resume named more leaves than the session has: the client's count is not this session's. |

So a client that missed records keeps two verdicts apart. The records it missed, and those after the hole up to the next seal, are unchecked: it holds no leaves to rebuild the root over them. But the next seal is proven to extend the last tree it verified, so whatever it checked before the hole is still in the tree the collector seals now, and it carries on from that seal's peaks. Only when the proof is missing does it take the tree up on the collector's word, and it can say which span that is.

## Design

**Map and ring buffer access: bpf(2) itself, through `libc`.** The collector needs three bpf(2) commands (`BPF_OBJ_GET` to open a pin, `BPF_OBJ_GET_INFO_BY_FD` to check what map it is, `BPF_MAP_LOOKUP_ELEM` to read a counter) and one mmap of the ring buffer, which is what `gnet/gn_loader.py` already does through ctypes with only the standard library. libbpf-rs would link libbpf and build it from C, and aya brings an object loader, a BTF parser and a dependency tree, both to do far more than this, and the more a binary with `CAP_BPF` can do, the more it must be trusted not to. Writing the calls in [`src/bpf.rs`](src/bpf.rs) keeps the reach visible: one call site, the three commands as the only variants of the command enum, one writable mapping, and `tests/hostile.rs` holds the source to exactly that. The dependencies are the repository's own crates and four that the root `Cargo.lock` already resolves, pinned to the same releases by the collector's own `Cargo.lock`.

| crate | release | licence |
|---|---|---|
| `prismpath-rs` (canon/2, the cause registry, the RFC 6962 accumulator) | path | Apache-2.0 |
| `prismpath-telemetry-rs` (the receipt stream profile) | path | Apache-2.0 |
| `libc` | 0.2.189 | MIT OR Apache-2.0 |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 |
| `hex` | 0.4.3 | MIT OR Apache-2.0 |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0 |

Their own dependencies are MIT, MIT OR Apache-2.0, Unlicense OR MIT, BSD-3-Clause (`subtle`) and Unicode-3.0 (`unicode-ident`), all compatible with Apache-2.0 (`cargo metadata --locked` lists them).

**Read only.** The counter and configuration maps are opened with `BPF_F_RDONLY`, so the kernel refuses a write through the descriptor whatever the code does. The ring buffer is opened read and write for one reason. A BPF ring buffer's reader reports how far it has read by storing its consumer position in the one page the kernel maps writable to it, and that is how the producer learns the space is free. That position is the only thing the collector writes into the kernel. It changes no map the program reads its policy from and no program, and the kernel test checks the configuration map is byte for byte what the loader wrote.

**Privilege.** The collector refuses to start as root, and refuses to start holding any capability but `CAP_BPF` and `CAP_PERFMON`, naming the extra ones. It sets `no_new_privs` and clears the ambient set at once. After the pins are open it keeps `CAP_BPF` alone in its permitted and effective sets, because a host with unprivileged BPF disabled refuses every bpf(2) call without it and the counter reads are bpf(2) calls; for `selector` and `--recorded`, which read no counters, it keeps nothing. Nothing is inheritable. The systemd unit [`prismpath-collector.service`](prismpath-collector.service) runs it as its own account with `AmbientCapabilities=CAP_BPF CAP_PERFMON`, the same `CapabilityBoundingSet`, `NoNewPrivileges=yes`, `ProtectSystem=strict` and a system call filter, so there is no root shell anywhere in its life. `CAP_PERFMON` is accepted at start because the plan and the unit grant the pair, and dropped once the pins are open, since nothing the collector does with these maps needs it.

**The pins.** The bpf filesystem is mounted mode 0700 for root, so an account with `CAP_BPF` and nothing else cannot reach a pin. The one time setup below gives the collector's group search on the pin directories and read (and on the ring buffer write) on exactly the three pins, instead of giving the collector `CAP_DAC_OVERRIDE`, which would open every file on the host to it.

**The socket.** The feed socket is created under umask 0077 and then set to mode 0660 with the feed group (`--socket-group`), so the operating system admits only that group's members. Then the collector checks the peer's credentials as the kernel recorded them at connect (`SO_PEERCRED`) against the allow list, the collector's own uid plus `--allow-uid` and `--allow-gid`, so membership of the group alone is not enough. The loopback TCP listener (`--tcp`) has no peer credentials, which is why it is off by default and refused for any address but loopback. A remote enforcer's feed is reached the same way, by forwarding its Unix socket over SSH, never by binding a network address.

**Back pressure.** The drain loop never waits on a client. It offers each record to every client's bounded queue (`--queue` records), and a full queue drops the record for that client alone and counts it. The client is then sent a `gap` record with the count at the place in its stream where the records went missing, so it always knows what it missed and, from the indexes, which leaves. A client whose socket accepts nothing for the write timeout is disconnected. The seal covers every record drained whatever any client was sent, and the drops are evidence twice over, in the `gap` records and in `status.feed.dropped`. On the kernel side, the ring buffer is freed as fast as the drain loop reads it, which does not depend on any reader, so the program's `GN_DROP_NOLOG` (an allowed request dropped because its event could not be written) happens only if the collector itself stops, and then the enforcer's counters show it.

**Framing.** One canon/2 object per line, written by `prismpath_rs::canon2`, which refuses a float or an integer beyond 2^53 - 1, and no line over 8,192 bytes, which the largest possible seal (53 peaks) fits. The subscription is read with a five second deadline over the whole line, not per read, at most 256 bytes, and must be the exact canonical bytes. Anything else, including more bytes after its newline, is refused with a `refused` record. Anything a client sends after its subscription ends its connection (`status.feed.extra_input`).

**Sealing.** One tree per session, kept by `prismpath_rs::merkle::Accumulator`, the streaming form `formal/Core/Merkle.lean` proves equal to the tree. Proofs come from `prismpath_rs::merkle::ProofWindow`, which keeps the tree's state at a base (an accumulator, 2 KiB) and the leaf hashes since, at most `--proof-window` of them, the oldest folded into the base as new ones arrive: 32 bytes a leaf, 2 MiB at the default, whatever the session's length. That is enough because a proof from m to n leaves is made only of subtrees that lie wholly before m or wholly after it. Those after m are hashed from the window's leaves (O(n - m)). Those before m are peaks of the tree at m, and the collector keeps, per client, the tree's state at the last seal it was queued (2 KiB a client, 32 KiB at the client limit), so the common proof, from the previous seal, never touches the leaves before it; a resume rebuilds the state at its count from the base once. The window must hold at least `--seal-count` leaves, so a client that was sent the last seal is always proved from it, and the default holds 64 count seals' worth, so a client that lost up to 64 seals in a gap is still proved. Clients at the same place share one seal line. A seal is cut every second while leaves arrive, after every 1,024 leaves, when a client joins (for that client) and at the end. A second bounds how stale the newest root a reader holds can be, and 1,024 leaves bound how much a reader must hold between two roots when decisions arrive faster than that. The collector does not sign. A seal is a checkpoint a signer can take into a root statement, and keeping the instance key out of the one process that holds `CAP_BPF` keeps a compromise of either from being a compromise of both.

**Hostile ring buffer content.** The walk trusts nothing in a record header. A record of the wrong length for its source is a `malformed` leaf with its bytes; one longer than 4,096 bytes is hashed and named by its length and leaf alone. A BUSY record holds the walk until it is committed and a discarded one is counted. A header whose length runs past the producer position or the data area, or a producer position that is not within one data area of the consumer, is corruption: the collector publishes an `error` record and a final seal and exits 3 rather than guess where the next record starts.

## Deploying

Once, as root, on the enforcement host (`kernel_test.sh` runs exactly this):

```sh
groupadd --system prismpath-collector      # the collector's own group, which may open the pins
groupadd --system prismpath-feed           # who may connect to the feed socket
useradd --system --gid prismpath-collector --no-create-home --shell /usr/sbin/nologin prismpath-collector
# after the enforcer is attached and its maps pinned (governed net: SETUP.md A.1)
PINS=/sys/fs/bpf/tc/globals
for dir in /sys/fs/bpf /sys/fs/bpf/tc $PINS; do chgrp prismpath-collector $dir; chmod g+x $dir; done
chgrp prismpath-collector $PINS/gn_events $PINS/gn_config_map $PINS/gn_counts_map
chmod 0660 $PINS/gn_events
chmod 0640 $PINS/gn_config_map $PINS/gn_counts_map
install -m 0755 target/release/prismpath-collector /usr/local/bin/
install -m 0644 prismpath-collector.service /etc/systemd/system/
echo 'COLLECTOR_ARGS=--source gnet --maps-dir /sys/fs/bpf/tc/globals --socket-group prismpath-feed --allow-uid 1000' \
    > /etc/default/prismpath-collector
usermod -aG prismpath-feed <the console account>
systemctl daemon-reload && systemctl enable --now prismpath-collector
```

The pin permissions last as long as the pins, so a detach and a fresh attach (which `gn_loader.py detach` makes by removing the pins) needs the `chgrp` and `chmod` lines again before the collector is restarted. The feed is at `/run/prismpath-collector/feed.sock`.

## Tests

Locally, with no kernel and no privilege, `cargo test --manifest-path prismpath-ebpf/collector/Cargo.toml` runs the collector against recorded ring buffer frames.

- `tests/recorded.rs`. The nine receipts the selector committed in the kernel during the decision delta session (`../decision-delta-demo/evidence/receipt_trail.log`), rebuilt byte for byte (the test recomputes the root that session logged under the retired tree), go through a ring buffer image and the feed, and the final seal is the RFC 6962 root `d875a10a...`, which the batch tree and `seal_receipts.c` built from this repository give too. A C program built from `gn_common.h` and `ppt_common.h` reads frames the Rust side wrote, member by member. The binary serves a recording file (`--recorded`), a late client's join seal covers what was drained before it, and a TERM ends with a final seal and the socket removed.
- `tests/consistency.rs`. Every seal after a connection's first verifies from the seal before it; a client that never reads until 20,000 records have gone by is sent a gap and then a seal proved from the last seal it holds; a resume is proved from the count it names, a count past the session is `missing: "ahead"`, one before the window `missing: "window"`, another session's a fresh join; only the two subscriptions in canonical form are accepted; and the longest seal with the longest proof (2^53 - 1 leaves, 53 peaks, a proof of up to 54 hashes) fits a record. `prismpath-rs/tests/test_merkle_consistency.rs` holds `ProofWindow` to the Python reference's corpus (`prismpath/portable/conformance/merkle_consistency.json`) and the transparency-dev reference probes.
- `tests/console_fixtures.rs`. The console's recorded feeds (`prismpath/tests/fixtures/collector_feed/`) are what this drain loop and feed send one client, byte for byte, regenerated with `PRISMPATH_WRITE_FEED_FIXTURES=1`.
- `tests/hostile.rs`. Frames of the wrong length, an oversized frame, BUSY and discarded records, records that wrap the data area, four kinds of lying header and a corrupt ring that ends the run. Records that are not canon/2 or too long, and the largest seal. A reader that subscribes and never reads (20,000 records, the drain never waits, another client gets every record and checks the final root, the stalled one gets gaps that account for what it missed), and one cut off by the write timeout. Ten wrong subscriptions (oversized, extra bytes, not canonical, not the subscription, a slow drip, nothing), a client that sends after subscribing, a peer off the allow list, the client limit, the socket mode, a file in the socket's place, loopback only TCP. The capability check, the source's reach into the kernel, and the systemd unit's grants.

In CI, the `ebpf_kernel` job runs [`kernel_test.sh`](kernel_test.sh) on a throwaway runner. It attaches the governed net program to `lo` in generic XDP mode through iproute2, fills it with the network policy for 127.0.0.1, does the one time setup above, starts the collector under the shipped unit, and checks that the running collector holds `CAP_BPF` alone with nothing inheritable or ambient and `no_new_privs`, that the binary refuses to run as root, that [`kernel_check.py`](kernel_check.py) (the invoking account, in the feed group only, with no capability) receives a decision for every request it sends over loopback with the outcome and cause the plain rules (`integrations/governed_net/owner_rules.py`) give, every leaf its frame's hash and every seal the tree it rebuilds from the join seal and the consistency proof from the seal before it, a resumed connection's join seal proved from the last seal it verified, that the enforcer's counters as the collector reads them match what was sent, and that the configuration map is as the loader left it. The selector is checked from its recorded kernel frames only.

## What the console consumes (WP4, WP6)

- **Transport.** Connect to the Unix socket (`/run/prismpath-collector/feed.sock` under the unit), or a loopback port given with `--tcp`, send the subscription line, read lines. The console's account must be in the feed group and on the allow list. Treat the end of the stream as the collector gone and reconnect with backoff, resuming the session from the count of the last seal it verified. A new `session` in `hello` is a new tree.
- **Reading.** Read each line with the strict canon/2 reader (`prismpath.kernel.canon2`) and refuse a line over `max_record`. Dispatch on `kind` and ignore a kind it does not know, so the feed can add one without breaking the console.
- **Operating (WP6).** `decision` and `receipt` records are the live view: `outcome_name`, `cause_name`, `reading`, `src_ip`. `status.enforcer.counters` is the per verdict tally and `loaded` whether a policy is in. `status.feed` and `gap` records say what the console itself missed. The cause series of WP3 can be bucketed from `cause` and `t_ns` (monotonic since boot, not wall time; bucket by arrival time or by `t_ns` differences).
- **Auditing (WP4).** Keep the records as evidence. Start an accumulator from the `join` seal's `count` and `peaks`, add each leaf (`MerkleAccumulator.add(leaf)` in Python, which hashes it as SHA-256(0x00 || leaf)), check `index` is the accumulator's count, check `leaf` is SHA-256 of `frame`, and check every later `seal`'s root and its `consistency` proof from the last seal the connection was sent. Show a `gap` as a hole the console's own copy has and the collector's seal does not: the records up to the next seal are unchecked, and that seal is proven, or (with `missing`, or no proof to check against) not proven, to extend the tree before the hole. A seal is the collector's statement, unsigned; a signed root statement over it is the operator's step, and the console says whose verdict each check is.
