# The operator's day

The operator runs a governed system day to day: watches what it decides, judges whether the policy
needs to change, makes short lived changes when it does, and feeds what they learn back to the
process owner who maintains the policy of record. This guide is the operator's map. The other three
people are described in [`SYSTEM_MAP.md`](../SYSTEM_MAP.md) section 2.

## 1. Your console is Mission Control

`prismpath/mission_control/` is the operator's console and API
([`mission-control-api.md`](mission-control-api.md)): observe the followed run (`/api/v1/status`,
`/interactions`, `/flow`, `/flow/graph`), prove things about a flow without running it
(`/prove/level-m`, `/prove/reach`), verify the console's own audit log (`/prove/audit`), and the one
write surface, editing a flow file through the API with every path checked. The CLI is the scripted
path to the same operations; `prismpath --help` lists your commands under "Operator".

## 2. Swap and attest

A policy reaches an enforcement point as a signed pack. Two of the `swap` actions are yours:

```bash
prismpath swap swap   --out <state dir> --pub <authority.pub> --envelope <envelope.json> --ppt <new.ppt>
prismpath swap attest --out <state dir> --pub <authority.pub> --envelope <envelope.json>
```

`swap` verifies the signature against the authority keys and the revocation list, checks the image
fits the envelope the engineer declared (fields, capabilities, size caps), refuses a version below the
persisted floor, stages the image, and flips atomically. Every attempt, accepted or refused, is one
audit event with a named reason (`sig:missing`, `image:sha256-mismatch`, `version:not-monotonic`, and
the rest of the cause registry). `attest` prints what the host is running, signed, so a reader can
check that the policy in force is the one they think it is. The engineer's three actions, `keygen`,
`envelope`, and `pack`, set up the structure you swap within; you do not need them day to day.

On stateful substrates a swap also carries a migration: the pack declares `by-name` (keep the
resident posture if the node still exists) or `reset-to` (park on the fail safe), and the loader
writes a migration receipt with cause 0 or 66 into the same signed trail as every decision receipt
(ledger rows #131 to #135).

## 3. A short lived change that expires by construction

You will want changes that hold for an incident and then go away. Do not model that as pack metadata.
Write it as policy semantics in the flow, so the same signed, decidable, receipted machinery carries
it and nothing on any substrate has to learn a new field:

```markdown
## heightened
-> gate: on event stand_down
-> gate: on timeout
```

The worked example is [`examples/operator_overlay/overlay.md`](../../prismpath/examples/operator_overlay/overlay.md):
a baseline posture (`gate`) that holds requests at `heightened` while `incident_active` is set and
severity is at or above two; the hold ends on your `stand_down` event or when the worker's
`timeout_s` elapses, and either way the run returns to the baseline node. The fixtures beside it
assert the deterministic routing, and `prismpath/tests/test_operator_overlay.py` exercises the real
suspension and both resumes. A `visits` cap on the baseline node keeps the hold and release loop
bounded, which the validator would otherwise flag.

How the timer fires: the engine is pure and never fires timers itself. A run holding at `heightened`
is checkpointed as `waiting` with its `timeout_s`; the reference scanner in `prismpath/scheduler.py`
(`fire_due_timeouts`) runs on a tick, a cron entry or a systemd timer, and delivers `__timeout__` to
every due checkpoint, taking the `on timeout` edge. Your stand down is
`checkpoint.resume(ckpt, agent, event="stand_down")`, or the same through Mission Control.

Where this pattern does and does not reach:

- It holds wherever the engine runs, the Python, JS, Rust, and Go kernels, because event edges and
  the timer are engine features.
- Compiled table images skip event edges by design (`prismpath-hw/TABLE_FORMAT.md`, the declared
  subset), so a kernel, MCU, or fabric target does not see `on timeout`. `prismpath capability`
  reports the overlay flow as Level M for exactly that reason. On those substrates the short lived
  change is a swap in and a swap out, both attested in the trail, and the time bound that protects
  resident state is the refresh profile's staleness bound (row #125): a consumer past it parks on the
  fail safe with cause 64. If you need a timed reversion on a device, the host performs the second
  swap when the timer fires; the scheduler can drive it.

Marking the overlay so the owner can see it: pack it with `--overlay-of <policy of record>`. The name
rides the signed manifest, the host carries it into its active record, and `attest` prints it as
`overlay_of`, so anyone reading the attestation or the trail sees that a short lived change is in
force and which baseline it overrides. It changes nothing about verification or the version floor;
the owner's next version still wins when it lands.

```bash
prismpath swap pack --ppt overlay.ppt --fields ... --version 2 --overlay-of network_admission --priv authority.priv --pub authority.pub
```

## 4. Reading the trail

Every decision leaves a receipt with its cause code, Merkle rooted per session and anchored. The
operator's read side is `trail`:

```bash
prismpath trail run.audit.jsonl                  # everything: decisions by outcome, rule, cause; swaps; attestations
prismpath trail run.audit.jsonl --last 200       # the most recent 200 events
prismpath trail run.audit.jsonl --since 2026-09-09T00:00:00Z --json
```

It reads the append only log `prismpath.audit_log` writes, checks that the Merkle root still verifies,
and summarises the window in cause code terms: how many decisions, which outcomes and rules, which
causes (0 clean, 34 the worker asked for a human, 36 nothing matched, 64 state went stale, 66 a swap
reset the resident state, and the rest of the registry), and every swap, refusal, rollback, and
attestation with its overlay line. A cause that starts climbing is the signal to look at the policy;
a root that no longer matches an anchored one is the signal that the log was edited. The console's
`/interactions` and `/prove/audit`, the kernel and fabric receipt journals sealed by
`prismpath-ebpf/seal_receipts.c`, and the evaluator's `ledger verify` sit beside it.

## 5. Feeding back to the owner

An overlay that keeps coming back is a policy change waiting to be made. Hand the owner the fixture
rows that would have caught it (`prismpath test` reads the same table you would write) and the
receipts that show the pattern. The owner's change then goes through `validate` and `test`, the
engineer's `contract` says whether the interface moved, and your next swap carries it.
