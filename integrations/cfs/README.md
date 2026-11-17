# PrismPath in NASA cFS

A cFS application that decides every proposed command with PrismPath's C kernel before it reaches the vehicle, and
keeps a receipt of every decision that the ground can verify after downlink. It is work packages S1 (the app) and S2
(receipts and survival across a processor reset) of [the flight software plan](../../docs/design/cfs-app-plan.md),
running in a native Linux cFS build.

```
autonomy app --PROPOSED_CMD--> prismpath_app --VEHICLE_CMD--> vehicle apps        (allowed only, after the receipt)
                                    |
                                    +--> cFE events: ALLOW, REFUSE (registered cause), ESCALATE (registered cause)
                                    +--> housekeeping telemetry: the counters, the receipt count, the root
                                    +--> /cf/pprun: a signed core run (receipts, root statements) for downlink
                                    +--> Critical Data Store: the receipts' Merkle peaks and the version floor
```

What it does:

- Loads a policy image from the cFE table `PRISMPATH_APP.PolicyTable` at startup. The table's validation callback runs
  the kernel's own checks (below), and the app runs the same checks again when it takes the image from the table, so an
  image that fails never decides. With no active image every proposal is refused (cause 32) and nothing is allowed.
- Subscribes to one message id, `PROPOSED_CMD`, and no other app needs to. Each proposal's payload is read into the
  policy's fields as [`fsw/inc/prismpath_app_layout.h`](prismpath_app/fsw/inc/prismpath_app_layout.h) defines them. A
  field outside its definition's bounds, or a payload too short, is the core's own refusal (`route:contract-violation`),
  made before any rule is read.
- Decides the reading with the embedded evaluator `prismpath-hw/ppt_eval.h`, the one copy every firmware includes. It is
  included from this checkout and never copied.
- Republishes an allowed command on `VEHICLE_CMD` with a fresh checksum, and sends an event for each decision: `ALLOW`,
  `REFUSE` or `ESCALATE`, with the registered cause code of a refusal or escalation (the codes in
  `prismpath/kernel/causes.py`, named by each rule's target in the policy). A refused or escalated command is never
  republished.
- Keeps counters in housekeeping telemetry (proposed, allowed, refused, escalated, forwarded, forward errors, policies
  loaded and rejected, the last cause, the layout hash). A `SEND_HK` request also sends them as an event.
- Allocates nothing after initialization: the kernel, the republished command and the housekeeping packet are static.
  The decision is wrapped in its own cFE performance marker (`PRISMPATH_APP_DECIDE_PERF_ID`).

The kernel's structural checks on an image (`PP_Kernel_Check`, each failure answered with its registered cause): the header and
length, the capacity caps, every atom's operator, type and field index, every node's and edge's range, every program
as a stack machine (operands present, one result left), that the image's one node has exactly the table's rules and
each rule leads to its own terminal node, that the image reads exactly the fields of the layout (a hash of the layout,
so an image written for another reading is refused), and that every rule's action and cause are consistent.

## Receipts, root statements and the downlink (S2)

Every decision under an active image is a receipt, written before an allowed command is republished: a decision
that cannot be receipted is not acted on (an allow is withheld and counted as a record error). The receipt is the
exact `prismpath.core-receipt/1` line the repository's verifier
([`prismpath/ledgers/core_evidence.py`](../../prismpath/ledgers/core_evidence.py)) holds a receipt to, with nothing
reconstructed on the ground:

- `image_sha256` is the SHA-256 of the signed core image (`prismpath.core/1`, canon/2 bytes), which the table now
  carries beside the PPT image it was compiled from;
- `reading_sha256` is the SHA-256 of the reading's canon/2 bytes, which the app writes from the payload the way the
  reference reads it: every field the payload holds, in register order, a bool as `false` or `true` when its byte is
  0 or 1 and as its number otherwise;
- the decision is a `route` to the rule's target (`allow`, `refuse_<code>`, `escalate_<code>`, as the core image
  names it) or the core's own `refuse` with its cause, field and reason (`missing`, `wrong_type`, `out_of_range`),
  exactly as the reference refuses the same reading. The boundary is now field by field like the reference's: a
  payload that ends before a field refuses as that field missing, and six bytes that hold every field are decided.
- one case per image version, with the id `v<version>`; `decider` is `cfs:prismpath_app`.

The SHA-256 of each line is a leaf of the RFC 6962 Merkle tree, kept as the streaming accumulator
`struct ppt_merkle_acc` from [`prismpath-ebpf/merkle.h`](../../prismpath-ebpf/merkle.h) (its root is the tree's,
`acc_root_eq_mth` in `formal/Core/Merkle.lean`), included from this checkout. The app writes the run under
`/cf/pprun` in the core run layout: `receipts.jsonl`, `images.jsonl` (the authority's image attestation, carried in
the table), and the cases file as it grows. A `SEAL` ground command (function code 2) closes the cases file into
`cases.jsonl`, writes the manifest `run.json`, signs one `prismpath.core-run-root/2` statement over every receipt
**onboard** with the instance key, and appends it to `roots.log.jsonl`, the history of every root sealed. The
signing is Ed25519 by Monocypher 4.0.2, already vendored in this repository for the ESP32 mesh
(`prismpath-hw/mesh/main`, BSD-2-Clause or CC0) and compiled from there; no new crypto code was added. The SHA-256
is merkle.h's default seam, OpenSSL's, so the app links libcrypto; a flight target without OpenSSL supplies its own
SHA-256 through `PPT_MERKLE_SHA256_EXTERNAL`.

One file name differs on board: OSAL limits a file name to 19 characters and the core run's `receipts.roots.jsonl`
is 20, so the app writes the root statement as `roots.jsonl` and the ground's copy renames it. Housekeeping carries
the receipt count, the version floor, the seal count and the first 16 bytes of the root (the full root is in the
`SEALED` event and the files).

What is not receipted: a proposal decided while no image is active. It is refused (cause 32) and counted as
`Unreceipted`, because a core receipt binds an image and there is none.

### Survival across a processor reset

The Critical Data Store block `PPRunState` holds the run state (`PP_RunState_t` in
[`prismpath_app_run.h`](prismpath_app/fsw/inc/prismpath_app_run.h)): the accumulator's peaks and count, the highest
image version accepted and that table's digest, the open case, and the length of every appended run file. It is
saved after every receipt and every activation. After a processor reset the app restores it, cuts back any run file
longer than its recorded length (a reset between the file write and the store update), and continues: the next
receipt is numbered after the last, the root grows from the same peaks, and the cases file's open case continues.
A power on reset clears the CDS, so it begins a new run (and, until a mission keeps the floor in non volatile
storage too, a new floor); downlink a run before a power cycle.

### The image's version and the two signatures

The PPT v1 image format has no version, so the version is a field of the table (`Version` in `PP_PolicyTable_t`),
which is the smallest change that gives the floor something to hold. A version alone is not enough: anyone who can
load a table could raise it. So the table also carries two authority signatures, both made on the ground with the
authority key by [`ground/table.py`](ground/table.py) over the built table file:

- `ImageSig`, the core run's own image attestation: Ed25519 over `prismpath.core-image/1\0` and the core image;
- `TableSig`: Ed25519 over `prismpath.cfs-table/1\0` and the SHA-256 of every table byte before the signatures,
  which binds the version, the compiled PPT image, the rules and the core image to each other. This is a format
  local to this app; the core run format has no place for the compiled image.

A table is refused, in its validation callback and again at activation, with a registered cause: the kernel's
structural checks first, then `sig:missing` (1) with no authority key, `sig:invalid` (2) when either signature does
not verify (a changed threshold is caught here now), and `image:version-replay` (9) when its version is below the
floor, or equal to it with other bytes. The committed table source carries zero signatures, so a build boots with no
policy (every proposal refused) until it is provisioned.

### Keys

`python -m integrations.cfs.ground.provision --exe-dir <cpu1> --keys <dir>` makes the two test keys with the
repository's generators when absent (the authority key and the instance key, as `core_evidence.ensure_keys` does),
writes the authority's public key to `cf/pp_authority.pub` and the instance key's raw seed to `cf/pp_instance.key`,
and signs `cf/pp_app_policy.tbl`. These are test keys in the flight file system; a mission builds the authority key
into its boot image and provisions the instance key per vehicle in protected storage.

### Verify a downlinked run on the ground

```
python -m integrations.cfs.ground.downlink <copy of /cf/pprun> <ground run dir> --keys <dir>
prismpath evidence verify <ground run dir> --sample all --pin-authority <dir>/authority.pub --pin-instance <dir>/instance.pub
```

The first copies the run (renaming the root statement's file), runs the repository's verifier with both keys pinned
and every receipt replayed through the reference kernel, and checks the root history: every sealed statement is
signed by the pinned instance key and its root is the root of the first receipts of the run, so a root sealed before
a reset is a prefix of the run after it. The second is the same verifier from the command line.

## The example policy

[`prismpath_app/policy/example.rules.md`](prismpath_app/policy/example.rules.md) is a readable rules source for a
command guard: three command classes (attitude, thruster, payload), limits on slew and thrust, and a rule that
escalates a large burn or slew when there is no ground contact. It is compiled with the PrismPath CLI and converted to
the kernel's bytes:

```
prismpath policy compile integrations/cfs/prismpath_app/policy/example.rules.md \
    -o integrations/cfs/prismpath_app/policy/example.core.json      # the signed core image, canon/2 bytes
python -m integrations.cfs.prismpath_app.policy.gen_image            # the PPT v1 table, as the cFE table's include
```

The include also carries the table's `Version` (`gen_image.VERSION`, 2 for the example), the core image's canon/2
bytes and its canonical flow rendering spelled as a canon/2 string, which the cases file holds.

`gen_image.py` checks the core image with the port of the Lean oracle's `loadPolicy`, compiles it to a PPT v1 table
the way `integrations/governed_net/policy.py` does for the XDP program (one node, one edge per rule, in order), and
writes `fsw/tables/prismpath_app_policy_image.inc`. The table (`fsw/tables/prismpath_app_policy_tbl.c`) is built into
`cf/pp_app_policy.tbl` by cFS's own table tool.

## Build it into a cFS checkout

This is written against the cFS bundle at `nasa/cFS` main (2026-11-12, cFE 7.0.2-rc1) on aarch64 Linux. Needs Make,
CMake and GCC.

```
git clone --recurse-submodules https://github.com/nasa/cFS.git
integrations/cfs/stage.sh ./cFS            # link the app into apps/, list it in targets.cmake and the startup script
export PRISMPATH_HW_DIR=$PWD/prismpath-hw  # where ppt_eval.h lives; the build stops with a message when it is missing
cd cFS
make native_std.prep                       # the cFS README's build for the host (SIMULATION=native)
make native_std.install                    # compile and stage into build-native_std/exe/cpu1
```

`stage.sh` makes three edits, which you can also make by hand: symlink or copy `integrations/cfs/prismpath_app` to
`cFS/apps/prismpath_app` (a symlink is followed back to this checkout, so `PRISMPATH_HW_DIR` can be left unset), add
`prismpath_app` to `MISSION_GLOBAL_APPLIST` in `sample_defs/targets.cmake`, and add
`CFE_APP, prismpath_app, PRISMPATH_APP_Main, PRISMPATH_APP, 51, 32768, 0x0, 0;` after the `sample_app` line in
`sample_defs/generate_startup.cmake`, which writes `cfe_es_startup.scr`.

Use `native_std.prep` and not a bare `make prep`: the bundle's other configuration, `native_eds`, needs Lua
development packages and builds the EDS flavor, which this app does not support yet (its configuration headers are the
plain ones). The app compiles with the bundle's own flags, including `-Werror`.

Message ids: topic ids 0xE0 (ground commands), 0xE1 (send housekeeping, and the housekeeping telemetry), 0xE2
(`PROPOSED_CMD`) and 0xE3 (`VEHICLE_CMD`), clear of every topic the bundle's apps use. A mission overrides them with its
own `prismpath_app_topicid_values.h`, as cFS apps allow. Fields are little endian.

## Run it

```
cd build-native_std/exe/cpu1 && ./core-cpu1
```

Provision it first (above), or the app refuses the unsigned table. The console then shows `PRISMPATH_APP POLICY
LOADED v2` and `initialized, policy active`. To send proposals and watch the decisions, use the test driver, which
provisions and boots the staged build itself:

```
python integrations/cfs/tests/run_scenario.py        # --build-dir <cFS>/build-native_std/exe/cpu1 if it is elsewhere
```

It provisions the build with fresh test keys and plays the thirteen S1 proposals into `ci_lab` over UDP (allowed,
refused by a rule, escalated, refused at the boundary, a payload too short), subscribes the stock `to_lab` to
`VEHICLE_CMD` and the app's housekeeping, and checks every event (with its receipt number) against the Python
reference decision (`prismpath.agent.policy`) for that reading, that exactly the allowed proposals reach
`VEHICLE_CMD` with their payload, and the counters, receipt count and root. It seals, sends the cFE ES restart
command for a processor reset, boots again (a processor reset from the PSP's boot record) and checks the run was
restored from the CDS. It sends four more proposals, then loads through cFE Table Services the same policy signed
as version 1 (refused, cause 9) and the version 2 table with one threshold changed and not signed again (refused,
cause 2), and two more proposals still decided by version 2. It seals again, copies `/cf/pprun` off, and verifies it
with `prismpath evidence verify --sample all` and both keys pinned (19 receipts, all replayed, all agree) and the
root history (13 then 19 leaves). It then boots on a table whose image has one byte corrupted and checks that the
image is rejected and nothing is allowed. The build's own table file is put back and the key files removed after.

Tests (`python -m pytest integrations/cfs -q`) need no cFS build except the last: the rules compile to the committed
image, the generated include is current, the layout header matches the policy's field definitions and the C command
struct, and the kernel (compiled alone, with undefined behaviour checking) agrees with the Python reference on 1,764
readings and refuses every corruption of its image. `tests/test_cfs_run.py` compiles the receipt module with the
kernel and Monocypher, drives it through stdio (`tests/run_check.c`), and checks that the table's C layout and
initializer are the bytes the ground signs, that every receipt line is the reference's byte for byte and the root
is the Python root over the same leaves, that the run passes `prismpath evidence verify` with both keys pinned, that
a simulated processor reset (state copied out as the CDS holds it, memory scribbled, torn writes on the files)
writes the same bytes as a run without one, and that an older, a tampered, a foreign and an unsigned table are
refused with their causes. Those need OpenSSL's headers and the `cryptography` package, and skip without them. The
end to end test skips, saying why, when no cFS build with the app is staged (set `CFS_EXE_DIR` to the staged `cpu1`
directory if it is not under `.cfs-build`).

## What it does not do yet

- An escalation is an event, a counter and a receipt. It is not held, there is no request to the ground and no
  ground command that names a receipt to run it.
- The PPT image is not compiled onboard from the core image, so the table signature is what ties the two; a
  compiler fault on the ground would show as a disagreement when the ground replays the receipts.
- A power on reset clears the CDS, and with it the floor and the run; the floor is not yet also kept in non volatile
  storage.
- The run is a set of files under `/cf/pprun`, not yet a CFDP transaction or a Facet encoded decision stream, and the
  cases file carries every reading in full.
- No NOS3 scenario and no fault injection through a simulator bridge (S3).
- No EDS flavor, no F Prime component (S4).
- The cFE performance marker is there, but the signed cycle bound has not been compared with a measured time on a target.
