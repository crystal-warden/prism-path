# PrismPath in NASA cFS

A cFS application that decides every proposed command with PrismPath's C kernel before it reaches the vehicle. It is
work package S1 of [the flight software plan](../../docs/design/cfs-app-plan.md): the app skeleton, running in a
native Linux cFS build.

```
autonomy app --PROPOSED_CMD--> prismpath_app --VEHICLE_CMD--> vehicle apps        (allowed only)
                                    |
                                    +--> cFE events: ALLOW, REFUSE (registered cause), ESCALATE (registered cause)
                                    +--> housekeeping telemetry: the counters
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

The kernel's checks on an image (`PP_Kernel_Check`, each failure answered with its registered cause): the header and
length, the capacity caps, every atom's operator, type and field index, every node's and edge's range, every program
as a stack machine (operands present, one result left), that the image's one node has exactly the table's rules and
each rule leads to its own terminal node, that the image reads exactly the fields of the layout (a hash of the layout,
so an image written for another reading is refused), and that every rule's action and cause are consistent.

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

The console shows `PRISMPATH_APP POLICY LOADED` and `initialized, policy active`. To send proposals and watch the
decisions, use the test driver, which boots the staged build itself:

```
python integrations/cfs/tests/run_scenario.py        # --build-dir <cFS>/build-native_std/exe/cpu1 if it is elsewhere
```

It plays thirteen proposals into `ci_lab` over UDP (allowed, refused by a rule, escalated, refused at the boundary, a
payload too short), subscribes the stock `to_lab` to `VEHICLE_CMD` and the app's housekeeping, and checks that every
event matches the Python reference decision (`prismpath.agent.policy`) for that reading, that exactly the allowed
proposals reach `VEHICLE_CMD` with their payload, and that the counters add up. It then boots again on a table whose
image has one byte corrupted and checks that the image is rejected and nothing is allowed.

Tests (`python -m pytest integrations/cfs -q`) need no cFS build except the last: the rules compile to the committed
image, the generated include is current, the layout header matches the policy's field definitions and the C command
struct, and the kernel (compiled alone, with undefined behaviour checking) agrees with the Python reference on 1,764
readings and refuses every corruption of its image. The end to end test skips, saying why, when no cFS build with the
app is staged (set `CFS_EXE_DIR` to the staged `cpu1` directory if it is not under `.cfs-build`).

## What S1 does not do yet

- No receipts and no root statements: the decision is not yet appended to a Merkle accumulator (S2).
- No Critical Data Store: the accepted image version and the tree state do not survive a processor reset, so a reset
  can reopen an older image. The image is not signed or version checked on load; a ground load is trusted as far as the
  structural checks go. A corrupted but well formed image (a different threshold) is accepted (S2).
- An escalation is an event and a counter. It is not held, there is no request to the ground and no ground command that
  names a receipt to run it (S2).
- No NOS3 scenario and no fault injection through a simulator bridge (S3).
- No EDS flavor, no F Prime component (S4), no decision downlink in the Facet encoding.
- The cFE performance marker is there, but the signed cycle bound has not been compared with a measured time on a target.
