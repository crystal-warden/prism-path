# A runtime monitor beside the PrismPath app

Work package S5 of [the flight software plan](../../../docs/design/cfs-app-plan.md). NASA's runtime monitors check
temporal properties of telemetry. PrismPath decides each proposed command and receipts it. This scenario shows the
two compose: a monitor's verdict is a field the policy routes on, and a violation forces an escalation.

```
 payload housekeeping --> pp_monitor (R2U2, one step a second) --MONITOR_VERDICT, once a second--> prismpath_app
                                                                                                        |
 pp_autonomy --PROPOSED_CMD--> prismpath_app: reading = the proposal + monitor_ok --> allow | refuse | escalate
                               (monitor_ok is the app's, from the latest verdict and its age; receipted)
```

The monitor only watches. It never sees a command and never decides one. PrismPath reads the verdict as one more field
of the reading, so the decision, the reason for it and the verdict it relied on are all in one receipt that the ground
verifies.

## The monitor

[R2U2](https://github.com/R2U2/r2u2) (NASA, C version 4.2.4) is used as a tool and a build input. It is licensed
Apache-2.0 or MIT, at the user's choice (the repository's `LICENSE-APACHE` and `LICENSE-MIT`). Nothing of it is copied
into this repository: the script clones it into the gitignored `.cfs-build/r2u2` at the commit it was run against
(`2875a1d`), compiles the property with R2U2's own compiler (C2PO), and the monitor app compiles R2U2's library sources
from that checkout inside NOS3's build.

The property, [`spec/payload_quiet.c2po`](spec/payload_quiet.c2po), over one input, the payload instrument's device
status word:

```
PTSPEC
  payload_quiet: H[0,5] (!fault);        -- fault := status != 0
```

It holds while no fault status has been seen in the last five seconds (a past time formula, so R2U2 reports on the step
the fault arrives). The tests hold R2U2's verdicts on several traces to a Python model of this sentence.

Ogma and Copilot were not tried: R2U2 built and ran on this aarch64 host, so there was no reason to bring in a Haskell
toolchain.

## Run it

```
python integrations/cfs/monitor/run_monitor_scenario.py        # --nos3 .cfs-build/nos3-monitor, --r2u2 .cfs-build/r2u2
```

It needs what [the S3 scenario](../nos3/README.md) needs (a NOS3 checkout with its submodules at
`.cfs-build/nos3-monitor`, Docker, Make, Python 3 and this repository's environment), plus `git` and network access once,
to clone R2U2. It stages four apps into that NOS3 checkout (`prismpath_app`, `pp_vehicle`, `pp_autonomy` with a plan
of its own, and `pp_monitor`), builds with `PP_MONITOR_STALE_SECS=3` in the environment (which is what turns the monitor
field on in the PrismPath app), and runs the same nine capped containers as S3, headless. The generated files (the
plan include and the compiled property) are written under `.cfs-build/monitor-apps`, never committed. It uses a
checkout of its own so that it does not disturb a staged S3 build. `--skip-build` uses the staged build as it is.

## What it shows

The ground drives one run, and every step is checked from the logs:

1. The autonomy app proposes steady, nominal commands, one a second (a slew of 25 or 30 degrees in ground contact, which
   the rules alone would allow). The monitor holds, `monitor_ok` is true, they are allowed. The one 120 degree slew in
   the plan is refused by its own rule, as it is in S3.
2. The ground tells the monitor to go quiet (`HALT`, standing in for it hanging). No fault, no violation, only silence.
   The last verdict ages past the three second bound, the app reads `monitor_ok` as false, and the next proposals are
   escalated (`route:needs-human`, 34) though nothing is wrong with them.
3. The ground restarts the monitor and the proposals are allowed again.
4. The ground injects a payload fault through NOS3's command bus bridge (`STATUS=3`). The monitor's property is
   violated and it says so. From the next proposal on, everything not already refused is escalated with `monitor_ok`
   false, including the autonomy app's fault playbook.
5. The run is sealed, downlinked and verified on the ground with both keys pinned, every receipt replayed through the
   reference kernel.

A run on this repository's development host (aarch64, NVIDIA GB10) passed all 17 checks in 66 s:

- Each of the 46 decisions is the policy's for the reading the app made, `monitor_ok` included, and is the Python
  reference's, with its receipt number.
- The monitor's verdict and the app's reading move together: before the silence 6 proposals read true; during it 2
  steady proposals read false and were escalated while nothing else was wrong; after the restart 3 were allowed again;
  after the violation 31 in a row were escalated with `monitor_ok` false.
- The reaction wheel simulator saw exactly the torques of the 10 allowed attitude commands, in order, and the payload
  simulator the one allowed payload command, so nothing escalated or refused reached a simulator.
- The downlinked run verifies (`prismpath evidence verify --sample all`, both keys pinned, 46 receipts, 46 agree). The
  receipt of each escalation names the field: the reading it was decided on, held in the run's cases file, has
  `monitor_ok` false, and every allowed command's has it true. Because the verifier replays each reading through the
  reference kernel, the escalation is shown to follow from that field and nothing else.
- Docker is left as it was.

The policy change is one rule in [`example.rules.md`](../prismpath_app/policy/example.rules.md), after the refusals and
before the other escalations, with a new `monitor_ok: bool` field: `-> escalate route:needs-human: when not
monitor_ok`. The cause is the registered 34, so no new cause. A refusal still wins over it: a command the policy would
refuse is refused whatever the monitor says. The image was recompiled with the repository's own compiler and its
version is now 3. The C layout has the field as a `MONITOR` row that the app fills, not the proposer, and a drift test
holds it to the policy's definition and to the command struct.

## What it does not show

- The monitor is not a flight qualified one wired to real telemetry. It watches one status word from a simulated
  instrument, and its property is simple. It shows the composition, not a monitor design.
- The verdict lags the telemetry it watches by a step. In this run the playbook's first command was proposed on the same
  second the verdict was published, and it was decided on the last ok verdict and allowed; the checks allow for that one
  proposal in flight and require everything after it to escalate. A monitor that has to be ahead of the commands needs
  a faster step or a hold on the first proposal after a status change.
- The silent monitor is simulated with a ground command. A real monitor can also fail by saying ok wrongly, which no
  staleness bound catches.
- Escalation here is an event and a receipt, as in S2 and S3. Nothing holds the command for a ground decision, and
  nothing clears `monitor_ok` except the monitor reporting ok again (the payload's status word stays nonzero in this
  simulator, so after the fault it never does).
- The staleness bound is compile time (`PRISMPATH_APP_MONITOR_STALE_SECS`, from the environment variable
  `PP_MONITOR_STALE_SECS`), measured in mission elapsed time. A build without it reads `monitor_ok` as always true, so
  a mission that wants monitoring must build with it.
- It is the same simulation as S3: no flight hardware, no real time operating system, no radio link.
- Only R2U2 was used. Ogma and Copilot, which generate monitors as cFS apps, were not tried.

## Tests

`python -m pytest integrations/cfs/tests/test_monitor_scenario.py` holds the outcome function to the reference decision
for every proposal with the verdict either way, the C layout's `monitor_ok` row to the policy's field and the command
struct, and the message ids to each other and to NOS3's. With a checkout of R2U2 it compiles the property and holds
R2U2's verdicts on traces to the model. With a staged NOS3 build, R2U2 and Docker it runs the scenario
(`--skip-build`, about 65 s). Each part skips, saying why, when what it needs is missing.
