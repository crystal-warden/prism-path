# The PrismPath app in a NOS3 mission

Work package S3 of [the flight software plan](../../../docs/design/cfs-app-plan.md): the PrismPath cFS app
([`../prismpath_app`](../prismpath_app), S1 and S2) between an autonomy app and the vehicle in NASA's NOS3 small
satellite simulator, with a fault injected through NOS3's simulator command bus bridge.

```
                                  NOS3 flight software (cFS, NOS3's cFE)
 pp_autonomy --PROPOSED_CMD--> prismpath_app --VEHICLE_CMD--> pp_vehicle --SET_TORQUE--> generic_rw --UART--> wheel 0 sim --> 42
   ^   proposes the plan and                  (allowed only,               --CONFIG-----> sample -----UART--> payload sim
   |   the fault playbook                      after the receipt)
   +---- payload housekeeping (device status) <------------------------------------------ sample <---------- payload sim
                                                                                                                  ^
 run_nos3_scenario.py --TCP 12020--> command bus bridge --{"node": "sample-command", "cmd": "STATUS=3"}-----------+
```

## Run it

```
python integrations/cfs/nos3/run_nos3_scenario.py            # --nos3 <checkout>, default .cfs-build/nos3
```

It needs a NOS3 checkout with its submodules (`git clone --recurse-submodules https://github.com/nasa/nos3.git`
into `.cfs-build/nos3`, which is gitignored), Docker, Make, Python 3 and the repository's environment (the verifier
and `cryptography`). It never runs anything as root and edits only the NOS3 checkout, never this repository:

1. **Stage.** Links `prismpath_app`, `pp_autonomy` and `pp_vehicle` into NOS3's `components/`, writes
   `cfg/spacecraft/sc-prismpath-config.xml` from NOS3's own minimal spacecraft with the reaction wheels turned on
   and the file and storage apps off, runs NOS3's `make config` with it, then adds the three apps to the generated
   `targets.cmake` and startup script and copies the message id overrides in [`mission/`](mission) into the
   generated mission definitions.
2. **Build.** NOS3's flight software and simulators with NOS3's own make targets inside NOS3's own image
   (`ivvitc/nos3-64:20261021`, pulled if absent), and NASA's 42 dynamics (cloned beside the NOS3 checkout from the
   branch NOS3's `make prep` uses, and built in the same image).
3. **Provision** the flight file system with fresh test keys and the signed version 2 policy table
   ([`../ground/provision.py`](../ground/provision.py)), and start a new run (power on reset).
4. **Launch** nine containers on one private Docker network, each with a memory cap: the NOS Engine server, 42 with
   no graphics, the payload simulator (NOS3's sample instrument), the three reaction wheel simulators, the command
   bus bridge, the time driver and the flight software. There is no ground station: no COSMOS, no YAMCS, no GUI.
   The script is the ground, sending commands to `ci_lab` over UDP and reading the containers' logs.
5. **The scenario.** The ground enables the payload and wheel 0 (commands to NOS3's own apps, as an operator does)
   and starts the autonomy app. After four proposals it injects the fault: `STATUS=3` to the payload simulator's
   command node, through the bridge. Then it seals the run.
6. **Check** (below), then **tear down** every container and the network, put the table back, remove the keys, and
   check that `docker ps -a`, `docker network ls` and `docker volume ls` are as they were before the run.

`--skip-build` uses the staged build as it is (what the test does); `--keep-run DIR` keeps the downlinked run and the
ground's keys; `--leave-running` and `--teardown` are for debugging.

## The apps

- [`pp_autonomy`](pp_autonomy) proposes the plan in [`plan.py`](plan.py) one command a second (paced by cFE Time
  Services' 1 Hz command, which follows NOS3's simulation clock) on `PROPOSED_CMD`, which only the PrismPath app
  reads. It reads the payload's housekeeping, and when the device status word turns nonzero it proposes its fault
  playbook at once, ahead of the rest of the plan. Each proposal carries a tag in the command's spare word, which no
  policy field reads, and a `PROPOSE` event, so the PrismPath decision with sequence number n is the decision on
  the n-th proposal. It never commands the vehicle.
- [`pp_vehicle`](pp_vehicle) subscribes to `VEHICLE_CMD`, where the PrismPath app republishes only what it allowed,
  and turns an attitude command into NOS3's reaction wheel command (`SET_TORQUE` on wheel 0, `slew_deg` x 10^-4 N m)
  and a payload command into NOS3's sample instrument configuration command (the configuration word is the tag).
  It is the only app in the mission that commands those two apps.
- The PrismPath app is the S2 app unchanged in behaviour. Building it on NOS3's older cFE needed three small
  compatibility changes in the app, none of them a change to what it does: its configuration header wrappers fall
  back to `generate_config_includefile` where `generate_configfile_set` is absent, `CFE_MSG_PTR` is defined when
  cFE does not, and libcrypto is linked as `-lcrypto` because NOS3 has a CMake target of its own called `crypto`.
  NOS3's cFE has no topic ids, so [`mission/`](mission) gives the app message ids 0x18C0 to 0x18C3 (telemetry
  0x08C1), clear of every message id NOS3 defines; the autonomy app's command is 0x18C4.

`plan.py` is the source of the plan: `python -m integrations.cfs.nos3.plan` writes the C include the autonomy app
compiles, and `EXPECTED` is the outcome table, written by hand from
[`example.rules.md`](../prismpath_app/policy/example.rules.md):

| tag | proposal | decision |
| --- | --- | --- |
| 1 | attitude: slew 20 deg, in contact | allow |
| 2 | payload: first observation | allow |
| 3 | attitude: slew 120 deg | refuse, route:contract-violation (37) |
| 4 | payload: second observation | allow |
| 5 | attitude: slew 70 deg, contact lost | escalate, route:needs-human (34) |
| 6 | command class 7 | refuse, agent:unclassifiable (104) |
| 7 | attitude: slew 60 deg, back in contact | allow |
| 8 | attitude: slew 35 deg, out of contact | allow |
| 101 | fault playbook: slew 30 deg off the sun | allow |
| 102 | fault playbook: slew 75 deg to sun safe, no contact | escalate, route:needs-human (34) |

The plan's payload commands come before the fault on purpose: NOS3's sample instrument app halts the device when it
reads a nonzero status (its own fault response), so after the fault no payload command could reach the instrument
whatever PrismPath decided, and the check on the instrument would say nothing about PrismPath.

## What it shows

Every check is printed. A run on this repository's development host (aarch64, NVIDIA GB10) passed all of them:

- Ten proposals, ten decisions, each the outcome table's and the Python reference's (the same reading through
  `prismpath.agent.policy`), with its receipt number.
- The fault went in through the bridge (the bridge's log names the node and the command, and the payload simulator
  logs it arriving on its command bus node), the autonomy app saw the status word turn 3 and proposed the playbook
  once, together, after the fault and before the plan ended. The policy allows the small slew and escalates the
  large one with no ground contact.
- **From the simulators' side**: reaction wheel 0's simulator logged `SET_TORQUE` requests of exactly 20, 30, 60
  and 35 x 10^-4 N m, the allowed attitude commands in order, and the payload simulator logged configuration
  commands of exactly 2 and 4. Nothing refused or escalated (tags 3, 102, 5, 6) reached a simulator, and wheels 1
  and 2 saw no torque. The check reads the simulators' own logs, not PrismPath's events.
- The run, sealed onboard and copied off the flight file system, verifies on the ground:
  `prismpath evidence verify --sample all` with the authority and instance keys pinned, 10 receipts replayed
  through the reference kernel, 10 agree, and the root statement is signed by the pinned instance key.
- Docker is left as it was.

The tests (`python -m pytest integrations/cfs/tests/test_nos3_scenario.py`) hold the plan and the outcome table to
the reference decision path, check that the generated include is current, that the plan has each kind of decision
and that allowed and blocked proposals leave different traces on the simulators, that the mission's message ids are
clear of the app's defaults and (with a NOS3 checkout) of NOS3's, and that the log readers parse NOS3's lines. With
a staged NOS3 build and Docker they also run the scenario (`--skip-build`, about 30 s); without them that test
skips and says why.

## What it does not show

- It is a simulation. The flight software runs as a Linux process in a container, NOS3's hardware models stand in
  for the wheels and the instrument, and 42 integrates the dynamics. Nothing ran on flight hardware or a flight
  processor, under a real time operating system, or over a radio link: the ground commands went straight to
  `ci_lab` over UDP, and the downlink is a file copy, not CFDP.
- The autonomy app is a fixed plan and a fixed playbook, not a planner. It assumes no ground contact when it
  answers a fault, and contact is a flag in its plan, not a property of the orbit.
- An escalated command is an event and a receipt (as in S2): nothing holds it for a ground decision.
- The wheel torque is commanded and left on; the scenario does not check the attitude 42 integrates.
- The test keys are files in the flight file system.

## Resources and time

Measured on the development host (aarch64, NVIDIA GB10, 20 cores):

- **Disk**: NOS3's image, 8.0 GB; the NOS3 checkout with its submodules and builds, 1.4 GB (the flight software
  build 146 MB, the simulators 231 MB); the 42 checkout and build, 1.2 GB.
- **Memory**: the nine containers are capped at 4 GB together (the flight software and 42 at 1 GB each, the engine
  server at 512 MB, the four simulators, the bridge and the time driver at 256 MB each) and used about 70 MB
  together; the build containers are capped at 8 GB; the driver script peaks at about 400 MB.
- **Time**: a first run from a clean checkout, the image already pulled, took 65 s (the flight software and the
  simulators about 10 s each with 12 build jobs, cloning and building 42 about 20 s, the scenario 28 s); a run on
  a staged build takes about 30 s. Pulling the image is a one time 8 GB download.

NOS3 publishes the image for both amd64 and arm64, and its build uses the native compiler (its toolchain file is
called `amd64-nos3` but names `/usr/bin/gcc`), so the same script should run on x86_64 Linux; it was run here only
on aarch64.
