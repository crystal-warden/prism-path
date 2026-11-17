# PrismPath in flight software

*A plan for a PrismPath app in NASA's core Flight System (cFS) and a component in JPL's F Prime, demonstrated in NASA's NOS3 small satellite simulator with no hardware. Written 2026-11-16 against research main 0297c9c. It follows the governed agent work and does not block it.*

## 0. Why this, and who else is there

Spacecraft act alone between ground contacts, their links are slow and rationed, and their policy updates must be small and authenticated. Those are the conditions PrismPath was built for: a decision before the action, a receipt for every decision, one compiled image with a bounded cost, refusal of a stale or rolled back image, and a decision sufficient encoding for the downlink.

The market scan of 2026-11-16 found the slot occupied but not filled.

- Sedaro's Autonomy Framework for the Edge validated 189 autonomous commands from Shield AI's Hivemind on a NOVI satellite in August 2026, under an SBIR Phase II with AFRL and Space Systems Command. That is the nearest competitor and proof the government buys command validation in orbit. Nothing public says it proves its decision core, keeps receipts anyone can check offline, or runs one policy on an FPGA.
- NASA's own runtime monitors, R2U2 (selected for the Lunar Gateway vehicle system manager) and Ogma/Copilot (which generates monitors as cFS apps), check temporal properties of telemetry. They are where a cFS reviewer will start. PrismPath sits beside them: they monitor, PrismPath decides each proposed command and receipts it.
- Onboard autonomy is multiplying (Shield AI, Ubotica, Loft Orbital, Satlyt, PiLogic, AstroForge). Each is a proposer PrismPath could govern, so they are partners more than competitors.

## 1. The shape

```
autonomy app ──proposed command──> PrismPath app ──allowed command──> vehicle apps
                                        │
                     refuse / escalate  │  receipt per decision (Merkle leaf)
                                        v
                         event + housekeeping telemetry, root statements, decision downlink
```

The autonomy app publishes its proposed commands on a message id only the PrismPath app subscribes to. The PrismPath app reads each into the policy's typed fields, decides it with the C kernel against the active image, appends the receipt, and republishes an allowed command on the vehicle's real command message id. A refusal is an event with its registered cause and receipt number, and the command never reaches the vehicle. An escalation is held and sent to the ground as a request, and runs only on a ground command that names its receipt.

What already exists and carries over: the C kernel and image format (`prismpath-hw/ppt_eval.h`, `prismpath-ebpf/ppt_image.h`), the streaming Merkle accumulator in C (`merkle.h`, `ppt_merkle_acc`) with its proof that the accumulator root equals the RFC 6962 tree, the image's signed cycle bound, the cause registry, and the Facet decision encoding.

## 2. How it fits cFS and F Prime

These come from the projects' own docs (read 2026-11-16 from nasa/cFS, nasa/fprime and nasa/nos3) and are to be confirmed against the code when built.

- **Policy image as a cFE table.** Table Services load, validate and activate tables, with active and inactive images and double buffering for a switch that does not block. The validate callback is where the signature, the version floor and the image's own checks run, so an image that fails never activates. F Prime's parameter database is the equivalent there.
- **Rollback refusal across resets.** The Critical Data Store survives processor resets. It holds the highest accepted image version and the current tree state (the accumulator's peaks, at most 64 hashes), so a reset cannot reopen an older image or truncate the receipts.
- **Interception.** In cFS, a message id routing; in F Prime, a component on the command path (message pre hooks or a filter component between the autonomy component and the command dispatcher).
- **Determinism.** Allocation only at initialization, the decision in its own task or rate group, and cFE performance markers around the decision so the signed cycle bound can be checked against the measured time on the target.
- **Downlink.** Refusals and escalations as events; root statements and counts in housekeeping telemetry; the receipts and the decision stream as a file or data product for CFDP, and the Facet encoding where bandwidth is the constraint.
- **Ground verify.** The ground runs `prismpath evidence verify` on the downlinked run with both keys pinned. The in-toto export (`prismpath/ledgers/intoto.py`) gives the same run as a standard attestation.
- **Security layer.** Uplink and downlink authentication stays with CCSDS SDLS (CryptoLib in cFS, the AES-GCM components in F Prime). F Prime's notes say its decryptor has no anti replay, which PrismPath's version floor and its own replay refusal for images cover at the policy layer.

## 3. Work packages

**S1 cFS app skeleton.** `integrations/cfs/prismpath_app` built with `add_cfe_app`, running `SIMULATION=native` on Linux. It loads an image from a table with a validate callback, decides proposed commands from a test message id, republishes allowed ones, and emits events. Check: the cFS native build runs, and a scripted sequence of proposals gives the expected allow, refuse and escalate events.

**S2 Receipts and reset.** The accumulator and root statements in the app, the accepted version and tree state in the Critical Data Store, and housekeeping telemetry. Check: after a simulated processor reset, the receipt count and root continue and an older image is refused with its cause. The downlinked run verifies on the ground with the existing verifier.

**S3 NOS3 scenario.** A NOS3 mission where a simple autonomy app proposes attitude and payload commands, some outside policy, with a fault injected through the simulator bridge. Check: the scenario runs from a script, nothing outside policy reaches the simulated vehicle, and the run verifies on the ground.

**S4 F Prime component.** The same decision and receipt core as an F Prime component, in a reference deployment. Check: the same proposals give the same decisions and the same receipts byte for byte as the cFS app, which is the cross framework conformance claim.

**S5 Beside R2U2 and Copilot.** One scenario where a runtime monitor's verdict is a field PrismPath routes on (a monitor violation forces escalate), to show the two compose. Check: the scenario and a short note.

**S6 Proposal kit.** A two page summary, the scenario video and the run, aimed at NASA's SBIR/STTR appendices and the Department of the Air Force's focused topics on autonomy.

Order: S1, then S2 and S3, then S4 and S5, then S6. Each lands as a research PR with all checks green.

## 4. Funding doors, as of 2026-11-16

- NASA SBIR/STTR now runs one broad agency announcement, open through 2027-09-30, that releases topical appendices on a rolling basis; Phase I is about $225K. The appendices to watch are autonomy, onboard data reduction and software assurance.
- The Department of the Air Force (AFWERX and SpaceWERX) moved from open topics to focused, mission driven topics after the 2026 reauthorization, many of them direct to Phase II, with autonomy, ISR and space resilience named as priorities. A direct to Phase II needs prior feasibility, which S3 is meant to be.

Dates move; check sam.gov and the NASA SBIR site before any submission.

## 5. Constraints

- **Licences.** cFS and F Prime are Apache-2.0, like PrismPath. NOS3 is the NASA Open Source Agreement 1.3, so NOS3 code is used as a test harness and never copied into this repository.
- **Export control.** Open, public work is generally outside ITAR and the EAR, but spacecraft items are listed under both, and defence funded work can bring controls in. This goes with the export control question already open for NV012, before any funded space work.
- **Contributions upstream.** F Prime requires disclosure of generative AI use in contributions. Anything offered upstream says how it was made.
