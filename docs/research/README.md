# Research directions

PrismPath does three things. It decides before the action, from a policy a person can read. It leaves a
receipt anyone can check offline. And it compiles one policy that decides the same way from Python down to a
microcontroller or an FPGA. The front page tells that story and nothing else.

Everything else the repository holds that is a research direction, an experiment, a study or a plan is listed
here, one row each, so that nothing is hidden and nothing is oversold. The status column uses the repository's
own words, taken from the status table in [README.md](../../README.md), from [POSITION.md](../POSITION.md), or
from the document or ledger row that backs the row. A status here is never stronger than the source it comes
from. The ledger column names rows of the [evidence ledger](supporting-evidence.md). A dash means the ledger has
no row for that direction.

| direction | what it is | status | where it lives | ledger rows |
|---|---|---|---|---|
| Drift detection and authorized recovery | Noticing that an embedder, a model or a policy has drifted past what the lockfile and the staleness bound already catch, and recovering only through an authorized step. | research direction, not claimed | Nothing built for the direction itself. The pieces that exist today are `prismpath/lockfile.py` and `prismpath/telemetry/refresh.py`. Planned drift probes are in [ROADMAP.md](../../ROADMAP.md) phase 5. | none (#125 backs the staleness bound that exists today) |
| Homeostatic control | Policies that hold a system near a set point rather than only permit or refuse single actions. | research direction, not claimed | Nothing built for the direction itself. The nearest implemented piece is the hysteresis band policy in `prismpath-hw/hyst-cert/`, which is claimed only as a stateful selector. | none (#119 and #123 back the selector, not homeostasis) |
| Multimodal sensing | Deciding over several kinds of sensor at once. | research direction, not claimed | The fusion pieces that were measured are the next two rows and carry their own scope statements. | none for the direction |
| Quantum assisted computation and quantum sensing | Using quantum hardware as a worker or a sensor under a policy. | research direction, not claimed | Nothing in the repository. The post quantum suites in the crypto agility row are a different subject. | none |
| Decision fusion plane | One decidable flow that joins several decision sources, for example IMU posture and SIEM verdicts, into one fused decision carried on the Facet wire. | measured on a bench and a live rig, as the rows state | `adapters/fusion/`, `prismpath-hw/esp-fusion-pod/` | #82 to #85, #95 |
| Mesh | Small radio fleets that swap a signed policy behind a quorum, fuse distributed readings, treat a silent node as a stale input, and carry Facet frames over the air. | distributed policy update behind a quorum on real radios, demonstrated in the field | `prismpath-hw/mesh/`, `prismpath-hw/mesh-fusion/`, `prismpath-hw/spiral-mesh/`, `prismpath-hw/walker-demo/` | #100 to #102, #116, #120, #121, #136 |
| Camera node and constrained link | A camera that ships decision state instead of images over a low power link, with admission, replay refusal, a privacy control and an actuator that verifies before it acts. | measured on a bench, one system closed in layers, as the ledger states | `prismpath-hw/esp-vision-node/`, `prismpath-hw/esp-vision-c6/` | #144 to #157 |
| Governed harness | A small agent harness in which every proposed tool call is a decision of a signed policy, receipted before it runs and run only on allow inside a sandbox. | research example | `integrations/governed_harness/`. The `prismpath agent` command and [governed-agent.md](../guides/governed-agent.md) build on it. | none |
| Governed intent | Embedding derived fields as policy input that can only turn an allow into a refusal or an escalation, never grant. | research example, pre registered | `integrations/governed_intent/` | none |
| Governed net | The harness with each tool call as one datagram, decided in XDP before the tool server sees it and decided again by the server. | research example, run on the userspace path of the XDP program in the original layout | `integrations/governed_net/`, `prismpath-ebpf/gnet/` | none |
| Governed population | Copying, recovery and version change for a population of agents, each act a decision of a policy that lives outside any agent. | research example, a design note and a pure Python simulation, no cluster run | `integrations/governed_population/` | none |
| Governed fleet bench | Agreement on an authorization edge across non bit identical semantic evaluators, tamper resistant denials, and a fleet verdict driving in kernel admission. | bench demonstrator, one bench, as the rows state | The code is not in this repository. The rows name their provenance. | #158 to #161 |
| Decision sufficient quantization (also called Figueroa quantization) | Deriving from the policy text the cells of each field that can change a decision, so that a reading can be sent as one symbol per cell. | implemented, proven within the declared domain | `formal/`, `prismpath/telemetry/quantizer.py`, [the Facet paper](paper-facet-figueroa-quantization.md) | #140, #141, #162 |
| Facet wire, Vector codec, Wireshark dissector | The telemetry wire that carries the decision rather than the data, with self framing codes, Merkle roots, a refresh profile and replay refusal. | implemented and measured | [PROTOCOL.md](../../PROTOCOL.md), `prismpath/telemetry/`, `integrations/vector/`, `integrations/wireshark/` | #81, #84, #86, #95, #103 to #105, #107, #124 to #127 |
| Comparisons study | A pre registered comparison against OPA, Cedar, Cerbos, OpenFGA and Openlane, and a routing head to head against LangGraph and CrewAI. | pre registered, run to the end, verdict published including what did not hold | `prismpath/comparisons/` and its `VERDICT.md` | #142, #143, and the head to head line in section A |
| GRC adjudication adapter | Machine checkable controls, evidence typed determinations and OSCAL output for governance, risk and compliance work. | implemented, dogfooded on a real enclave | `adapters/compliance/` | #137 to #139 (#65 to #71 measured the first build, see the ledger note) |
| Routing spectrum study | The study of deterministic, embedding and model routing, including four density experiments that failed their bars. | measured, with the open claims stated in the ledger | `research/`, `prismpath/benchmark/`, [the routing spectrum paper](paper-routing-spectrum.md) | sections A to D, including #39, #41, #42, #47, #48, #52 |
| Safety floor bypass measurement | A pre registered protocol for measuring how often the deterministic floor is bypassed, by stratum. | pre registered protocol with an amendment trail | [bypass-measurement.md](bypass-measurement.md), `prismpath/guard.py`. A roleplay framing detector is planned in [ROADMAP.md](../../ROADMAP.md) phase 5. | none numbered |
| Crypto agility control plane | Deciding which approved cryptographic suite a channel may use and moving forward without a flag day. | phases 1 to 5 implemented in the software tier and gated, later phases named follow ons | [spec-crypto-agility.md](../design/spec-crypto-agility.md), `prismpath/hotswap/crypto_registry.py` | #94, #96 |
| Context ledger | An append only ledger that attests what a frozen model was conditioned on. | measured in the ledger row, Python and cross language | `prismpath/context_ledger.py` | #91 |
| Delivery through Zarf and UDS | Delivering a signed policy and its SBOM, verifying it on arrival and activating it, failing closed when tampered. | runs with the real binaries, as the integrations README states | `integrations/zarf/`, `integrations/zarf-kernel/`, `integrations/zarf-tampered/`, `integrations/uds/` | none numbered |
| Theory of governed autonomous execution | A proposed theory of authority separation and semantic invariance, with a machine checked core in Lean 4. | proposed, not validated, with the machine checked results claimed | [the paper](governed-autonomous-execution/paper.md) | #162 |
| Flight software | A plan for PrismPath as an app in cFS and a component in F Prime, shown in a simulator. | plan, not built | [cfs-app-plan.md](../design/cfs-app-plan.md) | none |

## How a direction reaches the front page

A direction moves onto the front page when two things are true. It is implemented, meaning the code ships in
this repository and its tests run in CI. And it has ledger rows that state its claim, its method, its result
and its honest scope. A direction that is only measured on a bench, or only designed, stays here with its
status unchanged. When a direction is promoted, its row moves into the status table in the README and in
[POSITION.md](../POSITION.md), and the wording of the status comes from the ledger rows, not from this page.
A direction that fails its measurement stays here too, with the negative result left in.
