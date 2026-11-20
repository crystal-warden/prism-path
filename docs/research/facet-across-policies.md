# Facet cost across every shipped policy

Measured 2026-11-20 on main 30b6101 with `tools/facet_across_policies.py`, results in `results/facet_across_policies_2026-11-20.json`. This is a measurement. No product code changed.

## What was asked

The Facet paper and `adapters/fusion/bench/otlp_results.md` give 1.516 bytes per decision. That is one policy, the fusion adapter's 4-field SIEM alert policy, over 64,484 decisions, on that population's own cell mix. This note costs every policy the repository ships.

## Result

66 distinct shipped policies encode (7 more are conformance cases or a docs example, listed apart below). At n = 64,484 with the cells of every field equally likely, the cost per decision is:

- minimum 0.328 B, median 1.257 B, maximum 40.644 B
- under 1 B: 25 of 66 (38%); under 2 B: 52 (79%); under 4 B: 59 (89%)

The cost follows the field count. A one-field policy with two cells costs 2.5 bits, a 4 to 6 field policy 10 to 18 bits, the agent policies' core images (11 to 12 fields) 34 to 37 bits, and the 101-field occupancy grid 325 bits. Cell count matters less than field count, because a code for a symbol grows with the logarithm of the symbol and every field pays at least 2 bits for its terminator.

Most expensive, bytes per decision at n = 64,484 (uniform cells):

1. occupancy_6x8 (prismpath-hw/esp-vision-node/flows/occupancy_6x8.md): 40.644 B, 101 fields, 325.0 bits
2. occupancy_6x8_v2 (prismpath-hw/esp-vision-node/flows/occupancy_6x8_v2.md): 40.642 B, 101 fields, 325.0 bits
3. admission (integrations/governed_population/policy/admission.core.json): 6.671 B, 19 fields, 53.2 bits
4. intent_calls (integrations/governed_intent/policy/intent_calls.core.json): 6.654 B, 18 fields, 53.1 bits
5. agent_rules (prismpath/agent/policy/agent_rules.core.json): 4.615 B, 12 fields, 36.8 bits

Least expensive:

1. demo_binary (prismpath-hw/demo/flows/demo_binary.md): 0.328 B, 1 fields, 2.5 bits
2. fanout_review (prismpath/flows/fanout_review.md): 0.328 B, 1 fields, 2.5 bits
3. review_one (prismpath/flows/review_one.md): 0.328 B, 1 fields, 2.5 bits
4. triage_support (prismpath/flows/triage_support.md): 0.328 B, 1 fields, 2.5 bits
5. example.rules (integrations/cfs/prismpath_app/policy/example.rules.md): 0.392 B, 1 fields, 3.0 bits

The most expensive are the 101-field occupancy grids, the two 18 and 19 field governed core images, and the agent core images. They pay for field count: the policy compiles every field its rules read into one symbol per decision, and the wire sends every field on every decision whichever branch is taken. Their cells are many (up to 3e59 joint cells) but the cost is the sum of per-field codes, not the log of the joint space. The cheapest are one-field policies with 2 or 3 cells.

## Where the fusion SIEM policy sits

The fusion policy (`adapters/fusion/flows/fusion_triage.md`, 4 fields, 108 joint cells) costs 1.548 B at uniform cells and 1.658 B on the boundary mix. It ranks 43 of 66 from cheapest, so it is a mid-sized policy, above the median (1.257 B).

The paper's 1.516 is a measured-population number. Its population averages exactly 12.000 payload bits. Zeckendorf coding makes the payload depend on which cells readings land in, so the same policy costs 12.25 bits (1.548 B) when every cell is equally likely and 13.1 bits when readings sit at the boundaries. Check: 12.000 bits over 64,484 decisions is 96,726 B, plus 16 epochs of 64 B of roots is 1,024 B, total 97,750 B, which is 1.516 B per decision. The synthetic fixture in the repository (50 decisions) also gives 12.0 bits per decision through bandwidth.py.

**The ACK.** `otlp_results.md` and the paper say the Facet figure counts "Merkle epoch roots and the ACK channel". `bandwidth.py` computes `wire_bytes_total` as the packed payload plus 64 B of roots per epoch (a 32 B Merkle root and a 32 B chained root). The 32 B ACK is itemised as `ack_bytes` and not added. So the sentence and the number disagree by the ACK. With the ACK the figure is 1.524 B per decision (16 epochs x 32 B = 512 B more). Every row here shows both: the plain column follows bandwidth.py and so is comparable to 1.516, and the ACK column adds 32 B per epoch.

## O2, the band-ID stream

O2 sends one Zeckendorf code of the band number per decision node instead of one code per field. It applied to 59 of 66 shipped policies. It was not built for seven policies whose joint cell grid is over 300,000 cells at one node (the occupancy grids, the governed intent and admission images, the agent images), because the layout enumerates every joint cell. For multi-node policies the table's O2 column sums one band code per node, and a second column gives the largest node alone. The fusion paper's O2 is its `correlate` node: 4.70 bits, against 8.04 bits when both nodes are summed. O2 round trips (band to route on every node) were checked on a boundary sample.

## Against OTLP

The OTLP figures are for the 4-field SIEM record, 101.372 B faithful and 7.162 B zstd-19 batched. They hold only for policies of similar record shape. For the 31 shipped policies with 3 to 5 fields, Facet costs 0.95 to 2.08 B, so OTLP faithful is 49 to 106 times larger and zstd-batched OTLP of that record would be 3.4 to 7.5 times larger, if those records were the same size, which they are not. For one-field policies and for the 11 to 101 field policies the OTLP figures say nothing, since an OTLP record would carry a different number of attributes. No OTLP record was built for any policy other than the fusion one.

## Method

1. **Enumeration.** Every git-tracked `*.core.json` and every `.md` whose frontmatter has `start:` (excluding `.tests.md` and READMEs), plus the six decisions.json corpus cases, parsed with `parser.parse` (core images through `core_render.render`). fq_redundancy.py's list is a subset of this. Identical file hashes are counted once. Excluded: 23 deliberately broken parser fixtures and 7 retired agent images kept for migration tests.
2. **Codebook.** `quantizer.build_partitions`. A defined integer field only admits values inside its declared range, so a cell wholly outside the range can never be sent. "Cells reachable" counts joint cells whose every field cell has at least one admissible value.
3. **Bits.** Per PROTOCOL.md 2.2 a symbol s is sent as the Fibonacci code of s + 1, of length 2 bits for s = 0, 3 for s = 1, 4 for s = 2 to 3, 5 for s = 4 to 6, 6 for s = 7 to 11 (lengths taken from `zeckendorf.encode`). Bits per decision = sum over fields of that length. The computed figure is the mean of the length over each field's reachable cells, summed over fields, which equals the mean over the joint grid when cells are equally likely.
4. **Bytes.** `bandwidth._stream_stats` itself, per epoch of 4,096: packed payload (padded to a byte) + 32 B Merkle root + 32 B chained root. The ACK column adds 32 B per epoch. Epoch share is roots over wire bytes at n = 4,096.
5. **Measured.** Every policy was encoded with `wire.encode_reading` on real readings. For 66 policies whose reachable grid is at most 150,000 cells every joint cell was encoded once and the measured mean equals the computed mean exactly (asserted). For the other 7 a sample of 64,484 readings with uniform cells was encoded; its mean bits are in the JSON next to the computed ones. The stream for n = 4,096 or 64,484 repeats the encoded population. The boundary mix draws, per field, among values at and next to every cut, every named constant, a near-miss and an unlisted string, and the absent value where allowed; readings a defined field refuses are dropped and counted. Each encoded reading was checked three ways: bit length equals the sum of code lengths, decode returns every field's cell, and the decoded reading routes the same as the raw reading at every decision node.
6. Seed 20261120. The batch ran in a memory-capped scope.

## Policies that could not be encoded

- `prismpath-hw/esp-vision-node/flows/normal_policy.md`: routes on a condition outside Level M (a field compared to another field), so the codec refuses it by design.
- `prismpath/flows/bugfix.md`: no deterministic field-routing decision, so there is no field to carry.
- `prismpath/flows/release.md`: a float threshold (1.0) in a comparison. The codec compares integers and refuses it by design.

The agent policies' core images do encode. In all: 73 encodable (of which 66 shipped), 3 not encodable, 30 excluded.

## Cells outside a defined field's range

My first run reported five policies refused or mismatched. None is a quantizer bug, and none is a policy authoring error. Evidence:

- `intent_responses.core.json` defines `intent_reader_version` as `int min=2 max=2` and its rule is `intent_reader_version == 2`. The quantizer cuts the integer line around 2 and gets three cells, (..1), 2 and (3..). Two lie outside the range, so no admissible reading falls in them, and the encoder refusing a 1 with `out_of_range` is the field definition doing its job. Grid 24 cells, 8 reachable.
- `governed_population/evaluation.core.json`: the four count fields (`out_of_policy`, `wrong_cause`, `unverified`, `benign_failed`) are `int min=0` and the rule tests each `== 0`, which gives a cell (..-1) below the range. 162 cells, 32 reachable.
- `governed_net/net_rules.core.json`: `cmd` is `int min=1 max=11` with rules on 3, 4, 5, 10 and 11, and the quantizer keeps cells (..0) and (12..) outside the range. 3,744 cells, 3,168 reachable.
- `cfs/example.core.json` and `example.rules.md` were refused because of my script, not the policy: the boundary mix tried `cmd_class` = -1 in the O2 sample, and the field is `int min=0 max=10`. The partition itself is fine.

The two "means did not match" cases (net_rules, evaluation) are the same effect: my first script averaged over all cells instead of the reachable ones. After counting reachable cells only, computed and measured means are equal on every whole-grid policy.

So this is expected behaviour: the quantizer is blind to a field's declared range and builds cells for the whole integer line, and the field definition refuses what the cell cannot hold. The cost is some unreachable cells in the codebook, which cost nothing on the wire but make the codebook larger than needed; if one wanted a tighter codebook the quantizer would clip cells to the declared range, a design change that was not made here. No code was changed. 
## Caveats

- The headline per-policy numbers assume equally likely cells. Zeckendorf codes are shorter for low symbols, so a real population that favours cell 0 costs less and one that favours high cells costs more. Real populations were measured only for fusion (the paper's 64,484 decisions, not in the repository; the fixture is synthetic).
- 66 distinct shipped policies include siblings and versions of one another (for example the two occupancy grids and three agent images), so the distribution is by file, not by independent design. Counting each once by content hash removed 9 copies.
- The decisions.json cases and `tools/release_policy.md` are not shipped policies and are kept out of the distribution; they are in the table below.
- O2 is only measured where the layout builds. For policies with more than one decision node, a stream carries one band code per node here; whether a deployment sends every node on every decision is a design question this note does not settle.
- OTLP ratios use the SIEM record sizes only.

## Table: shipped policies, cheapest first

| policy | path | sha256 | fields | cells reachable | uniform bits (computed) | boundary bits (measured) | B/dec n=4,096 | B/dec n=64,484 | with ACK, n=64,484 | epoch share n=4,096 | O2 B/dec n=64,484 | O2 bits, largest node | method |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| demo_binary | prismpath-hw/demo/flows/demo_binary.md | 8e769fbeb09b | 1 | 2 | 2.50 | 2.50 | 0.328 | 0.328 | 0.336 | 4.8% | 0.328 |  | measured, whole grid |
| fanout_review | prismpath/flows/fanout_review.md (also prismpath/gallery/fanout_review/fanout_review.md) | 562e7213ad8d | 1 | 2 | 2.50 | 2.50 | 0.328 | 0.328 | 0.336 | 4.8% | 0.328 |  | measured, whole grid |
| review_one | prismpath/flows/review_one.md (also prismpath/gallery/fanout_review/review_one.md) | bc35c41c7051 | 1 | 2 | 2.50 | 2.66 | 0.328 | 0.328 | 0.336 | 4.8% | 0.328 |  | measured, whole grid |
| triage_support | prismpath/flows/triage_support.md | 68dc75fb3721 | 1 | 2 | 2.50 | 2.66 | 0.328 | 0.328 | 0.336 | 4.8% | 0.328 |  | measured, whole grid |
| example.rules | integrations/cfs/prismpath_app/policy/example.rules.md | 3020964165f6 | 1 | 3 | 3.00 | 3.17 | 0.393 | 0.392 | 0.399 | 4.0% | 0.349 |  | measured, whole grid |
| demo_input | prismpath-hw/demo/flows/demo_input.md (also prismpath-hw/hyst-cert/evidence/demo_input.md) | a0275dcbc1ca | 1 | 3 | 3.00 | 3.00 | 0.391 | 0.392 | 0.399 | 4.0% | 0.391 |  | measured, whole grid |
| neg_literal_test.flow | prismpath-hw/evidence/neg_literal_test.flow.md | e02a271b91c4 | 1 | 3 | 3.00 | 3.00 | 0.391 | 0.392 | 0.399 | 4.0% | 0.391 |  | measured, whole grid |
| pipeline | prismpath/examples/code_nodes/pipeline.md | 48eab709e7ca | 1 | 3 | 3.00 | 3.00 | 0.391 | 0.392 | 0.399 | 4.0% | 0.391 |  | measured, whole grid |
| posture_selector | prismpath-ebpf/posture_selector.md | 738f1a9a6daf | 1 | 4 | 3.25 | 3.16 | 0.422 | 0.422 | 0.430 | 3.7% | 0.922 (3 nodes) | 2.25 | measured, whole grid |
| posture_selector_v2 | prismpath-ebpf/posture_selector_v2.md | f62165d44360 | 1 | 4 | 3.25 | 3.17 | 0.422 | 0.422 | 0.430 | 3.7% | 0.922 (3 nodes) | 2.25 | measured, whole grid |
| hyst_band | prismpath-hw/demo/flows/hyst_band.md (also prismpath-hw/hyst-cert/evidence/hyst_band.md) | df07a5cd04f9 | 1 | 5 | 3.60 | 3.63 | 0.467 | 0.467 | 0.475 | 3.4% | 1.016 (3 nodes) | 2.60 | measured, whole grid |
| ci_gate | prismpath/examples/cli_worker/ci_gate.md | 05c0f44cd0f1 | 2 | 4 | 5.00 | 5.00 | 0.641 | 0.641 | 0.649 | 2.4% | 0.360 |  | measured, whole grid |
| log_alert | prismpath/examples/cli_worker/log_alert.md | 9182c3f32dee | 2 | 4 | 5.00 | 5.17 | 0.641 | 0.641 | 0.649 | 2.4% | 0.422 |  | measured, whole grid |
| release_gate | prismpath/examples/cli_worker/release_gate.md | 7f021c67b76b | 2 | 4 | 5.00 | 5.16 | 0.641 | 0.641 | 0.649 | 2.4% | 0.422 |  | measured, whole grid |
| alert_router | prismpath/examples/code_nodes_gemma/alert_router.md (also prismpath/tests/fixtures/alert_router.md) | 3d7544085940 | 2 | 4 | 5.00 | 5.00 | 0.641 | 0.641 | 0.649 | 2.4% | 0.641 (2 nodes) | 2.50 | measured, whole grid |
| governed_worker | prismpath/examples/governed_worker/governed_worker.md | 5de3a483f27c | 2 | 4 | 5.00 | 5.00 | 0.641 | 0.641 | 0.649 | 2.4% | 0.422 |  | measured, whole grid |
| pipeline | prismpath/examples/mdflow_interop/pipeline.md | f55e4c86add9 | 2 | 4 | 5.00 | 5.00 | 0.641 | 0.641 | 0.649 | 2.4% | 0.641 (2 nodes) | 2.50 | measured, whole grid |
| coding | prismpath/flows/coding.md | 7f183528555b | 2 | 4 | 5.00 | 5.00 | 0.641 | 0.641 | 0.649 | 2.4% | 0.422 |  | measured, whole grid |
| support_triage | prismpath/gallery/support_triage/support_triage.md | cc23b0b97604 | 2 | 6 | 5.50 | 5.67 | 0.703 | 0.704 | 0.712 | 2.2% | 0.703 (2 nodes) | 3.00 | measured, whole grid |
| nist_800171_access_control | adapters/compliance/flows/nist_800171_access_control.md | 2a0dee8831cf | 2 | 8 | 5.75 | 6.07 | 0.734 | 0.735 | 0.743 | 2.1% | 1.735 (6 nodes) | 2.25 | measured, whole grid |
| triage.before | prismpath/examples/pr_demo/triage.before.md | 667b1705df4c | 2 | 8 | 5.75 | 6.24 | 0.734 | 0.735 | 0.743 | 2.1% | 0.469 |  | measured, whole grid |
| build_prismpath | prismpath/flows/build_prismpath.md | 029f25323415 | 3 | 8 | 7.50 | 7.50 | 0.953 | 0.953 | 0.961 | 1.6% | 0.735 (2 nodes) | 3.25 | measured, whole grid |
| data_pipeline | prismpath/flows/data_pipeline.md | 9363df4dfed3 | 3 | 8 | 7.50 | 7.50 | 0.953 | 0.953 | 0.961 | 1.6% | 0.703 (2 nodes) | 3.00 | measured, whole grid |
| pr_review | prismpath/flows/pr_review.md | 2bf62f01c80f | 3 | 8 | 7.50 | 7.50 | 0.953 | 0.953 | 0.961 | 1.6% | 0.953 (3 nodes) | 2.50 | measured, whole grid |
| sprint_loop | prismpath/flows/sprint_loop.md | 5875a5f82924 | 3 | 8 | 7.50 | 7.50 | 0.953 | 0.953 | 0.961 | 1.6% | 0.953 (3 nodes) | 2.50 | measured, whole grid |
| demo_fusion | prismpath-hw/demo/flows/demo_fusion.md | ccf9fc48a8fe | 3 | 12 | 8.00 | 8.00 | 1.018 | 1.017 | 1.025 | 1.5% | 0.328 |  | measured, whole grid |
| demo_fusion_v2 | prismpath-hw/demo/flows/demo_fusion_v2.md | ee29347a6879 | 3 | 12 | 8.00 | 8.00 | 1.016 | 1.017 | 1.025 | 1.5% | 0.328 |  | measured, whole grid |
| agy_800171_assessment | adapters/compliance/flows/agy_800171_assessment.md | 7362c11546c5 | 3 | 16 | 8.25 | 8.58 | 1.047 | 1.047 | 1.055 | 1.5% | 1.047 (3 nodes) | 3.25 | measured, whole grid |
| triage | prismpath/examples/pr_demo/triage.md | f2ea634419af | 3 | 16 | 8.25 | 8.73 | 1.047 | 1.047 | 1.055 | 1.5% | 0.485 |  | measured, whole grid |
| incident_severity | prismpath/gallery/incident_severity/incident_severity.md (also decisions.json:incident_severity) | b183edf13476 | 3 | 16 | 8.25 | 8.33 | 1.047 | 1.047 | 1.055 | 1.5% | 0.453 |  | measured, whole grid |
| hop_power | prismpath-hw/esp-vision-c6/flows/hop_power.md | 692341c8bb67 | 3 | 18 | 8.50 | 8.50 | 1.078 | 1.079 | 1.087 | 1.5% | 0.447 |  | measured, whole grid |
| net_deliver_admit | prismpath-hw/demo/flows/net_deliver_admit.md | 718781a94c8e | 3 | 45 | 9.60 | 9.69 | 1.217 | 1.217 | 1.225 | 1.3% | 0.344 |  | measured, whole grid |
| big_values | integrations/vector/interference/big_values.md (also integrations/vector/soak/big_values.md) | 1b556f3a8028 | 3 | 60 | 9.85 | 9.95 | 1.248 | 1.248 | 1.256 | 1.2% | 0.570 |  | measured, whole grid |
| crypto_agility_cnsa2 | prismpath/flows/crypto_agility_cnsa2.md | b09a107541d9 | 4 | 16 | 10.00 | 10.34 | 1.266 | 1.266 | 1.274 | 1.2% | 1.172 (3 nodes) | 3.25 | measured, whole grid |
| pr_review | prismpath/gallery/pr_review/pr_review.md | e8dde1862e89 | 4 | 16 | 10.00 | 10.00 | 1.266 | 1.266 | 1.274 | 1.2% | 1.016 (3 nodes) | 3.00 | measured, whole grid |
| intent_responses | integrations/governed_intent/policy/intent_responses.core.json | 4e71d6cf5609 | 4 | 8 of 24 | 10.50 | 10.83 | 1.328 | 1.328 | 1.336 | 1.2% | 0.428 |  | measured, whole grid |
| overlay | prismpath/examples/operator_overlay/overlay.md | 57e2873cdf2e | 4 | 24 | 10.50 | 10.50 | 1.330 | 1.330 | 1.338 | 1.2% | 0.532 |  | measured, whole grid |
| net_triage | prismpath-ebpf/net_triage.md | 473f884879a2 | 3 | 90 | 10.54 | 10.70 | 1.334 | 1.334 | 1.342 | 1.2% | 0.491 |  | measured, whole grid |
| nist_800171_generic | adapters/compliance/flows/nist_800171_generic.md | f357f13d9f0a | 4 | 32 | 10.75 | 11.07 | 1.359 | 1.360 | 1.368 | 1.1% | 2.078 (7 nodes) | 2.25 | measured, whole grid |
| net_triage_enforce | prismpath-ebpf/net_triage_enforce.md | ee19046589b0 | 3 | 110 | 10.83 | 11.00 | 1.371 | 1.370 | 1.378 | 1.1% | 0.505 |  | measured, whole grid |
| sensor_interlock | prismpath/comparisons/systems/prismpath/generated/sensor_interlock/sensor_interlock.md | a46fb46041af | 4 | 36 | 11.00 | 11.00 | 1.391 | 1.392 | 1.400 | 1.1% | 0.474 |  | measured, whole grid |
| access_control_rbac_abac | prismpath/comparisons/systems/prismpath/generated/access_control_rbac_abac/access_control_rbac_abac.md | af8c73c99d1f | 4 | 54 | 11.50 | 12.47 | 1.455 | 1.455 | 1.463 | 1.1% | 0.400 |  | measured, whole grid |
| fusion_triage | adapters/fusion/flows/fusion_triage.md | f7aa7328367c | 4 | 108 | 12.25 | 13.13 | 1.549 | 1.548 | 1.556 | 1.0% | 1.021 (2 nodes) | 4.70 | measured, whole grid |
| network_admission | prismpath/comparisons/systems/prismpath/generated/network_admission/network_admission.md | 4cea1e0a12dd | 4 | 144 | 12.75 | 12.83 | 1.611 | 1.611 | 1.619 | 1.0% | 0.517 |  | measured, whole grid |
| switch_nav | prismpath-hw/demo-display/switch_nav.md (also prismpath-hw/hyst-cert/evidence/switch_nav.md) | 09320ba510d6 | 4 | 256 | 13.00 | 12.67 | 1.641 | 1.641 | 1.649 | 0.9% | 1.196 (4 nodes) | 2.36 | measured, whole grid |
| expense_approval | prismpath/comparisons/systems/prismpath/generated/expense_approval/expense_approval.md | 3bcef6036083 | 5 | 72 | 13.50 | 14.24 | 1.703 | 1.704 | 1.712 | 0.9% | 0.613 |  | measured, whole grid |
| wazuh_triage | prismpath/flows/wazuh_triage.md | 33e5d918483a | 5 | 128 | 14.00 | 14.64 | 1.766 | 1.766 | 1.774 | 0.9% | 1.485 (4 nodes) | 3.50 | measured, whole grid |
| wazuh_triage_decomposed | prismpath/flows/wazuh_triage_decomposed.md | 2a8562e47bf2 | 5 | 128 | 14.00 | 14.64 | 1.766 | 1.766 | 1.774 | 0.9% | 4.703 (13 nodes) | 3.25 | measured, whole grid |
| agent_review.rules | prismpath/agent/policy/agent_review.rules.md | bbb3331be6e6 | 5 | 120 | 14.10 | 15.53 | 1.779 | 1.780 | 1.787 | 0.9% | 0.328 |  | measured, whole grid |
| net_frontend_cert | prismpath-ebpf/net_frontend_cert.md | e48bbd040d91 | 5 | 162 | 14.50 | 14.50 | 1.830 | 1.830 | 1.838 | 0.9% | 0.502 |  | measured, whole grid |
| example | integrations/cfs/prismpath_app/policy/example.core.json | f1656994405e | 5 | 180 | 14.60 | 14.83 | 1.842 | 1.842 | 1.850 | 0.9% | 0.433 |  | measured, whole grid |
| hr_onboarding | prismpath/flows/hr_onboarding.md | d03b3b2ebd41 | 6 | 96 | 15.50 | 15.50 | 1.955 | 1.955 | 1.963 | 0.8% | 0.953 (2 nodes) | 3.83 | measured, whole grid |
| room_fusion | prismpath-hw/esp-vision-c6/flows/room_fusion.md | f33c781633f4 | 6 | 144 | 16.00 | 16.01 | 2.016 | 2.017 | 2.024 | 0.8% | 0.603 |  | measured, whole grid |
| evaluation | integrations/governed_population/policy/evaluation.core.json | 89aae0e33a1f | 5 | 32 of 162 | 16.50 | 17.16 | 2.078 | 2.078 | 2.086 | 0.8% | 0.390 |  | measured, whole grid |
| ai_action_gate | prismpath/comparisons/systems/prismpath/generated/ai_action_gate/ai_action_gate.md | 2e35f8effd12 | 6 | 600 | 17.70 | 19.14 | 2.229 | 2.229 | 2.237 | 0.7% | 0.636 |  | measured, whole grid |
| agent_default.rules | prismpath/agent/policy/agent_default.rules.md | 40d664a9ba5a | 6 | 672 | 17.75 | 19.28 | 2.234 | 2.235 | 2.243 | 0.7% | 0.318 |  | measured, whole grid |
| agent_rules.rules | prismpath/agent/policy/agent_rules.rules.md | aeb47fd1452f | 6 | 672 | 17.75 | 19.28 | 2.234 | 2.235 | 2.243 | 0.7% | 0.318 |  | measured, whole grid |
| receiver_admission | prismpath-hw/esp-vision-node/flows/receiver_admission.md | 6898308afd5e | 6 | 729 | 18.00 | 17.99 | 2.268 | 2.267 | 2.275 | 0.7% | 0.576 |  | measured, whole grid |
| net_rules | integrations/governed_net/policy/net_rules.core.json | fccaa84d59d5 | 6 | 3,168 of 3,744 | 20.17 | 21.07 | 2.537 | 2.539 | 2.546 | 0.6% | 0.532 |  | measured, whole grid |
| agent_review | prismpath/agent/policy/agent_review.core.json | 5b646d0d2699 | 11 | 537,600 | 34.28 | 36.49 | 4.303 | 4.304 | 4.312 | 0.4% | n/a |  | measured, sample |
| agent_default | prismpath/agent/policy/agent_default.core.json | 14972b2e16ee | 12 | 1,075,200 | 36.78 | 39.17 | 4.621 | 4.614 | 4.622 | 0.3% | n/a |  | measured, sample |
| agent_rules | prismpath/agent/policy/agent_rules.core.json | 44ac23b8ec63 | 12 | 1,075,200 | 36.78 | 39.17 | 4.621 | 4.615 | 4.623 | 0.3% | n/a |  | measured, sample |
| intent_calls | integrations/governed_intent/policy/intent_calls.core.json | 948062fd7e35 | 18 | 206,438,400 | 53.12 | 56.21 | 6.660 | 6.654 | 6.662 | 0.2% | n/a |  | measured, sample |
| admission | integrations/governed_population/policy/admission.core.json | 3bd992d76ebe | 19 | 44,040,192 of 55,050,240 | 53.25 | 54.97 | 6.676 | 6.671 | 6.678 | 0.2% | n/a |  | measured, sample |
| occupancy_6x8_v2 | prismpath-hw/esp-vision-node/flows/occupancy_6x8_v2.md | 2e900946be09 | 101 | 3.01e+59 | 325.00 | 333.01 | 40.656 | 40.642 | 40.650 | 0.0% | n/a |  | measured, sample |
| occupancy_6x8 | prismpath-hw/esp-vision-node/flows/occupancy_6x8.md (also prismpath-hw/esp-vision-node/flows/occupancy_6x8_cam2.md) | af02be13bb55 | 101 | 3.01e+59 | 325.00 | 332.96 | 40.625 | 40.644 | 40.652 | 0.0% | n/a |  | measured, sample |

## Table: conformance cases and docs example (not in the distribution)

| policy | path | sha256 | fields | cells reachable | uniform bits (computed) | boundary bits (measured) | B/dec n=4,096 | B/dec n=64,484 | with ACK, n=64,484 | epoch share n=4,096 | O2 B/dec n=64,484 | O2 bits, largest node | method |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| decisions.json:strtruthy | decisions.json:strtruthy | 6efb04c30abe | 1 | 3 | 3.00 | 3.40 | 0.393 | 0.392 | 0.399 | 4.0% | 0.391 |  | measured, whole grid |
| decisions.json:numeq | decisions.json:numeq | 0c48a94846f2 | 1 | 4 | 3.25 | 3.44 | 0.422 | 0.422 | 0.430 | 3.7% | 0.360 |  | measured, whole grid |
| decisions.json:truthynum | decisions.json:truthynum | c7bc2b0f3399 | 1 | 4 | 3.25 | 3.44 | 0.422 | 0.422 | 0.430 | 3.7% | 0.391 |  | measured, whole grid |
| decisions.json:numin | decisions.json:numin | 5c188bf765a0 | 1 | 9 | 4.44 | 4.36 | 0.572 | 0.573 | 0.580 | 2.7% | 0.391 |  | measured, whole grid |
| decisions.json:cat | decisions.json:cat | e5d5316a6ba1 | 2 | 8 | 5.75 | 6.24 | 0.734 | 0.735 | 0.743 | 2.1% | 0.469 |  | measured, whole grid |
| decisions.json:pipeline | decisions.json:pipeline | c60ff970cf35 | 3 | 12 | 8.00 | 8.40 | 1.016 | 1.017 | 1.025 | 1.5% | 0.745 (2 nodes) | 3.33 | measured, whole grid |
| release_policy | tools/release_policy.md | ebb822e7828b | 10 | 2,304 | 26.00 | 26.18 | 3.266 | 3.267 | 3.275 | 0.5% | 0.391 |  | measured, whole grid |
