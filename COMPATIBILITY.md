# Compatibility

What this product promises about the research material it carries: the frozen reference hashes below, at the
research revision they were taken at. A check that passes here means the product still agrees with those
hashes. The product repository is generated from the research repository (`PROVENANCE.md` names the commit
of this tree), so there is no separate line to be current with.

## Revision the hashes were taken at

Research source: crystal-warden/prism-path at commit `386539913bf721e6f7fff42f2d49ddd38212406d` (research main).
The hashes of the research files at that commit are the adopted hashes below, and they change only when a
frozen corpus, the cause registry or a compiler reference changes on purpose, in the same research commit.
The product's own copies of the specifications are the research files, so a product copy may have been
reworded with the meanings preserved; `SHA256SUMS` holds the hashes of every file of this tree, which are a
different thing. The Rust parity work (the engine, causes, wire profiles, hot swap host and receipt verifiers)
was done in the product first and is research's too, so the corpora it generates are research's bytes.

## Specifications

| Document | Adopted version | Adopted sha256 | Product copy |
|---|---|---|---|
| SPEC.md, the flow format | spec version 1 (draft) | `934cf9d2244cdbbd3739697a4800f6983e003afce06b5353cbe0a734a6a68034` | unedited copy |
| PROTOCOL.md, the Facet wire | Facet/1 (draft) | `7a5b9230a86775b83c5fdd6fa519155f0813bb68c806af4a13a8595c65e826af` | unedited copy |
| TABLE_FORMAT.md, the PPT v1 image | PPT v1 | `f0561aaeef21e7494f63cf363b23d425417b904bcf655c67e69b7a6751dd017c` | not carried, [read it at the adopted revision](https://github.com/crystal-warden/prism-path/blob/a0cccf85e92823b3ec5cc8b102c1420bdf3dfb47/prismpath-hw/TABLE_FORMAT.md) |
| docs/DICTIONARY.md, the vocabulary | as of the adopted revision | `ac333f1941118f702f8d178433b6a0bef473068ca5b63b6002ead4d1bf6678e7` | product subset, meanings preserved, see below |

The supported subset: the product implements spec version 1 in Python and Rust and carries the
frozen vectors for it; the JavaScript kernel, the Go kernel, the C target, the fabric, the
microcontroller firmware and the kernel programs implement the same spec in research and are not
carried. Facet/1 is implemented in Python and Rust here. The PPT v1 image is produced by the carried
compiler and consumed by the carried pack, verify, swap and attest machinery; the substrates that
execute it are not carried.

## Formats and shared identifiers

| Item | Value | Where it is checked |
|---|---|---|
| Cause registry | sha256 `9471482836236670c8986c40dace5b28261f1242cab7cbaecc135e756f07f58e` over the registry, every identifier and meaning frozen | `prismpath/tests/test_causes.py` |
| Pack format | `ppt-pack/1` | `prismpath/tests/test_policy_pack.py` |
| Signing suites | the crypto agility registry | `prismpath/tests/test_crypto_registry.py`, `test_crypto_agility.py` |
| Wire framing | Facet/1 packed records, epochs, receipts | `prismpath/telemetry/tests` and `prismpath-telemetry-rs/tests` |

A shared cause identifier keeps its research meaning. The product never repurposes one to report
product only behavior; a new condition would need a new identifier, proposed to research first.

## Frozen conformance corpora

Adopted byte for byte. Each crate carries the files its tests read as byte identical copies under
`tests/fixtures/`, checked by `tools/fixture_sync.py`.

| Corpus | Adopted sha256 |
|---|---|
| `prismpath/portable/conformance/capability.json` | `aae25200a171935e0b044d5a6d30189255779416eeb2e33fa03bbf2af9f1c166` |
| `prismpath/portable/conformance/connector.json` | `450b06cc4cdf9437f5d01b91cf619c74b06141dc422a46374eea8989824e0cfe` |
| `prismpath/portable/conformance/context.json` | `92ee7ef710dbcb3fbed8e1ef0710db0aa4789286019a3945761a7eaa8d6af78f` |
| `prismpath/portable/conformance/crypto_agility.json` | `1b53137bc7ce40f92e2db9019dd7b45d09e7fa53ff5b6172e04a3910522df335` |
| `prismpath/portable/conformance/crypto_migration.json` | `cc66c981e249f0985645d952f7ea7bdcdf2829048acfe03a0e69ee4005005a25` |
| `prismpath/portable/conformance/durable.json` | `a583cca8f431219c0ac8826435c7adf7402734aa1d93fac5d6a9ba6d8a0fc097` |
| `prismpath/portable/conformance/field_definitions.json` | `9b7ac91eef3b596f6fbd09235cb909500fa4a45a0425a2cab0ec699987f4e02b` |
| `prismpath/portable/conformance/flows.json` | `61b2f5dca524de5dfa5756470e0120aa27126e57cf738c048d5b7839ccbbfb67` |
| `prismpath/portable/conformance/hotswap.json` | `3ae0e3c79abcd3d198cf949254d40585ed3c01e48e903bcfb7a264b547ae9a1e` |
| `prismpath/portable/conformance/level_m.json` | `58b811a0ba277b359508ca15eed690415b0e0751ccbe76037001ad967bcb8d1d` |
| `prismpath/portable/conformance/locked_flows.json` | `b47ba47d9bed0e1dada54edc7d9c9c274cd39524075ae66360b9efd503ada1e4` |
| `prismpath/portable/conformance/predicates.json` | `7ac112866e36147202866f7615ea6592ba828578d04368bebb2d90405e7bb711` |
| `prismpath/portable/conformance/reach.json` | `98f00afc250f68dc8b552905236fdca221e0e4ee31bc306644c290cd017ff9d6` |
| `prismpath/portable/conformance/safety.json` | `c1a5c7e5bbe3ada30a275d9c803572497bf9c8f2a0f240a0e8aea208ef6febe1` |
| `prismpath/portable/conformance/canon2.json` | `d7586e08b0553c6c43c96ce4ceb28f848220b5847c11514b914c5c19347120f9` |
| `prismpath/portable/conformance/causes.json` | `7c6d03c2ccf93a304cd9262f8dfaa6396bd1ad8c90248eedb091953a6dc99fcb` |
| `prismpath/portable/conformance/contract.json` | `4870c09d492e8b284c295f711b069b336b524e9397e7cb8a97609a25a3aabf7c` |
| `prismpath/portable/conformance/host_trace.json` | `b8b2e544933b8686b82208ae4055463b01a9870c17512595d6b99a6d00d07923` |
| `prismpath/portable/conformance/parse_limits.json` | `d8ab4b07445cb0feb0babdfdaf3ad76fefd4873f8a4e2d09b5aeeee51ac16bf2` |
| `prismpath/portable/conformance/receipts.json` | `d7046902c0c51ebaae9244ec729532179a0c7a95374310bea49e0b8d42610203` |
| `prismpath/telemetry/conformance/boundary.json` | `00d4ec70d1f49b7fbe0d985f51d325fdeea60c52a5e8b9ff39f4cc29fa3062c4` |
| `prismpath/telemetry/conformance/decisions.json` | `6b68a08de7f57cdd11bee07bd256587094dc353b959d1195473c6880472479c8` |
| `prismpath/telemetry/conformance/defined_wire.json` | `b786774c3abbf9826fc33d1ee831aa8be4b3ee2023e043f0d8c41a27eca818db` |
| `prismpath/telemetry/conformance/inputs.json` | `3af3541d5107695114acbb7d19e0083e3e1e5ff53623cb8427bffbe443a4f7dc` |
| `prismpath/telemetry/conformance/policy_forms.json` | `1f7b71c29a7b5983b31dbb10bfd72d6e3757d5ee84bc07b919a553ed8468699d` |
| `prismpath/telemetry/conformance/receipts.json` | `78181a5873ed88e5cd17ccae216641a09f9ec3bd79fcc3562fc4de452c539974` |
| `prismpath/telemetry/conformance/spiral.json` | `050b031bf5c55cbf0fbd88a562ad80a58446b1466a10d1126fc974bb9a0dc444` |
| `prismpath/telemetry/conformance/refresh.json` | `354097ed1289233787789718baeb2f03367f56e303d6fac213621571dd9f0194` |
| `prismpath/telemetry/conformance/replay.json` | `8cc5617e2e08c36fcdaf8c577360384d0f6eb1fc73e2877f59b434cf94890bdd` |
| `prismpath/telemetry/conformance/receipt_stream.json` | `f61fc3b9fd705e66ad8d928a0f9d2adcefd6055fe505b8e838db2390ab062ab8` |
| `prismpath/telemetry/conformance/concentrator.json` | `3e8730d0ec208c7ccba34df20b597105bffade447f73249d8cb50c956885f706` |

`prismpath/portable/conformance/flows.json` and `locked_flows.json` are regenerated, in research as well: every `expect` carries `cause`, the registry code `RunResult.cause` holds when the run stops (0 for `terminal` and `waiting`, 37 `route:contract-violation`, 36 `route:stuck`, 35 `route:max-steps`, 34 `route:needs-human`, 33 `route:below-human-floor`), and `prismpath-rs`'s conformance binary compares it. `flows.json` also holds 80 cases after the 27 frozen ones (107 in all; the product's earlier 45 were extended with the error kinds, the guard records and the refusal of a negative `max_transcript`) (`prismpath/portable/engine_surface_fixtures.py`) for the engine options the frozen cases leave out: each has `opts` (`type_gate`, `max_transcript`) and expects the `contract_violation` stop with its `violations`, and the persisted `transcript` and `state_dropped` after a `@state_bound`; a malformed `@state_bound` expects the error. A kernel that does not implement the options skips a case that has `opts`, and the 27 frozen cases and their order are unchanged. Their adopted hashes above are research's.

`prismpath/portable/conformance/contract.json` is a generated corpus, adopted from research byte for byte: `prismpath/portable/gen_contract_fixtures.py` writes it by running `prismpath.kernel.contract` (derive, JSON Schema, describe and the type gate's `validate_output`) over 56 flows and 21 worker outputs, `prismpath/tests/test_contract_corpus.py` regenerates it, and `prismpath-rs/tests/test_contract.rs` replays it and derives every flow again by a live Python. `prismpath-rs/tests/test_engine_cross_language.rs` runs both engines over every flow of `flows.json` and `locked_flows.json` and over a seeded random sample of 600 flows (20,000 once, by hand: no mismatch) with every combination of the type gate, the bound, `run_id` and the routing decision observer, and compares the path, stop, cause, pending decision, transcript, dropped counts, visit counters, each step's whole info (how it was routed, the scores of a locked route to 1e-5, the worker's error kind, the count of unevaluable error guards), the guards recorded, each refusal's class and message, each `on_step` call and each decision record in order (the sample's workers fail with kinds, and its flows route on them and on guards that cannot be evaluated and into a node that is not defined); `prismpath-rs/tests/test_engine_surface.rs` has Python resume a gated checkpoint Rust wrote and Rust resume one Python wrote.

`prismpath/portable/conformance/parse_limits.json` is a generated corpus, adopted from research byte for byte: `prismpath/portable/gen_parse_limits_fixtures.py` writes it by running `prismpath.kernel.parser.parse` under small caps (49 documents: each cap exactly met and one over it, where the reference counts, which cap a document reaches first), under the default caps (6 documents built from a rule) and over the strings an environment variable may hold, `prismpath/tests/test_parse_limits_corpus.py` regenerates it, and `prismpath-rs/tests/test_parse_limits.rs` replays it and has a live Python parse 1500 random documents under random caps. A document over a cap comes back from Rust's `parse` with `parse_error` set and no nodes (Python raises `ParseError`), which the engine and `parse_checked` refuse.

`prismpath/portable/conformance/causes.json` is a generated corpus, adopted from research byte for byte: `prismpath/portable/gen_causes_rs.py` writes it and `prismpath-rs/src/causes.rs` from `prismpath.kernel.causes`, so the Rust registry cannot drift, and `prismpath-rs/tests/test_causes.rs` holds the table, the registry hash and the stop mapping to it and, with `PRISMPATH_PYTHON` set, to the live Python registry. `prismpath-hotswap-rs/tests/test_cause_names.rs` holds every refusal name the Rust verifier emits to the registry. Causes 48 to 51 (`wire:no-terminator`, `wire:dangling-codeword`, `wire:symbol-overflow`, `wire:codebook-mismatch`) are registered and no code in either language emits them; `prismpath/tests/test_causes_rs.py` pins that.

`prismpath/portable/conformance/hotswap.json` is generated: `prismpath/portable/gen_hotswap_fixtures.py` runs the Python gates over the image flag, safe node, WCET, packing, overlay and flow hash cases as well as the original signed packs, and the Rust crate replays all of it.

`prismpath/portable/conformance/canon2.json` is a generated corpus, adopted from research byte for byte:
`prismpath/portable/gen_canon2_fixtures.py` writes it by running `prismpath.kernel.canon2`, and
`prismpath-rs/tests/test_canon2.rs` replays it. It pins the canon/2 bytes, the strict reader's refusals by rule
(a case's `refuse`, among them `not-canonical` for a document spelled another way) and the canonicalize
path's bytes (`canonical_hex`), and `prismpath/tests/test_canon2.py` also checks it against the Lean oracle
when one is built, which the product does not carry. canon/1 is retired in research and here, so the former
`canonical.json` corpus and its generator are gone; the inputs canonical JSON has no form for are pinned in
`prismpath-rs/tests/test_canonical.rs` and `prismpath/tests/test_canon_nonfinite.py`.

`prismpath/portable/conformance/host_trace.json` is a generated corpus, adopted from research byte for byte, too:
`prismpath/portable/gen_host_trace_fixtures.py` runs the Python `PolicyHost` and `AuditLog` over 65
operation lists under a counter clock and records every result, audit event, leaf, Merkle root and
state directory file; `prismpath/tests/test_host_trace_corpus.py` regenerates it, and
`prismpath-hotswap-rs/tests/test_host_trace.rs` replays it byte for byte. The crash injection test
(`test_host_crash.rs`, a stop or a kill before each step of a swap and of a rollback) and the cross language host test (`test_host_cross_language.rs`) read the same packs.

`prismpath/portable/conformance/receipts.json` holds 251 cases for the receipt and flow authority verifiers: the Merkle tree, audit trails with their root statements, receipt bundles, flow manifests, the version floor and the instance and authority key separation. `prismpath/portable/gen_receipt_fixtures.py` writes it from the Python reference with fixed keys and clocks, so regeneration is byte identical; `prismpath/tests/test_receipt_vectors.py` regenerates it and replays every case through `prismpath.ledgers.root_statement` and `prismpath.hotswap.flow_authority`, and `prismpath-hotswap-rs/tests/test_receipt_verify.rs` replays it through the crate's verifiers (`root_statement`, `merkle`, `flow_authority`) and requires every verdict to match, with `test_receipt_edges.rs` pinning the places the crate is stricter (the README lists them). The Rust side verifies and never signs.

The wire profiles each have a corpus and a Rust consumer. `receipts.json` is adopted as frozen; `receipt_stream.json`,
`replay.json`, `refresh.json` and `concentrator.json` are generated and adopted too, written from the Python
modules by `prismpath/telemetry/gen_profile_corpora.py` (`prismpath/telemetry/tests/test_profile_corpora.py`
regenerates them and fails on a difference), with the crate's copies checked by `tools/fixture_sync.py`.

| Telemetry corpus | Python consumer | Rust consumer |
|---|---|---|
| `boundary.json` | `test_boundary_parity.py` | `prismpath-telemetry-rs/tests/test_boundary_parity.rs` |
| `decisions.json` | `test_decisions_preserved.py` | `test_conformance_decisions.rs`, `test_xwire_parity.rs` |
| `defined_wire.json` | `test_defined_fields.py` | `test_defined_fields.rs` |
| `inputs.json` | `test_acceptance.py` | `test_acceptance.rs` |
| `policy_forms.json` | `test_policy_forms.py` | `test_policy_forms.rs` |
| `spiral.json` | `test_spiral.py` | `test_conformance_spiral.rs` |
| `receipts.json` | `test_receipts.py` | `test_receipts.rs` |
| `receipt_stream.json` | `test_profile_corpora.py` | `test_receipts.rs` |
| `replay.json` | `test_profile_corpora.py` | `test_replay.rs` |
| `refresh.json` | `test_profile_corpora.py` | `test_refresh.rs` |
| `concentrator.json` | `test_profile_corpora.py` | `test_concentrator.rs` |

`test_cross_language.rs` has Python verify the receipts, concentrated datagram and tick stream Rust writes,
and Rust verify what Python writes. A Facet integer beyond 64 bits is read by Python and refused by Rust (DIVERGENCES.md).

Checks that run on them: `prismpath/tests/test_conformance_vectors.py` (the Python engine regenerates
`flows.json` and the predicate vectors identically), `test_level_m_conformance.py`,
`test_reach_conformance.py`, `test_capability_conformance.py`, `test_safety_vectors.py`,
`test_crypto_agility.py`, `test_crypto_migration.py`, `test_rust_conformance.py` (cross language),
`test_field_definitions.py` (field definitions, the canonical conversion and lowering, SPEC.md section
4.5), the crate tests, and `prismpath/telemetry/tests` with `prismpath-telemetry-rs/tests` for the wire,
where `test_acceptance`, `test_defined_fields` and `test_policy_forms` replay the acceptance, defined
wire and policy forms corpora in both languages.

## Compiler references

`prismpath/tests/fixtures/compiler/` holds thirteen regression pairs, each an image and its names
sidecar, plus one historical image, with `SHA256SUMS` over all of them except itself.
`prismpath/tests/test_compiler_parity.py` compiles each source flow into temporary output and
compares bytes against these references. It never regenerates them.

compiler references generated 2026-09-19T16:12Z
source: crystal-warden/prism-path 40a9b05b3523cb4943b583b77c6fb86f93d795ee, materialized with git archive into scratch (prismpath/ and prismpath-hw/ppt_compile.py), never the working tree
tool: prismpath-hw/ppt_compile.py at that commit, run as: python prismpath-hw/ppt_compile.py prismpath/<flow>.md -o <stem>.ppt --json <stem>.names.json (max-steps default 25)
interpreter: Python 3.12.3, numpy 2.5.1, PYTHONDONTWRITEBYTECODE=1
determinism: each pair compiled twice, both outputs byte identical
sidecar serialization: json.dumps(dbg, indent=1) + newline, as written by ppt_compile --json; compared byte for byte
historical image: git show 40a9b05:prismpath-hw/evidence/incident_severity.ppt, sha256 314b033cd1251b6da7671cbd8a209be0b46d3babd77e254bed1b669ea4d83065, equal to the pinned recompile of gallery/incident_severity/incident_severity.md; anchored in prismpath-hw/evidence/SHA256SUMS at that commit

The thirteen pairs are regression evidence for the carried flows. They are not a proof over the
whole supported compiler domain. The historical image carries its own provenance, the research
hardware evidence manifest at the adopted revision
([`prismpath-hw/evidence/SHA256SUMS`](https://github.com/crystal-warden/prism-path/blob/a0cccf85e92823b3ec5cc8b102c1420bdf3dfb47/prismpath-hw/evidence/SHA256SUMS)); its presence
here establishes nothing new about FPGA, microcontroller, eBPF, timing or field behavior.

## Dictionary

The product Dictionary is the file `tools/mirror/docs/DICTIONARY.md` in the research repository, kept by hand
beside the research Dictionary it is a subset of: every entry whose layer is flow authoring, kernel evaluation, wire and transport, evidence and
receipts, control plane, or all, plus `image`, and dropping the substrate execution and GRC entries.
Entry text is unchanged; the preamble is the product's. A term shared with research keeps its
meaning here.

## What the research evidence does and does not cover

The research evidence ledger at the adopted revision
([`docs/research/supporting-evidence.md`](https://github.com/crystal-warden/prism-path/blob/a0cccf85e92823b3ec5cc8b102c1420bdf3dfb47/docs/research/supporting-evidence.md)) supports
the behavior of the code as it was at that commit. Once the code changes, only the checks run on the shipped
version speak for it: the product CI and the acceptance gates listed in `tools/README.md`. A pinned
evidence link certifies the commit it names, not later code.

## Running the checks

```bash
python tools/check_compatibility.py      # adopted hashes, registry, compiler references, crate fixture equality
python tools/fixture_sync.py             # crate fixtures byte equal to the product corpora
```

Both read only files in this repository. Neither needs the network or a research checkout.
