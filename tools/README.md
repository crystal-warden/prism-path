# The maintenance tools

This directory checks that the product tree is what the research repository makes and that it holds
together. The product repository, crystal-warden/prismpath, is a generated copy of the research
repository, crystal-warden/prism-path: all work lands in research `main`, and the product repository's
`main` changes only by export (`tools/export_clean.py`, which lives in research only). Every tool reads
files in the tree it is part of, none pushes, none merges, none publishes.

| Tool | What it is for |
|---|---|
| `tree.py` | the tree a tool looks at: its root, its files, and whether it is a product tree |
| `provenance.py` | `check` proves every file hashes to its line in `SHA256SUMS`; `check --research PATH` also runs the research checkout's exporter and proves the tree is exactly its output at the commit `PROVENANCE.md` names |
| `check_compatibility.py` | the frozen corpus hashes, the cause registry, the frozen compiler references recompiled into temporary output, crate fixture equality |
| `check_boundary.py` | no dangling local link, research links pinned to a commit, the files shipped features need are present; with `--wheel` or `--sdist`, every member of a built artifact is a file of the tree or build metadata, and the required members are there |
| `fixture_sync.py` | each crate's `tests/fixtures` corpora byte identical to the corpora in `prismpath/` |
| `acceptance.sh` | the acceptance gates, run from an exported copy of the tree outside any checkout; `--leg full`, `python`, or `rust`; `--research DIR` adds the proof against a research checkout; refuses any other leg and fails when a defined gate recorded no status; the extracted crates are tested together, patched to one another, never alone against the registry |
| `end_to_end.py` | one flow through the installed wheel (command line, engine, compiler, signing, host, ledger, wire, receipts, journal, preflight, console) and through the extracted Rust candidates, the two compared at every seam; the full leg runs it, and it refuses to run from a source tree |
| `release_policy.md` | a PrismPath flow, every edge deterministic, that decides release eligibility over the acceptance facts: eligible, refused, or missing evidence |
| `release_eligibility.py` | runs the flow over an acceptance output directory and writes `release_receipt.json`, bound to the revision, the artifact hashes, the policy flow and image hashes and the report hashes, appended to a Merkle committed `release_receipts.log`; advisory during adoption, the script's exit status decides |
| `tests/` | the maintenance suite for the tools above; needs the source tree |

In the research repository the same directory also holds `export_clean.py` and its overlay (`mirror/`,
`mirror_readme.md`, `mirror_publish.yml`), `tests/test_export.py`, and the research lint tools
(`arch_guard.py`, `arith_lint.py`, `docs_health.py`, `evidence_check.py`, `ledger_lint.py`,
`run_corpora.py`). The export carries none of them.

## The suites, selected explicitly

| Suite | Command | Needs |
|---|---|---|
| Product runtime | `python -m pytest --pyargs prismpath.tests prismpath.telemetry.tests -m "not cross_language"` | the installed package, numpy; the signing and control-plane extras and git to run every case |
| Cross language | `python -m pytest --pyargs prismpath.tests -m cross_language`, and `PRISMPATH_REQUIRE_CROSS_LANGUAGE=1 PRISMPATH_PYTHON=$(command -v python) cargo test -p prismpath-hotswap-rs --test test_hotswap_conformance --test test_host_trace --test test_host_crash --test test_host_cross_language` and `cargo test -p prismpath-rs --test test_connector file_deferral_store_is_cross_runtime`, `cargo test -p prismpath-rs --test test_causes`, `cargo test -p prismpath-rs --test test_contract --test test_engine_surface --test test_engine_cross_language` and `cargo test -p prismpath-telemetry-rs --test test_cross_language` | cargo and rustc on the PATH, the crate sources, and for the legs that run Python (a Rust signed pack, the two hosts opening each other's state directory, the file deferral store) a Python with prismpath and `cryptography`; with `PRISMPATH_REQUIRE_CROSS_LANGUAGE` set those tests fail instead of skipping when none is found; runs only in the combined gate |
| End to end | `python tools/end_to_end.py --candidates DIR --out DIR` | the installed wheel with every extra, the Rust toolchain, and a directory holding the four extracted candidate crates; the full leg supplies both |
| Crates | `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` | the Rust toolchain; no Python |
| Repository maintenance | `python -m pytest tools/tests` | the source tree and git |
| Compatibility | `python -m tools.check_compatibility` | the source tree or the installed package; no network |
| Boundary | `python -m tools.check_boundary` | the source tree |

The product runtime suite ships in the wheel. Cases that need an optional extra skip with a stated
reason when it is absent; the acceptance run installs the extras and treats any other skip as a
failure. The skips that remain legitimate, by test and reason, are listed in the acceptance report.

## One line of work, and how the product repository is updated

There is no second line. A change to the product is a change to the research repository, made on research
`main` and tested there. To update the product repository from a research commit:

1. On a clean checkout of research `main`, `python tools/export_clean.py --out ../prismpath` writes the
   tree over the product checkout's working tree (it keeps `.git`). The exporter refuses a working tree
   with uncommitted changes, so the tree names a commit that exists.
2. In the product checkout, `git status` shows exactly what the research commit changed. Review the diff.
3. Run `tools/acceptance.sh --leg full --research ../prism-path` from the product checkout, with the
   research checkout at the commit `PROVENANCE.md` names, and commit the tree and the report.

What the tree carries is the manifest at the top of `export_clean.py`; what it says about packaging and
CI is `tools/mirror/` in research; its README is `tools/mirror_readme.md`. Edit those in research. Nothing
in the product repository is edited by hand: a hand edit shows in `provenance check` and `check --research`.

`COMPATIBILITY.md` records the research revision its frozen reference hashes were taken at. It changes
when a frozen corpus, the cause registry or a compiler reference changes on purpose, in the same research
commit as the change.

## What the checksums are

`SHA256SUMS` lets a tree be compared with its export and lets a hand edit be noticed; `PROVENANCE.md` names the
research commit and tree. They are not signatures and prove nothing about who produced the tree.
