# Formal toolchain (installed 2026-09-08)

| item | value |
|---|---|
| host | gx10-f60f, aarch64, 6.17.0-1032-nvidia |
| elan | elan 4.2.4 (227caca13 2026-08-25) |
| Lean | Lean (version 4.33.1, aarch64-unknown-linux-gnu, commit 819816b2e0a3bf405af45ae5c7af2491d8f5bee6, Release) |
| Lake | Lake version 5.0.0-src+819816b (Lean version 4.33.1) |
| Mathlib | tag v4.33.1, commit `0df444a360eaa60ab8c11dca51a86af692955474` (pinned in `lake-manifest.json`) |
| Mathlib cache | `lake exe cache get`, 8,690 files, `.lake/` about 7.5 GB, gitignored |

Lean was installed with `elan` into the user directory only (`~/.elan`), nothing system wide. The
project is `formal/` (`lakefile.toml`, `lean-toolchain`). Rebuild from a clean checkout:

```bash
curl -sSf https://elan.lean-lang.org/elan-init.sh | sh -s -- -y --default-toolchain leanprover/lean4:v4.33.1
cd formal && lake exe cache get && lake build
```

`lake build` compiles every module, evaluates the `#guard` checks in `FQ/Bridge.lean` (a false
guard fails the build), and prints the axiom audit from `FQ/Axioms.lean`. Not in the main CI matrix
by design (bare CI stays numpy plus pytest); this is a documented local gate.
