# prismpath-go · conformance certification against the frozen kernel spec

**Date:** August 2026 · **Verdict: CONFORMANT (Go Implementation)**

`prismpath-go` is the **third independent implementation** of the PrismPath core specification (joining `prismpath` Python reference and `portable/prismpath.mjs` / `prismpath-rs`).

## Architecture & Implementation Overview

`prismpath-go` provides a clean, zero-dependency Go implementation of the portable P0 kernel:

* **`predicates.go`**: Safe AST parser and recursive descent evaluator for `when` conditions. Implements Python AST truthiness rules, numeric boolean comparisons, keyword rejection, and depth-limited AST execution (max depth 50).
* **`parser.go`**: Markdown flow parser matching Python `splitlines()` boundaries (`\r\n`, `\r`, `\n`, `\v`, `\f`, U+0085, U+001C..U+001E, U+2028, U+2029) and parsing frontmatter, headings (`##`), edges (`->`), and annotations (`@`).
* **`engine.go`**: Engine execution loop tracking `visits`, `max_steps`, `needs_human`, `waiting`/`spawn`, and error tiers (`on error`). Refuses non-portable flows up front via `PortabilityViolations`.
* **`conformance_test.go`**: Go test runner asserting 100% bit-for-bit conformance against `portable/conformance/predicates.json` and `flows.json`.

## Replaying Conformance Tests

To run the conformance test suite:

```bash
cd prismpath-go
go test -v ./...
```

## Scope boundary

Kernel conformance ≠ the guard. The P0 content **guard** (`guard.py` / Journeyman's `guard.ts`) is an
**optional** floor, not a kernel feature; this package implements **no content guard**, by design.
Content safety is delegated to the model or an opt-in guardrail, while PrismPath owns provable routing
and (where it runs code) governed execution (the code-node sandbox). A conformant kernel is not a content-guarded one. See `docs/design/spec-guard-onion.md` §1.5.
