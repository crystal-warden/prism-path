# Security policy

## Reporting

Use **GitHub's private vulnerability reporting** on this repository (Security → "Report a
vulnerability"). Please do not open public issues for suspected vulnerabilities. You'll get an
acknowledgment within 72 hours, a triage verdict within 14 days, and we follow a **90-day
coordinated disclosure** window (shorter by mutual agreement, longer only if you agree).
Reporters are credited in the changelog unless you prefer otherwise.

## Supported versions

Pre-1.0: the latest release (and `main`) only.

## Scope — what counts

This project makes specific, falsifiable safety claims. Anything that breaks one of them is a
vulnerability we want to hear about **at highest priority**:

1. **Predicate-sandbox escape.** A flow document whose `when` / `on error when` condition
   achieves *any* code execution, file access, or non-`PredicateError` crash through
   `predicates.eval_condition` (or the portable port's `evalCondition`). The sandbox is
   fuzz-gated in CI; a bypass is a critical finding.
2. **Static-analysis false negatives on safety checks.** An unsafe predicate that
   `check_predicate`/`validate` passes but the evaluator accepts differently — or any
   divergence between `check` and `eval` acceptance (they must accept the same language,
   SPEC §4.4).
3. **Field-only boundary bypass.** A `@field_only` node whose routing can still be influenced
   by raw worker prose without a lint error.
4. **Conformance divergence.** An input on which the Python reference and the shipped JS port
   route differently (this is a *security* surface, not just correctness: policy enforced on
   two engines must be one policy). Repro = a `(condition, context)` pair or flow fixture.
5. **Lockfile/attestation bypass.** Routing that silently diverges from a verified lock, or a
   `verify_lock`/`verify_tree` pass on tampered vectors or a drifted embedder identity.
6. **Path traversal / queue escape** in checkpoint, queue, or ledger handling (e.g.
   `resolve_queue_item`), or Mission Control endpoint issues (note: MC binds loopback by
   design).
7. **Playground XSS** — `prismpath/portable/playground.html` renders user-pasted flows; script
   execution from a crafted flow document is in scope.
8. **Anchoring / attestation forgery.** With the ledger anchored (`ledger_ots.py`,
   `docs/design/spec-ledger-opentimestamps.md`): `verify_unit`/`verify_leaf` accepting a leaf not in the
   anchored batch, a backdated or otherwise invalid `.ots` proof passing verification, or a
   Merkle path validating against the wrong root. OTS's claim is *adversarial temporal
   integrity* — proofs that cannot be backdated or silently rewritten even with filesystem
   access — and breaking it is a finding.
9. **Policy hot-swap bypass** (`policy_pack.py` / `policy_host.py`,
   `docs/design/spec-secure-hotswap.md`): a `PolicyHost` accepting a swap that is unsigned, signed by
   an unknown or revoked key, over a tampered image, outside the signed envelope, or with a version
   at or below the persisted floor; a swap that leaves the runtime in a torn state instead of
   atomically keeping the prior policy; or the eBPF pre-loader (`net_swap.py`) reaching the kernel
   loader on any of the above. Authorization attaches to the **policy artifact** (its signed
   manifest), never to a user session, consistent with the control plane's "auth is a non-goal"
   posture: the swap gate authenticates *what runs*, and session/operator auth stays the deployer's
   responsibility.

## Scope — what does not count

- **Malicious or compromised workers.** Workers (including CLI workers) are arbitrary code you
  chose to run — the trust boundary is documented in AUTHORING §3 and GETTING_STARTED. The
  sandbox claim covers the *routing* layer only.
- **Resource exhaustion via authored flows you control** (e.g. `max_steps`-bound loops in your
  own document) — that's an authoring lint concern, not a vulnerability.
- **The git Flow-Ledger *without external anchoring* against an adversary with filesystem
  access** — an unanchored ledger's tamper-evidence is explicitly scoped to *accident*. Once
  anchored via OpenTimestamps / RFC-3161 (`ledger_ots.py`, shipped), this exclusion no longer
  applies — see in-scope item 8.
- Findings requiring a hostile local user on the operator's own machine.

## Hardening notes for deployers

**Mission Control is single-user and unauthenticated by design.** It binds loopback (`127.0.0.1`) by
default and ships no login, sessions, or credentials — authentication is a deliberate non-goal for the
reference control plane, not an oversight. Do not bind it to a public interface or expose it through a
reverse proxy without putting your own authentication in front of it; there is no built-in access control
to fall back on. Its only write surface is one path-contained endpoint (traversal rejected via `_safe`),
and request bodies, file reads, checkpoint loads, and the file listing are size/entry-bounded
(`MC_MAX_FILE_BYTES`, `MC_MAX_TREE_ENTRIES`) so a runaway request cannot exhaust memory. The
Content-Length body gate covers the common case; a chunked upload without a declared length is still
caught by the per-endpoint size check.

Treat flow documents from untrusted sources as untrusted *input* (they are safe to parse and lint by
design — that claim is exactly what §1–2 above defend), and pin your lockfiles in CI
(`prismpath lock --check`).

**Flow-parser input bounds.** The Python parser caps document size, node count, and edge count
(`PRISMPATH_MAX_FLOW_BYTES` = 2 MiB, `PRISMPATH_MAX_NODES` = 5000, `PRISMPATH_MAX_EDGES` = 20000) and
fails fast with a `ParseError` (a `ValueError`, so Mission Control returns it as a 400) before an
oversized or accidental document can exhaust memory or drive the polynomial static analysis off a
cliff. These are **host DoS bounds, not routing semantics**: they sit outside the cross-kernel
conformance contract (§4), which covers routing *decisions* on valid flows, and no realistic or
conformance-corpus flow approaches them. The portable JS/Rust/Go kernels are libraries bounded by
their host (the JS playground runs client-side, where an oversized paste only affects the paster's own
tab); raise the env caps if you have a legitimately enormous flow.
