# The integration contract — templating "first-class support" for external md-native tools

**Private (pre-launch).** The repeatable template for shipping first-class support for an external
tool, so each new synergy is a checklist instead of a negotiation-from-scratch. First instance:
prismpath-by-johnlindquist (below). The plugin ecosystem (`plugins/registry.py`, worker packs via
`prismpath plugins --new`) is the delivery vehicle for every row.

## What "first-class support" means (the deliverable set)

An integration ships ALL of these, or it isn't called first-class:

1. **A worker pack** (`<ourname>-<theirs>` via the `--new` scaffold): their tool wrapped as
   `@worker(<name>.<verb>)` bindings through `CliWorker` — we call their installed CLI; we never
   vendor or redistribute their code (license-clean regardless of their license, and their updates
   flow to users through their own channel).
2. **A pinned compatibility statement**: the pack declares the tool version range it is tested
   against; CI smoke-tests against the pinned version. Fast-moving tools (77 releases) make an
   unpinned adapter a support liability wearing a partnership costume.
3. **A gallery entry** that uses the pack — a real flow, `validate` clean, routing tests green —
   so `prismpath init --template <name>` scaffolds a working example of the integration.
4. **A docs page** with accurate, nominative attribution: their name used to refer to their tool,
   never to market ours; no implication of endorsement unless they've given it; a link out.
5. **The outreach note before shipping** (see etiquette).

## Etiquette (the "is this overstepping?" test, generalized)

Interop with an OSS tool is not overstepping — it is the normal life of open source — provided:
- **Adapter, not fork.** Call their interface; don't absorb their code or re-implement their tool.
- **Nominative use only.** Their mark names their tool. Ours names ours.
- **No implied endorsement.** "Works with X" is fine; "in partnership with X" needs their yes.
- **The gracious note.** Before the pack ships publicly, a short note to the maintainer: what we
  built, why their tool is a great worker, link to the adapter, offer to fix anything they dislike.
  Best case: a cross-link and a blessed integration. Worst case: we learn their objection before
  it's public. (For Lindquist specifically this note also gracefully settles the naming history.)
- **Version pinning + honest breakage policy.** When their interface moves and breaks the pack,
  the pack says so loudly (the registry audit lists versions) rather than silently misbehaving.

## The scouting checklist (for the md-entry-point repo hunt)

Score a candidate repo on:
| criterion | question |
|---|---|
| entry-point fit | is the .md file genuinely the executable/config artifact, or decoration? |
| altitude | do they run WORKERS (great — they slot under us), AUTHOR documents (great — they slot beside us), or route CONTROL FLOW (overlap — importer territory, like LangGraph)? |
| interface | machine-readable output (JSON/exit codes)? stdin/stdout discipline? |
| license | permissive enough for an adapter + example in our gallery? |
| activity + churn | alive enough to matter; stable enough to pin? |
| audience | does their community contain our buyer/user, or is it disjoint? |

## The integration ladder (cheapest sufficient rung wins)

1. **Gallery template** — a flow that happens to use their CLI via `cli_agent`. Zero contract.
2. **Worker pack** — named, pinned, tested bindings (`@worker`). The default rung.
3. **Adapter plugin** — deeper: their artifacts become flow inputs/outputs (e.g. their md file
   per node, engine inferred from their filename convention).
4. **Importer** — their control-flow-ish artifacts translate into flows (LangGraph precedent).
5. **Contracted partnership** — co-marketing, named compatibility, roadmap coupling. Requires
   their signature, not just their license.

Rungs 1–4 need no permission (license + etiquette suffice). Rung 5 is the only one that is
"templating contracts with an existing product" in the legal sense — and the template for it is
rungs 1–4 shipped first, as the demonstration that the integration is real.

## First instance: prismpath by johnlindquist (github.com/johnlindquist/prismpath, prismpath.dev)

**Facts (checked 2026-07-13):** MIT. A .md file = ONE LLM task: YAML frontmatter → CLI flags,
body → prompt, engine inferred from filename (`task.claude.md` → Claude, `task.codex.md` → Codex);
`md file.md` runs it; stdout output, `--json` for structured; stdin pipes in as `{{ _stdin }}`.
**No orchestration: no branching, routing, or multi-file control flow — each file is standalone**
(chaining = unix pipes). v4.6.0 (2026-07-13!), 77 releases, 595 stars — active and fast-moving.

**The altitude verdict: zero collision, maximal complementarity.** He owns "run one md task well";
we own "route between tasks with typed, auditable control flow." His files are *ideal workers* for
our nodes — frontmatter-configured, engine-per-file, JSON-out. The convergent belief (md as the
toolchain substrate) is validation, not competition: he made the md file the *unit of execution*;
we make the md file the *unit of control flow*. Together: an entire agent system where every layer
is a readable document.

**The pack (build when the locks clear; ~1 hour with the scaffold):**
- `@worker(prismpath.run)` — node instruction names/locates the task file; `CliWorker(["md",
  "{task}.md", "--json"])`; JSON fields feed `when` predicates; nonzero exit rides the error tier.
- The per-node engine story writes itself: a flow whose nodes are `triage.claude.md`,
  `summarize.codex.md`, `verify.gemini.md` — heterogeneous engines, one auditable control plane.
- Gallery entry: exactly that flow. Docs page: "PrismTrail + prismpath: route between md tasks."
- Naming in our docs post-rename: "prismpath" refers ONLY to his tool. Clean, and the gracious note
  turns the name history into goodwill.

**Sequencing unchanged:** pack ships post-locks (rename + provisional filed), note goes out just
before, week-2 drumbeat post follows. Nothing about today's research changes the gate.

## Candidate synergy classes for the hunt (seed list, verify before scoring)

- **Spec-driven dev**: GitHub spec-kit (md specs driving agent builds), PRP-style repos —
  altitude: beside/above us; integration: gallery templates + maybe importer.
- **Agent-config conventions**: AGENTS.md, CLAUDE.md, llms.txt — not tools but conventions;
  integration: our flows reference/consume them; a docs page claiming the convention.
- **md-native knowledge tools**: Obsidian (plugin embedding the playground via the postMessage
  hook), Foam/Dendron — altitude: authoring; integration: editor-surface ports.
- **md-runners like Lindquist's**: any repo where `run file.md` means something — the worker-pack
  rung by default.
- **Docs-site generators**: MkDocs/Docusaurus — live flow embeds via the playground hook (rung 1,
  nearly free already).
