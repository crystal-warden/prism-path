# PrismPath flows · the VS Code editor surface

Three things, all thin wrappers over the repo's own tooling:

1. **Tier-aware highlighting.** A TextMate *injection* grammar colors flow constructs inside
   ordinary Markdown; no new file extension, `.md` stays `.md`. Edge lines are scoped by **tier**
   (`when …` deterministic, `on error`, `on event`/`on timeout`, `always`, and natural-language
   semantic conditions render as italic strings), plus `@annotations`. Any theme picks it up.
2. **Live preview** (`Flow: Open Preview`, editor-title button). Hosts the SAME
   `portable/playground.html` + `prismpath.mjs` as the browser playground; the dependency-free,
   conformance-tested JS kernel; in a webview, seeded from your buffer and re-fed on every edit:
   tier badges, live compile checks, ▶ Run, the Mermaid graph. **No Python required.**
3. **Validate-on-save diagnostics** (optional). If the Python toolchain is installed,
   `prismpath validate --json` findings appear as squiggles on their `## node` lines
   (configure/disable via `prismpath.validateCommand`).

## Run it from the repo (no build)

Open this repo in VS Code → Run and Debug → **Run Extension** (or `code --extensionDevelopmentPath
prismpath/editor/vscode`). In dev mode the preview reads `../../portable/` directly; no copies.

## Package it

```bash
cd prismpath/editor/vscode
npm test                 # grammar tier-classification tests + syntax checks
npx @vscode/vsce package # runs the sync script, emits prismpath-flows-0.1.0.vsix
```

The `.vsix` bundles its own copy of the playground + kernel (synced at package time; the repo never
carries duplicates). Marketplace publication is launch-gated with everything else.

## Other editors

Any LSP-capable editor (Neovim, JetBrains, Zed, …) gets diagnostics/completion/hover from
`prismpath lsp` instead; see [`../README.md`](../README.md). For highlighting alone:
the grammar (`syntaxes/prismpath.injection.json`) is plain TextMate; Sublime, Zed, and TextMate-lineage
editors can consume it directly; the semantic anchor is the scope names (`*.prismpath`).
