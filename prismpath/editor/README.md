# Editor support

Two complementary surfaces, both thin wrappers over the repo's own tooling:

1. **`prismpath lsp`**: a Language Server (stdlib only, ships with the pip package) for any
   LSP-capable editor: live diagnostics (the full `validate` check set, anchored to the
   offending edge line), completion (edge targets, predicate fields derived from the flow's own
   `when` edges, tier keywords, annotations), hover (node/edge tier summaries), document
   symbols, and a custom `prismpath/graph` request returning Mermaid for graph previews.
2. **The VS Code extension** (`vscode/`); tier-aware TextMate highlighting injected into plain
   Markdown, a live playground preview webview (the same JS kernel as the browser playground,
   no Python needed), and validate-on-save squiggles.

Semantic lint (`ambiguous-conditions` / `polarity-mirror`, needs `pip install -e
".[embeddings]"`) is opt-in: pass `initializationOptions: {"semantic": true}`.

## Neovim (built-in LSP client, 0.11+)

```lua
vim.lsp.config("prismpath", {
  cmd = { "prismpath", "lsp" },
  filetypes = { "markdown" },
  root_markers = { ".git" },
  -- init_options = { semantic = true },  -- enable embedder-backed lint checks
})
vim.lsp.enable("prismpath")
```

On Neovim 0.10 or with nvim-lspconfig, register the same `cmd`/`filetypes` via
`lspconfig.configs`. Diagnostics arrive on every keystroke; `gO` shows the node outline.

## JetBrains (IntelliJ, PyCharm, …)

Install the **LSP4IJ** plugin (Red Hat, marketplace), then *Languages & Frameworks → Language
Servers → +*:

- **Command:** `prismpath lsp`
- **Mappings → File name patterns:** `*.md` (or a `flows/` scope to keep prose Markdown clean)

## VS Code

The bundled extension (`vscode/`) already provides highlighting, the live preview, and
validate-on-save without the LSP. To use the LSP instead (or in another VS Code-family editor),
any generic LSP client extension works; point it at `prismpath lsp` for `markdown`.

## Zed / Helix / Sublime

Any editor with a generic LSP client config can register `prismpath lsp` against Markdown the
same way; the TextMate injection grammar in `vscode/syntaxes/` is directly consumable by
Sublime and Zed for highlighting.
