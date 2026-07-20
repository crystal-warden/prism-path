/* prismpath VS Code extension — the editor surface for flow files.
 *
 * Three things, all thin (the real machinery is the repo's own tooling):
 *  1. Syntax highlighting — a TextMate injection grammar (syntaxes/) colors edge lines by TIER
 *     (deterministic / semantic / error / event / always) and @annotations inside ordinary Markdown.
 *  2. Live preview — "Flow: Open Preview" hosts portable/playground.html (the SAME dependency-free,
 *     conformance-tested JS kernel as the browser playground) in a webview, seeded from the buffer
 *     and re-fed on every edit: tier badges, live checks, and the Mermaid graph, no Python needed.
 *  3. Diagnostics — on save, if the Python toolchain is on PATH, `prismpath validate --json` findings
 *     are mapped to their `## node` lines as squiggles. Silently disabled when the CLI is absent.
 */
const vscode = require("vscode");
const cp = require("child_process");
const fs = require("fs");
const path = require("path");

// A "flow" is a Markdown doc with front-matter (name/start) and `-> target:` edge lines.
function looksLikeFlow(doc) {
  if (doc.languageId !== "markdown") return false;
  const head = doc.getText(new vscode.Range(0, 0, Math.min(doc.lineCount, 12), 0));
  return /^---[\s\S]*?\bstart:\s*\S+[\s\S]*?---/.test(head) || /^\s*->\s*[\w-]+\s*:/m.test(doc.getText());
}

// The playground + kernel: bundled media/ (packaged extension) or ../../portable (repo dev mode).
function mediaDir(context) {
  const bundled = path.join(context.extensionPath, "media");
  if (fs.existsSync(path.join(bundled, "playground.html"))) return bundled;
  const repo = path.join(context.extensionPath, "..", "..", "portable");
  if (fs.existsSync(path.join(repo, "playground.html"))) return repo;
  return null;
}

function previewHtml(webview, dir) {
  let html = fs.readFileSync(path.join(dir, "playground.html"), "utf8");
  const kernel = webview.asWebviewUri(vscode.Uri.file(path.join(dir, "prismpath.mjs")));
  html = html.replace(/from\s+["']\.\/prismpath\.mjs["']/, `from "${kernel}"`);
  const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; ` +
    `img-src ${webview.cspSource} https: data:; style-src ${webview.cspSource} 'unsafe-inline'; ` +
    `script-src ${webview.cspSource} 'unsafe-inline' https://cdn.jsdelivr.net; ` +
    `connect-src https://cdn.jsdelivr.net; font-src ${webview.cspSource};">`;
  return html.replace(/<head>/i, `<head>\n  ${csp}`);
}

function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection("prismpath");
  context.subscriptions.push(diagnostics);
  let panel = null;

  const pushFlow = (doc) => {
    if (panel && doc && looksLikeFlow(doc)) {
      panel.webview.postMessage({ type: "prismpath:flow", text: doc.getText() });
    }
  };

  context.subscriptions.push(vscode.commands.registerCommand("prismpath.openPreview", () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !looksLikeFlow(editor.document)) {
      vscode.window.showInformationMessage("Open a flow (.md with front-matter + `->` edges) first.");
      return;
    }
    const dir = mediaDir(context);
    if (!dir) {
      vscode.window.showErrorMessage("prismpath preview assets missing (media/ or ../../portable).");
      return;
    }
    if (!panel) {
      panel = vscode.window.createWebviewPanel("prismpathPreview", "Flow Preview",
        vscode.ViewColumn.Beside,
        { enableScripts: true, localResourceRoots: [vscode.Uri.file(dir)], retainContextWhenHidden: true });
      panel.onDidDispose(() => { panel = null; }, null, context.subscriptions);
      panel.webview.html = previewHtml(panel.webview, dir);
    } else {
      panel.reveal(vscode.ViewColumn.Beside, true);
    }
    // seed after the module has a beat to load; the hook is idempotent, so also feed on edits
    setTimeout(() => pushFlow(editor.document), 300);
  }));

  let pending;
  context.subscriptions.push(vscode.workspace.onDidChangeTextDocument((ev) => {
    clearTimeout(pending);
    pending = setTimeout(() => pushFlow(ev.document), 300);
  }));

  context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((doc) => {
    if (!looksLikeFlow(doc)) return;
    const cmd = vscode.workspace.getConfiguration("prismpath").get("validateCommand");
    if (!cmd) return;
    cp.execFile(cmd.split(/\s+/)[0], [...cmd.split(/\s+/).slice(1), doc.fileName, "--json"],
      { timeout: 15000 }, (err, stdout) => {
        // The CLI exits nonzero on findings — that's data, not failure. Absent CLI: stay silent.
        if (!stdout) { diagnostics.delete(doc.uri); return; }
        let report;
        try { report = JSON.parse(stdout); } catch { diagnostics.delete(doc.uri); return; }
        const lines = doc.getText().split("\n");
        const nodeLine = (node) => {
          const i = lines.findIndex((l) => l.match(new RegExp(`^##\\s+${node}\\s*$`)));
          return i >= 0 ? i : 0;
        };
        diagnostics.set(doc.uri, (report.findings || []).map((f) => {
          const line = nodeLine(f.node);
          const d = new vscode.Diagnostic(
            new vscode.Range(line, 0, line, lines[line].length),
            `${f.message}`,
            f.severity === "error" ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning);
          d.source = "prismpath validate";
          d.code = f.code;
          return d;
        }));
      });
  }));
}

function deactivate() {}

module.exports = { activate, deactivate };
