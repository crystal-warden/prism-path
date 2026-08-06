"""lsp.py — a Language Server for PrismPath flows (`prismpath lsp`). Stdlib only.

Speaks LSP over stdio (JSON-RPC with Content-Length framing) so any LSP-capable editor —
Neovim's built-in client, JetBrains via LSP4IJ, VS Code, Helix, Zed — gets, on every keystroke:

  * **diagnostics** — the full `analysis.analyze` check set (+ composition checks when the
    document is on disk), mapped to the offending edge line where the finding names one,
    else the node's heading line;
  * **completion** — edge targets after `-> `, predicate fields (derived from the flow's own
    `when` edges via `contract.derive_contract`) + tier keywords in condition position, and
    annotation names after `@`;
  * **hover** — a node summary (edges with their routing tiers) or an edge's tier explanation;
  * **document symbols** — the nodes, so the outline pane is the flow;
  * **`prismpath/graph`** (custom request) — the Mermaid source for the current document, for
    clients that render graph previews.

Design constraints honored: zero dependencies (the kernel philosophy), and the reference parser
is untouched — line positions come from a standalone scan reusing `parser`'s own regexes, so the
parse itself cannot drift from the spec. Semantic lint (`ambiguous-conditions`, needs the
embedder extra) is opt-in via `initializationOptions: {"semantic": true}`.
"""
from __future__ import annotations

import json
import sys
from typing import Dict, List, Optional

from prismpath import analysis, predicates
from prismpath.parser import ANNO_RE, EDGE_RE, HEAD_RE, parse

# ------------------------------------------------------------------ framing

def _frame(payload: dict) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def _read_message(stream) -> Optional[dict]:
    """One framed JSON-RPC message from a binary stream; None on EOF."""
    length = None
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.strip()
        if not line:                                   # blank line ends the header block
            break
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    if length is None:
        return None
    body = stream.read(length)
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


# ------------------------------------------------------------------ document scanning

def _scan(text: str) -> dict:
    """Line map for a flow document, using the parser's own regexes: node heading lines and
    edge lines (0-based, LSP convention). Node names normalized exactly like the parser."""
    node_lines: Dict[str, int] = {}
    edges: List[dict] = []
    current = None
    for i, line in enumerate(text.splitlines()):
        h = HEAD_RE.match(line)
        if h:
            current = h.group(1).strip().lower().replace(" ", "_")
            node_lines.setdefault(current, i)
            continue
        e = EDGE_RE.match(line)
        if e and current is not None:
            edges.append({"node": current, "target": e.group(1), "condition": e.group(2),
                          "line": i, "text": line})
    return {"nodes": node_lines, "edges": edges}


def _line_range(i: int, text_line: str = "") -> dict:
    return {"start": {"line": i, "character": 0},
            "end": {"line": i, "character": max(len(text_line), 1)}}


def _finding_range(f, scan: dict, lines: List[str]) -> dict:
    """Best anchor for a finding: the edge line its message names, else the node heading."""
    if f.node and f.node in scan["nodes"]:
        for e in scan["edges"]:
            if e["node"] != f.node:
                continue
            if (f"-> {e['target']!r}" in f.message or f"'{e['target']}'" in f.message
                    or repr(e["condition"]) in f.message):
                return _line_range(e["line"], e["text"])
        i = scan["nodes"][f.node]
        return _line_range(i, lines[i] if i < len(lines) else "")
    return _line_range(0, lines[0] if lines else "")


def _tier(cond: str) -> str:
    if predicates.is_deterministic(cond):
        return "deterministic"
    if predicates.is_error(cond):
        return "error"
    if predicates.is_event(cond):
        return "event"
    return "semantic"


_TIER_BLURB = {
    "deterministic": "evaluated against the outcome fields — free, exact, first match wins",
    "semantic": "routed by embedding similarity (LLM on low margin) — needs the semantic tier",
    "error": "fires only when the worker raises (error context: error_count, error_type, …)",
    "event": "fires only when a suspended run is resumed with this event",
}

_KEYWORDS = ["when ", "always", "else", "false", "on error", "on error when ",
             "on event ", "on timeout"]
_ANNOTATIONS = ["checkpoint", "emits", "expect", "field_only", "spawn", "state_bound", "worker"]


# ------------------------------------------------------------------ the server

class Server:
    def __init__(self, instream, outstream):
        self.inp = instream
        self.out = outstream
        self.docs: Dict[str, str] = {}
        self.semantic = False
        self.running = True

    # -- plumbing ------------------------------------------------------------
    def _send(self, payload: dict) -> None:
        self.out.write(_frame(payload))
        self.out.flush()

    def _reply(self, msg_id, result=None, error=None) -> None:
        payload = {"jsonrpc": "2.0", "id": msg_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result
        self._send(payload)

    def _notify(self, method: str, params: dict) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def serve_forever(self) -> int:
        while self.running:
            msg = _read_message(self.inp)
            if msg is None:
                break
            self.handle(msg)
        return 0

    def handle(self, msg: dict) -> None:
        method = msg.get("method", "")
        params = msg.get("params") or {}
        msg_id = msg.get("id")
        try:
            handler = {
                "initialize": self._initialize,
                "initialized": lambda p: None,
                "shutdown": lambda p: None,
                "exit": self._exit,
                "textDocument/didOpen": self._did_open,
                "textDocument/didChange": self._did_change,
                "textDocument/didSave": self._did_save,
                "textDocument/didClose": self._did_close,
                "textDocument/completion": self._completion,
                "textDocument/hover": self._hover,
                "textDocument/documentSymbol": self._symbols,
                "prismpath/graph": self._graph,
            }.get(method)
            if handler is None:
                if msg_id is not None:                  # unknown request -> MethodNotFound
                    self._reply(msg_id, error={"code": -32601, "message": f"unknown method {method}"})
                return
            result = handler(params)
            if msg_id is not None and method != "exit":
                self._reply(msg_id, result=result)
        except Exception as e:                          # noqa: BLE001 - a server must not die mid-edit
            if msg_id is not None:
                self._reply(msg_id, error={"code": -32603, "message": str(e)})

    # -- lifecycle -----------------------------------------------------------
    def _initialize(self, params: dict) -> dict:
        opts = params.get("initializationOptions") or {}
        self.semantic = bool(opts.get("semantic"))
        return {
            "capabilities": {
                "textDocumentSync": 1,                  # full-document sync
                "completionProvider": {"triggerCharacters": [">", " ", "@", ":"]},
                "hoverProvider": True,
                "documentSymbolProvider": True,
            },
            "serverInfo": {"name": "prismpath-lsp", "version": "0.1.0"},
        }

    def _exit(self, params: dict) -> None:
        self.running = False

    # -- documents -----------------------------------------------------------
    def _did_open(self, params: dict) -> None:
        doc = params["textDocument"]
        self.docs[doc["uri"]] = doc.get("text", "")
        self._publish(doc["uri"])

    def _did_change(self, params: dict) -> None:
        uri = params["textDocument"]["uri"]
        changes = params.get("contentChanges") or []
        if changes:
            self.docs[uri] = changes[-1].get("text", "")
        self._publish(uri)

    def _did_save(self, params: dict) -> None:
        uri = params["textDocument"]["uri"]
        if "text" in params:
            self.docs[uri] = params["text"]
        self._publish(uri)

    def _did_close(self, params: dict) -> None:
        uri = params["textDocument"]["uri"]
        self.docs.pop(uri, None)
        self._notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": []})

    # -- diagnostics ---------------------------------------------------------
    def _publish(self, uri: str) -> None:
        text = self.docs.get(uri, "")
        lines = text.splitlines()
        scan = _scan(text)
        diags: List[dict] = []
        try:
            graph = parse(text)
            findings = list(analysis.analyze(graph))
            path = _uri_to_path(uri)
            if path:
                try:
                    findings += analysis.analyze_composition(graph, path)
                except Exception:                       # noqa: BLE001 - unsaved/moved children
                    pass
            if self.semantic:
                try:
                    from prismpath import lint
                    findings += lint.semantic_ambiguity(graph)
                    findings += lint.polarity_mirror(graph)
                except Exception:                       # noqa: BLE001 - embedder extra absent
                    pass
            for f in findings:
                diags.append({
                    "range": _finding_range(f, scan, lines),
                    "severity": 1 if f.severity == "error" else 2,
                    "code": f.code,
                    "source": "prismpath",
                    "message": f.message,
                })
        except Exception as e:                          # noqa: BLE001 - unparseable mid-edit
            diags.append({"range": _line_range(0, lines[0] if lines else ""),
                          "severity": 1, "code": "parse-error", "source": "prismpath",
                          "message": str(e)})
        self._notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": diags})

    # -- language features ---------------------------------------------------
    def _completion(self, params: dict) -> dict:
        uri = params["textDocument"]["uri"]
        pos = params["position"]
        text = self.docs.get(uri, "")
        lines = text.splitlines()
        line = lines[pos["line"]] if pos["line"] < len(lines) else ""
        prefix = line[:pos["character"]]
        items: List[dict] = []

        try:
            graph = parse(text)
        except Exception:                               # noqa: BLE001
            graph = None

        stripped = prefix.lstrip()
        if stripped.startswith("@"):
            items = [{"label": a, "kind": 14, "insertText": f"{a}()"} for a in _ANNOTATIONS]
        elif "->" in prefix and ":" in prefix.split("->", 1)[1]:
            # condition position: tier keywords + the fields this flow's predicates read
            items = [{"label": k, "kind": 14} for k in _KEYWORDS]
            fields = {"visits", "error_count"}
            if graph is not None:
                from prismpath.contract import derive_contract
                for spec in derive_contract(graph).values():
                    fields |= set(spec)
            items += [{"label": f, "kind": 5} for f in sorted(fields)]
        elif "->" in prefix:
            # target position: every node in the document
            if graph is not None:
                items = [{"label": n, "kind": 6} for n in graph.nodes]
        else:
            items = [{"label": "-> ", "kind": 15, "detail": "edge"}] + \
                    [{"label": a, "kind": 14, "insertText": f"@{a}()"} for a in _ANNOTATIONS]
        return {"isIncomplete": False, "items": items}

    def _hover(self, params: dict) -> Optional[dict]:
        uri = params["textDocument"]["uri"]
        pos = params["position"]
        text = self.docs.get(uri, "")
        lines = text.splitlines()
        if pos["line"] >= len(lines):
            return None
        line = lines[pos["line"]]
        scan = _scan(text)

        e = EDGE_RE.match(line)
        if e:
            tier = _tier(e.group(2))
            md = (f"**edge** `-> {e.group(1)}`  \n"
                  f"tier: **{tier}** — {_TIER_BLURB[tier]}")
            return {"contents": {"kind": "markdown", "value": md},
                    "range": _line_range(pos["line"], line)}

        # inside (or on the heading of) a node: summarize it
        current = None
        for name, nline in sorted(scan["nodes"].items(), key=lambda kv: kv[1]):
            if nline <= pos["line"]:
                current = name
        if current is None:
            return None
        try:
            graph = parse(text)
            node = graph.nodes.get(current)
        except Exception:                               # noqa: BLE001
            node = None
        if node is None:
            return None
        rows = [f"- `-> {t}` — *{_tier(c)}* `{c}`" for t, c in node.edges] or ["- *(terminal)*"]
        annos = ", ".join(f"@{a}" for a in node.annotations) if node.annotations else ""
        anno_part = "  \n" + annos if annos else ""
        md = f"**## {current}**{anno_part}\n" + "\n".join(rows)
        return {"contents": {"kind": "markdown", "value": md}}

    def _symbols(self, params: dict) -> List[dict]:
        uri = params["textDocument"]["uri"]
        text = self.docs.get(uri, "")
        lines = text.splitlines()
        scan = _scan(text)
        ordered = sorted(scan["nodes"].items(), key=lambda kv: kv[1])
        out = []
        for i, (name, nline) in enumerate(ordered):
            end = ordered[i + 1][1] - 1 if i + 1 < len(ordered) else max(len(lines) - 1, nline)
            out.append({
                "name": name, "kind": 6,                # Method — reads well in outlines
                "location": {"uri": uri, "range": {
                    "start": {"line": nline, "character": 0},
                    "end": {"line": end, "character": 0}}},
            })
        return out

    def _graph(self, params: dict) -> dict:
        uri = params.get("uri") or params.get("textDocument", {}).get("uri", "")
        text = self.docs.get(uri, "")
        from prismpath.graph_export import to_mermaid
        return {"mermaid": to_mermaid(parse(text))}


def _uri_to_path(uri: str) -> Optional[str]:
    if uri.startswith("file://"):
        from urllib.parse import unquote, urlparse
        return unquote(urlparse(uri).path)
    return None


# ------------------------------------------------------------------ CLI (`prismpath lsp`)

def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        'lsp', help='Language Server over stdio: live diagnostics, completion, hover, and graph '
                    'preview in any LSP editor (Neovim, JetBrains via LSP4IJ, VS Code, …). '
                    'Stdlib only — see prismpath/editor/README.md for client setup.')
    p.set_defaults(func=lsp_cmd)


def lsp_cmd(args) -> int:
    return Server(sys.stdin.buffer, sys.stdout.buffer).serve_forever()
