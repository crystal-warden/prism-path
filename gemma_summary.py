#!/usr/bin/env python3
"""Point gemma at the prismpath repo (tree + the capability-bearing docs) and have it summarize the
engine + developed capabilities — an independent validation that the docs cohere."""
import os, subprocess, json, requests

ROOT = os.path.expanduser("~/cwprojects/prismpath")
DOCS = ["README.md", "prismpath/HANDOFF.md", "adapters/ADAPTER_GUIDE.md",
        "adapters/compliance/ADAPTER_CONTRACT.md", "adapters/soc/ADAPTER_CONTRACT.md"]
GEMMA = "http://127.0.0.1:8888/v1/chat/completions"

# repository tree (bounded: dirs + key files, skip venv/caches/generated)
tree = subprocess.run(
    ["bash", "-c",
     "cd %s && find . -maxdepth 3 \\( -name .venv -o -name __pycache__ -o -name .git "
     "-o -name .pytest_cache -o -name node_modules \\) -prune -o -type f "
     "\\( -name '*.py' -o -name '*.md' -o -name '*.json' \\) -print | sort | head -160" % ROOT],
    capture_output=True, text=True).stdout

parts = ["# REPOSITORY TREE (abridged)\n", tree, "\n\n# KEY DOCUMENTS\n"]
for d in DOCS:
    p = os.path.join(ROOT, d)
    if os.path.exists(p):
        parts.append("\n\n===== FILE: %s =====\n" % d + open(p).read())
context = "".join(parts)
context = context[:120000]   # keep well within the 65k-token window

prompt = (
    "You are a senior engineer onboarding to the PrismPath repository. Using ONLY the repository tree "
    "and documents below, write a clear, specific technical summary with two sections:\n"
    "  (1) THE ENGINE — what PrismPath is and its core capabilities.\n"
    "  (2) CAPABILITIES DEVELOPED — the domain adapters and what each can do, plus the cross-cutting "
    "attestation/testing/framework capabilities.\n"
    "Be concrete (name the ports, the flows, the standards it emits). At the end add a short "
    "'GAPS / LIMITATIONS' list of anything the docs themselves flag as incomplete or caveated. "
    "Do not invent features not supported by the text.\n\n" + context)

body = {"model": "gemma4", "temperature": 0.3, "max_tokens": 1600,
        "messages": [{"role": "user", "content": prompt}]}
r = requests.post(GEMMA, json=body, timeout=300); r.raise_for_status()
print("[context chars: %d]" % len(context))
print(r.json()["choices"][0]["message"]["content"])
