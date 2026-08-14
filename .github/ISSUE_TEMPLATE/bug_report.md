---
name: Bug report
about: Something behaves incorrectly
labels: bug
---

**What happened / what you expected.**

**Repro.** If it's a *routing* bug, the best repro is a failing fixture row; it becomes the
regression test verbatim:

| node | outcome | fields | expect |
|------|---------|--------|--------|
|      |         |        |        |

Otherwise, the smallest flow (or `(condition, context)` pair) that shows it:

```markdown

```

**Environment.** PrismPath version / commit, Python version, OS, and whether the embeddings extra
is installed.
