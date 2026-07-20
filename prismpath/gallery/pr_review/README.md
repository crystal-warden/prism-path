# pr_review — approval with a human gate

Routes a pull request from lint through CI to a **human review gate** and out to
approve / request-changes / needs-discussion — the classic "machines check what machines can,
a person decides what a person must" shape. The lint and CI hops are deterministic (`when clean`,
`when ci_pass` — free, exact); the human-review outcomes route semantically on what the reviewer
actually said; `needs_discussion` loops back to re-review once the design question settles.
Readers: the eng team; the loop-backs (`request_changes → lint`) are the part worth diffing when
someone proposes a process change. The fixture table covers the deterministic tier, so
`prismpath test pr_review.md` is green with no model installed.
