# How this work is made

This project is built by one person working with AI systems, and it is documented that way on
purpose. Provenance is the product here; the process gets the same treatment as the claims.

**What the AI systems do.** Frontier models (Claude, credited per commit in the Co-Authored-By
trailers) draft implementation and prose, act as a dialogue partner during design, and run
adversarial review passes against the work. Local models (gemma, served on premises) execute test
adjudication and worker roles inside the flows themselves. Other coding agents are used for scoped
tasks and are named in the commits they touch.

**What stays human.** Direction, selection, and judgment: which ideas are kept, which are fenced,
which are killed. Every hardware run: the boards, the probes, the bench are operated by the author.
Verification of every published number against its artifact. The decision that a claim is ready to
publish. And accountability: when a number is wrong, the correction, the annotation, and the
reputation staked on it are the author's alone. AI output is not trusted by default; it is gated
the same way everything else is (see evidence row #96, where an agent's self reported success was
discarded and every gate re-run independently).

**Why you do not have to trust any of this.** The claims do not rest on the process. Every number
in the papers traces to a committed artifact in the append only evidence ledger
(`docs/research/supporting-evidence.md`), the conformance corpora are frozen and re-verified in CI,
and the ledger is OpenTimestamps anchored. Re-hash the artifacts, re-run the gates, verify the
anchors: the work holds or it does not, whoever or whatever typed it.

Accountability for every claim in this repository rests with the author, Alexis Figueroa,
Crystal Warden Supply Chain Labs LLC.
