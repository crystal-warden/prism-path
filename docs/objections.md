# Two objections, answered up front

The two strongest critiques this project has faced, answered with the concessions left
in. This lived on the front page and moved here to keep the README short: nothing was
softened in the move.

**"Structured output already solved routing: ask the worker for JSON and branch on the field."**
Where the worker can emit a clean enum, agreed, and that *is* this system's recommendation:
`@emits` + `when` is exactly that pattern, the polarity lint exists to push authors toward it, and
the one production flow is P0 with no semantic edges at all. What the objection misses is that
structured output doesn't eliminate the routing decision: it relocates it *inside the model* and
strips the confidence signal. The classification into your enum is the same semantic judgment,
now made where nothing measures it, exiting in a deterministic costume. JSON mode has no doubt
channel: the field looks equally confident right or wrong, and you cannot calibrate an abstention
threshold ([`calibrate`](../prismpath/calibrate.py)'s risk controlled τ) over a score that doesn't
exist. The semantic tier is for the residue: outcomes that resist enumeration, and workers that
aren't promptable LLMs at all (CLI tools, humans, legacy scripts emit text and exit codes, not
your schema). And even all structured, the schema + routing live in *one* statically checked flow
document (`emits-type-mismatch`, `undeclared-field`) rather than scattered across a Pydantic
model, a prompt string, and a callback.

**"Logic as data is a rules engine, and we buried those."** Rules engines died of two specific
diseases, and this design is built against both. *Emergence*: a RETE engine fires N rules in
data dependent order: nobody could answer "can this rule ever fire?". PrismPath routing is
first match deterministic in document order over a decidable core, which is why
`shadowed-edge` / `always-false-edge` lints and a bounded model checker with witnesses
([`verify`](../prismpath/model_check.py)) can exist at all. *Expressiveness*: rules engines could
hold the application, so the application moved in. The Level M predicate fragment **cannot**:
comparisons, membership, counters, nothing else, so anything complicated is forced across the
worker boundary into ordinary code, and the flow stays coordination. The weakness of the
predicate language is the moat. The sharpest form of the objection: a one word semantic edit
whose behavioral shift hides in embedding geometry, is real, and it is every semantic system's
problem (the same drift in a prompt string has *zero* tripwires). Here it trips three:
[`lock --check`](../prismpath/lockfile.py) fails CI until the moved vectors are relocked, the
flow's fixture table reruns modelless and names any flipped case, and emitted labels rescore
the change before merge. You review a semantic change by its pinned consequences: the same way
you review any refactor. What remains honestly open: composition at scale (`@spawn` is young; no
flow beyond ~30 nodes is battle tested).

---

Back to the [README](../README.md) · the papers treat both objections as named
limitations: [research paper §6](research/paper-routing-spectrum.md) ·
[whitepaper §11](research/whitepaper-engineering.md).
