# support_triage · route the inbox: bug / billing / feature / question

Classifies an incoming customer message and routes each kind to resolution or escalation. The
classification edges are semantic (the message *is* prose); the money and severity decisions are
deterministic guard rails a support lead can read and change in one line; `when amount > 500`
routes straight to escalation before any judgment call, `when severity == "high"` pages
engineering. That mix is the template's point: judgment where judgment belongs, hard thresholds
where policy demands them, both in the same reviewable document. Readers: the support lead who
owns the escalation policy. The fixture table covers the deterministic tier, so
`prismpath test support_triage.md` is green with no model installed; the classify edges join the
tests once the `[embeddings]` extra is present.
