# Author a PrismPath "maps and directions" file

A PrismPath map IS a single markdown file that the engine walks as a decision graph: nodes are
`## headings`, edges are `-> target: condition` lines. You will author one and validate it with the
engine.

## Step 1 — Learn the rules (read before writing)
Read the normative authoring contract:
  - /home/cwadmin/cwprojects/prismpath/prismpath/AUTHORING.md
  - /home/cwadmin/cwprojects/prismpath/SPEC.md
Note especially: node/edge syntax; the routing spectrum — deterministic `-> t: when <expr>` (also
always/else) vs semantic `-> t: <natural language>` vs `-> t: on error ...` / `on event ...`;
precedence (deterministic edges first, in document order, first-true-wins; then semantic); terminal
nodes (zero edges end the run); and the frontmatter (`name:`, `start:`).

## Step 2 — Author the map (design the graph yourself)
Write a map that dispositions a NIST SP 800-171 control-assessment request. The task it automates:
  - INPUT to a run: one control (its id, its 800-171A assessment objectives, and its assessment
    methods) plus a tenant evidence bundle scoped to a system boundary.
  - It must reach a determination of met / partially-met / not-met under ESCALATION-DEFAULT logic:
    a control is NOT MET unless the evidence POSITIVELY DEMONSTRATES each objective on the boundary
    by the required method (Examine / Interview / Test). Intent-only policy, out-of-scope evidence,
    or a missing objective each mean that objective is not satisfied.
  - Handle the real cases: observe/ingest the request; retrieve the objectives as criteria; adjudicate
    (this is where judgment lives); if evidence is missing or insufficient, route to REQUEST more
    evidence (a discovery loop) rather than silently failing; record a finding + POA&M for gaps, or a
    met-record; end at a final report/attest node.
  - Use DETERMINISTIC `when` edges where the transition is logic (e.g. `when determination == "met"`,
    `when no_evidence`) and SEMANTIC (natural-language) edges where it is judgment. Include a terminal
    node and a start.
  - Design the graph FROM THE RULES AND THIS SPEC. Do not read or copy any existing compliance flow in
    this repo; the point is your independent authoring.

## Step 3 — Self-validate with the engine (iterate until clean)
Run:
  /home/cwadmin/cwprojects/prismpath/.venv/bin/python -m prismpath.cli validate <your-file>
Fix whatever it reports (dangling edge targets, missing start, malformed edges) and re-run until it
prints: clean OK — the flow compiles.

## Output + rules
Write the file to: /home/cwadmin/cwprojects/mdflow/adapters/compliance/flows/agy_800171_assessment.md
Authoring + `prismpath validate` (static, read-only) ONLY. Do NOT run the flow (prismpath run), do NOT
start any model/inference server, do NOT use the GPU, do NOT touch port 8888. When done, print the final
validate output and a 3-line summary of your graph (node count, and how you split deterministic vs
semantic routing).
