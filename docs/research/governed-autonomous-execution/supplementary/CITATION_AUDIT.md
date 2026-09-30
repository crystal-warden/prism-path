# Citation and claim audit

Supplementary artifact for "Governed Autonomous Execution: Authority Separation and Semantic Invariance Across
Execution Boundaries". It records the source-by-source audit of the citation flags in the paper's sections 8 and
9, run 2026-09-16 with live web verification. Each row gives the claim, the source checked, the
verdict, and any change made to the draft. Verified means a primary or authoritative source states the
distinction the draft attributes to it. Downgrade means the source only resembles the claim and the evidence
grade or wording was weakened.

## Section 8, direct instantiations

- A1 capability vs authority. Source: mandatory versus discretionary access control (Bell and LaPadula;
  SELinux). Verdict VERIFIED. MAC enforces system-wide policy invariants on top of subject ability and
  overrides discretionary grants (a Secret subject cannot read Top Secret data even if the owner grants it).
  This is authorization applied on top of ability, which is the claim. The draft was already switched off
  capability-security tokens onto MAC/DAC to avoid the capability overload, and that switch is what the
  source supports.
- A2 proposal vs authorization. Source: OASIS XACML, policy enforcement point and policy decision point.
  Verdict VERIFIED. The PEP forms and forwards a request, the PDP evaluates policy and returns grant or deny, and
  the separation of the point that receives a request from the point that decides it is explicit.
- A3 authenticity vs authority. Source: OAuth 2.0 (RFC 6749), OpenID Connect Core 1.0, audience via RFC 8707.
  Verdict VERIFIED. OAuth is authorization, OIDC adds authentication as a distinct layer, and scopes gate access
  and audience or resource indicators are validated apart from identity. Supports authentication is not
  authorization.
- A4 absence vs explicit state. Source: Saltzer and Schroeder 1975, fail-safe defaults. Verdict VERIFIED.
  Base access decisions on permission rather than exclusion, and the default is lack of access. This is the
  fail-closed treatment of missing authorization-relevant state. Draft wording already weakened from correct
  systems to fail-closed designs, which matches the source.
- A5 representation vs semantics. Source: Unicode UTS 39 (Unicode Security Mechanisms) and OWASP
  canonicalization guidance. Verdict VERIFIED, with a scope note. The sources establish canonicalize before
  the security check, framed as before validation generally rather than specifically before the authorization
  decision. Kept as a direct instantiation, since the wording says before deciding, which is faithful.
- A6 provenance vs truth. Source: the SLSA specification and the in-toto attestation framework. Verdict
  VERIFIED. SLSA scopes itself to provenance and build integrity and explicitly not to the functional
  correctness of the artifact. This is the evidence-plane honesty limit, provenance is not truth.

## Section 8, structural analogues

- A7 sequencing vs authority. Source: the Kubernetes API request lifecycle. Verdict VERIFIED as an analogue,
  with a correction. The verified order is authentication, then authorization, then admission control before
  persistence to etcd. Scheduling is a separate control loop after persistence, not the next pipeline stage.
  The draft previously wrote then persistence, then scheduling, then auditing as a linear pipeline, which
  overstated the ordering; corrected to admission before persistence with scheduling as a later separate loop.
  Kept structural, since this shows ordering and permission are separated but does not establish the general
  proposition that sequencing can expand authority.
- A8 execution vs evidence. Source: the dual-write problem and the transactional outbox pattern. Verdict
  VERIFIED as an analogue. A write to two systems can leave the effect and its recorded event divergent. The
  external record is weaker than the theory's evidence (a verifiable object from which the decision is
  re-derivable), so the grade stays analogue.

## Section 8, theory interpretation

- A5 theory interpretation, HTTP request smuggling. Source: PortSwigger Web Security Academy. Verdict VERIFIED as a
  known failure, kept as our interpretation. Front-end and back-end disagree on Content-Length versus
  Transfer-Encoding and desynchronize. The reading that this is two evaluators disagreeing on one input is our
  framing, not the literature's, and remains labeled a theory interpretation.

## Section 9, related work

- Shielding. Source: Alshiekh et al, Safe Reinforcement Learning via Shielding, AAAI-18 (arXiv 1708.08611).
  Verdict VERIFIED. A shield is synthesized from a temporal-logic specification and acts at each decision to
  keep the agent to safe actions. Primary object is the safety constraint. The preprint is 2017 and the
  publication is AAAI-18, cited as 2018.
- AgentSpec. Source: AgentSpec, arXiv 2503.18666 (ICSE 2026). Verdict VERIFIED for structure, DOWNGRADE on
  specifics. The three rule components trigger, predicate, enforcement are confirmed, and an example
  enforcement is requiring user confirmation. The draft previously listed stop execution, request human
  inspection, substitute a safer action as the enforcement repertoire; that triad was not confirmed from the
  source, so the wording was softened to the verified structure plus the confirmed example.
- Proof of Execution. Source: Proof of Execution, Runtime Verification for Governed AI Agent Actions (arXiv
  2607.05397). Verdict VERIFIED verbatim. An execution is a triple x = (C, T, R), a contract, an Execution
  Causal Event Stream, and a replay context. The Prime Execution Model separates planning, enforcement,
  effect, and recordkeeping into distinct authority planes. The PoE validity predicate is a well-formedness
  condition plus five validator-checkable invariants, the semantic guarantees of authorization, path
  compliance, null effect on deny, history integrity, and replayability. Section 9 was sharpened to these
  terms. This is the closest neighbour and the characterization is accurate.
- Classical authorization. Source: RBAC (Sandhu et al), ABAC (NIST SP 800-162), XACML. Verdict XACML
  VERIFIED, RBAC and ABAC standard references (not separately re-verified this pass, foundational).
- Attested execution. Source: trusted execution environment and remote attestation literature. Verdict
  standard references (not separately re-verified this pass, foundational).

## Outcome

All nine section-8 flags and all section-9 flags resolved. No mapping was found to be unsupported. One
correction (A7 Kubernetes ordering) and one downgrade (AgentSpec enforcement specifics) were applied to the
draft. The remaining open citation work is bibliographic formatting, not verification: turn these named
sources into a reference list when the paper is typeset. Nothing in sections 8 or 9 now claims more than a
checked source supports.

## Section 5 and 9, Walsh (added 2026-09-20, live web verification)

- Walsh, action-sufficient compression. Source: Walsh, M. "Support sufficiency as action-sufficient compression:
  a single-cycle rate-regret formulation," 2026. Verdict VERIFIED, arXiv:2606.09858 (submitted 2026-05-28). The
  coarsest exactly action-sufficient compression is the quotient of support space by policy equivalence, merging
  two states exactly when they require the same optimal action. This is the source the paper cites for the
  action-sufficient reading of the equivalence and the coarsest-exact-partition point.
- Walsh, belief arbitration. Source: Walsh, M. "Support Sufficiency as Consequence-Sensitive Compression in
  Belief Arbitration," 2026. Verdict VERIFIED, arXiv:2604.16434. The consequence-sensitive, resource-regulated
  extension, cited for the approximate and consequence-sensitive version. Both Walsh entries carry arXiv IDs to
  match the rest of the reference list.

## Section 8 and Appendix C, missing canonical sources (added 2026-09-30, live web verification)

A review pass found three external realizations in section 8 named without a bibliography entry. Since section 8
is the external countermodel search, each claimed realization needs a canonical source.

- SELinux, cited for mandatory access control applied over discretionary ability. Source: Loscocco, P., and
  Smalley, S. "Integrating Flexible Support for Security Policies into the Linux Operating System," FREENIX Track,
  USENIX Annual Technical Conference, 2001. Verdict VERIFIED. The paper presents the Flask MAC architecture as
  implemented in Linux, producing the SELinux prototype. Replaces the bare "SELinux" in the in-text citation.
- SQL three-valued logic, cited for keeping a null distinct from an ordinary value. Source: Codd, E. F.
  "Extending the Database Relational Model to Capture More Meaning," ACM TODS 4(4), pages 397 to 434, 1979.
  Verdict VERIFIED. This is where nulls and their three-valued treatment enter the relational model.
- Break-glass, cited as the external realization of urgency is not authority. Source: Brucker, A. D., and
  Petritsch, H. "Extending Access Control Models with Break-glass," SACMAT 2009, pages 197 to 206,
  doi:10.1145/1542207.1542239. Verdict VERIFIED. Break-glass integrated into standard access control models as a
  separately governed exceptional path, which is the claimed realization. Cited in section 8 and Appendix C.

## Release pass, bibliography normalized (2026-09-30, live verification)

Every reference now carries authors or the issuing body, a dated version, and a DOI or canonical URL, checked
against the publisher, the standards body, or rfc-editor.org. Two changes are corrections, not formatting.

- A5, OWASP. CORRECTION. The earlier audit counted OWASP canonicalization guidance as support for canonicalize
  before the decision, citing Proactive Controls. Rechecked against the documents, Proactive Controls 2024 does not
  mention canonicalization and the 2018 entry defines it without stating the ordering. The document that states the
  ordering is the OWASP Application Security Verification Standard 5.0.0, requirement 1.1.1 (Level 2), which
  requires decoding to canonical form before input is processed further and not after validation. The citation now
  reads OWASP ASVS 5.0.0. The A5 verdict stands on Unicode UTS 39 and ASVS 5.0.0 together.
- A6, SLSA. VERSION. SLSA v1.0 is retired. The citation is now specification v1.2 (24 November 2025), whose "What
  SLSA doesn't cover" section keeps the soundness of the source out of scope. The draft's wording moved from
  "correctness of what was built" to "soundness of what was built" to match.
- A8, dual write. The Confluent material, previously a see-also inside the Richardson entry, is now its own entry,
  Waldron 2024, and is cited alongside Richardson in section 8 and Appendix C.
- Current versions recorded: UTS 39 is version 18.0.0 (27 August 2026); OpenID Connect Core 1.0 is cited in its
  errata set 2 form (15 December 2023), first final 25 February 2014. Loscocco and Smalley carry no page numbers
  because USENIX publishes none for that paper.
