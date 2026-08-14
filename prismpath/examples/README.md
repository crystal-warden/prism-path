# Examples, by persona

One flow each; pick the one shaped like your job. Every file below is a real, runnable flow
(`prismpath validate` clean); the tier tells you what it needs at runtime (`P0` = zero ML, runs on
the [browser/edge kernel](../portable/README.md); `P2` = uses semantic edges → the full engine,
or `prismpath lock` for P1).

| you are | the flow | what it shows | tier |
|---|---|---|---|
| **SOC analyst / security engineer** | [`flows/wazuh_triage.md`](../flows/wazuh_triage.md) | live alert triage: decision-memoization prefilter, structured-verdict routing, human-gated containment, per alert ledger proofs | P0 |
| **Support / ops lead** | [`pr_demo/triage.md`](pr_demo/triage.md) | ticket routing where **the PR is the process change**: one prose diff + one fixture row changes production ([the demo](pr_demo/README.md)) | P0 |
| **Release manager** | [`flows/release.md`](../flows/release.md) | a gated release train: checks route deterministically, judgment calls stay semantic | P2 |
| **HR / people ops** | [`flows/hr_onboarding.md`](../flows/hr_onboarding.md) | onboarding with timers (`on timeout`), webhooks (`on event docs_received`), error-tier retries, and a human security-review gate | P2 |
| **Platform / SRE** | [`flows/fanout_review.md`](../flows/fanout_review.md) + [`flows/review_one.md`](../flows/review_one.md) | fan-out: one durable child run per changed file, deterministic child identity, `on event all_done` join | P0 |
| **The skeptic** | [`flows/sprint_loop.md`](../flows/sprint_loop.md) | the control plane that builds this repo, as a flow: gate-green routing, 3×-same-error as an edge, `@checkpoint` proofs: the dogfood | P2 |

No terminal at all? The **[playground](../portable/playground.html)** runs the P0 kernel in your
browser; paste any of these, watch them route.
