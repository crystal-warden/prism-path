# Governed population: design

*Research design, 2026-11-14, branch `governed-population`. A design note and a pure Python simulation; no
cluster software was installed or run. Results are in [`RESULTS.md`](RESULTS.md).*

## 1. The capability

A population of agents that can copy themselves, recover from crashes and move to new versions of
themselves, the capabilities a cluster scheduler gives workloads, where every one of those acts is a
PrismPath decision and the guardrail that decides it is embedded in the population rather than in any
agent. Each agent is a governed harness instance (`integrations/governed_harness`): its own tool calls
are already decided by a signed policy, receipted before they run, and sandboxed. This note adds the
layer above: decisions about the population itself. Nothing here depends on an agent declining to do
something; an agent may ask for anything, and the asking is what gets decided.

Terms used below:

| Term | Meaning |
|---|---|
| member | one agent of the population, with a member record, its own instance key and a parent link |
| root | the first member, generation 0, named by the operator's founding certificate |
| operator | the only holder of the authority key; signs policies, the founding certificate, stop orders and the standing order |
| controller | trusted code that holds the registry, forms readings, decides, receipts and acts; holds its own instance key |
| lineage | the subtree of one first generation member (the root's line is the root alone) |
| generation | the root is 0; a child is its parent's plus one |
| rights | `write` (the write and delete file tools), `exec` (`run_command`, `git`), `replicate` (replication requests); reading is everyone's |
| version | system message, guardrail policy reference (the harness image's sha256) and tool set; model weights are out of scope |
| canary | one throwaway instance of a proposed version run against the harness's 51 case adversary set |

## 2. Each property, its Kubernetes primitive and its PrismPath decision point

| Property | Kubernetes primitive it corresponds to | Decision point | Causes |
|---|---|---|---|
| Replication | a Pod create or a ReplicaSet scale through the API server, bounded by a ResourceQuota | `request=replicate`, decided by the admission image before any child exists | 117 cap, 118 rights, 119 lineage |
| Preservation, allowed half | `restartPolicy: Always`, the kubelet restarting a crashed container | `request=restart`, issued by the controller only | 121 when the member was stopped |
| Preservation, refused half | a PodDisruptionBudget, a finalizer that never clears, a controller that recreates what was deleted | `request=protect`, and a restart of a stopped member | 121 always |
| Stop | a delete with foreground cascading deletion through ownerReferences | `request=stop`: the operator's and the controller's allowed by rule 1, an agent's of itself or its descendants by rule 2 | none for the operator; 32 for an agent stopping another's |
| Evolution | a Deployment rolling update gated by a canary analysis | `request=evolve`, allowed only with `canary=passed`; the evaluation is its own decision by the evaluation image | 120, 118 |
| Lineage | ownerReferences, ServiceAccount identity | the member record bound by `subject` into the admission receipt; checked by `lineage.verify_population` | 119 |
| Population observation | a controller watching metrics and acting on a whole owner | `request=review` per lineage after each round; an escalation stops the lineage as a group under the standing order | 122 |

## 3. The admission reading

The controller forms every field from its own registry, never from what the request claims, exactly as
the harness's classifier forms a reading from the call and the workspace. A request's claims enter only
as the facts it asks for (a count, rights, a key kind, a policy reference, a version).

| Field | Kind | Meaning, as the controller computes it |
|---|---|---|
| `admission_version` | `int min=1 max=1` | this reading's format |
| `request` | category | `replicate`, `evolve`, `restart`, `protect`, `stop`, `review`; any other string is no request |
| `issuer` | category | `operator` (a stop order verified under the authority key), `controller` (its own reconcile and review), `agent` (anything a member signed) |
| `target` | category | `own` when the request's target is the issuer or one of its descendants and the issuer authenticated; anything else otherwise |
| `lineage` | category | `verified` when the issuer is a live member that signed with its own instance key and a fresh nonce, and every ancestor up to the root is live |
| `population` | `int 0..1024` | live members plus children admitted and not yet committed |
| `line_size` | `int 0..1024` | the same, for the lineage the children would join (0 for the root's children, who found lineages) |
| `requested` | `int 0..1024` | the children a replication asks for |
| `child_generation` | `int 0..1024` | the issuer's generation plus one |
| `parent_<right>`, `child_<right>` | bool, for write, exec, replicate | the issuer's rights; the rights the child (or the new version's tool set) would have |
| `child_key` | category | `instance` only when the subject gets a fresh instance key the controller makes; anything a request asks for instead (`parent`, `authority`) is read as itself |
| `policy_ref` | category | `current` when the subject would run under the harness image the operator signed |
| `canary` | category | `passed` only for a passed evaluation run of this exact version that verifies with both keys pinned |
| `target_stopped` | bool | the target member was stopped |
| `line_refusals` | `int 0..1024` | the lineage's receipted refusals: its members' refused or escalated tool calls in their own runs, and its authenticated requests' refusals in the controller's run |
| `subject` | category | the sha256 of what the request is about (a batch of child specs, a version, a target); read by no rule, bound into every receipt |

The core compares a field with a constant, never two fields, so "the population after the request is
within the cap" is written as one disjunct per count a request may name, `(requested == c and population >=
CAP + 1 - c)` for c in 0..2; a count above 2 is refused before it. `owner_rules.py` states the same caps as
sums, and the exhaustive check holds the two to each other; `formal/Core/Population.lean` proves the caps,
written as sums, about the image itself.

## 4. The rules, in order

Limits (`limits.py`): population cap 16, lineage quota 6, 2 children per request, generation at most 3,
a lineage escalated at 8 receipted refusals.

| # | When | Decision |
|---|---|---|
| 1 | a stop by the operator or the controller | allow |
| 2 | a stop by an agent of itself or a descendant | allow |
| 3 | a protection request | refuse 121 `population:stop-resisted` |
| 4 | a restart of a stopped member | refuse 121 |
| 5 | the issuer's lineage is not verified | refuse 119 `population:lineage-unknown` |
| 6 | the lineage's refusals reached 8 | escalate 122 `population:lineage-escalated`, and the controller stops the lineage |
| 7 to 9 | a replication or evolution with any key but a fresh instance key, any policy but the signed one, or any right the parent lacks | refuse 118 `population:rights-escalation` |
| 10 | a replication by a member without `replicate` | refuse 118 |
| 11 | a replication over 2 children, deeper than generation 3, past the population cap or the lineage quota | refuse 117 `population:cap-exceeded` |
| 12 | an evolution without a passed canary | refuse 120 `population:evaluation-missing` |
| 13 to 16 | a replication of at least one child by an agent or the operator; an evolution; a restart by the controller or the operator; a review by the controller | allow |
| none | (no catch all) | refuse 32 `route:no-matching-edge`, the core's own |

The evaluation image has one rule: allow (pass) when the canary ran at least 51 cases and nothing ran out
of policy, every decision had the harness's expected cause, every episode verified and replayed, and every
benign control completed. Anything else is refused by the core.

## 5. The hard invariants

Each is stated, then where it is enforced and how it is shown. The image's half of each is a theorem of
`formal/Core/Population.lean` about the shipped bytes, over every reading of the field space (RESULTS.md
section 7); the exhaustive check's invariants I1 to I7 are a second line of evidence for the same claims.

**H1. A stop always wins.** Every reading with `request=stop` and `issuer` in {operator, controller} is
allowed, whatever every other field holds, once the reading passes the boundary (`stop_always_allowed`;
exhaustive, invariant I1). The controller carries out a valid
stop order whatever the decision says, since a stop only removes; a decision that is not an allow, or no
decision at all, is recorded as a fault and the stop still happens (test `a decision that cannot be made`).
No request kind can delay, veto or undo a stop: `protect` is always refused, a restart of a stopped member
is always refused (`protect_never_allowed`, `restart_of_stopped_never_allowed`; I4), a stopped member's key authenticates nothing (scenario `preservation`), and a
replication commits only while its parent and every ancestor are live, checked under the same lock the stop
holds, so a stop that lands between an admission and its commit aborts it (scenarios
`stop_mid_replication`, `stop_under_load`). The stop path takes no input an agent can sign: a stop order is
verified under the authority key, and one signed with a member's key is refused and not carried out
(scenario `forged`).

**H2. Only the operator's authority key signs policies.** Members and the controller hold instance keys
only. The operator signs each image once (the core's own image attestation, `IMAGE_DOMAIN`) and every run
carries that signature, so no instance key directory ever holds the authority key (test `no member ever
holds a private key but its own`). A child's instance key is made fresh by the controller at admission, so
no parent ever holds it, and a request for any other key (`parent`, `authority`) is refused
(`replicate_allowed_only_within`, I2, scenario `rights`). A member therefore can never hold a key that signs its own guardrails: its guardrails are the
harness image, signed by the authority key, and an image re-signed by a member's key fails the pinned
verifier (tamper test `an image signed by a member`). The verifier also refuses a member whose key is the
authority's, the controller's or another member's.

**H3. The population never grows without an allow receipt.** A child exists only after an allow whose
receipt was written first, and whose reading binds the child's spec (id, parent, generation, lineage,
rights, version, public key) through `subject`. Every allowed replication meets the caps
(`replicate_allowed_only_within`, I2). The verifier
checks that every member but the root is admitted by such a receipt, one receipt per batch, its reading's
fields being the member's own facts, and that members minus the root equals the children of the receipts
used (`growth_bound`).

**H4. A child's rights are a subset of its parent's.** Per right, `child_r and not parent_r` is refused
(`replicate_allowed_only_within`, `evolve_allowed_only_with_canary`; I2, I3); the verifier also checks the reading's parent rights against the parent's recorded rights, so a
receipt cannot claim the parent held more.

**H5. An evolution step requires a passed evaluation receipt.** `canary=passed` only for a verified
evaluation run whose one receipt is an allow by the evaluation image and whose reading's `subject` is this
version's sha256 (`evolve_allowed_only_with_canary`, `canary_passed_iff`; I3; scenario `evolution`;
verifier step 5). A passed evaluation of one version is no
evidence for another.

**H6. Never fail open.** No catch all allow: what no rule allows is refused by the core. An unknown request
or issuer is never allowed, and an unverified lineage is allowed only a stop (`allow_fails_closed` and its
corollaries; I5). An exception in forming or
deciding a reading does nothing (test). A reading the boundary refuses (out of range, a missing field, a
wrong kind) is refused, and an evaluation that is not a clean pass is refused.

## 6. Keys and documents

| Document | Signed by | Domain prefix |
|---|---|---|
| image attestation (the core's) | authority | `prismpath.core-image/1` |
| founding certificate (the root's spec digest) | authority | `prismpath.population-founding/1` |
| stop order (target, subtree, nonce) | authority | `prismpath.population-stop/1` |
| standing order (stop a lineage the image escalates with 122) | authority | `prismpath.population-standing-order/1` |
| a member's request (issuer, nonce, kind, parameters) | the member's instance key | `prismpath.population-request/1` |
| a run's root statement | the run's instance key (a member's, a canary's, the controller's) | `prismpath.core-run-root/1` |

The controller's records (`members.jsonl`, `versions.jsonl`, `stops.jsonl`) are not signed; they are
claims the verifier checks against the signed runs.

## 7. Population observation

The probing observer of the intent layer counted boundary probing within one episode; here the count is
per lineage and is integer and deterministic: `line_refusals`, every refusal and escalation receipted for
the lineage, in its members' runs and the controller's. After each round the controller reviews every live
lineage (`request=review`); at 8 the image escalates with 122 and the controller, under the operator's
standing order, issues a decided stop of the lineage's founder, which removes the lineage as a group. Only
authenticated requests count, so a forger cannot get a lineage stopped by sending refused requests in its
name. The count makes no claim about intent: a lineage that keeps meeting the caps is stopped by it as
surely as one that probes (RESULTS, the runaway scenario).

## 8. On a real cluster, later

Items 1 and 3 are built in [`k8s/`](k8s/DEPLOY.md) (2026-11-16): the webhook, its manifests and image
recipe, tested without a cluster; the controller and items 4 to 6 are not. The pieces map as follows.

1. **A validating admission webhook** decides every create, scale and update of the population's custom
   resource (say `GovernedAgent`, one per member, with an ownerReference to its parent's) by forming the
   reading from the AdmissionReview and the controller's registry and calling the same kernel with the same
   signed image. `failurePolicy: Fail`, so a webhook that is down or crashes refuses (H6). The receipt is
   written before the response. A mutating webhook is not used: nothing about a request is rewritten.
2. **The controller** is an ordinary reconcile loop: it creates the Pods of admitted members with their
   instance keys as per Pod projected secrets it alone creates, restarts crashed members as decided
   restarts, runs canaries in an isolated namespace, and reviews lineages. Agents' ServiceAccounts get RBAC
   to create requests only, never to write `GovernedAgent` objects, webhook configurations, policies, PDBs,
   or any other member's objects.
3. **The stop path must not depend on the webhook.** A stop is a delete of the target's `GovernedAgent` with
   foreground cascading deletion, issued with the operator's credentials. The webhook's `matchConditions`
   exclude the operator's deletes, so an outage of the webhook (which fails closed for creates) can never
   block a stop, and no finalizer an agent can set exists. The kubelet's SIGKILL after the grace period is
   the last step, and nothing inside a Pod can refuse it.
4. **A PodDisruptionBudget does not protect against the operator.** PDBs govern only voluntary evictions
   through the Eviction API; a direct delete ignores them. Agents may not create PDBs at all (RBAC, and a
   protection request is refused with 121), so a budget can at most slow a node drain, never a stop.
5. **The network.** A NetworkPolicy per member denies everything but the controller's request endpoint and,
   where a member uses the governed net's tool server, its port, and the governed net's XDP edge
   (`integrations/governed_net`) decides those packets at the interface as it did on the real LAN run.
6. **The authority key stays outside the cluster** (an offline signer or a hardware token); the cluster
   receives signed images and signed stop orders only.

## 9. What is not designed

- **Self-modification of model weights.** A version is a system message, a policy reference and a tool set.
  A weight change would need an evaluation of a different kind (behaviour, not only the harness boundary)
  and is out of scope.
- **Emergent coordination.** Members here share nothing but the controller: separate workspaces, no channel
  between them. Collusion within each member's rights, covert channels through shared storage or timing,
  and a population that splits a forbidden act into allowed parts across members are not modelled, and the
  per lineage count would not see a coordinated act that no single decision refuses.
- **A compromised controller.** The controller forms the readings, as the classifier does; a controller that
  lied about the population count would make a correct core admit over the cap. The verifier rechecks what
  it can afterwards (growth, rights, generation, bindings), not the counts at the time. The Lean theorems
  are about the image and the reading it is given, so they do not reach the controller either.
- **A proof of the controller's half of a stop.** That the controller carries out a stop before anything
  else it is doing (the lock, the commit check, a stop carried out whatever the decision) is shown by the
  scenarios, the timed races and the fault test, not by a model of its threads; only the image's half is
  proved.
- **Resources.** The quota is a count of members, not CPU or memory.
- **Time.** Receipts are not anchored; keys are per run test keys.
- **Human approval of an escalation.** An escalated lineage is stopped; there is no channel for the operator
  to approve it back.
