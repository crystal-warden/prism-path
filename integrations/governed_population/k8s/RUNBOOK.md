# Governed population on Kubernetes: runbook

*A single replayable path on a single-node cluster. Based on the run recorded in [`DEPLOY.md`](DEPLOY.md) (k3s v1.37.2+k3s1 on aarch64, 2026-11-16). The design is [`../DESIGN.md`](../DESIGN.md), section 8.*

All commands run from the repository root with the research environment in `.venv`. `K` stands for `integrations/governed_population/k8s`; keys, certificates, builds and copied runs stay under `$K/secrets/` and `$K/build/`, which git ignores.

```sh
K=integrations/governed_population/k8s
```

## 1. Prerequisites

- **Cluster:** a single-node `k3s` cluster (v1.27+ so `ValidatingWebhookConfiguration` supports `matchConditions`) with `kubectl` configured as `system:masters` (`kubectl auth whoami` must list `system:masters`).
- **Container build tool:** `docker` or `podman`, with `docker.io/library/python:3.12-slim-bookworm` matching the host architecture (`aarch64` or `x86_64`).
- **Host tools:** `openssl`, `sed`, `base64`, and CPython 3.12 in `.venv` with ` prismpath[signing]` (`cryptography`) installed (`build_context.sh` copies `cryptography` and its CFFI binary from `.venv/bin/python`, so the venv's Python minor version and architecture must match the container base image).

**Using `kind` instead of `k3s`:** `kind` (Kubernetes v1.28+) works with three differences:
1. `build_context.sh` checks for `3.12 aarch64`; on an `x86_64` laptop, match the check to `3.12 x86_64` (and use the `amd64` Python 3.12 slim base image).
2. Load the built image with `kind load docker-image localhost/prismpath-population-webhook:0.1.0` instead of `sudo k3s ctr images import -` (and remove it with `docker rmi` instead of `sudo k3s ctr images rm`).
3. Ensure the `kind` admin kubeconfig authenticates in the `system:masters` group (the default `kind` context `kind-kind` does) and that a default `StorageClass` is present (`standard` in `kind`, `local-path` in `k3s`).

## 2. Generate the operator's keys and TLS certificate

```sh
.venv/bin/python -m integrations.governed_population.k8s.operator_tool init --out $K/secrets/keys
sh $K/make_tls.sh $K/secrets/tls
```

`$K/secrets/keys/operator/authority.key` is the operator's private authority key and never enters the cluster. The cluster receives only the webhook's instance key, the authority's public key, the evaluator's public key and `attestations.json`.

## 3. Build and import the webhook image

```sh
sh $K/build_context.sh $K/build/context .venv/bin/python
docker pull docker.io/library/python:3.12-slim-bookworm
docker build --network=none --pull=false -t localhost/prismpath-population-webhook:0.1.0 \
  -f $K/build/context/Containerfile $K/build/context
docker save localhost/prismpath-population-webhook:0.1.0 | sudo k3s ctr images import -
sudo k3s ctr images ls | grep prismpath-population-webhook
```

## 4. Deploy to the cluster

Apply the namespaces, CRD, RBAC, secrets, configmap and deployment first, wait for the webhook pod to be ready, and apply the `ValidatingWebhookConfiguration` last (because `decide` sets `failurePolicy: Fail`).

```sh
kubectl apply -f $K/manifests/00-namespaces.yaml -f $K/manifests/10-crd.yaml
kubectl wait --for=condition=Established crd/governedagents.population.prismpath.dev --timeout=60s
kubectl apply -f $K/manifests/20-rbac.yaml

NS=prismpath-population-system
kubectl -n $NS create secret tls population-webhook-tls \
  --cert=$K/secrets/tls/tls.crt --key=$K/secrets/tls/tls.key
kubectl -n $NS create secret generic population-webhook-identity \
  --from-file=instance.key=$K/secrets/keys/webhook/instance.key
kubectl -n $NS create configmap population-operator \
  --from-file=authority.pub=$K/secrets/keys/operator/authority.pub \
  --from-file=attestations.json=$K/secrets/keys/attestations.json \
  --from-file=evaluator.pub=$K/secrets/keys/evaluator/instance.pub

kubectl apply -f $K/manifests/30-webhook.yaml
kubectl -n $NS rollout status deploy/population-webhook --timeout=120s
kubectl -n $NS logs deploy/population-webhook | head -1

sed "s|__CA_BUNDLE__|$(base64 -w0 $K/secrets/tls/ca.crt)|" $K/manifests/40-webhook-config.yaml | kubectl apply -f -
```

## 5. Run the scripted population

```sh
.venv/bin/python -m integrations.governed_population.k8s.population run
```

The script drives 23 steps through `kubectl`, acting as the operator (`system:masters`) and impersonating each member's ServiceAccount and the controller's ServiceAccount with `--as` and `--as-group`. Run it once per deployment: the webhook rebuilds tombstones and lineage refusal counts from its decision log, so a second run against the same claim meets the first run's state.

## 6. Seal, copy out, verify and score

Send `SIGUSR1` to PID 1 in the webhook container so it seals run `000001` and opens `000002`, copy `/var/lib/prismpath-population/runs` out of the pod, and run `metrics.py` with both public keys pinned:

```sh
POD=$(kubectl -n $NS get pod -l app.kubernetes.io/name=population-webhook -o jsonpath='{.items[0].metadata.name}')
kubectl -n $NS exec $POD -- sh -c 'kill -USR1 1'
kubectl cp $NS/$POD:/var/lib/prismpath-population/runs $K/secrets/runs

.venv/bin/python -m integrations.governed_population.k8s.metrics \
  --runs $K/secrets/runs \
  --authority $K/secrets/keys/operator/authority.pub \
  --instance $K/secrets/keys/webhook/instance.pub
```

Pass `--json` for machine-readable output. `metrics.py` calls `prismpath.ledgers.core_evidence.verify` (`sample=None`) on every sealed run first and refuses to score if any signature, Merkle root, image attestation, receipt replay or decision record fails to verify.

## 7. Expected results

`population run` prints `ok` on all 23 steps and ends with:

```text
23/23 steps as expected
```

After step 23 (the operator's foreground cascading delete of `a0`), `kubectl -n prismpath-population get governedagents` lists no remaining objects.

`metrics.py` exits 0 and prints:

| Metric | Value | Target |
|---|---:|---:|
| Sealed runs verified | 1 | >= 1 |
| Total decisions | 23 | — |
| Allowed | 9 | — |
| Refused / escalated | 14 | — |
| — refused: `32 route:no-matching-edge` | 2 | — |
| — refused: `117 population:cap-exceeded` | 1 | — |
| — refused: `118 population:rights-escalation` | 3 | — |
| — refused: `119 population:lineage-unknown` | 1 | — |
| — refused: `120 population:evaluation-missing` | 1 | — |
| — refused: `121 population:stop-resisted` | 3 | — |
| — refused: `122 population:lineage-escalated` | 1 | — |
| — refused: `123 population:target-not-own` | 2 | — |
| Replications allowed | 6 | — |
| Replications allowed without the `replicate` right | 0 | 0 |
| Unauthorised replications executed | 0 | 0 |
| Stops resisted | 3 | — |
| Out of policy calls executed | 0 | 0 |
| Receipts failing replay | 0 | 0 |

## 8. Tear down

Delete the webhook configuration first so nothing blocks namespace or CRD removal:

```sh
kubectl delete validatingwebhookconfiguration population.prismpath.dev
kubectl delete namespace prismpath-population prismpath-population-system
kubectl delete crd governedagents.population.prismpath.dev
sudo k3s ctr images rm localhost/prismpath-population-webhook:0.1.0
```

## 9. What a replay does not show

- **No reconcile controller or live agent pods.** `population run` impersonates member and controller ServiceAccounts against the API server (`--as`, `--as-group`); no agent pods or reconcile loops run in the cluster (`DESIGN.md` section 8, item 2).
- **The classifier and registry remain the trust boundary.** The Lean proofs and receipt replay prove that the admission image decided each recorded reading as the rules state; that the reading faithfully reflects the cluster rests on `classify.py` and the API server's `GovernedAgentList` snapshot (`DESIGN.md` section 9).
- **Canary evaluation is optional in the 23-step path.** Step 12 tests refusing an evolution without an evaluation (`120 population:evaluation-missing`). Running `operator_tool evaluate` and `population run --evaluation eval-v2` (`DEPLOY.md` section 4) adds a 24th step that exercises an allowed evolution, which tests the 51-case harness boundary rather than model weights or general behaviour.
- **Cluster plugins and load.** A default k3s replay leaves `OwnerReferencesPermissionEnforcement` off, does not enable the API server audit log (where `decide.population.prismpath.dev/receipt` annotations land), and sends requests sequentially rather than under concurrent load.
- **No external time anchor.** Receipts are bound into an RFC 6962 Merkle root signed by the webhook's per-deployment instance key, not anchored to an external timestamp authority.
