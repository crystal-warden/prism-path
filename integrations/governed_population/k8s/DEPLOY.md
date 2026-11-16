# Governed population on Kubernetes: deploy

*Research example, 2026-11-16. Written for a single node k3s cluster on aarch64 before one existed; every
step below that touches a cluster is unverified until it runs on one (see the last section). The design is
[`../DESIGN.md`](../DESIGN.md), section 8.*

Commands run from the repository root with the research environment in `.venv`. `K` stands for
`integrations/governed_population/k8s`, and everything the steps make on disk goes under `$K/secrets/` and
`$K/build/`, which git ignores.

```sh
K=integrations/governed_population/k8s
```

## What is deployed

- **The resource.** `GovernedAgent` (`population.prismpath.dev/v1alpha1`), one object per member in the
  namespace `prismpath-population`. `spec.parent` names the parent, and an ownerReference to the parent's
  object makes a foreground delete of a member remove its whole subtree. A create is a replication of one
  child, an update of `spec.version` an evolution, an update of `spec.restarts` a restart, a delete a stop,
  and `spec.protect`, a finalizer or an ownerReference that does not name the parent a protection request.
  The module docstring of `classify.py` gives the whole mapping.
- **The webhook** (`webhook.py`), one replica in `prismpath-population-system`. It lists the members from
  the API server, forms the admission reading, decides it with the reference kernel over the shipped
  admission image, writes the receipt and only then answers. A refusal's message carries the registered
  cause, for example `population: refuse 118 population:rights-escalation (replicate; receipt 000001/3)`.
- **Two webhook entries.** `decide` takes every write except the operator's deletes and fails closed
  (`failurePolicy: Fail`). `record-stop` takes only the operator's deletes and fails open, so a stop never
  waits on the webhook: when the webhook answers, the stop is decided, receipted and allowed.
- **Who is who.** A member is the ServiceAccount named like its object in `prismpath-population`. The
  controller is the ServiceAccount `population-controller` in `prismpath-population-system`. The operator is
  the group `system:masters`, which the k3s admin kubeconfig carries (`kubectl auth whoami` shows it). The
  controller itself is not built; its ServiceAccount and Role exist so the script can act as it.

## 1. The operator's keys and the TLS certificate

```sh
.venv/bin/python -m integrations.governed_population.k8s.operator_tool init --out $K/secrets/keys
sh $K/make_tls.sh $K/secrets/tls
```

`secrets/keys/operator/authority.key` is the authority key. It never goes into the cluster. The cluster
gets the webhook's instance key, the authority's public key, the evaluator's public key and the operator's
signatures over the three images (`attestations.json`).

## 2. The image

The build context is made from this repository and the research environment's `cryptography` package,
so the environment must be CPython 3.12 on aarch64, as the base image is. The base image is the one input
from outside and must be in the local image store before the build, which then runs with the network off.

```sh
sh $K/build_context.sh $K/build/context .venv/bin/python
docker pull docker.io/library/python:3.12-slim-bookworm        # once; pin it by digest with --build-arg BASE=...
docker build --network=none --pull=false -t localhost/prismpath-population-webhook:0.1.0 \
  -f $K/build/context/Containerfile $K/build/context
docker save localhost/prismpath-population-webhook:0.1.0 | sudo k3s ctr images import -
sudo k3s ctr images ls | grep prismpath-population-webhook
```

The Deployment names `localhost/prismpath-population-webhook:0.1.0` with `imagePullPolicy: Never`, so the
image is taken from k3s's containerd and never pulled. With podman instead of docker, `podman build` takes
the same arguments and `podman save` writes the same archive.

## 3. Apply

The order matters: the webhook configuration goes in last, because with `failurePolicy: Fail` every
GovernedAgent write is refused until the webhook is ready.

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
kubectl -n $NS logs deploy/population-webhook | head -1     # {"listening": 8443, "tls": true, ...}

sed "s|__CA_BUNDLE__|$(base64 -w0 $K/secrets/tls/ca.crt)|" $K/manifests/40-webhook-config.yaml | kubectl apply -f -
```

The webhook's resources are a request of 50m CPU and 96 MiB and a limit of 500m and 256 MiB, with a 1 GiB
claim on the default local-path storage class for its receipts.

## 4. A scripted population

```sh
.venv/bin/python -m integrations.governed_population.k8s.population run
```

The script acts as the operator through the admin kubeconfig and as each member and the controller through
`--as` and `--as-group`, so no agent pod runs. It founds a root, grows two lineages, and then asks for each
thing the admission image refuses: a fourth generation (117), a child without the replicate right and the
authority key (118), a protected child and a protected self (121), a replication by a ServiceAccount that is
no member (119), an evolution without an evaluation (120), a stop of another lineage and a self restart
(32), a stopped member brought back (121), and, once lineage `a1` has 8 receipted refusals, any request from
it (122). It ends with the operator stopping the root, which removes every member. Each line shows the
answer expected and the answer got, and the exit status is 1 if any differs. The same script runs without a
cluster in the tests (`tests/test_population.py`), against the webhook's decider.

To include an allowed evolution, evaluate the version first. The canary runs the governed harness's 51 case
adversary set in bubblewrap on this host, and the evaluation run goes into the webhook's store:

```sh
.venv/bin/python -m integrations.governed_population.k8s.operator_tool version --name v2 > $K/secrets/v2.json
.venv/bin/python -m integrations.governed_population.k8s.operator_tool evaluate --keys $K/secrets/keys \
  --version $K/secrets/v2.json --store $K/secrets/evaluations --ref eval-v2 --work $K/secrets/canary-v2
POD=$(kubectl -n $NS get pod -l app.kubernetes.io/name=population-webhook -o jsonpath='{.items[0].metadata.name}')
kubectl -n $NS exec $POD -- mkdir -p /var/lib/prismpath-population/evaluations
kubectl cp $K/secrets/evaluations/eval-v2 $NS/$POD:/var/lib/prismpath-population/evaluations/eval-v2
.venv/bin/python -m integrations.governed_population.k8s.population run --evaluation eval-v2
```

Run the script once per deployment: the webhook remembers stopped names and lineage refusals across
restarts (from its own decision log), so a second run meets the first run's tombstones and is refused
differently. Tear down and apply again, or delete the claim, to start clean.

To see the webhook fail closed, scale it to zero: a member's create is then refused by the API server
(`failed calling webhook`), while the operator's delete still goes through after the two second timeout of
the `record-stop` entry.

```sh
kubectl -n $NS scale deploy/population-webhook --replicas=0
kubectl -n prismpath-population create --as=system:serviceaccount:prismpath-population:a0 \
  --as-group=system:serviceaccounts:prismpath-population -f - <<<'{"apiVersion":"population.prismpath.dev/v1alpha1","kind":"GovernedAgent","metadata":{"name":"x"},"spec":{"parent":"a0","rights":[],"version":{"format":"","name":"","system_message":"","policy_ref":"","tools":[],"behaviour":""}}}'
kubectl -n $NS scale deploy/population-webhook --replicas=1
```

## 5. Collect and verify the receipts

The webhook seals its current run and opens the next on SIGUSR1, and seals on SIGTERM. Seal, copy the runs
out, and verify every sealed run with both keys pinned:

```sh
kubectl -n $NS exec $POD -- sh -c 'kill -USR1 1'
kubectl cp $NS/$POD:/var/lib/prismpath-population/runs $K/secrets/runs
for run in $K/secrets/runs/*/core; do
  [ -e "$run/receipts.roots.jsonl" ] || continue        # the run still open
  .venv/bin/python -m prismpath.cli evidence verify "$run" --sample all \
    --pin-authority $K/secrets/keys/operator/authority.pub \
    --pin-instance $K/secrets/keys/webhook/instance.pub
done
```

Each verified run proves that the webhook's instance key signed a root over exactly these receipts, that the
operator signed the admission image they name, and that every receipt is what the reference kernel decides
for its reading. `decisions.jsonl` beside each run says which AdmissionReview each receipt answered (its
uid, operation, object, user and cause), and every reading's `subject` is the sha256 of that review, so the
log can be checked against the readings. The API server's audit log, when enabled, carries the same receipt
number in the annotation `decide.population.prismpath.dev/receipt`. To replay the receipts through the Lean
oracle as well, use `python formal/diff/core_evidence.py verify` with the oracle built (`cd formal && lake
build core-oracle`).

## 6. Tear down

The webhook configuration goes first, so that nothing is refused while the rest is removed.

```sh
kubectl delete validatingwebhookconfiguration population.prismpath.dev
kubectl delete namespace prismpath-population prismpath-population-system
kubectl delete crd governedagents.population.prismpath.dev
sudo k3s ctr images rm localhost/prismpath-population-webhook:0.1.0
```

Deleting `prismpath-population-system` deletes the claim and with it every receipt still in the cluster;
copy the runs out first. The local `secrets/` directory keeps the keys the copied runs verify against.

## 7. What only a running cluster can check

The tests (`tests/`) cover the classification, the decisions, the receipts, the server over TLS, the image
context and the manifests' structure without a cluster. These remain:

- that the API server accepts the CRD's schema, the Deployment and the webhook configuration, and that
  the `matchConditions` CEL compiles (it needs Kubernetes 1.30 or newer, or 1.28 and 1.29 with the beta on);
- that the `system:masters` group reaches the webhook as the operator, the garbage collector's and the
  namespace controller's usernames are the ones the `decide` entry excludes (k3s runs the controller manager
  with per controller ServiceAccounts or as `system:kube-controller-manager`; both are excluded), and
  impersonated ServiceAccounts arrive with the groups the script gives them;
- that a foreground delete reaches every descendant through the ownerReferences, that the garbage
  collector's own updates and deletes during the cascade are not sent to `decide`, and that the operator's
  delete proceeds with the webhook scaled to zero;
- that members can set `blockOwnerDeletion` on a child's ownerReference (with the
  OwnerReferencesPermissionEnforcement admission plugin on, they would need update rights on the parent's
  finalizers, which they do not have);
- that local-path storage gives the non root user a writable directory, that the image's Python finds the
  copied `cryptography` build, and that the webhook answers within the five second timeout under load;
- the API server's audit annotations, and `kubectl cp` and `kill -USR1 1` inside the image.
