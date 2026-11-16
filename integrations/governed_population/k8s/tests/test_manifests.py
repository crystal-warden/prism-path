# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The manifests checked with no cluster: each parses, has what its kind requires, and agrees with the
others and with the webhook's code (names, namespaces, ports, the CRD's fields, who the operator and the
controller are). Not a replacement for the API server's own validation, which only a cluster can run."""
import json
import re
from pathlib import Path

import yaml

from integrations.governed_population.agent import Version
from integrations.governed_population.k8s import classify, operator_tool
from integrations.governed_population.k8s import webhook as wh

K8S = Path(__file__).resolve().parents[1]
MANIFESTS = K8S / "manifests"
DNS = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
QUANTITY = re.compile(r"^(\d+)(m|Mi|Gi)?$")
# what DEPLOY.md creates by kubectl from local files, never committed
CREATED_AT_DEPLOY = {("Secret", "population-webhook-tls"), ("Secret", "population-webhook-identity"),
                     ("ConfigMap", "population-operator")}


def load():
    docs = []
    for path in sorted(MANIFESTS.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if doc is not None:
                docs.append((path.name, doc))
    return docs


DOCS = load()


def by_kind(kind):
    return [doc for _, doc in DOCS if doc["kind"] == kind]


def one(kind, name=None):
    found = [d for d in by_kind(kind) if name is None or d["metadata"]["name"] == name]
    assert len(found) == 1, (kind, name, len(found))
    return found[0]


def test_every_document_has_the_fields_every_object_needs():
    seen = set()
    for path, doc in DOCS:
        assert isinstance(doc, dict), path
        assert doc.get("apiVersion") and doc.get("kind"), path
        meta = doc.get("metadata")
        assert isinstance(meta, dict) and DNS.match(meta.get("name", "")) and len(meta["name"]) <= 253, path
        cluster_scoped = doc["kind"] in ("Namespace", "CustomResourceDefinition", "ValidatingWebhookConfiguration")
        assert ("namespace" in meta) is (not cluster_scoped), (path, doc["kind"])
        key = (doc["kind"], meta.get("namespace"), meta["name"])
        assert key not in seen, key
        seen.add(key)
    assert {d["kind"] for _, d in DOCS} == {"Namespace", "CustomResourceDefinition", "ServiceAccount", "Role",
                                            "RoleBinding", "ConfigMap", "PersistentVolumeClaim", "Deployment",
                                            "Service", "ValidatingWebhookConfiguration"}


def test_no_secret_material_is_committed():
    assert by_kind("Secret") == []
    text = "".join(p.read_text() for p in MANIFESTS.glob("*.yaml"))
    assert "PRIVATE KEY" not in text and "BEGIN CERTIFICATE" not in text
    gitignore = (K8S / ".gitignore").read_text().split()
    assert "secrets/" in gitignore and "build/" in gitignore


def test_namespaces_exist_for_everything_namespaced():
    names = {d["metadata"]["name"] for d in by_kind("Namespace")}
    assert names == {classify.Config.namespace, "prismpath-population-system"}
    for _, doc in DOCS:
        ns = doc["metadata"].get("namespace")
        assert ns is None or ns in names
    for ns in by_kind("Namespace"):
        assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"


def test_the_crd_is_the_resource_the_webhook_classifies_and_keeps_every_field_it_reads():
    crd = one("CustomResourceDefinition")
    spec = crd["spec"]
    assert crd["metadata"]["name"] == f"{classify.PLURAL}.{classify.GROUP}"
    assert spec["group"] == classify.GROUP and spec["scope"] == "Namespaced"
    assert spec["names"]["plural"] == classify.PLURAL and spec["names"]["kind"] == classify.KIND
    assert spec["names"]["listKind"] == "GovernedAgentList"
    [version] = spec["versions"]
    assert version["name"] == classify.API_VERSION and version["served"] and version["storage"]
    schema = version["schema"]["openAPIV3Schema"]
    fields = schema["properties"]["spec"]["properties"]
    # the API server prunes what the schema does not name: every field classify.py reads must be in it
    assert set(fields) == {"parent", "rights", "key", "version", "evaluation", "protect", "restarts"}
    version_doc = operator_tool.version_doc("v1")
    assert set(fields["version"]["properties"]) == set(version_doc) == set(fields["version"]["required"])
    assert Version.from_doc(version_doc) is not None

    def no_enums(node):
        if isinstance(node, dict):
            assert "enum" not in node, node
            for value in node.values():
                no_enums(value)
    no_enums(schema)                            # refusals are the webhook's, decided and receipted
    assert "status" in version["subresources"]


def test_rbac_gives_members_governed_agents_only_and_the_webhook_read_only():
    roles = {r["metadata"]["name"]: r for r in by_kind("Role")}
    member = roles["population-member"]["rules"]
    assert member == [{"apiGroups": [classify.GROUP], "resources": [classify.PLURAL],
                       "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]}]
    reader = roles["population-webhook-reader"]["rules"]
    assert reader == [{"apiGroups": [classify.GROUP], "resources": [classify.PLURAL], "verbs": ["get", "list"]}]
    for role in by_kind("Role"):
        for rule in role["rules"]:
            assert "*" not in rule["verbs"] and "*" not in rule["resources"]
            assert not {"poddisruptionbudgets", "validatingwebhookconfigurations", "roles", "rolebindings"} \
                & set(rule["resources"])
    bindings = {b["metadata"]["name"]: b for b in by_kind("RoleBinding")}
    for name, binding in bindings.items():
        assert binding["roleRef"]["name"] in roles, name
        assert binding["metadata"]["namespace"] == roles[binding["roleRef"]["name"]]["metadata"]["namespace"]
    sas = {(s["metadata"]["namespace"], s["metadata"]["name"]) for s in by_kind("ServiceAccount")}
    for binding in bindings.values():
        for subject in binding["subjects"]:
            if subject["kind"] == "ServiceAccount":
                assert (subject["namespace"], subject["name"]) in sas
    assert bindings["population-member"]["subjects"] == [
        {"kind": "Group", "name": f"system:serviceaccounts:{classify.Config.namespace}",
         "apiGroup": "rbac.authorization.k8s.io"}]
    assert by_kind("ClusterRole") == [] and by_kind("ClusterRoleBinding") == []


def _quantity(text, unit):
    number, suffix = QUANTITY.match(str(text)).groups()
    scale = {"cpu": {None: 1000, "m": 1}, "mem": {"Mi": 1, "Gi": 1024}}[unit]
    return int(number) * scale[suffix]


def test_the_deployment_is_small_locked_down_and_mounts_what_the_webhook_reads():
    dep = one("Deployment", "population-webhook")
    spec = dep["spec"]
    assert spec["replicas"] == 1 and spec["strategy"]["type"] == "Recreate"
    pod = spec["template"]["spec"]
    assert spec["selector"]["matchLabels"].items() <= spec["template"]["metadata"]["labels"].items()
    assert pod["serviceAccountName"] in {s["metadata"]["name"] for s in by_kind("ServiceAccount")}
    assert pod["securityContext"]["runAsNonRoot"] and pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    [container] = pod["containers"]
    assert container["imagePullPolicy"] == "Never" and container["image"].startswith("localhost/")
    sc = container["securityContext"]
    assert sc["allowPrivilegeEscalation"] is False and sc["readOnlyRootFilesystem"] and sc["capabilities"]["drop"] == ["ALL"]
    res = container["resources"]
    assert _quantity(res["limits"]["memory"], "mem") <= 512 and _quantity(res["limits"]["cpu"], "cpu") <= 1000
    assert _quantity(res["requests"]["memory"], "mem") <= _quantity(res["limits"]["memory"], "mem")
    assert _quantity(res["requests"]["cpu"], "cpu") <= _quantity(res["limits"]["cpu"], "cpu")
    # the volumes are defined, and every Secret or ConfigMap is in the manifests or made at deploy time
    volumes = {v["name"]: v for v in pod["volumes"]}
    mounts = {m["name"]: m["mountPath"] for m in container["volumeMounts"]}
    assert set(mounts) == set(volumes)
    configmaps = {c["metadata"]["name"] for c in by_kind("ConfigMap")}
    claims = {c["metadata"]["name"] for c in by_kind("PersistentVolumeClaim")}
    for volume in volumes.values():
        if "secret" in volume:
            assert ("Secret", volume["secret"]["secretName"]) in CREATED_AT_DEPLOY
        elif "configMap" in volume:
            name = volume["configMap"]["name"]
            assert name in configmaps or ("ConfigMap", name) in CREATED_AT_DEPLOY
        elif "persistentVolumeClaim" in volume:
            assert volume["persistentVolumeClaim"]["claimName"] in claims
        else:
            assert "emptyDir" in volume
    # the arguments are the webhook's own, and each path lies under a mount
    args = dict(a[2:].split("=", 1) for a in container["args"])
    parser_flags = {"data", "identity", "authority", "attestations", "config", "evaluations", "evaluators",
                    "tls-cert", "tls-key", "port"}
    assert set(args) == parser_flags
    for key, value in args.items():
        if value.startswith("/"):
            assert any(value == m or value.startswith(m + "/") for m in mounts.values()), key
    # the probes and the port
    port = container["ports"][0]
    assert port["containerPort"] == int(args["port"])
    for probe in ("readinessProbe", "livenessProbe"):
        assert container[probe]["httpGet"]["path"] == "/healthz" and container[probe]["httpGet"]["scheme"] == "HTTPS"
    # the config the webhook reads is the classifier's own defaults
    config = json.loads(one("ConfigMap", "population-webhook-config")["data"]["config.json"])
    assert config == operator_tool.DEFAULT_CONFIG


def test_the_service_reaches_the_deployment():
    svc = one("Service", "population-webhook")
    dep = one("Deployment", "population-webhook")
    labels = dep["spec"]["template"]["metadata"]["labels"]
    assert svc["spec"]["selector"].items() <= labels.items()
    [port] = svc["spec"]["ports"]
    assert port["port"] == 443 and port["targetPort"] == dep["spec"]["template"]["spec"]["containers"][0]["ports"][0]["name"]


def test_the_webhook_configuration_fails_closed_except_for_the_operators_stops():
    vwc = one("ValidatingWebhookConfiguration")
    hooks = {h["name"]: h for h in vwc["webhooks"]}
    assert set(hooks) == {"decide.population.prismpath.dev", "record-stop.population.prismpath.dev"}
    svc = one("Service", "population-webhook")
    crd = one("CustomResourceDefinition")
    for hook in hooks.values():
        client = hook["clientConfig"]["service"]
        assert (client["namespace"], client["name"], client["port"]) == (svc["metadata"]["namespace"],
                                                                         svc["metadata"]["name"], 443)
        assert client["path"] == "/validate"
        assert hook["clientConfig"]["caBundle"] == "__CA_BUNDLE__"
        assert hook["admissionReviewVersions"] == ["v1"] and hook["sideEffects"] == "NoneOnDryRun"
        [rule] = hook["rules"]
        assert rule["apiGroups"] == [crd["spec"]["group"]] and rule["resources"] == [crd["spec"]["names"]["plural"]]
        assert rule["apiVersions"] == [crd["spec"]["versions"][0]["name"]] and rule["scope"] == "Namespaced"
        assert hook["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] == classify.Config.namespace
        assert 1 <= hook["timeoutSeconds"] <= 30
    decide, record = hooks["decide.population.prismpath.dev"], hooks["record-stop.population.prismpath.dev"]
    assert decide["failurePolicy"] == "Fail" and decide["rules"][0]["operations"] == ["CREATE", "UPDATE", "DELETE"]
    assert record["failurePolicy"] == "Ignore" and record["rules"][0]["operations"] == ["DELETE"]
    assert decide["timeoutSeconds"] > 4.0          # the decider's own deadline answers first
    # the CEL names the classifier's operator group, and the two entries split the deletes exactly
    [group] = classify.Config.operator_groups
    excluded = [c["expression"] for c in decide["matchConditions"]]
    assert any(f"g == '{group}'" in e and e.startswith("!(request.operation == 'DELETE'") for e in excluded)
    assert any("generic-garbage-collector" in e and e.startswith("!(") for e in excluded)
    [only] = record["matchConditions"]
    assert only["expression"] == excluded[1][2:-1]
    for hook in hooks.values():
        for condition in hook["matchConditions"]:
            assert condition["expression"].count("(") == condition["expression"].count(")")
            assert DNS.match(condition["name"])


def test_the_controller_user_in_the_config_is_the_controller_service_account():
    [user] = classify.Config.controller_users
    ns, name = user.split(":")[2:]
    assert ("ServiceAccount", ns, name) in {("ServiceAccount", s["metadata"]["namespace"], s["metadata"]["name"])
                                             for s in by_kind("ServiceAccount")}


def test_the_containerfile_is_local_only_and_arm64_ready():
    text = (K8S / "Containerfile").read_text()
    lowered = text.lower()
    for word in ("pip install", "apt-get", "apk add", "curl ", "wget ", "add http"):
        assert word not in lowered, word
    assert "python:3.12" in text and "USER 10001:10001" in text
    assert 'ENTRYPOINT ["python3", "-m", "integrations.governed_population.k8s.webhook"]' in text
    image = one("Deployment", "population-webhook")["spec"]["template"]["spec"]["containers"][0]
    assert image["securityContext"]["readOnlyRootFilesystem"] and "PYTHONDONTWRITEBYTECODE=1" in text
    assert wh.MAX_BODY >= 1 << 20
