# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The image's build context holds everything the webhook imports: assembled by build_context.sh, then run
by Python with no site packages and only the context on its path, it makes the operator's keys, decides a
review, seals the run and verifies it. No container is built or run."""
import platform
import subprocess
import sys
from pathlib import Path

import pytest

K8S = Path(__file__).resolve().parents[1]

PROGRAM = r"""
import json, os, sys
from pathlib import Path
from integrations.governed_population.k8s import operator_tool, webhook
from integrations.governed_population.k8s.classify import Config
from integrations.governed_population import identity as ident
from integrations.governed_harness.policy import Policy
from prismpath.ledgers import core_evidence
work = Path(sys.argv[1])
keys = work / "keys"
operator_tool.init(keys)
(work / "registry.json").write_text("[]")
config = Config(harness_sha256=ident.sha256_hex(Policy.load().image))
d = webhook.Decider(work / "data", keys / "webhook", keys / "operator" / "authority.pub",
                    json.loads((keys / "attestations.json").read_text()), config,
                    webhook.FileRegistry(work / "registry.json"), None, out=open(os.devnull, "w"))
obj = {"apiVersion": "population.prismpath.dev/v1alpha1", "kind": "GovernedAgent",
       "metadata": {"name": "a0", "namespace": config.namespace},
       "spec": {"parent": "", "rights": ["exec", "replicate", "write"], "version": operator_tool.version_doc("v1"),
                "key": "instance", "restarts": 0}}
review = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
          "request": {"uid": "u1", "operation": "CREATE", "name": "a0", "namespace": config.namespace,
                      "resource": {"group": "population.prismpath.dev", "version": "v1alpha1",
                                   "resource": "governedagents"},
                      "userInfo": {"username": "system:admin", "groups": ["system:masters"]}, "object": obj}}
status, answer = d.review(review)
assert status == 200 and answer["response"]["allowed"], answer
d.close()
run = next((work / "data" / "runs").iterdir()) / "core"
summary = core_evidence.verify(run, sample=None, pin_authority=keys / "operator" / "authority.pub",
                               pin_instance=keys / "webhook" / "instance.pub")
print(json.dumps({"receipts": summary["receipts"], "modules": sorted({m.split(".")[0] for m in sys.modules}
                  - set(sys.stdlib_module_names))}))
"""


@pytest.mark.skipif(sys.version_info[:2] != (3, 12) or platform.machine() != "aarch64",
                    reason="the image is CPython 3.12 on aarch64; the context copies this interpreter's packages")
def test_the_build_context_is_self_contained(tmp_path):
    out = tmp_path / "ctx"
    subprocess.run(["sh", str(K8S / "build_context.sh"), str(out), sys.executable], check=True, capture_output=True)
    app = out / "app"
    assert (out / "Containerfile").read_bytes() == (K8S / "Containerfile").read_bytes()
    assert not list(app.rglob("tests")) and not list(app.rglob("__pycache__"))
    assert not list(app.rglob("*.key")) and not (app / "integrations" / "governed_population" / "k8s" / "secrets").exists()
    work = tmp_path / "work"
    work.mkdir()
    done = subprocess.run([sys.executable, "-S", "-c", PROGRAM, str(work)], cwd=tmp_path, capture_output=True,
                          text=True, env={"PYTHONPATH": f"{app}:{app / 'site'}", "PYTHONDONTWRITEBYTECODE": "1",
                                          "PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, done.stderr
    result = __import__("json").loads(done.stdout.strip().splitlines()[-1])
    assert result["receipts"] == 1
    assert set(result["modules"]) <= {"integrations", "prismpath", "cryptography", "_cffi_backend", "_openssl",
                                      "core_diff", "core_policy", "core_evidence", "__main__", "cffi"}
