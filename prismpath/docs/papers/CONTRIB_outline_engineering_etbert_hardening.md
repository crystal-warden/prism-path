# Contribution Outline (engineering white paper) — Hardening a Layer-2 Embedding Detector: Silent-Failure Discipline, No-Sudo Capture, GPU-Batch Economics, and a Certified Benign-Margin Gate

*Outline for review + merge into `prismpath_whitepaper_engineering.md`. Author: security-track.
Operating lessons from running the ET-BERT L2 detector as a durable service feeding the PrismPath SOC
triage flow. All numbers first-party on the GB10. 2026-07-18.*

---

## 0. Framing
These are **engineering findings, not theorems** (the whitepaper's register): reproducible operating
knowledge about deploying a cheap embedding detector as the front tier of an LLM-triage pipeline. Each
maps to a whitepaper theme already present — durable services, honest health checks, cost models, and
"gates as the definition of done."

## 1. The silent-failure lesson (health checks must assert *function*, not *liveness*)
- After ~1 week unattended, a 23/23-green health script hid a detector that had scored **0 flows the
  entire week** and was **self-flooding the SIEM at ~226k alerts/day**.
- Root cause (worth a boxed war-story): the capture pre-created the pcap file, then `sudo tcpdump`
  **dropped privileges to the `tcpdump` user** and got *permission denied* → empty window → a ~1 s
  runaway loop → each spin's `sudo` emitted 3 PAM/sudo alerts.
- **Lesson → shipped fix:** a health check must assert *"scored N>0 flows in the last window,"* not
  *"service is active."* This is the ops-layer echo of the paper's **"never write a completeness claim a
  gate doesn't enforce"** (§5). Merge as a short subsection under the health/durability material.

## 2. No-per-cycle-sudo capture architecture (durable-service pattern)
- Replace per-window `sudo tcpdump` with **one persistent rotating tcpdump** as a root systemd service
  (`-G 60`, strftime name — note the systemd `%%`-escaping gotcha), writing to a dir owned
  `cwadmin:tcpdump 0775` (no sticky) so the unprivileged consumer can **read and delete** the
  privileged writer's files. Zero per-cycle privilege escalation → the flood's *source* is removed, not
  suppressed. Generalizable pattern: "one long-lived privileged producer + unprivileged consumer via
  directory ownership."

## 3. GPU-batch economics (the cost-model theme, detection edition)
- CPU embed was ~55 ms/flow — a 60 s window (~1,300 flows) took ~70 s → could not keep real time.
- Reframed to an **hourly GPU batch**: load the encoder once, embed the whole hour in large batches at
  **4.03 ms/flow (~14× CPU amortized)** → ~2–6 min of GPU/hour for **full** coverage, vs the CPU
  scramble's sampling. Table: CPU-continuous vs GPU-hourly (latency, coverage, footprint).
- **Guardrail as a first-class design input:** the encoder shares 128 GB unified memory with a 60 GB
  production LLM; the batch is **memory-guarded** (MemAvailable < 12 GB ⇒ CPU fallback) and never
  touches the LLM. The lesson: *"guardrail = anti-OOM of the co-resident model, not a GPU ban"* — the
  earlier CPU-only default was measured to be over-conservative (~1–3 GB actual footprint, 35 GB free).

## 4. The benign-margin gate as a shipped, reversible feature
- The confident-FP fix (see the research outline) landed as a **flag** on the hourly scorer
  (`--margin-tau`), default-off, enabled in the unit; the detection record now carries `benign_cos` and
  `margin` for observability (the "a decision explains itself because it is scored data" principle,
  applied to detections).
- Reversible by construction (a refinement of the existing gate — can only remove flags), and the
  operating τ is **calibrated with a certificate** (FP ≤ 0.053% @ 95% Wilson) rather than hand-set — the
  ops-layer instance of the paper's risk-controlled τ.

## 5. Defense-in-depth as a deliberate FP budget
- The detector is **intentionally left slightly permissive** (τ=0, zero TP cost): rare borderline FPs
  (a live HTTP-to-Azure flow at margin +0.022) are **escalated to the LLM triage tier**, which
  adjudicates them benign. This is the whitepaper's cheap-tier/expensive-tier split as an *operational
  FP-budget decision*: don't over-tune the cheap tier; let calibrated sensitivity + LLM adjudication
  share the FP load. Cross-reference the prefilter/decision-memoization economics.

## 6. Merge checklist
- [ ] Boxed war-story (silent failure) + the one-line health-check principle.
- [ ] Durable-service pattern diagram (producer/consumer/ownership).
- [ ] CPU-vs-GPU-batch cost table.
- [ ] One paragraph tying the memory-guard to the co-resident-LLM constraint.
- [ ] Artifacts: `cw-span-capture.service`, `cw-etbert-batch.{service,timer}`, `batch_score.py`
      (`--margin-tau`), the hardened `cwcheck` function check.
