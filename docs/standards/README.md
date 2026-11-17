# Standards data

Machine readable mappings from PrismPath to outside taxonomies, with the version of each taxonomy pinned as data.

| File | What it holds |
|---|---|
| `cause-crosswalk.json` | Every registered cause in `prismpath/kernel/causes.py` mapped to OWASP Top 10 for Agentic Applications 2026, MITRE ATLAS 2026.10 and CWE 5.0 ids, each with a one line rationale or an explicit none with its reason |
| `crosswalks/` | The evidence PrismPath produces mapped to the EU AI Act, the NIST AI RMF, NIST AI 600-1 and NIST SP 800-53 Rev 5 AU and SI. See `regulatory-mapping.md` |
| `otel-decision-attributes.md` | A proposal for OpenTelemetry GenAI attributes that carry a tool call's decision, its registered cause and its receipt, produced today by `prismpath/agent/otel.py` |
| `taxonomies/` | The pinned id lists the referees check against, each with its version, release date and source |

A cause code names a condition a defense refuses. An entry says which risk, technique or weakness has that condition, and does not claim the cause detects the attack. Internal routing, state and integrity causes say none and why. A cause appended to the registry fails `prismpath/tests/test_cause_crosswalk.py` until it has an entry, as `docs/design/spec-cause-codes.md` section 4.1 requires.

To move to a newer taxonomy version, replace its file in `taxonomies/`, update the version in `cause-crosswalk.json` and review the entries in the same commit.
