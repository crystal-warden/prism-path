---
name: release
start: cut_candidate
---

## cut_candidate
Build a release candidate artifact from the current main branch.
-> smoke_test: when always

## smoke_test
Run the smoke-test suite against the release candidate.
-> security_scan: when smoke_pass
-> rollback: when not smoke_pass

## security_scan
Scan the candidate for known vulnerabilities and license issues.
-> staging: when no_criticals
-> rollback: when criticals_found

## staging
Deploy the candidate to staging and watch the health metrics.
-> production: the staging metrics are healthy and stable
-> rollback: the staging metrics show regressions or errors

## production
Promote the candidate to production with a gradual rollout.
-> done: when healthy
-> rollback: when error_budget_burn > 1.0

## rollback
Revert to the previous known-good release and file an incident.
-> done: when always

## done
The release pipeline finished (shipped or rolled back). Finish.
