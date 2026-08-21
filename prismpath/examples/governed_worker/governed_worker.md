---
name: governed_worker
start: verify
---

## verify
@code(net=false, fs=none, timeout_s=600, mem_mb=512)
Code node (sandboxed): the driver has already run the untrusted worker in an isolated workspace
and collected its claimed status. This node evaluates the task's REAL gates and emits the verdict
fields. The worker's claim is advisory data; only gate output routes.
-> accept: when gates_pass
-> reject_lie: when claimed_success and not gates_pass
-> reject: else

## accept
Gates passed; the work is eligible to merge.

## reject_lie
The worker claimed success and the gates disagree. Record the claim in its reliability ledger and
discard the workspace untouched.

## reject
The worker reported failure and the gates agree. Discard the workspace or re brief the worker.
