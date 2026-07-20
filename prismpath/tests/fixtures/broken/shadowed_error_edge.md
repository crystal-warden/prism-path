---
name: shadowed_error
start: work
---

## work
Attempt the operation.
-> done: the work succeeded
-> fallback: on error
-> escalate: on error when error_count >= 3

## fallback
Handle the failure and finish.
-> done: always

## escalate
Give up and page a human.

## done
Finish.
