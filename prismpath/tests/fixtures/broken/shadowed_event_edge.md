---
name: shadowed_event
start: work
---

## work
Wait for a signal.
-> done: on event ready
-> retry: on event ready

## retry
Retry the work.
-> done: on event go

## done
Finish.
