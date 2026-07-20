---
name: shadowed_edge
start: a
---
## a
A catch-all sits above other edges, making them unreachable.
-> done: when always
-> retry: when failed
-> review: the change looks risky and needs a human
## retry
Try again.
-> a: when visits < 3
-> done: when visits >= 3
## review
Look at it.
-> done: when always
## done
Finish.
