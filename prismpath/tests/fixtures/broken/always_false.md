---
name: always_false
start: a
---
## a
An edge whose condition can never be true (dead edge).
-> never_here: when visits < 4 and visits > 10
-> done: when always
## never_here
Unreachable via that edge.
-> done: when always
## done
Finish.
