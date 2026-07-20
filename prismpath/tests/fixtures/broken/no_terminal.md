---
name: no_terminal
start: a
---
## a
Loop forever.
-> b: when always
## b
Loop back.
-> a: when visits < 5
-> a: when visits >= 5
