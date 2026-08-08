---
name: refund_router
start: extract
---
## extract
@code(net=false, fs=none, timeout_s=5, mem_mb=128)
Code node: parse the refund amount from the incoming request. Emits the field `amount`
(an unparseable request emits -1). The branching below lives on the edges, not in the code.
-> high_value: when amount > 500
-> standard: when amount >= 0
-> invalid: else

## high_value
A human manager reviews the refund.

## standard
Auto-approve the refund.

## invalid
Reject: the amount could not be parsed.
