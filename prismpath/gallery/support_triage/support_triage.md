---
name: support_triage
start: classify
---

## classify
Read the incoming customer message and decide what kind of request it is.
-> bug_report: the customer is reporting that something is broken or erroring
-> billing: the message is about payment, invoices, refunds, or subscription charges
-> feature_request: the customer is asking for a new capability or enhancement
-> general_question: it is a how-to or general usage question

## bug_report
Reproduce the issue and gather logs. Emit `severity` (high/normal). Decide if engineering
must be looped in.
-> escalate: when severity == "high"
-> resolve: the issue is understood and a workaround or fix can be given directly
-> escalate: it needs engineering investigation beyond first-line support

## billing
Look up the account and the disputed charge. Emit the disputed `amount` in dollars.
-> escalate: when amount > 500
-> resolve: when amount <= 50
-> resolve: the charge is correct or a refund can be issued on the spot
-> escalate: a manager approval or exception is required

## feature_request
Acknowledge the request and capture the details for the product backlog.
-> resolve: when always

## general_question
Answer the how-to question using the docs.
-> resolve: when always

## resolve
Send the answer or fix to the customer and close the ticket.

## escalate
Hand the ticket to the escalation queue with the evidence gathered so far.
