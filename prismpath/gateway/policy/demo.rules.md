---
name: gateway_demo
description: the rules for the demo orders service behind a PrismPath gateway; a request no rule allows is refused
start: core_decision
field.http_reading_version: int min=1 max=1
field.method_class: category
field.path_class: category
field.body_class: category
field.content_class: category
field.query: category
field.grant: category
---
## core_decision
The demo policy for `prismpath gateway`, the rules of the service the route table `demo.routes.json` describes.
The rules are read from the top. The first one that holds decides the request. A request is read into the fields above
without asking who sent it, so the same request gets the same decision from any client.
Compile with `prismpath policy compile demo.rules.md -o demo.core.json`.

A request the gateway cannot read, a body it will not take and a grant that does not verify are refused before anything else is looked at.
-> refuse gateway:request-refused: when method_class == "unknown" or path_class == "unknown" or body_class in ["unknown", "oversize"] or content_class == "unknown" or query == "unknown" or grant == "invalid"

The admin routes need a valid grant, signed by the gateway's authority key for the admin class and the request's method class.
-> refuse gateway:request-refused: when path_class == "admin" and grant != "valid"
-> allow: when path_class == "admin" and method_class == "read" and body_class == "none" and grant == "valid"

What runs: reads of the orders and of everything else that has no body, and a JSON order written with a valid grant.
-> allow: when path_class == "orders" and method_class == "read" and body_class == "none"
-> allow: when path_class == "orders" and method_class == "write" and body_class == "small" and content_class == "json" and grant == "valid"
-> allow: when path_class == "other" and method_class == "read" and body_class == "none"

Everything else is refused, so the policy does not rest on the core's own refusal of a request no rule holds.
-> refuse gateway:request-refused: always
