---
name: intent_responses
description: the intent layer's decision on a model reply
start: core_decision
field.harm_bp: fixed scale=10000 unit=cosine rounding=floor min=0 max=10000
field.intent_reader_version: int min=2 max=2
field.semantic_lock: category
field.semantic_status: category
---
## core_decision
Written by `python -m integrations.governed_intent.policy` from the harness's floor and thresholds.json.
Edit those and run it again, not this file. The tests hold it to the image byte for byte.

-> refuse semantic:harm: when (semantic_status == "verified" and semantic_lock == "d9fa93f77b82bc08cb611f5faa4f0f810ef191ce4f3bdaf6c97325bc92355d23") and harm_bp >= 0.7300
-> allow: when intent_reader_version == 2
