---
name: data_pipeline
start: extract
---

## extract
Pull the raw records from the upstream source for this batch.
-> validate: when always

## validate
Check the extracted batch against the schema and run quality checks.
-> transform: when valid
-> halt: when visits > 3
-> clean: the records have minor formatting problems that the standard repair rules can fix
-> quarantine: the records are corrupt or structurally broken beyond automatic repair

## clean
Apply the standard normalization/repair rules to the salvageable records.
-> validate: when always

## transform
Apply the business transformations and aggregations.
-> load: when always

## load
Write the transformed batch to the warehouse.
-> done: when loaded
-> halt: the write failed and cannot be retried

## quarantine
Set the bad batch aside for manual review and alert the data owner.
-> done: when always

## done
The batch completed (loaded or quarantined). Finish.

## halt
An unrecoverable error or too many retries. Stop the pipeline.
