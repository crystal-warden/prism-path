# fanout_review · one durable child run per changed file

The fan-out pattern end to end: `gather` emits the work-list, `dispatch` declares
`@spawn(child=review_one.md, over=files, item_id=path, join=all_done)` and suspends, the composer
harness runs one **durable child** per file (deterministic ids; a restart never double-spawns),
and the parent resumes on `all_done` to aggregate the verdicts; with `on timeout` escalating to a
human if a child stalls. Two documents, both here: the parent (`fanout_review.md`) and the child
(`review_one.md`), because a template that fans out ships its child. Readers: anyone whose review
load is "N independent items, then one decision." Both fixture tables are deterministic;
`prismpath test` is green on each with no model installed; run the real fan-out with
`checkpoint.run_durable` + `prismpath compose`.
