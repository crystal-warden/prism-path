# Routing tests — `prismpath test review_one.md` (the fan-out's child; deterministic, no model)

| node   | outcome                                | fields       | expect          |
|--------|----------------------------------------|--------------|-----------------|
| review | change is a safe rename, tests intact  | verdict=pass | approve         |
| review | mutates shared state without a lock    | verdict=fail | request_changes |
