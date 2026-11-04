# Example nudges

These are example nudges: prompts you can give PrismPath's orchestrator to help it build a feature. They are kept here as examples of the format, not as live task briefs.

A nudge states the goal, the interfaces the work must talk to, and the hard rules the result has to respect, in plain language and in as few words as the task allows.

| file | what it asks for |
|---|---|
| [`chat_orchestrator_ui.md`](chat_orchestrator_ui.md) | a whole feature: a plan, approve and execute chat front end over the orchestrator's HTTP API |
| [`chat_execute_panel.md`](chat_execute_panel.md) | a narrow change to a project that already works: add a build-progress panel without touching the working flow |
| [`tic_tac_toe.md`](tic_tac_toe.md) | a small app from nothing: a self-contained browser game, core logic separate from the page |

The prompt assets that the orchestrator reads at runtime, such as the architecture contract `APP_ARCHITECTURE.md`, stay in [`../../nudges/`](../../nudges/).
