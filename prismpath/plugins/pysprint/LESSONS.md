# Hard-won lessons · Python sprints under the pysprint gate

- The gate runs `pytest` with the project dir on `PYTHONPATH`, so `import <module>` resolves to
  the sandbox copy. If your edit doesn't import, the whole suite errors; check imports first.
- A blocking call at import time (opening a socket, `serve_forever`) will hang the gate until it
  times out. Keep module import side-effect-free; do work inside functions/handlers.
- When adding an HTTP handler branch, register it in the right dispatch method (`do_GET` vs
  `do_POST`) and return through the same `_send`/`_sse` path the siblings use.
- Threading: shared mutable module state is guarded by an existing lock (e.g. `_CHAT_LOCK`,
  `_FILE_LOCK`). Reuse the matching lock; don't invent a new one for the same data.
