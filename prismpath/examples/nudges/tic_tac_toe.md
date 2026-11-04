# Build: a browser Tic-Tac-Toe game (self-contained, no backend)

Build a single-page browser **Tic-Tac-Toe** game:
- The player is **X** and clicks an empty cell to place a mark.
- The **computer (O)** then responds automatically (a simple strategy is fine).
- Detect **win / draw** and show the result clearly.
- A **Reset / New Game** button clears the board and starts over.

Self-contained: runs entirely from local files — **no backend, no server, no network, no CDNs.**

Follow the architecture contract (onion core + hexagonal adapters):
- **CORE** (pure): board state, place-move, win/draw detection, the computer's move choice. No DOM/timers.
- **Renderer PORT + adapter**: draw the 3×3 board + status message to the DOM.
- **Input PORT + adapter**: capture cell clicks and the reset button.
- **main.js**: composition root — instantiate the adapters, wire them to the core, start the game.

Keep every file small and single-responsibility.
