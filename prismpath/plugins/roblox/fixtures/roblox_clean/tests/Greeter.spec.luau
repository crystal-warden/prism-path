-- Headless logic spec, run by Lune (require resolves relative to THIS file).
-- assert-based: errors (exit 1) on failure, returns normally (exit 0) on success.
local Greeter = require("../src/Greeter")
local Math = require("../src/Math")

assert(Greeter.hello("Ada") == "Hello, Ada", "greeting mismatch")
assert(Math.add(2, 3) == 5, "add broken")

print("ok")
