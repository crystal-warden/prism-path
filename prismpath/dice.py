"""Back-compat shim — `dice` moved to the council plugin (`prismpath.plugins.council.dice`).

The council machinery is an OPTIONAL expansion (see plugins/council/README.md), not core; this shim
keeps the existing `import dice` / `from prismpath import dice` call sites (run_sprint, mission_control)
working unchanged until the launch-inversion cleanup retires them.
"""
from prismpath.plugins.council.dice import *          # noqa: F401,F403
from prismpath.plugins.council import dice as _mod

def __getattr__(name):                             # anything not exported by *: delegate
    return getattr(_mod, name)
