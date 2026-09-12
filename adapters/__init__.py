# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The bounded adapters: domain code that sits behind the kernel's ports.

Each adapter is a subpackage imported from the repository root, so a sibling module is reached by
its package path rather than by putting the adapter's directory on sys.path. An adapter imports
the kernel; the kernel never imports an adapter."""
