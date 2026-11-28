# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The ports: interfaces only. Each file names one port as `typing.Protocol` classes and plain dataclasses, and
imports nothing but kernel types. The onion and the surfaces depend on these names; the adapters behind them are
chosen where a process starts."""
