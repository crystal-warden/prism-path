# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The optional extras, and the one error a missing one raises.

The core installs with no heavy dependency; each extra in pyproject.toml brings in what a family of
commands needs (the embedder, policy signing, the control plane, the local LLM router). A module that
needs an extra raises `MissingExtra` when it is absent, so the command line can print the install
line alone instead of a traceback, and a library caller still catches it as the ImportError it is.
"""
from __future__ import annotations

from typing import Optional

# Importable top-level module -> (extra, the pip distribution that provides it). Mirrors
# [project.optional-dependencies] in pyproject.toml; test_cli_errors keeps the two in step.
EXTRAS = {
    "sentence_transformers": ("embeddings", "sentence-transformers"),
    "cryptography": ("signing", "cryptography"),
    "requests": ("control-plane", "requests"),
    "fastapi": ("control-plane", "fastapi"),
    "uvicorn": ("control-plane", "uvicorn"),
    "pydantic": ("control-plane", "pydantic"),
    "transformers": ("llm-local", "transformers"),
}


def install_line(extra: str) -> str:
    return f"pip install 'prismpath[{extra}]'"


class MissingExtra(ImportError):
    """An optional extra a command needs is not installed. `str()` is the full explanation for a
    library caller; `install` is the one line the command line prints."""

    def __init__(self, extra: str, package: str, message: Optional[str] = None):
        self.extra = extra
        self.package = package
        self.install = f"needs {package} (the {extra} extra): {install_line(extra)}"
        super().__init__(message or self.install, name=package)


def from_exception(exc: BaseException) -> Optional[MissingExtra]:
    """The MissingExtra behind `exc`, if a missing extra is what caused it: `exc` itself, or a
    ModuleNotFoundError for one of the EXTRAS modules anywhere in its cause/context chain. None for
    every other failure, so an ImportError that is a real bug keeps its traceback."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, MissingExtra):
            return exc
        if isinstance(exc, ModuleNotFoundError) and exc.name:
            top = exc.name.split(".")[0]
            if top in EXTRAS:
                return MissingExtra(*EXTRAS[top])
        exc = exc.__cause__ or exc.__context__
    return None
