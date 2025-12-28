"""CLI wrapper for the generator entrypoint."""

from __future__ import annotations

from .generator import main as _generator_main


def main(argv: list[str] | None = None) -> int:
    return _generator_main(argv)
