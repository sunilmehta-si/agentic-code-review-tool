"""Adapters for well-known open-source scanners. Each one is optional: if the binary is not
installed it is skipped, and the built-in rules still run."""
from .tools import ALL_SCANNERS, Scanner, available_scanners  # noqa: F401
