"""memory-blackbox: provenance and incident-reconstruction toolkit for AI agent memory."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("memory-blackbox")
except PackageNotFoundError:  # not installed (e.g. running from a source tree)
    __version__ = "0.0.0"

__all__ = ["__version__"]
