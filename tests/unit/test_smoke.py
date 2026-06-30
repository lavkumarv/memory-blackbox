"""Smoke tests that prove the package imports and the CLI is wired up."""

from __future__ import annotations

from typer.testing import CliRunner

import memory_blackbox
from memory_blackbox.cli import app


def test_package_imports() -> None:
    assert isinstance(memory_blackbox.__version__, str)


def test_cli_version_command() -> None:
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert memory_blackbox.__version__ in result.stdout
