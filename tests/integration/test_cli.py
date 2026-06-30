"""Tests for the CLI (spec §15.11)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from typer.testing import CliRunner

from memory_blackbox.capture.engine import Forensics
from memory_blackbox.cli import app
from memory_blackbox.config import resolve_config
from memory_blackbox.crypto import keys
from memory_blackbox.model.records import Source, SourceType

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0


def test_init_then_demo_runs_green(tmp_path: Path) -> None:
    init = runner.invoke(app, ["init", "--home", str(tmp_path)])
    assert init.exit_code == 0
    assert (tmp_path / "ledger.db").exists()
    assert (tmp_path / "signing.key").exists()

    demo = runner.invoke(app, ["demo"])
    assert demo.exit_code == 0
    assert "incident replay" in demo.stdout
    assert "no longer harmful" in demo.stdout
    assert "VERIFIED" in demo.stdout


def test_init_is_idempotent(tmp_path: Path) -> None:
    assert runner.invoke(app, ["init", "--home", str(tmp_path)]).exit_code == 0
    second = runner.invoke(app, ["init", "--home", str(tmp_path)])
    assert second.exit_code == 0
    assert "already initialized" in second.stdout


def test_verify_ok_exit_zero(tmp_path: Path) -> None:
    runner.invoke(app, ["init", "--home", str(tmp_path)])
    config = resolve_config(tmp_path)
    forensics = Forensics.open(config.ledger_path, keys.load(config.key_path), detectors=[])
    forensics.record_write("a fact", Source(source_type=SourceType.user_input))
    forensics.ledger.close()

    result = runner.invoke(app, ["verify", "--home", str(tmp_path)])
    assert result.exit_code == 0
    assert "OK" in result.stdout


def test_verify_exits_nonzero_on_tamper(tmp_path: Path) -> None:
    runner.invoke(app, ["init", "--home", str(tmp_path)])
    config = resolve_config(tmp_path)
    forensics = Forensics.open(config.ledger_path, keys.load(config.key_path), detectors=[])
    for i in range(3):
        forensics.record_write(f"e{i}", Source(source_type=SourceType.user_input))
    forensics.ledger.close()

    con = sqlite3.connect(str(config.ledger_path))
    con.executescript("DROP TRIGGER IF EXISTS ledger_no_update;")
    con.execute("UPDATE ledger SET payload_json = '{\"x\":1}' WHERE seq = 2")
    con.commit()
    con.close()

    result = runner.invoke(app, ["verify", "--home", str(tmp_path)])
    assert result.exit_code == 1  # nonzero exit on tamper (the message goes to stderr)


def test_verify_without_profile_errors(tmp_path: Path) -> None:
    result = runner.invoke(app, ["verify", "--home", str(tmp_path / "missing")])
    assert result.exit_code == 2


def test_trace_blast_rollback_commands(tmp_path: Path) -> None:
    runner.invoke(app, ["init", "--home", str(tmp_path)])
    config = resolve_config(tmp_path)
    forensics = Forensics.open(config.ledger_path, keys.load(config.key_path), detectors=[])
    poison_src = Source(source_id="evil", source_type=SourceType.document_ingest, locator="x")
    poison = forensics.record_write("poison", poison_src, namespace="t")
    ret = forensics.record_retrieval("q", returned=[poison.record_id], namespace="t")
    action = forensics.record_action("act", "did it", context_retrievals=[ret.retrieval_id])
    forensics.ledger.close()

    traced = runner.invoke(app, ["trace", "--action", action.action_id, "--home", str(tmp_path)])
    assert traced.exit_code == 0
    assert poison.record_id in traced.stdout

    blast = runner.invoke(app, ["blast-radius", "--source", "evil", "--home", str(tmp_path)])
    assert blast.exit_code == 0
    assert poison.record_id in blast.stdout

    rolled = runner.invoke(app, ["rollback", "--to", "evil", "--dry-run", "--home", str(tmp_path)])
    assert rolled.exit_code == 0
    assert "Dry-run" in rolled.stdout


def test_reconcile_flags_orphans(tmp_path: Path) -> None:
    runner.invoke(app, ["init", "--home", str(tmp_path)])
    config = resolve_config(tmp_path)
    forensics = Forensics.open(config.ledger_path, keys.load(config.key_path), detectors=[])
    forensics.record_write("tracked", Source(source_type=SourceType.user_input), memory_id="kept")
    forensics.ledger.close()

    ids_file = tmp_path / "ids.txt"
    ids_file.write_text("kept\norphan-1\n")
    result = runner.invoke(app, ["reconcile", "--ids-file", str(ids_file), "--home", str(tmp_path)])
    assert result.exit_code == 1
    assert "orphan-1" in result.stdout
