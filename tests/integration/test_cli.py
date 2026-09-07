"""Tests for the CLI (spec §15.11)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from memory_blackbox.capture.engine import MemoryBlackbox
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
    blackbox = MemoryBlackbox.open(config.ledger_path, keys.load(config.key_path), detectors=[])
    blackbox.record_write("a fact", Source(source_type=SourceType.user_input))
    blackbox.ledger.close()

    result = runner.invoke(app, ["verify", "--home", str(tmp_path)])
    assert result.exit_code == 0
    assert "OK" in result.stdout


def test_verify_exits_nonzero_on_tamper(tmp_path: Path) -> None:
    runner.invoke(app, ["init", "--home", str(tmp_path)])
    config = resolve_config(tmp_path)
    blackbox = MemoryBlackbox.open(config.ledger_path, keys.load(config.key_path), detectors=[])
    for i in range(3):
        blackbox.record_write(f"e{i}", Source(source_type=SourceType.user_input))
    blackbox.ledger.close()

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
    blackbox = MemoryBlackbox.open(config.ledger_path, keys.load(config.key_path), detectors=[])
    poison_src = Source(source_id="evil", source_type=SourceType.document_ingest, locator="x")
    poison = blackbox.record_write("poison", poison_src, namespace="t")
    ret = blackbox.record_retrieval("q", returned=[poison.record_id], namespace="t")
    action = blackbox.record_action("act", "did it", context_retrievals=[ret.retrieval_id])
    blackbox.ledger.close()

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
    blackbox = MemoryBlackbox.open(config.ledger_path, keys.load(config.key_path), detectors=[])
    blackbox.record_write("tracked", Source(source_type=SourceType.user_input), memory_id="kept")
    blackbox.ledger.close()

    ids_file = tmp_path / "ids.txt"
    ids_file.write_text("kept\norphan-1\n")
    result = runner.invoke(app, ["reconcile", "--ids-file", str(ids_file), "--home", str(tmp_path)])
    assert result.exit_code == 1
    assert "orphan-1" in result.stdout


# --- anchoring --------------------------------------------------------------
def _seed(home: Path, count: int = 4) -> None:
    """Initialize a profile and write ``count`` records into its ledger."""
    runner.invoke(app, ["init", "--home", str(home)])
    config = resolve_config(home)
    blackbox = MemoryBlackbox.open(config.ledger_path, keys.load(config.key_path), detectors=[])
    for i in range(count):
        blackbox.record_write(f"m-{i}", Source(source_type=SourceType.user_input))
    blackbox.ledger.close()


def test_anchor_requires_a_backend(tmp_path: Path) -> None:
    _seed(tmp_path)
    result = runner.invoke(app, ["anchor", "--home", str(tmp_path)])
    assert result.exit_code == 2
    assert "No anchoring backend configured" in result.stderr


def test_anchor_rejects_an_unknown_backend(tmp_path: Path) -> None:
    _seed(tmp_path)
    result = runner.invoke(app, ["anchor", "--home", str(tmp_path), "--backend", "smoke-signal"])
    assert result.exit_code == 2
    assert "Unknown anchoring backend" in result.stderr


def test_anchor_then_verify_with_anchors(tmp_path: Path) -> None:
    _seed(tmp_path)
    witness = tmp_path / "witness.jsonl"
    args = ["--home", str(tmp_path), "--backend", "file", "--witness-file", str(witness)]

    anchored = runner.invoke(app, ["anchor", *args])
    assert anchored.exit_code == 0, anchored.stdout
    assert "Anchored to file-witness" in anchored.stdout
    assert witness.exists()

    verified = runner.invoke(app, ["verify", "--anchor", *args])
    assert verified.exit_code == 0, verified.stdout
    assert "external witness" in verified.stdout


def test_anchor_status_reports_the_witness_count(tmp_path: Path) -> None:
    _seed(tmp_path)
    args = ["--home", str(tmp_path), "--backend", "file"]
    runner.invoke(app, ["anchor", *args])

    status = runner.invoke(app, ["anchor-status", *args])
    assert status.exit_code == 0, status.stdout
    assert "witnesses:         1" in status.stdout


def test_verify_anchor_detects_a_rollback_that_plain_verify_misses(tmp_path: Path) -> None:
    _seed(tmp_path, count=6)
    args = ["--home", str(tmp_path), "--backend", "file"]
    assert runner.invoke(app, ["anchor", *args]).exit_code == 0

    con = sqlite3.connect(str(tmp_path / "ledger.db"))
    con.executescript(
        """
        DROP TRIGGER IF EXISTS ledger_no_delete;
        DROP TRIGGER IF EXISTS merkle_checkpoints_no_delete;
        DROP TRIGGER IF EXISTS anchors_no_delete;
        """
    )
    con.execute("DELETE FROM ledger WHERE seq > 3")
    con.execute("DELETE FROM merkle_checkpoints WHERE leaf_count > 3")
    con.execute("DELETE FROM anchors")
    con.commit()
    con.close()

    plain = runner.invoke(app, ["verify", "--home", str(tmp_path)])
    assert plain.exit_code == 0, "plain verify cannot see a rollback; that is the gap"

    anchored = runner.invoke(app, ["verify", "--anchor", *args])
    assert anchored.exit_code == 1
    assert "rollback" in anchored.stderr


def test_verify_anchor_without_a_backend_warns_and_fails(tmp_path: Path) -> None:
    # Asking for the anchor check with no backend must not read as a clean pass.
    _seed(tmp_path)
    result = runner.invoke(app, ["verify", "--anchor", "--home", str(tmp_path)])
    assert result.exit_code == 1
    assert "No anchoring backend configured" in result.stderr


def test_a_bad_anchor_environment_value_is_an_error_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MEMORY_BLACKBOX_ANCHOR", "morse-code")
    result = runner.invoke(app, ["verify", "--home", str(tmp_path)])
    assert result.exit_code == 2
    assert "not a known anchoring backend" in result.stderr
