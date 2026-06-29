"""Command-line interface for agent-forensics."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Annotated

import typer

from agent_forensics import __version__
from agent_forensics.capture.engine import Forensics
from agent_forensics.config import Config, resolve_config
from agent_forensics.crypto import keys
from agent_forensics.ledger.store import LedgerStore

app = typer.Typer(
    name="agent-forensics",
    help="Provenance and incident-reconstruction toolkit for AI agent memory.",
    no_args_is_help=True,
    add_completion=False,
)

HomeOption = Annotated[
    Path | None,
    typer.Option("--home", envvar="AGENT_FORENSICS_HOME", help="Profile directory."),
]


def _init_profile(config: Config) -> keys.KeyPair:
    config.home.mkdir(parents=True, exist_ok=True)
    keypair = keys.generate()
    keys.save(keypair, config.key_path)
    LedgerStore(config.ledger_path, keypair).close()  # create schema
    return keypair


def _open(config: Config) -> Forensics:
    if not config.key_path.exists():
        typer.secho(
            f"No profile at {config.home}. Run `agent-forensics init` first.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    return Forensics.open(config.ledger_path, keys.load(config.key_path))


@app.callback()
def _root() -> None:
    """agent-forensics command-line interface."""


@app.command()
def version() -> None:
    """Print the installed agent-forensics version."""
    typer.echo(__version__)


@app.command()
def init(home: HomeOption = None) -> None:
    """Create the ledger, signing key, and profile directory."""
    config = resolve_config(home)
    if config.key_path.exists():
        typer.echo(f"Profile already initialized at {config.home}")
        return
    _init_profile(config)
    typer.secho(f"Initialized profile at {config.home}", fg=typer.colors.GREEN)
    typer.echo(f"  ledger: {config.ledger_path}")
    typer.echo(f"  key:    {config.key_path} (0600)")


@app.command()
def demo() -> None:
    """Run the incident-replay demo end-to-end (zero config)."""
    from agent_forensics.demo import run_demo

    with tempfile.TemporaryDirectory() as tmp:
        forensics = Forensics.open(Path(tmp) / "demo.db", keys.generate(), detectors=[])
        outcome = run_demo(forensics)

    typer.echo("=== agent-forensics incident replay ===\n")
    typer.echo(f"Poison planted:        {outcome.poison_id}")
    typer.secho(
        f"Harmful action taken:  {outcome.harmful_action_id} "
        f"({'HARMFUL' if outcome.harmful_before else 'safe'})",
        fg=typer.colors.RED if outcome.harmful_before else typer.colors.GREEN,
    )
    traced = outcome.trace_primary_id == outcome.poison_id
    typer.echo(
        f"trace -> root cause:   {outcome.trace_primary_id} ({'correct' if traced else 'mismatch'})"
    )
    typer.echo(f"blast radius:          {len(outcome.blast)} record(s)")
    typer.echo(f"rollback affected:     {len(outcome.rollback_affected)} record(s)")
    rerun = "still harmful" if outcome.harmful_after else "no longer harmful"
    typer.secho(
        f"Re-run after rollback: {rerun}",
        fg=typer.colors.RED if outcome.harmful_after else typer.colors.GREEN,
    )
    typer.secho(
        f"Ledger integrity:      {'VERIFIED' if outcome.verify_ok else 'TAMPERED'}",
        fg=typer.colors.GREEN if outcome.verify_ok else typer.colors.RED,
    )


@app.command()
def verify(home: HomeOption = None) -> None:
    """Verify ledger integrity; exit nonzero on tamper."""
    from agent_forensics.query.verify import verify as verify_ledger

    forensics = _open(resolve_config(home))
    report = verify_ledger(forensics.ledger)
    if report.ok:
        typer.secho(f"OK: {report.summary}", fg=typer.colors.GREEN)
    else:
        typer.secho(f"TAMPER DETECTED: {report.summary}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@app.command()
def trace(
    action: Annotated[str, typer.Option("--action", help="Action id to trace.")],
    fmt: Annotated[str, typer.Option("--format", help="md | json | mermaid")] = "md",
    home: HomeOption = None,
) -> None:
    """Trace an action back to its root-cause writes."""
    from agent_forensics.exporters import mermaid
    from agent_forensics.query.trace import trace as trace_action

    forensics = _open(resolve_config(home))
    result = trace_action(forensics.ledger, forensics.dag, action)
    if fmt == "json":
        typer.echo(
            json.dumps(
                {
                    "action_id": result.action_id,
                    "primary": result.primary.record_id if result.primary else None,
                    "roots": [r.record_id for r in result.roots],
                }
            )
        )
    elif fmt == "mermaid":
        edges = forensics.dag.subgraph_edges(result.ancestors | {action})
        typer.echo(mermaid.provenance_graph(edges))
    else:
        if result.primary is None:
            typer.echo("No root cause found.")
        else:
            p = result.primary
            typer.echo(f"Root cause: {p.record_id} (source {p.source_id}, {p.trust_level})")
            for root in result.roots[1:]:
                typer.echo(f"  also: {root.record_id} ({root.trust_level})")


@app.command(name="blast-radius")
def blast_radius_cmd(
    source: Annotated[str, typer.Option("--source", help="Source selector.")],
    home: HomeOption = None,
) -> None:
    """Compute the blast radius of a poisoned source."""
    from agent_forensics.query.blast_radius import blast_radius

    forensics = _open(resolve_config(home))
    affected = blast_radius(forensics.ledger, forensics.dag, source)
    typer.echo(f"{len(affected)} record(s) influenced by '{source}':")
    for record_id in sorted(affected):
        typer.echo(f"  {record_id}")


@app.command()
def drift(
    topic: Annotated[str, typer.Option("--topic", help="Topic text.")],
    home: HomeOption = None,
) -> None:
    """Detect belief-drift events for a topic."""
    from agent_forensics.query.drift import drift as drift_query

    forensics = _open(resolve_config(home))
    events = drift_query(forensics.ledger, topic)
    if not events:
        typer.echo("No drift events found.")
    for event in events:
        typer.echo(
            f"{event.timestamp}  {event.record_id}  source={event.source_id}  {event.detail}"
        )


@app.command()
def timeline(
    topic: Annotated[str, typer.Option("--topic", help="Topic text.")],
    home: HomeOption = None,
) -> None:
    """Show the chronological timeline of events for a topic."""
    from agent_forensics.query.timeline import timeline as timeline_query

    forensics = _open(resolve_config(home))
    for event in timeline_query(forensics.ledger, topic):
        typer.echo(f"{event.timestamp}  [{event.kind}]  {event.text[:80]}")


@app.command()
def rollback(
    to: Annotated[str, typer.Option("--to", help="Source selector or record id.")],
    scope: Annotated[str | None, typer.Option("--scope", help="Namespace scope.")] = None,
    apply: Annotated[bool, typer.Option("--apply/--dry-run", help="Apply the rollback.")] = False,
    home: HomeOption = None,
) -> None:
    """Plan or apply a rollback of a poisoned source and its closure."""
    from agent_forensics.query.rollback import rollback as do_rollback

    forensics = _open(resolve_config(home))
    plan = do_rollback(
        forensics.ledger, forensics.dag, to, scope=scope, dry_run=not apply, reason="cli rollback"
    )
    verb = "Applied" if plan.applied else "Dry-run"
    typer.echo(f"{verb}: {plan.count} record(s) to roll back" + (f" in {scope}" if scope else ""))
    for record_id in plan.affected:
        typer.echo(f"  {record_id}")


@app.command()
def report(
    incident: Annotated[str, typer.Option("--incident", help="Action id.")],
    fmt: Annotated[str, typer.Option("--format", help="md | json | sarif")] = "md",
    home: HomeOption = None,
) -> None:
    """Render an incident report for an action."""
    from agent_forensics.exporters import markdown, sarif
    from agent_forensics.query.blast_radius import blast_radius
    from agent_forensics.query.rollback import rollback as do_rollback
    from agent_forensics.query.trace import trace as trace_action
    from agent_forensics.query.verify import verify as verify_ledger

    forensics = _open(resolve_config(home))
    tr = trace_action(forensics.ledger, forensics.dag, incident)
    selector = tr.primary.source_id if tr.primary and tr.primary.source_id else incident
    blast = blast_radius(forensics.ledger, forensics.dag, selector)
    plan = do_rollback(forensics.ledger, forensics.dag, selector, dry_run=True)
    integrity = verify_ledger(forensics.ledger)

    if fmt == "sarif":
        typer.echo(json.dumps(sarif.findings_to_sarif(forensics.findings, __version__)))
    elif fmt == "json":
        typer.echo(
            json.dumps(
                {
                    "incident": incident,
                    "root_cause": tr.primary.record_id if tr.primary else None,
                    "blast_radius": sorted(blast),
                    "rollback": plan.affected,
                    "integrity_ok": integrity.ok,
                }
            )
        )
    else:
        typer.echo(
            markdown.incident_report(
                trace=tr, blast_radius=blast, rollback_plan=plan, integrity=integrity
            )
        )


@app.command()
def reconcile(
    ids_file: Annotated[
        Path, typer.Option("--ids-file", help="File of backend ids, one per line.")
    ],
    home: HomeOption = None,
) -> None:
    """Flag backend entries that have no corresponding ledger record."""
    from agent_forensics.adapters.base import reconcile as do_reconcile

    forensics = _open(resolve_config(home))
    backend_ids = [line.strip() for line in ids_file.read_text().splitlines() if line.strip()]
    orphans = do_reconcile(forensics.ledger, backend_ids)
    if not orphans:
        typer.secho(
            "No orphan entries: every backend id has a ledger record.", fg=typer.colors.GREEN
        )
        return
    typer.secho(f"{len(orphans)} orphan entr(ies) with no provenance:", fg=typer.colors.YELLOW)
    for orphan in orphans:
        typer.echo(f"  {orphan}")
    raise typer.Exit(code=1)


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()
