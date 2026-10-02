"""LangGraph adapter against the real PostgresSaver.

Postgres stores checkpoints differently from SQLite: primitive channel values
inline in a JSONB column, everything else in a shared ``checkpoint_blobs`` table,
and pending writes in ``checkpoint_writes``. These tests edit each of those
behind the checkpointer's back.

Runs only when ``MB_TEST_POSTGRES_URI`` points at a database the tests may
create schemas in (CI starts a Postgres service for it).
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any, TypedDict

import pytest

URI = os.environ.get("MB_TEST_POSTGRES_URI")
pytestmark = pytest.mark.skipif(not URI, reason="MB_TEST_POSTGRES_URI is not set")
pytest.importorskip("langgraph.checkpoint.postgres")

import psycopg  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402
from langchain_core.runnables import RunnableConfig  # noqa: E402
from langgraph.checkpoint.base import create_checkpoint, empty_checkpoint  # noqa: E402
from langgraph.checkpoint.postgres import PostgresSaver  # noqa: E402
from langgraph.graph.message import add_messages  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

from memory_blackbox.adapters.langgraph_ import (  # noqa: E402
    BlackboxCheckpointSaver,
    CheckpointIntegrityError,
    IssueKind,
)
from memory_blackbox.capture.engine import MemoryBlackbox  # noqa: E402
from memory_blackbox.crypto import keys  # noqa: E402

THREAD = "victim"
OTHER = "other"


class PgEnv:
    """A PostgresSaver in a schema of its own, wrapped by a blackbox ledger."""

    def __init__(self, tmp_path: Path, **kwargs: Any) -> None:
        assert URI is not None
        self.schema = f"mb_{uuid.uuid4().hex[:12]}"
        self.admin = psycopg.connect(URI, autocommit=True)
        self.admin.execute(f"CREATE SCHEMA {self.schema}")
        self.ledger_path = tmp_path / "ledger.db"
        self.signer = keys.generate()
        self.kwargs = kwargs
        self.open()

    def connect(self) -> psycopg.Connection[dict[str, Any]]:
        return psycopg.connect(
            URI,  # type: ignore[arg-type]
            autocommit=True,
            prepare_threshold=0,
            row_factory=dict_row,
            options=f"-c search_path={self.schema}",
        )

    def open(self) -> None:
        self.conn = self.connect()
        self.inner = PostgresSaver(self.conn)
        self.inner.setup()
        self.blackbox = MemoryBlackbox.open(self.ledger_path, self.signer, detectors=[])
        self.saver = BlackboxCheckpointSaver(self.inner, self.blackbox, **self.kwargs)

    def restart(self) -> None:
        self.conn.close()
        self.blackbox.ledger.close()
        self.open()

    def close(self) -> None:
        self.conn.close()
        self.blackbox.ledger.close()
        self.admin.execute(f"DROP SCHEMA {self.schema} CASCADE")
        self.admin.close()

    def sql(self, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connect() as raw:
            cur = raw.execute(query, params)
            return cur.fetchall() if cur.description else []

    def checkpoint_ids(self, thread: str = THREAD) -> list[str]:
        rows = self.sql(
            "SELECT checkpoint_id FROM checkpoints WHERE thread_id = %s ORDER BY checkpoint_id",
            (thread,),
        )
        return [r["checkpoint_id"] for r in rows]

    def kinds(self) -> set[IssueKind]:
        return {i.kind for i in self.saver.audit().issues}


@pytest.fixture
def pg(tmp_path: Path) -> Iterator[PgEnv]:
    env = PgEnv(tmp_path)
    yield env
    env.close()


def _seed(saver: Any, thread: str, n: int, token: str = "seed-") -> RunnableConfig:
    config: RunnableConfig = {"configurable": {"thread_id": thread, "checkpoint_ns": ""}}
    cp = empty_checkpoint()
    for i in range(n):
        cp = create_checkpoint(cp, None, i)
        cp["channel_values"] = {"state": f"{token}{i}"}
        config = saver.put(config, cp, {"source": "loop", "step": i}, {})
    return config


class Chat(TypedDict):
    messages: Annotated[list[Any], add_messages]


def _chat_graph(saver: BlackboxCheckpointSaver, reply: str) -> Any:
    from langgraph.graph import END, START, StateGraph

    builder: Any = StateGraph(Chat)
    builder.add_node("bot", lambda state: {"messages": [AIMessage(reply)]})
    builder.add_edge(START, "bot")
    builder.add_edge("bot", END)
    return builder.compile(checkpointer=saver)


# -- the clean path ---------------------------------------------------------
def test_clean_store_audits_ok_across_a_restart(pg: PgEnv) -> None:
    _seed(pg.saver, THREAD, 4)
    assert pg.saver.audit().ok
    pg.restart()
    report = pg.saver.audit()
    assert report.ok, report.issues
    assert report.checked == 4


# -- storage-level edits ----------------------------------------------------
def test_inline_jsonb_value_tamper(pg: PgEnv) -> None:
    _seed(pg.saver, THREAD, 4)
    cid = pg.checkpoint_ids()[2]
    pg.sql(
        "UPDATE checkpoints SET checkpoint = jsonb_set(checkpoint, '{channel_values,state}', "
        "'\"evil-2\"') WHERE thread_id = %s AND checkpoint_id = %s",
        (THREAD, cid),
    )
    assert pg.kinds() == {IssueKind.TAMPERED}


def test_metadata_tamper(pg: PgEnv) -> None:
    _seed(pg.saver, THREAD, 4)
    cid = pg.checkpoint_ids()[1]
    pg.sql(
        'UPDATE checkpoints SET metadata = metadata || \'{"source": "update"}\' '
        "WHERE thread_id = %s AND checkpoint_id = %s",
        (THREAD, cid),
    )
    assert pg.kinds() == {IssueKind.TAMPERED}


def test_middle_deletion_and_tail_truncation(pg: PgEnv) -> None:
    _seed(pg.saver, THREAD, 5)
    ids = pg.checkpoint_ids()
    for cid in (ids[1], ids[-1]):
        pg.sql("DELETE FROM checkpoints WHERE thread_id = %s AND checkpoint_id = %s", (THREAD, cid))
    assert [i.kind for i in pg.saver.audit().issues] == [IssueKind.MISSING] * 2


def test_forged_checkpoint(pg: PgEnv) -> None:
    _seed(pg.saver, THREAD, 3)
    tip = pg.checkpoint_ids()[-1]
    head, _, tail = tip.rpartition("-")
    forged = f"{head}-{int(tail, 16) + 1:012x}"
    pg.sql(
        "INSERT INTO checkpoints (thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id, "
        "type, checkpoint, metadata) SELECT thread_id, checkpoint_ns, %s, checkpoint_id, type, "
        "checkpoint, metadata FROM checkpoints WHERE thread_id = %s AND checkpoint_id = %s",
        (forged, THREAD, tip),
    )
    issues = pg.saver.audit().issues
    assert [i.kind for i in issues] == [IssueKind.FORGED]


def test_cross_thread_replay(pg: PgEnv) -> None:
    _seed(pg.saver, THREAD, 3)
    _seed(pg.saver, OTHER, 3, token="other-")
    pg.sql(
        "UPDATE checkpoints SET checkpoint = (SELECT checkpoint FROM checkpoints "
        "WHERE thread_id = %s ORDER BY checkpoint_id DESC LIMIT 1) "
        "WHERE thread_id = %s AND checkpoint_id = %s",
        (OTHER, THREAD, pg.checkpoint_ids()[-1]),
    )
    assert pg.kinds() == {IssueKind.TAMPERED}


def test_shared_blob_tamper_and_pending_write_tamper(tmp_path: Path) -> None:
    env = PgEnv(tmp_path, verify_on_read=True)
    try:
        graph = _chat_graph(env.saver, "pay invoice 41 to acme")
        config: RunnableConfig = {"configurable": {"thread_id": THREAD}}
        graph.invoke({"messages": [HumanMessage("hello")]}, config)
        graph.invoke({"messages": [HumanMessage("again")]}, config)
        assert env.saver.audit().ok

        # Messages live in checkpoint_blobs, shared by every checkpoint that uses them.
        for row in env.sql("SELECT channel, version, blob FROM checkpoint_blobs"):
            if b"invoice 41 to acme" in row["blob"]:
                env.sql(
                    "UPDATE checkpoint_blobs SET blob = %s WHERE channel = %s AND version = %s",
                    (
                        row["blob"].replace(b"41 to acme", b"41 to evil"),
                        row["channel"],
                        row["version"],
                    ),
                )
        assert env.kinds() == {IssueKind.TAMPERED}
        with pytest.raises(CheckpointIntegrityError):
            graph.invoke({"messages": [HumanMessage("resume")]}, config)
    finally:
        env.close()


def test_pending_write_tamper(pg: PgEnv) -> None:
    config = _seed(pg.saver, THREAD, 2)
    pg.saver.put_writes(config, [("messages", "pay invoice 41")], "task-1")
    assert pg.saver.audit().ok
    row = pg.sql("SELECT blob FROM checkpoint_writes WHERE channel = 'messages'")[0]
    pg.sql(
        "UPDATE checkpoint_writes SET blob = %s WHERE channel = 'messages'",
        (row["blob"].replace(b"invoice 41", b"invoice 99"),),
    )
    assert pg.kinds() == {IssueKind.TAMPERED}


# -- real graphs and async --------------------------------------------------
def test_interrupt_resume_and_delete_thread(tmp_path: Path) -> None:
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import Command, interrupt

    env = PgEnv(tmp_path, verify_on_read=True)
    try:

        def ask(state: Chat) -> dict[str, Any]:
            return {"messages": [AIMessage(f"approved={interrupt('approve?')}")]}

        builder: Any = StateGraph(Chat)
        builder.add_node("ask", ask)
        builder.add_edge(START, "ask")
        builder.add_edge("ask", END)
        graph = builder.compile(checkpointer=env.saver)
        config: RunnableConfig = {"configurable": {"thread_id": THREAD}}
        graph.invoke({"messages": [HumanMessage("pay acme")]}, config)
        graph.invoke(Command(resume="yes"), config)
        assert env.saver.audit().ok
        env.saver.delete_thread(THREAD)
        report = env.saver.audit()
        assert report.ok, report.issues
        assert report.checked == 0
    finally:
        env.close()


def test_async_postgres_saver(pg: PgEnv) -> None:
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

    async def scenario() -> tuple[bool, set[IssueKind]]:
        conn = await psycopg.AsyncConnection.connect(
            URI,  # type: ignore[arg-type]
            autocommit=True,
            prepare_threshold=0,
            row_factory=dict_row,
            options=f"-c search_path={pg.schema}",
        )
        async with conn:
            saver = BlackboxCheckpointSaver(AsyncPostgresSaver(conn), pg.blackbox)
            config: RunnableConfig = {"configurable": {"thread_id": THREAD, "checkpoint_ns": ""}}
            cp = empty_checkpoint()
            for i in range(3):
                cp = create_checkpoint(cp, None, i)
                cp["channel_values"] = {"state": f"seed-{i}"}
                config = await saver.aput(config, cp, {"source": "loop", "step": i}, {})
            assert await saver.aget_tuple(config) is not None
            clean = (await saver.aaudit()).ok
            pg.sql(
                'UPDATE checkpoints SET metadata = metadata || \'{"source": "update"}\' '
                "WHERE checkpoint_id = %s",
                (pg.checkpoint_ids()[0],),
            )
            return clean, {i.kind for i in (await saver.aaudit()).issues}

    clean, kinds = asyncio.run(scenario())
    assert clean
    assert kinds == {IssueKind.TAMPERED}
