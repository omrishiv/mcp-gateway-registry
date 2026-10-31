"""Property tests for SQL identifier safety in the metrics-service retention manager.

``metrics-service/app/core/retention.py`` interpolates table and column names
into SQL with f-strings, relying on allowlists (``ALLOWED_TABLE_NAMES``,
``ALLOWED_TIMESTAMP_COLUMNS``) and, for names read back from
``sqlite_master``, a safe-identifier check. The security property is that every
identifier that reaches an f-string SQL statement is either on the allowlist or
a plain ``[A-Za-z_][A-Za-z0-9_]*`` identifier naming exactly the table it came
from, and that any other name raises before a single statement executes.
"""

import asyncio
import importlib
import importlib.util
import re
import sqlite3
import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from hypothesis import (
    assume,
    example,
    given,
    settings,
)
from hypothesis import strategies as st

_REPO_ROOT = Path(__file__).resolve().parents[3]
_METRICS_APP_DIR = _REPO_ROOT / "metrics-service" / "app"
# Load metrics-service's `app` package under a private name so it cannot clash
# with any other top-level `app` module.
_METRICS_APP_ALIAS = "_metrics_service_app"

_SAFE_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Shapes of every f-string statement in retention.py that names a table or a
# timestamp column.
_TABLE_REFERENCE = re.compile(r"\bFROM\s+([^\s)]+)")
_COLUMN_REFERENCE = re.compile(r"\b(?:MIN|MAX)\(([^)]+)\)|\bWHERE\s+([^\s<]+)\s*<")

IDENTIFIER_SUFFIX_REASON = (
    "Known defect: _validate_identifier anchors its pattern with '$', which also "
    "matches before a trailing newline, so a name such as 'a\\n' is accepted."
)
STATS_SUFFIX_REASON = (
    "Known defect: a sqlite_master table named 'a\\n' passes _validate_identifier, "
    "and its stats query 'FROM a\\n' reads table 'a' instead."
)


class _AsyncCursor:
    """Async view of a sqlite3 cursor, shaped like an aiosqlite cursor."""

    def __init__(
        self,
        cursor: sqlite3.Cursor,
    ) -> None:
        """Wrap a sqlite3 cursor."""
        self._cursor = cursor

    @property
    def rowcount(self) -> int:
        """Return the wrapped cursor's row count."""
        return self._cursor.rowcount

    async def fetchone(self) -> Any:
        """Return the next row."""
        return self._cursor.fetchone()

    async def fetchall(self) -> list[Any]:
        """Return all remaining rows."""
        return self._cursor.fetchall()


class _AsyncConnection:
    """Async connection over a shared in-memory database that records SQL."""

    def __init__(
        self,
        backend: "_InMemoryAiosqlite",
    ) -> None:
        """Bind the connection to its backend."""
        self._backend = backend

    async def execute(
        self,
        sql: str,
        parameters: tuple[Any, ...] = (),
    ) -> _AsyncCursor:
        """Record and run one statement.

        Args:
            sql: Statement text.
            parameters: Bound parameters.

        Returns:
            The statement's cursor.
        """
        self._backend.statements.append(sql)
        return _AsyncCursor(self._backend.conn.execute(sql, parameters))

    async def commit(self) -> None:
        """Commit any open transaction."""
        if self._backend.conn.in_transaction:
            self._backend.conn.execute("COMMIT")

    async def rollback(self) -> None:
        """Roll back any open transaction."""
        if self._backend.conn.in_transaction:
            self._backend.conn.execute("ROLLBACK")

    async def __aenter__(self) -> "_AsyncConnection":
        """Enter the connection context."""
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        """Leave the shared connection open for the next caller."""
        await self.rollback()


class _InMemoryAiosqlite:
    """Stand-in for the ``aiosqlite`` module over one in-memory database.

    Every ``connect`` call shares the same sqlite3 connection, so the test can
    seed tables up front, and every executed statement is recorded.
    """

    def __init__(self) -> None:
        """Open the in-memory database in autocommit mode."""
        self.conn = sqlite3.connect(":memory:", isolation_level=None)
        self.statements: list[str] = []

    def connect(
        self,
        database: Any,
        **kwargs: Any,
    ) -> _AsyncConnection:
        """Return a connection to the shared database; the path is ignored."""
        return _AsyncConnection(self)


def _load_retention() -> types.ModuleType:
    """Import metrics-service ``app.core.retention`` without aiosqlite installed.

    The main venv does not install aiosqlite, so a placeholder module is
    present only while the package imports; each test then swaps the module's
    ``aiosqlite`` global for an in-memory backend.

    Returns:
        The retention module.
    """
    qualified = f"{_METRICS_APP_ALIAS}.core.retention"
    if qualified in sys.modules:
        return sys.modules[qualified]
    saved_aiosqlite = sys.modules.get("aiosqlite")
    sys.modules["aiosqlite"] = types.ModuleType("aiosqlite")
    try:
        spec = importlib.util.spec_from_file_location(
            _METRICS_APP_ALIAS,
            _METRICS_APP_DIR / "__init__.py",
            submodule_search_locations=[str(_METRICS_APP_DIR)],
        )
        package = importlib.util.module_from_spec(spec)
        sys.modules[_METRICS_APP_ALIAS] = package
        spec.loader.exec_module(package)
        return importlib.import_module(qualified)
    finally:
        if saved_aiosqlite is None:
            sys.modules.pop("aiosqlite", None)
        else:
            sys.modules["aiosqlite"] = saved_aiosqlite


retention = _load_retention()

ALLOWED_TABLES: frozenset[str] = frozenset(retention.ALLOWED_TABLE_NAMES)
ALLOWED_COLUMNS: frozenset[str] = frozenset(retention.ALLOWED_TIMESTAMP_COLUMNS)


def _seed_backend(
    backend: _InMemoryAiosqlite,
    policy_rows: list[tuple[str, int]] = (),
) -> None:
    """Create the allowlisted tables, the policy table and some expired rows.

    Args:
        backend: The in-memory database.
        policy_rows: ``(table_name, retention_days)`` rows for
            ``retention_policies``, all active.
    """
    conn = backend.conn
    for table in sorted(ALLOWED_TABLES):
        conn.execute(
            f'CREATE TABLE "{table}" (id INTEGER PRIMARY KEY, created_at TEXT, timestamp TEXT)'
        )
        conn.execute(
            f'INSERT INTO "{table}" (created_at, timestamp) VALUES (?, ?)',
            ("2000-01-01T00:00:00", "2000-01-01T00:00:00"),
        )
    conn.execute(
        "CREATE TABLE retention_policies ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, table_name TEXT UNIQUE NOT NULL,"
        " retention_days INTEGER NOT NULL, is_active BOOLEAN DEFAULT 1,"
        " cleanup_query TEXT, timestamp_column TEXT DEFAULT 'created_at',"
        " created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')))"
    )
    conn.executemany(
        "INSERT INTO retention_policies (table_name, retention_days, is_active) VALUES (?, ?, 1)",
        list(policy_rows),
    )


def _interpolated_identifiers(
    statements: list[str],
) -> tuple[set[str], set[str]]:
    """Extract the table and column names from retention's dynamic statements.

    Statements on ``retention_policies`` and ``VACUUM`` are fixed text with
    bound parameters, so they are skipped.

    Args:
        statements: Recorded SQL statements.

    Returns:
        (table names, column names) referenced by the dynamic statements.
    """
    tables: set[str] = set()
    columns: set[str] = set()
    for sql in statements:
        if "retention_policies" in sql or sql.strip().upper() in {"VACUUM", "BEGIN IMMEDIATE"}:
            continue
        tables.update(_TABLE_REFERENCE.findall(sql))
        for min_max, where in _COLUMN_REFERENCE.findall(sql):
            columns.add(min_max or where)
    columns.discard("*")
    return tables, columns


def _near_misses(
    allowed: frozenset[str],
) -> st.SearchStrategy[str]:
    """Draw names close to, but not on, an allowlist.

    Args:
        allowed: The allowlist.

    Returns:
        A strategy of arbitrary text and decorated allowlisted names.
    """
    decorated = st.builds(
        lambda prefix, name, suffix, upper: (prefix + (name.upper() if upper else name) + suffix),
        st.sampled_from(["", " ", '"', "main.", "x"]),
        st.sampled_from(sorted(allowed)),
        st.sampled_from(["", "\n", " ", ";", " WHERE 1=1; /*", "_x", "\x00"]),
        st.booleans(),
    )
    return st.one_of(st.text(max_size=24), decorated).filter(lambda name: name not in allowed)


@pytest.mark.unit
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(
    table_name=st.one_of(st.sampled_from(sorted(ALLOWED_TABLES)), _near_misses(ALLOWED_TABLES)),
    column=st.one_of(st.sampled_from(sorted(ALLOWED_COLUMNS)), _near_misses(ALLOWED_COLUMNS)),
    retention_days=st.integers(min_value=1, max_value=36525),
)
@example(table_name="metrics\n", column="created_at", retention_days=30)
@example(table_name="metrics", column="created_at; DROP TABLE metrics", retention_days=30)
@example(table_name="test_metrics", column="created_at", retention_days=30)
def test_policy_identifiers_come_from_the_allowlist(
    table_name: str,
    column: str,
    retention_days: int,
) -> None:
    """Property: a RetentionPolicy exists only for allowlisted table and column names."""
    assume(table_name not in ALLOWED_TABLES or column not in ALLOWED_COLUMNS)
    with pytest.raises(ValueError):
        retention.RetentionPolicy(
            table_name=table_name,
            retention_days=retention_days,
            timestamp_column=column,
        )


async def _call_entry_point(
    manager: Any,
    entry_point: str,
    table_name: str,
) -> None:
    """Invoke one RetentionManager entry point that takes a table name."""
    if entry_point == "update_policy":
        await manager.update_policy(table_name, 30)
    elif entry_point == "get_cleanup_preview":
        await manager.get_cleanup_preview(table_name)
    else:
        await manager.cleanup_table(table_name, dry_run=entry_point == "cleanup_table_dry_run")


@pytest.mark.unit
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(
    table_name=_near_misses(ALLOWED_TABLES),
    entry_point=st.sampled_from(
        ["update_policy", "get_cleanup_preview", "cleanup_table", "cleanup_table_dry_run"]
    ),
)
@example(table_name="metrics; DROP TABLE metrics", entry_point="cleanup_table")
@example(table_name="metrics\n", entry_point="get_cleanup_preview")
@example(table_name="sqlite_master", entry_point="update_policy")
def test_unknown_table_name_raises_before_any_sql(
    table_name: str,
    entry_point: str,
) -> None:
    """Property: a table name outside the allowlist raises before any statement executes."""
    backend = _InMemoryAiosqlite()
    _seed_backend(backend)
    with patch.object(retention, "aiosqlite", backend):
        manager = retention.RetentionManager()
        with pytest.raises((ValueError, KeyError)):
            asyncio.run(_call_entry_point(manager, entry_point, table_name))
    assert backend.statements == [], (
        f"{entry_point}({table_name!r}) executed SQL: {backend.statements}"
    )


@pytest.mark.unit
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(
    policy_rows=st.lists(
        st.tuples(
            st.one_of(st.sampled_from(sorted(ALLOWED_TABLES)), _near_misses(ALLOWED_TABLES)),
            st.integers(min_value=-5, max_value=40000),
        ),
        max_size=6,
        unique_by=lambda row: row[0],
    ),
)
@example(policy_rows=[("metrics; DROP TABLE auth_metrics", 30), ("metrics", 7)])
@example(policy_rows=[("sqlite_master", 30)])
def test_persisted_policies_only_ever_name_allowlisted_identifiers(
    policy_rows: list[tuple[str, int]],
) -> None:
    """Property: SQL built from stored policies names only allowlisted tables and columns."""
    backend = _InMemoryAiosqlite()
    _seed_backend(backend, policy_rows)
    with patch.object(retention, "aiosqlite", backend):
        manager = retention.RetentionManager()
        asyncio.run(manager.load_policies_from_database())
        asyncio.run(manager.get_cleanup_preview())
        asyncio.run(manager.cleanup_all_tables(dry_run=False))
    held = {(policy.table_name, policy.timestamp_column) for policy in manager.policies.values()}
    assert {table for table, _ in held} <= ALLOWED_TABLES, held
    assert {column for _, column in held} <= ALLOWED_COLUMNS, held
    tables, columns = _interpolated_identifiers(backend.statements)
    assert tables and tables <= ALLOWED_TABLES, (tables, backend.statements)
    assert columns <= ALLOWED_COLUMNS, (columns, backend.statements)


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=IDENTIFIER_SUFFIX_REASON)
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(identifier=st.text(max_size=12))
@example(identifier="a\n")
def test_identifier_check_accepts_only_plain_identifiers(
    identifier: str,
) -> None:
    """Property: _validate_identifier accepts a name only if it is a plain SQL identifier."""
    try:
        accepted = retention._validate_identifier(identifier)
    except ValueError:
        return
    assert _SAFE_IDENTIFIER.fullmatch(accepted), f"accepted unsafe identifier {accepted!r}"


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=STATS_SUFFIX_REASON)
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(
    names=st.lists(
        st.text(alphabet="ab_1 \n\"';-.", min_size=1, max_size=6),
        max_size=4,
        unique_by=str.lower,
    ),
)
@example(names=["a", "a\n"])
def test_table_stats_reads_exactly_the_named_table(
    names: list[str],
) -> None:
    """Property: stats are reported only for plain identifiers, counted from that very table."""
    backend = _InMemoryAiosqlite()
    expected_counts: dict[str, int] = {}
    for index, name in enumerate(names):
        quoted = '"' + name.replace('"', '""') + '"'
        backend.conn.execute(
            f"CREATE TABLE {quoted} (id INTEGER PRIMARY KEY, created_at TEXT, timestamp TEXT)"
        )
        backend.conn.executemany(
            f"INSERT INTO {quoted} (created_at) VALUES (?)",
            [("2000-01-01T00:00:00",)] * (index + 1),
        )
        expected_counts[name] = index + 1
    with patch.object(retention, "aiosqlite", backend):
        manager = retention.RetentionManager()
        stats = asyncio.run(manager.get_table_stats())
    for name, entry in stats.items():
        if "record_count" not in entry:
            continue
        assert _SAFE_IDENTIFIER.fullmatch(name), (
            f"stats reported for unsafe table name {name!r}: {entry}"
        )
        assert entry["record_count"] == expected_counts[name], (
            f"stats for {name!r} counted {entry['record_count']} rows, "
            f"table holds {expected_counts[name]}"
        )
