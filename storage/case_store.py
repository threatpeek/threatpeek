import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from config import config


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    database_path = config.CASE_DATABASE_PATH
    os.makedirs(os.path.dirname(database_path) or ".", exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize() -> None:
    with _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                tags_json TEXT NOT NULL,
                results_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
            );
            """
        )


def _case_from_row(row: sqlite3.Row, notes: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    results = json.loads(row["results_json"])
    case = {
        "id": row["id"],
        "title": row["title"],
        "tags": json.loads(row["tags_json"]),
        "created_at": row["created_at"],
        "result_count": len(results),
        "malicious_count": sum(item.get("status") == "malicious" for item in results),
        "suspicious_count": sum(item.get("status") == "suspicious" for item in results),
    }
    if notes is not None:
        case["results"] = results
        case["notes"] = notes
    return case


def create_case(title: str, tags: list[str], note: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    initialize()
    cleaned_tags = list(dict.fromkeys(tag.strip() for tag in tags if tag.strip()))
    with _connect() as connection:
        cursor = connection.execute(
            "INSERT INTO cases (title, tags_json, results_json, created_at) VALUES (?, ?, ?, ?)",
            (title.strip(), json.dumps(cleaned_tags), json.dumps(results), _now()),
        )
        case_id = cursor.lastrowid
        if note.strip():
            connection.execute(
                "INSERT INTO case_notes (case_id, body, created_at) VALUES (?, ?, ?)",
                (case_id, note.strip(), _now()),
            )
    return get_case(case_id)


def list_cases(limit: int = 25) -> list[dict[str, Any]]:
    initialize()
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM cases ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_case_from_row(row) for row in rows]


def get_case(case_id: int) -> dict[str, Any] | None:
    initialize()
    with _connect() as connection:
        row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            return None
        note_rows = connection.execute(
            "SELECT id, body, created_at FROM case_notes WHERE case_id = ? ORDER BY id ASC", (case_id,)
        ).fetchall()
    return _case_from_row(row, notes=[dict(note) for note in note_rows])


def add_note(case_id: int, body: str) -> dict[str, Any] | None:
    initialize()
    with _connect() as connection:
        exists = connection.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone()
        if exists is None:
            return None
        connection.execute(
            "INSERT INTO case_notes (case_id, body, created_at) VALUES (?, ?, ?)",
            (case_id, body.strip(), _now()),
        )
    return get_case(case_id)
