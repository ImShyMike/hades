"""Database utilities"""

import sqlite3
from typing import Any

SlackMessage = dict[str, Any]


def init_db(conn: sqlite3.Connection) -> None:
    """Initialize the database schema"""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            ts TEXT PRIMARY KEY,
            user_id TEXT,
            type TEXT,
            text TEXT,
            channel_name TEXT,
            channel_id TEXT,
            channel_type TEXT,
            team_id TEXT,
            permalink TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sync_state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()


def get_sync_state(conn: sqlite3.Connection, key: str) -> str | None:
    """Get a sync state value"""
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM sync_state WHERE key = ?", (key,))
    row = cursor.fetchone()
    return str(row[0]) if row else None


def set_sync_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Set a sync state value"""
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO sync_state (key, value) VALUES (?, ?)",
        (key, value),
    )
    conn.commit()


def _get_channel_type(channel: dict[str, Any]) -> str:
    """Determine channel type from channel metadata"""
    if channel.get("is_mpim"):
        return "mpim"
    if channel.get("is_private"):
        return "private"
    if channel.get("is_im"):
        return "im"
    if channel.get("is_channel"):
        return "channel"
    return "public"


def save_messages_batch(conn: sqlite3.Connection, messages: list[SlackMessage]) -> int:
    """Save a batch of messages to the database, returns count of new messages"""
    if not messages:
        return 0

    cursor = conn.cursor()
    new_count = 0

    for msg in messages:
        cursor.execute("SELECT 1 FROM messages WHERE ts = ?", (msg["ts"],))
        if cursor.fetchone() is None:
            channel: dict[str, Any] = msg.get("channel", {})
            cursor.execute(
                """
                INSERT INTO messages (
                    ts, user_id, type, text, channel_name,
                    channel_id, channel_type, team_id, permalink
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    msg["ts"],
                    msg.get("user") or msg.get("username", ""),
                    msg.get("type", "message"),
                    msg.get("text", ""),
                    channel.get("name", ""),
                    channel.get("id", ""),
                    _get_channel_type(channel),
                    msg.get("team", ""),
                    msg.get("permalink", ""),
                ),
            )
            new_count += 1

    conn.commit()
    return new_count
