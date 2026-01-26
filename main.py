"""funny stuff"""

import base64
import os
import sqlite3
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import typer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.web import SlackResponse
from tqdm import tqdm

app = typer.Typer()

# --- config ---
ITERATIONS = 200_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # AES-256
DB_PATH = "slack_messages.db"
BATCH_SIZE = 100  # Save to DB every N messages

SlackMessage = dict[str, Any]


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a key from a password and salt using PBKDF2HMAC"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt(text: str, password: str) -> str:
    """Encrypts text using a password"""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, text.encode(), None)

    blob = salt + nonce + ciphertext
    return "v1:" + base64.b64encode(blob).decode()


def decrypt(token: str, password: str) -> str:
    """Decrypts a token previously encrypted with `encrypt`"""
    if not token.startswith("v1:"):
        raise ValueError("Invalid format")

    blob = base64.b64decode(token[3:])
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN : SALT_LEN + NONCE_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN :]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


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
    """Determine channel type from channel metadata."""
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


class TokenPool:  # pylint: disable=too-few-public-methods
    """Rotating pool of Slack clients to distribute rate limits."""

    def __init__(self, tokens: list[str]) -> None:
        self.clients = [WebClient(token=t) for t in tokens]
        self.index = 0

    def next(self) -> WebClient:
        """Get the next client in rotation."""
        client = self.clients[self.index]
        self.index = (self.index + 1) % len(self.clients)
        return client


def api_call_with_retry(
    pool: TokenPool,
    method: str,
    max_retries: int = 5,
    base_delay: float = 1.0,
    **kwargs: Any,
) -> SlackResponse:
    """Execute an API call with token rotation and exponential backoff."""
    for attempt in range(max_retries * len(pool.clients)):
        client = pool.next()
        try:
            func: Callable[..., SlackResponse] = getattr(client, method)
            return func(**kwargs)
        except SlackApiError as e:
            if e.response.get("error") == "ratelimited": # type: ignore
                retry_after = int(
                    e.response.headers.get("Retry-After", base_delay * (2**attempt)) # type: ignore
                )
                print(f"\nRate limited. Rotating token, waiting {retry_after}s...")
                time.sleep(retry_after)
            else:
                raise
    raise RuntimeError(f"Max retries exceeded across all {len(pool.clients)} tokens")


def _get_search_totals(pool: TokenPool, query: str) -> tuple[int, int]:
    """Get total messages and pages for a search query."""
    response = api_call_with_retry(
        pool,
        "search_messages",
        query=query,
        count=1,
        page=1,
    )
    messages_data: dict[str, Any] = response.get("messages", {})
    total_messages: int = messages_data.get("total", 0)
    paging: dict[str, Any] = messages_data.get("paging", {})
    total_pages: int = paging.get("pages", 0)
    return total_messages, total_pages


def _fetch_page(pool: TokenPool, query: str, page: int) -> list[SlackMessage]:
    """Fetch a single page of search results."""
    response = api_call_with_retry(
        pool,
        "search_messages",
        query=query,
        count=100,
        page=page,
        sort="timestamp",
        sort_dir="asc",
    )
    messages_data: dict[str, Any] = response.get("messages", {})
    matches: list[SlackMessage] = messages_data.get("matches", [])
    return matches


def _get_newest_timestamp(messages: list[SlackMessage]) -> str | None:
    """Get the newest timestamp from a list of messages."""
    if not messages:
        return None
    newest: str = max(msg["ts"] for msg in messages)
    return newest


def _fetch_chunk(
    pool: TokenPool,
    conn: sqlite3.Connection,
    query: str,
    pbar: "tqdm[Any]",
) -> tuple[int, str | None]:
    """
    Fetch up to 100 pages (10k messages) for a query.
    Returns (saved_count, newest_timestamp) for pagination.
    """
    total_saved = 0
    batch: list[SlackMessage] = []
    newest_ts: str | None = None
    page = 1

    _, total_pages = _get_search_totals(pool, query)
    max_page = min(total_pages, 100)

    while page <= max_page:
        matches = _fetch_page(pool, query, page)
        if not matches:
            break

        batch.extend(matches)

        page_newest = _get_newest_timestamp(matches)
        if page_newest and (newest_ts is None or page_newest > newest_ts):
            newest_ts = page_newest

        if len(batch) >= BATCH_SIZE:
            total_saved += save_messages_batch(conn, batch)
            batch = []

        page += 1
        pbar.update(len(matches))

    if batch:
        total_saved += save_messages_batch(conn, batch)

    return total_saved, newest_ts


def search_user_messages(
    pool: TokenPool,
    user_id: str,
    conn: sqlite3.Connection,
) -> int:
    """
    Search for all public channel messages from a user.
    Uses date-based chunking to bypass the 10k message API limit.
    """
    base_query = f"from:<@{user_id}>"

    total_messages, _ = _get_search_totals(pool, base_query)
    if not total_messages:
        print("No public channel messages found for this user.")
        return 0

    print(f"Found {total_messages} public channel messages")

    last_after = get_sync_state(conn, "last_after")
    if last_after:
        print(f"Resuming from after:{last_after}")

    total_saved = 0
    after_date: str | None = last_after

    pbar = tqdm(total=total_messages, desc="Fetching messages", unit="msg")

    while True:
        if after_date:
            query = f"{base_query} after:{after_date}"
        else:
            query = base_query

        chunk_total, _ = _get_search_totals(pool, query)
        if not chunk_total:
            break

        saved, newest_ts = _fetch_chunk(pool, conn, query, pbar)
        total_saved += saved

        if not newest_ts:
            break

        newest_dt = datetime.fromtimestamp(float(newest_ts))
        padded_dt = newest_dt - timedelta(days=1)
        after_date = padded_dt.strftime("%Y-%m-%d")
        set_sync_state(conn, "last_after", after_date)

        if not saved:
            break

    pbar.close()
    set_sync_state(conn, "completed", "true")
    return total_saved


@app.command()
def run(
    user_id: str = typer.Option(..., help="Slack User ID to fetch messages for"),
    slack_tokens: list[str] = typer.Option(
        ...,
        "--token",
        help="Slack User Token(s). Pass multiple times to rotate.",
    ),
    resume: bool = typer.Option(
        False,
        help="Resume from last saved position",
    ),
) -> None:
    """
    Fetch all public channel messages from a Slack user using the search API.

    NOTE: This requires USER tokens (xoxp-...) with search:read scope,
    not bot tokens. Bot tokens cannot use the search API.

    Pass multiple tokens to distribute rate limits:
        --token xoxp-... --token xoxp-... --token xoxp-...
    """
    pool = TokenPool(slack_tokens)
    print(f"Using {len(slack_tokens)} token(s)")

    with sqlite3.connect(DB_PATH) as conn:
        init_db(conn)

        if not resume:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sync_state")
            conn.commit()

        try:
            total = search_user_messages(pool, user_id, conn)
            print(f"\nSaved {total} new messages to {DB_PATH}")
        except KeyboardInterrupt:
            print("\n\nInterrupted! Progress saved. Use --resume to continue.")
        except SlackApiError as e:
            print(f"\n\nSlack API error: {e.response['error']}")
            print("Progress saved. Use --resume to continue.")
            raise


@app.command()
def stats() -> None:
    """Show statistics about saved messages"""
    if not os.path.exists(DB_PATH):
        print("No database found.")
        return

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM messages")
        row = cursor.fetchone()
        total: int = row[0] if row else 0

        cursor.execute("SELECT MIN(ts), MAX(ts) FROM messages")
        ts_row = cursor.fetchone()
        min_ts: str | None = ts_row[0] if ts_row else None
        max_ts: str | None = ts_row[1] if ts_row else None

        if min_ts and max_ts:
            oldest = datetime.fromtimestamp(float(min_ts))
            newest = datetime.fromtimestamp(float(max_ts))
            print(f"Total messages: {total}")
            print(f"Date range: {oldest.date()} to {newest.date()}")
        else:
            print(f"Total messages: {total}")

        cursor.execute("""
            SELECT channel_name, COUNT(*) as count
            FROM messages
            GROUP BY channel_name
            ORDER BY count DESC
            LIMIT 10
        """)
        rows: list[tuple[str, int]] = cursor.fetchall()
        if rows:
            print("\nTop channels:")
            for name, count in rows:
                print(f"  #{name or 'unknown'}: {count}")


if __name__ == "__main__":
    app()
