"""funny stuff"""

import base64
import json
import os
import sqlite3
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import typer
import yaml
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
        None,
        "--token",
        help="Slack User Token(s). Pass multiple times to rotate.",
    ),
    apps_file: Path = typer.Option(
        None,
        "--apps",
        "-a",
        help="Path to apps.json to use user_tokens from",
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

    Or use tokens from apps.json:
        --apps apps.json
    """
    tokens: list[str] = []

    if apps_file:
        if not apps_file.exists():
            print(f"Apps file not found: {apps_file}")
            raise typer.Exit(1)
        with open(apps_file) as f:
            apps_list: list[dict[str, Any]] = json.load(f)
        tokens = [a["user_token"] for a in apps_list if a.get("user_token")]
        if not tokens:
            print("No user tokens found in apps file. Run 'install-apps' first.")
            raise typer.Exit(1)

    if slack_tokens:
        tokens.extend(slack_tokens)

    if not tokens:
        print("No tokens provided. Use --token or --apps.")
        raise typer.Exit(1)

    pool = TokenPool(tokens)
    print(f"Using {len(tokens)} token(s)")

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
def create_apps(
    config_token: str = typer.Option(
        ...,
        "--config-token",
        help="Slack App Configuration Token (xoxe.xoxp-...)",
    ),
    count: int = typer.Option(5, help="Number of apps to create"),
    manifest_path: Path = typer.Option(
        Path("manifest.yaml"),
        "--manifest",
        help="Path to manifest YAML file",
    ),
    output: Path = typer.Option(
        Path("apps.json"),
        "--output",
        "-o",
        help="Output file for app credentials",
    ),
) -> None:
    """
    Create multiple Slack apps from a manifest and dump their credentials.

    Requires an App Configuration Token from https://api.slack.com/apps
    (under "Your App Configuration Tokens").
    """
    if not manifest_path.exists():
        print(f"Manifest file not found: {manifest_path}")
        raise typer.Exit(1)

    with open(manifest_path) as f:
        manifest = yaml.safe_load(f)

    apps: list[dict[str, Any]] = []
    base_name = manifest.get("display_information", {}).get("name", "App")

    i = 1
    while i <= count:
        app_manifest = manifest.copy()
        app_manifest.setdefault("display_information", {})
        app_manifest["display_information"]["name"] = f"{base_name} {i}"

        print(f"Creating app {i}/{count}: {app_manifest['display_information']['name']}")

        response = httpx.post(
            "https://slack.com/api/apps.manifest.create",
            headers={"Authorization": f"Bearer {config_token}"},
            json={"manifest": app_manifest},
            timeout=30,
        )
        data = response.json()

        if not data.get("ok"):
            error = data.get("error", "unknown")
            print(f"  Error: {error}")
            if error == "ratelimited":
                retry_after = int(response.headers.get("Retry-After", 60))
                print(f"  Waiting {retry_after}s before retry...")
                time.sleep(retry_after)
                continue
            if "errors" in data:
                for err in data["errors"]:
                    print(f"    - {err.get('message')} at {err.get('pointer')}")
            i += 1
            continue

        credentials = data.get("credentials", {})
        app_info = {
            "app_id": data.get("app_id"),
            "name": app_manifest["display_information"]["name"],
            "client_id": credentials.get("client_id"),
            "client_secret": credentials.get("client_secret"),
            "verification_token": credentials.get("verification_token"),
            "signing_secret": credentials.get("signing_secret"),
            "oauth_authorize_url": data.get("oauth_authorize_url"),
        }
        apps.append(app_info)
        print(f"  Created: {app_info['app_id']}")

        i += 1
        time.sleep(2)

    with open(output, "w") as f:
        json.dump(apps, f, indent=2)

    print(f"\nCreated {len(apps)} apps. Credentials saved to {output}")
    print("\nTo install apps and get user tokens, run:")
    print("  python main.py install-apps")


@app.command()
def install_apps(
    apps_file: Path = typer.Option(
        Path("apps.json"),
        "--apps",
        "-a",
        help="Path to apps.json with app credentials",
    ),
    port: int = typer.Option(3000, help="Local port for OAuth callback"),
) -> None:
    """
    Install each app to your workspace via OAuth and capture user tokens.

    Opens a browser for each app to authorize. Requires a local callback server.
    """
    import http.server
    import urllib.parse
    import webbrowser
    from threading import Event

    if not apps_file.exists():
        print(f"Apps file not found: {apps_file}")
        raise typer.Exit(1)

    with open(apps_file) as f:
        apps_list: list[dict[str, Any]] = json.load(f)

    if not apps_list:
        print("No apps found in file.")
        raise typer.Exit(1)

    redirect_uri = f"http://localhost:{port}/callback"
    captured_code: str | None = None
    done_event = Event()

    class OAuthHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            nonlocal captured_code
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/callback":
                params = urllib.parse.parse_qs(parsed.query)
                if "code" in params:
                    captured_code = params["code"][0]
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>Success!</h1><p>You can close this tab.</p></body></html>")
                    done_event.set()
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Missing code parameter")
            else:
                self.send_response(404)
                self.end_headers()

    for i, app_info in enumerate(apps_list, 1):
        if app_info.get("user_token"):
            print(f"[{i}/{len(apps_list)}] {app_info['name']}: already has token, skipping")
            continue

        client_id = app_info.get("client_id")
        client_secret = app_info.get("client_secret")
        if not client_id or not client_secret:
            print(f"[{i}/{len(apps_list)}] {app_info['name']}: missing credentials, skipping")
            continue

        print(f"[{i}/{len(apps_list)}] Installing {app_info['name']}...")

        auth_url = (
            f"https://slack.com/oauth/v2/authorize"
            f"?client_id={client_id}"
            f"&user_scope=search:read,channels:read,channels:history"
            f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        )

        captured_code = None
        done_event.clear()

        server = http.server.HTTPServer(("localhost", port), OAuthHandler)
        server.timeout = 120

        webbrowser.open(auth_url)
        print(f"  Opened browser for authorization...")

        while not done_event.is_set():
            server.handle_request()

        server.server_close()

        if not captured_code:
            print(f"  Failed to get authorization code")
            continue

        token_response = httpx.post(
            "https://slack.com/api/oauth.v2.access",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": captured_code,
                "redirect_uri": redirect_uri,
            },
            timeout=30,
        )
        token_data = token_response.json()

        if not token_data.get("ok"):
            print(f"  Token exchange failed: {token_data.get('error')}")
            continue

        user_token = token_data.get("authed_user", {}).get("access_token")
        if user_token:
            app_info["user_token"] = user_token
            print(f"  Got user token!")
        else:
            print(f"  No user token in response")

        time.sleep(1)

    with open(apps_file, "w") as f:
        json.dump(apps_list, f, indent=2)

    tokens_count = sum(1 for a in apps_list if a.get("user_token"))
    print(f"\n{tokens_count}/{len(apps_list)} apps have user tokens. Saved to {apps_file}")


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
