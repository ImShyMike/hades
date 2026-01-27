"""transparent slack message anonymizer"""

import json
import os
import re
import sqlite3
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Optional

import httpx
import tqdm
import typer
import yaml
from slack_sdk.errors import SlackApiError
from typer import colors

from hades.crypto import decrypt_text, derive_key, encrypt_text
from hades.db import init_db
from hades.oauth import do_oauth_flow
from hades.slack import TokenPool, api_call_with_retry, search_user_messages
from hades.unicode import WORD_JOINER, PREFIX

app = typer.Typer(
    name="hades",
    help="transparent slack message anonymizer",
    add_completion=True,
    no_args_is_help=True,
)

DEFAULT_DB_PATH = "slack_messages.db"


def load_tokens_from_apps_file(apps_file: Path) -> list[str]:
    """Load user tokens from an apps.json file."""
    if not apps_file.exists():
        typer.echo(typer.style(f"Apps file not found: {apps_file}", fg=colors.RED))
        raise typer.Exit(1)
    with open(apps_file, encoding="utf8") as f:
        apps_list: list[dict[str, Any]] = json.load(f)
    tokens = [a["user_token"] for a in apps_list if a.get("user_token")]
    if not tokens:
        typer.echo(
            typer.style(
                "No user tokens found in apps file. Run 'install-apps' first.",
                fg=colors.RED,
            )
        )
        raise typer.Exit(1)
    return tokens


@app.command()
def download(
    user_id: str = typer.Argument(..., help="Slack User ID to fetch messages for"),
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
    path: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        help="Path to SQLite database file",
    ),
    purge: bool = typer.Option(
        False,
        "--purge",
        help="Purge existing data before downloading",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation prompt when purging",
    ),
    resume: bool = typer.Option(
        False,
        help="Resume from last saved position",
    ),
) -> None:
    """
    Fetch all public channel messages from a Slack user.

    NOTE: This requires USER tokens (xoxp-...) with search:read scope,
    not bot tokens. Bot tokens cannot use the search API.

    Pass multiple tokens to distribute rate limits:
        --token xoxp-... --token xoxp-... --token xoxp-...

    Or use tokens from apps.json:
        --apps apps.json
    """
    tokens: list[str] = []

    if apps_file:
        tokens.extend(load_tokens_from_apps_file(apps_file))

    if slack_tokens:
        tokens.extend(slack_tokens)

    if not tokens:
        typer.echo(
            typer.style("No tokens provided. Use --token or --apps.", fg=colors.RED)
        )
        raise typer.Exit(1)

    pool = TokenPool(tokens)
    typer.echo(
        f"Using {typer.style(str(len(tokens)), fg=colors.CYAN, bold=True)} token(s)"
    )

    with sqlite3.connect(path) as conn:
        if purge and not resume:
            if not yes:
                typer.echo(
                    typer.style(
                        f"WARNING: This will DELETE ALL DATA in {path}", fg=colors.RED
                    )
                )
                confirm = typer.prompt(
                    typer.style("Type 'purge' to proceed", fg=colors.YELLOW)
                )
                if confirm.lower() != "purge":
                    typer.echo(typer.style("Aborted.", fg=colors.RED))
                    raise typer.Exit(1)
            cursor = conn.cursor()
            cursor.execute("DROP TABLE IF EXISTS messages")
            cursor.execute("DROP TABLE IF EXISTS sync_state")
            conn.commit()

        init_db(conn)

        if not resume:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sync_state")
            conn.commit()

        try:
            total = search_user_messages(pool, user_id, conn)
            typer.echo(
                f"\nSaved {typer.style(str(total), fg=colors.GREEN, bold=True)} "
                f"new messages to {path}"
            )
        except KeyboardInterrupt:
            typer.echo(
                typer.style(
                    "\n\nInterrupted! Progress saved. Use --resume to continue.",
                    fg=colors.YELLOW,
                )
            )
        except SlackApiError as e:
            typer.echo(
                typer.style(
                    f"\n\nSlack API error: {e.response['error']}", fg=colors.RED
                )
            )
            typer.echo(
                typer.style(
                    "Progress saved. Use --resume to continue.", fg=colors.YELLOW
                )
            )
            raise


@app.command()
def create_apps(
    config_token: str = typer.Argument(
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
    (under "Your App Configuration Tokens", click "Generate" and copy the "Access Token").
    """
    if not manifest_path.exists():
        typer.echo(
            typer.style(f"Manifest file not found: {manifest_path}", fg=colors.RED)
        )
        raise typer.Exit(1)

    with open(manifest_path, encoding="utf8") as f:
        manifest = yaml.safe_load(f)

    apps: list[dict[str, Any]] = []
    base_name = manifest.get("display_information", {}).get("name", "App")

    i = 1
    while i <= count:
        app_manifest = manifest.copy()
        app_manifest.setdefault("display_information", {})
        app_manifest["display_information"]["name"] = f"{base_name} {i}"

        typer.echo(
            f"Creating app {typer.style(f'{i}/{count}', fg=colors.CYAN)}: "
            f"{app_manifest['display_information']['name']}"
        )

        response = httpx.post(
            "https://slack.com/api/apps.manifest.create",
            headers={"Authorization": f"Bearer {config_token}"},
            json={"manifest": app_manifest},
            timeout=30,
        )
        data = response.json()

        if not data.get("ok"):
            error = data.get("error", "unknown")
            typer.echo(typer.style(f"  Error: {error}", fg=colors.RED))
            if error == "ratelimited":
                retry_after = int(response.headers.get("Retry-After", 60))
                typer.echo(
                    typer.style(
                        f"  Waiting {retry_after}s before retry...", fg=colors.YELLOW
                    )
                )
                time.sleep(retry_after)
                continue
            if "errors" in data:
                for err in data["errors"]:
                    typer.echo(
                        typer.style(
                            f"    - {err.get('message')} at {err.get('pointer')}",
                            fg=colors.RED,
                        )
                    )
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
        typer.echo(f"  Created: {typer.style(app_info['app_id'], fg=colors.GREEN)}")

        i += 1
        time.sleep(2)

    with open(output, "w", encoding="utf8") as f:
        json.dump(apps, f, indent=2)

    typer.echo(
        f"\nCreated {typer.style(str(len(apps)), fg=colors.GREEN, bold=True)} apps. "
        f"Credentials saved to {output}"
    )
    typer.echo("\nTo install apps and get user tokens, run:")
    typer.echo(typer.style("  python main.py install-apps", fg=colors.CYAN))


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

    if not apps_file.exists():
        typer.echo(typer.style(f"Apps file not found: {apps_file}", fg=colors.RED))
        raise typer.Exit(1)

    with open(apps_file, encoding="utf8") as f:
        apps_list: list[dict[str, Any]] = json.load(f)

    if not apps_list:
        typer.echo(typer.style("No apps found in file.", fg=colors.RED))
        raise typer.Exit(1)

    do_oauth_flow(port, apps_list)

    with open(apps_file, "w", encoding="utf8") as f:
        json.dump(apps_list, f, indent=2)

    tokens_count = sum(1 for a in apps_list if a.get("user_token"))
    typer.echo(
        f"\n{typer.style(f'{tokens_count}/{len(apps_list)}', fg=colors.GREEN, bold=True)} "
        f"apps have user tokens. Saved to {apps_file}"
    )


@app.command()
def stats(
    path: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        help="Path to SQLite database file",
    ),
) -> None:
    """Show statistics about saved messages"""
    if not os.path.exists(path):
        typer.echo(typer.style("No database found.", fg=colors.RED))
        return

    with sqlite3.connect(path) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM messages")
        row = cursor.fetchone()
        total: int = row[0] if row else 0

        if total == 0:
            typer.echo(typer.style("No messages in database.", fg=colors.YELLOW))
            return

        cursor.execute("SELECT MIN(ts), MAX(ts) FROM messages")
        ts_row = cursor.fetchone()
        min_ts: str | None = ts_row[0] if ts_row else None
        max_ts: str | None = ts_row[1] if ts_row else None

        label = typer.style("Total messages:", fg=colors.CYAN)
        value = typer.style(f"{total:,}", fg=colors.WHITE, bold=True)
        typer.echo(f"{label} {value}")

        if min_ts and max_ts:
            oldest = datetime.fromtimestamp(float(min_ts))
            newest = datetime.fromtimestamp(float(max_ts))
            days_span = (newest - oldest).days or 1
            label = typer.style("Date range:", fg=colors.CYAN)
            typer.echo(f"{label} {oldest.date()} to {newest.date()} ({days_span} days)")
            label = typer.style("Average:", fg=colors.CYAN)
            typer.echo(f"{label} {total / days_span:.1f} messages/day")

        db_size = os.path.getsize(path)
        label = typer.style("Database size:", fg=colors.CYAN)
        typer.echo(f"{label} {db_size / 1024 / 1024:.2f} MB")

        cursor.execute("SELECT COUNT(DISTINCT channel_id) FROM messages")
        channel_row = cursor.fetchone()
        unique_channels: int = channel_row[0] if channel_row else 0
        label = typer.style("Unique channels:", fg=colors.CYAN)
        typer.echo(f"{label} {unique_channels}")

        cursor.execute("""
            SELECT CASE WHEN type = 'im' THEN 'im' ELSE channel_type END as ctype,
                   COUNT(*) as count
            FROM messages
            GROUP BY ctype
            ORDER BY count DESC
        """)
        type_rows: list[tuple[str, int]] = cursor.fetchall()
        if type_rows:
            typer.echo(typer.style("\nBy channel type:", fg=colors.GREEN, bold=True))
            for ctype, count in type_rows:
                channel_type = typer.style(ctype or "unknown", fg=colors.MAGENTA)
                typer.echo(f"  {channel_type}: {count:,}")

        cursor.execute("SELECT AVG(LENGTH(text)), MAX(LENGTH(text)) FROM messages")
        len_row = cursor.fetchone()
        if len_row and len_row[0]:
            avg_len, max_len = len_row
            typer.echo(typer.style("\nMessage length:", fg=colors.GREEN, bold=True))
            typer.echo(
                f"  {typer.style('average', fg=colors.MAGENTA)}: {avg_len:.0f} chars"
            )
            typer.echo(f"  {typer.style('max', fg=colors.MAGENTA)}: {max_len:,} chars")

        cursor.execute("""
            SELECT channel_name, type, channel_type, COUNT(*) as count
            FROM messages
            GROUP BY channel_name
            ORDER BY count DESC
            LIMIT 10
        """)
        rows: list[tuple[str, str, str, int]] = cursor.fetchall()
        if rows:
            typer.echo(typer.style("\nTop 10 channels:", fg=colors.GREEN, bold=True))
            for name, msg_type, ctype, count in rows:
                if ctype == "mpim":
                    name = ", ".join(name[5:].rsplit("-", 1)[0].split("--"))
                prefix = "" if msg_type == "im" or ctype == "mpim" else "#"
                channel = typer.style(f"{prefix}{name or 'unknown'}", fg=colors.MAGENTA)
                typer.echo(f"  {channel}: {count:,}")


class EncryptMode(Enum):
    """Possible encryption modes"""

    RANDOM = "random"
    TEXT = "text"
    INVISIBLE = "invisible"
    REDACT = "redact"


CHANNEL_TYPE_ALIASES = {
    "private": "private",
    "dm": "im",
    "public": "channel",
    "gdm": "mpim",
}
ALL_CHANNEL_TYPES = list(CHANNEL_TYPE_ALIASES.values())


@app.command()
def encrypt(
    password: str = typer.Argument(
        ...,
        help="Password to use for encryption",
    ),
    older_than: float = typer.Argument(
        ...,
        help="Only encrypt messages older than X days",
    ),
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
    mode: EncryptMode = typer.Option(
        EncryptMode.TEXT,
        "--mode",
        case_sensitive=False,
        help="Encryption mode: random, text, invisible",
    ),
    text: str = typer.Option(None, help="Text to use if mode is 'text'"),
    path: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        help="Path to SQLite database file",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Actually perform decryption instead of dry run",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation prompt",
    ),
    channel_types: Annotated[
        Optional[list[str]],
        typer.Option(
            "--channel-type",
            "-c",
            help="Channel types to include (private, dm, public, gdm). Can be repeated.",
        ),
    ] = None,
) -> None:
    """Encrypt your slack messages transparently"""

    types_filter: list[str] = []
    if channel_types:
        for ct in channel_types:
            if ct not in CHANNEL_TYPE_ALIASES:
                typer.echo(
                    typer.style(
                        f"Invalid channel type '{ct}'. Valid types: {', '.join(CHANNEL_TYPE_ALIASES.keys())}",
                        fg=colors.RED,
                    )
                )
                raise typer.Exit(1)
            types_filter.append(CHANNEL_TYPE_ALIASES[ct])
    else:
        types_filter = ["channel"]

    tokens: list[str] = []

    if apps_file:
        tokens.extend(load_tokens_from_apps_file(apps_file))

    if slack_tokens:
        tokens.extend(slack_tokens)

    if not tokens and execute:
        typer.echo(
            typer.style("No tokens provided. Use --token or --apps.", fg=colors.RED)
        )
        raise typer.Exit(1)

    pool = TokenPool(tokens) if tokens else None
    if pool:
        typer.echo(
            f"Using {typer.style(str(len(tokens)), fg=colors.CYAN, bold=True)} token(s)"
        )

    if not yes and execute:
        typer.echo(
            typer.style(
                "WARNING: This will modify your Slack messages by encrypting them.",
                fg=colors.RED,
                bold=True,
            )
        )
        typer.echo(
            typer.style(
                "This action cannot be undone without the password used.",
                fg=colors.RED,
                bold=True,
            )
        )
        confirm = typer.prompt(
            typer.style("Type 'encrypt' to proceed", fg=colors.YELLOW)
        )
        if confirm.lower() != "encrypt":
            typer.echo(typer.style("Aborted.", fg=colors.RED))
            raise typer.Exit(1)

    with sqlite3.connect(path) as conn:
        cursor = conn.cursor()

        cutoff_ts = time.time() - (older_than * 86400)
        placeholders = ",".join("?" * len(types_filter))
        cursor.execute(
            f"""SELECT ts, channel_id, text FROM messages
                WHERE ts < ?
                AND (channel_type IN ({placeholders}) OR (type = 'im' AND 'im' IN ({placeholders})))
                ORDER BY ts DESC""",
            (cutoff_ts, *types_filter, *types_filter),
        )
        rows: list[tuple[str, str, str]] = cursor.fetchall()

        total = len(rows)
        if total == 0:
            typer.echo(typer.style("No messages found to encrypt.", fg=colors.YELLOW))
            return

        typer.echo(
            f"Encrypting {typer.style(str(total), fg=colors.CYAN, bold=True)} messages "
            f"(channel types: {', '.join(types_filter)})..."
        )

        key, salt = derive_key(password)

        updated = 0
        with tqdm.tqdm(total=total, unit="msg") as pbar:
            for ts, channel_id, original_text in rows:
                if original_text.strip() == "":
                    pbar.update(1)
                    continue  # skip empty messages

                if original_text.startswith(PREFIX):
                    pbar.update(1)
                    continue  # already encrypted

                encrypted = encrypt_text(original_text, key, salt)

                filler = ""
                if mode == EncryptMode.RANDOM:
                    filler = os.urandom(32).hex()
                elif mode == EncryptMode.TEXT:
                    filler = text or "[anonymized with hades]"
                elif mode == EncryptMode.INVISIBLE:
                    filler = ""
                elif mode == EncryptMode.REDACT:
                    filler = re.sub(r"\S", "*", original_text)

                new_text = str(encrypted or "") + chr(WORD_JOINER) + str(filler or "")

                if not execute:
                    pbar.write(
                        f"[DRY RUN] '{original_text[:30]}{len(original_text) > 30 and '...' or ''}'"
                        f" -> '{filler[:30]}{len(filler) > 30 and '...' or ''}'"
                    )
                else:
                    assert pool is not None
                    try:
                        api_call_with_retry(
                            pool,
                            "chat_update",
                            channel=channel_id,
                            ts=ts,
                            text=new_text,
                        )
                    except SlackApiError as e:
                        pbar.write(
                            typer.style(
                                f"Failed to update {channel_id}/{ts}: {e.response['error']}",
                                fg=colors.RED,
                            )
                        )
                        continue

                updated += 1
                postfix: dict[str, object] = {
                    "channel": channel_id,
                    "ts": ts,
                }
                pbar.set_postfix(postfix)  # type: ignore
                pbar.update(1)


@app.command()
def decrypt(
    password: str = typer.Argument(
        ...,
        help="Password used for encryption",
    ),
    younger_than: float = typer.Argument(
        ...,
        help="Only decrypt messages younger than X days",
    ),
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
    path: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        help="Path to SQLite database file",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Actually perform decryption instead of dry run",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation prompt",
    ),
    channel_types: Annotated[
        Optional[list[str]],
        typer.Option(
            "--channel-type",
            "-c",
            help="Channel types to include (private, dm, public, gdm). Can be repeated.",
        ),
    ] = None,
) -> None:
    """Decrypt previously encrypted slack messages"""

    types_filter: list[str] = []
    if channel_types:
        for ct in channel_types:
            if ct not in CHANNEL_TYPE_ALIASES:
                typer.echo(
                    typer.style(
                        f"Invalid channel type '{ct}'. Valid types: {', '.join(CHANNEL_TYPE_ALIASES.keys())}",
                        fg=colors.RED,
                    )
                )
                raise typer.Exit(1)
            types_filter.append(CHANNEL_TYPE_ALIASES[ct])
    else:
        types_filter = ["channel"]

    tokens: list[str] = []

    if apps_file:
        tokens.extend(load_tokens_from_apps_file(apps_file))

    if slack_tokens:
        tokens.extend(slack_tokens)

    if not tokens and execute:
        typer.echo(
            typer.style("No tokens provided. Use --token or --apps.", fg=colors.RED)
        )
        raise typer.Exit(1)

    pool = TokenPool(tokens) if tokens else None
    if pool:
        typer.echo(
            f"Using {typer.style(str(len(tokens)), fg=colors.CYAN, bold=True)} token(s)"
        )

    if not yes and execute:
        typer.echo(
            typer.style(
                "WARNING: This will modify your Slack messages by decrypting them.",
                fg=colors.YELLOW,
                bold=True,
            )
        )
        confirm = typer.prompt(
            typer.style("Type 'decrypt' to proceed", fg=colors.YELLOW)
        )
        if confirm.lower() != "decrypt":
            typer.echo(typer.style("Aborted.", fg=colors.RED))
            raise typer.Exit(1)

    with sqlite3.connect(path) as conn:
        cursor = conn.cursor()

        if younger_than == 0:
            cutoff_ts = 0
        else:
            cutoff_ts = time.time() - (younger_than * 86400)
        placeholders = ",".join("?" * len(types_filter))
        cursor.execute(
            f"""SELECT ts, channel_id, text FROM messages
                WHERE ts > ?
                AND (channel_type IN ({placeholders}) OR (type = 'im' AND 'im' IN ({placeholders})))
                ORDER BY ts DESC""",
            (cutoff_ts, *types_filter, *types_filter),
        )
        rows: list[tuple[str, str, str]] = cursor.fetchall()

        total = len(rows)
        if total == 0:
            typer.echo(typer.style("No messages found.", fg=colors.YELLOW))
            return

        typer.echo(
            f"Checking {typer.style(str(total), fg=colors.CYAN, bold=True)} messages "
            f"(channel types: {', '.join(types_filter)})..."
        )

        decrypted_count = 0
        skipped = 0
        with tqdm.tqdm(total=total, unit="msg") as pbar:
            for ts, channel_id, text in rows:
                if not text or chr(WORD_JOINER) not in text:
                    skipped += 1
                    pbar.update(1)
                    continue

                encrypted_part = text.split(chr(WORD_JOINER))[0]
                if not encrypted_part:
                    skipped += 1
                    pbar.update(1)
                    continue

                try:
                    original_text = decrypt_text(encrypted_part, password)
                except ValueError:  # pylint: disable=broad-except
                    skipped += 1
                    pbar.update(1)
                    continue
                except Exception as e:  # pylint: disable=broad-except
                    pbar.write(
                        typer.style(
                            f"Failed to decrypt message {channel_id}/{ts}: {str(e)}",
                            fg=colors.RED,
                        )
                    )
                    skipped += 1
                    pbar.update(1)
                    continue

                if not execute:
                    filler = (
                        text.split(chr(WORD_JOINER), 1)[1]
                        if chr(WORD_JOINER) in text
                        else ""
                    )
                    pbar.write(
                        f"[DRY RUN] '{filler[:30]}{len(filler) > 30 and '...' or ''}'"
                        f" -> '{original_text[:30]}{len(original_text) > 30 and '...' or ''}'"
                    )
                else:
                    assert pool is not None
                    try:
                        api_call_with_retry(
                            pool,
                            "chat_update",
                            channel=channel_id,
                            ts=ts,
                            text=original_text,
                        )
                    except SlackApiError as e:
                        pbar.write(
                            typer.style(
                                f"Failed to update {channel_id}/{ts}: {e.response['error']}",
                                fg=colors.RED,
                            )
                        )
                        continue

                decrypted_count += 1
                postfix: dict[str, object] = {
                    "channel": channel_id,
                    "ts": ts,
                }
                pbar.set_postfix(postfix)  # type: ignore
                pbar.update(1)

        typer.echo(
            f"\n{'Would decrypt' if not execute else 'Decrypted'} "
            f"{typer.style(str(decrypted_count), fg=colors.GREEN, bold=True)} messages "
            f"(skipped {skipped} non-encrypted)"
        )


if __name__ == "__main__":
    app()
