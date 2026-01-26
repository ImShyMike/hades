"""transparent message anonymizer"""

import json
import os
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import typer
import yaml
from slack_sdk.errors import SlackApiError
from typer import colors

from hades.db import init_db
from hades.oauth import do_oauth_flow
from hades.slack import TokenPool, search_user_messages

app = typer.Typer(
    name="hades",
    help="transparent message anonymizer",
    add_completion=True,
    no_args_is_help=True,
)

DEFAULT_DB_PATH = "slack_messages.db"


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
    path: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        help="Path to SQLite database file",
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


if __name__ == "__main__":
    app()
