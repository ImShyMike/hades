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
            print(f"Apps file not found: {apps_file}")
            raise typer.Exit(1)
        with open(apps_file, encoding="utf8") as f:
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

    with sqlite3.connect(path) as conn:
        init_db(conn)

        if not resume:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sync_state")
            conn.commit()

        try:
            total = search_user_messages(pool, user_id, conn)
            print(f"\nSaved {total} new messages to {path}")
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
    (under "Your App Configuration Tokens", click "Generate" and copy the "Access Token").
    """
    if not manifest_path.exists():
        print(f"Manifest file not found: {manifest_path}")
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

        print(
            f"Creating app {i}/{count}: {app_manifest['display_information']['name']}"
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

    with open(output, "w", encoding="utf8") as f:
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

    if not apps_file.exists():
        print(f"Apps file not found: {apps_file}")
        raise typer.Exit(1)

    with open(apps_file, encoding="utf8") as f:
        apps_list: list[dict[str, Any]] = json.load(f)

    if not apps_list:
        print("No apps found in file.")
        raise typer.Exit(1)

    do_oauth_flow(port, apps_list)

    with open(apps_file, "w", encoding="utf8") as f:
        json.dump(apps_list, f, indent=2)

    tokens_count = sum(1 for a in apps_list if a.get("user_token"))
    print(
        f"\n{tokens_count}/{len(apps_list)} apps have user tokens. Saved to {apps_file}"
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
        print("No database found.")
        return

    with sqlite3.connect(path) as conn:
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
            SELECT channel_name, type, COUNT(*) as count
            FROM messages
            GROUP BY channel_name
            ORDER BY count DESC
            LIMIT 10
        """)
        rows: list[tuple[str, str, int]] = cursor.fetchall()
        if rows:
            print("\nTop channels:")
            for name, msg_type, count in rows:
                print(f"  {msg_type != 'im' and '#' or ''}{name or 'unknown'}: {count}")


if __name__ == "__main__":
    app()
