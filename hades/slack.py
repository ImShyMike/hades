"""Slack utilities"""

import sqlite3
import time
from datetime import datetime, timedelta
from typing import Any, Callable

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.web import SlackResponse
from tqdm import tqdm

from hades.db import get_sync_state, save_messages_batch, set_sync_state

MIN_BATCH_SIZE = 100

SlackMessage = dict[str, Any]


class TokenPool:  # pylint: disable=too-few-public-methods
    """Rotating pool of Slack clients to distribute rate limits"""

    def __init__(self, tokens: list[str]) -> None:
        self.clients = [WebClient(token=t) for t in tokens]
        self.index = 0

    def next(self) -> WebClient:
        """Get the next client in rotation"""
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
    """Execute an API call with token rotation and exponential backoff"""
    for attempt in range(max_retries * len(pool.clients)):
        client = pool.next()
        try:
            func: Callable[..., SlackResponse] = getattr(client, method)
            return func(**kwargs)
        except SlackApiError as e:
            if e.response.get("error") == "ratelimited":  # type: ignore
                retry_after = int(
                    e.response.headers.get("Retry-After", base_delay * (2**attempt))  # type: ignore
                )
                print(f"\nRate limited. Rotating token, waiting {retry_after}s...")
                time.sleep(retry_after)
            else:
                raise
    raise RuntimeError(f"Max retries exceeded across all {len(pool.clients)} tokens")


def _get_search_totals(pool: TokenPool, query: str) -> tuple[int, int]:
    """Get total messages and pages for a search query"""
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
    """Fetch a single page of search results"""
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
    """Get the newest timestamp from a list of messages"""
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

        if len(batch) >= MIN_BATCH_SIZE:
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
