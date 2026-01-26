"""Oauth utilities"""

import http.server
import time
import urllib.parse
import webbrowser
from threading import Event
from typing import Any

import httpx


def do_oauth_flow(port: int, apps_list: list[dict[str, Any]]):
    """Perform the OAuth flow and return authorization code"""

    redirect_uri = f"http://localhost:{port}/callback"
    captured_code: str | None = None
    done_event = Event()

    class OAuthHandler(http.server.BaseHTTPRequestHandler):
        """Handler for OAuth callback"""

        def log_message(self, format: str, *args: Any) -> None:  # pylint: disable=redefined-builtin
            pass

        def do_GET(self) -> None:  # pylint: disable=invalid-name
            """Handle GET request for OAuth callback"""
            nonlocal captured_code
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/callback":
                params = urllib.parse.parse_qs(parsed.query)
                if "code" in params:
                    captured_code = params["code"][0]
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h1>Success!</h1><p>You can close this tab.</p></body></html>"
                    )
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
            print(
                f"[{i}/{len(apps_list)}] {app_info['name']}: already has token, skipping"
            )
            continue

        client_id = app_info.get("client_id")
        client_secret = app_info.get("client_secret")
        if not client_id or not client_secret:
            print(
                f"[{i}/{len(apps_list)}] {app_info['name']}: missing credentials, skipping"
            )
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
        print("  Opened browser for authorization...")

        while not done_event.is_set():
            server.handle_request()

        server.server_close()

        if not captured_code:
            print("  Failed to get authorization code")
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
            print("  Got user token!")
        else:
            print("  No user token in response")

        time.sleep(1)
