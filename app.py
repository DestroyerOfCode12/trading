"""Secure entrypoint for Alpaca's official MCP server (paper trading only).

Alpaca's server has no HTTP authentication of its own. This file reuses
Alpaca's own build_server() unchanged and adds only:
  1. A hard paper-trading guard (refuses to start otherwise).
  2. GitHub OAuth (Claude connectors require OAuth) restricted to one login.
It fails closed: if any security setting is missing, the process exits.
"""

from __future__ import annotations

import os
import sys

REQUIRED = [
    "ALPACA_API_KEY",
    "ALPACA_SECRET_KEY",
    "GITHUB_CLIENT_ID",
    "GITHUB_CLIENT_SECRET",
    "PUBLIC_BASE_URL",
    "ALLOWED_GITHUB_LOGIN",
    "JWT_SIGNING_KEY",
]


def fail(message: str) -> None:
    print(f"FATAL: {message}", file=sys.stderr)
    sys.exit(1)


missing = [name for name in REQUIRED if not os.environ.get(name, "").strip()]
if missing:
    fail("missing required environment variables: " + ", ".join(missing))

# Paper-only guard. The flag is pinned here, so a stray value cannot enable live trading.
if os.environ.get("ALPACA_PAPER_TRADE", "true").strip().lower() not in ("true", "1", "yes"):
    fail("ALPACA_PAPER_TRADE must be true. Live trading is disabled in this deployment.")
os.environ["ALPACA_PAPER_TRADE"] = "true"

from alpaca_mcp_server import server as alpaca_server  # noqa: E402
from fastmcp.server.auth.providers.github import GitHubProvider  # noqa: E402
from fastmcp.server.dependencies import get_access_token  # noqa: E402
from fastmcp.server.middleware import Middleware, MiddlewareContext  # noqa: E402

# Second, independent check: the base URL Alpaca will actually call must be the paper API.
if alpaca_server._get_trading_base_url() != alpaca_server.TRADING_API_BASE_URLS["paper"]:
    fail("Alpaca trading base URL is not the paper endpoint.")

ALLOWED_LOGIN = os.environ["ALLOWED_GITHUB_LOGIN"].strip().lower()
BASE_URL = os.environ["PUBLIC_BASE_URL"].strip().rstrip("/")
if not BASE_URL.startswith("https://"):
    fail("PUBLIC_BASE_URL must be an https:// URL.")


class OwnerOnly(Middleware):
    """Defence in depth: only the allow-listed GitHub account may use any MCP method."""

    async def on_message(self, context: MiddlewareContext, call_next):
        token = get_access_token()
        login = str((token.claims or {}).get("login", "")).lower() if token else ""
        if login != ALLOWED_LOGIN:
            raise PermissionError("Access denied.")
        return await call_next(context)


def build():
    mcp = alpaca_server.build_server()
    mcp.auth = GitHubProvider(
        client_id=os.environ["GITHUB_CLIENT_ID"].strip(),
        client_secret=os.environ["GITHUB_CLIENT_SECRET"].strip(),
        base_url=BASE_URL,
        jwt_signing_key=os.environ["JWT_SIGNING_KEY"].strip(),
    )
    mcp.add_middleware(OwnerOnly())
    return mcp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    build().run(transport="streamable-http", host="0.0.0.0", port=port)
