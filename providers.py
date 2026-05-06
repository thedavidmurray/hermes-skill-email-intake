"""
Email provider abstraction.

Supports fetching emails from Gmail via CLI tool or direct API.
Add your own provider by subclassing EmailProvider.
"""

import json
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EmailMessage:
    id: str
    snippet: str = ""
    headers: dict = field(default_factory=dict)


class EmailProvider:
    """Base class for email providers."""

    def list_unread(self, query: str, max_results: int = 50) -> List[dict]:
        raise NotImplementedError

    def get_message(self, msg_id: str) -> Optional[dict]:
        raise NotImplementedError

    def mark_read(self, msg_id: str) -> bool:
        raise NotImplementedError

    def extract_headers(self, msg: dict) -> dict:
        out = {}
        for h in msg.get("payload", {}).get("headers", []) or []:
            out[h["name"].lower()] = h["value"]
        return out


class GmailCLIProvider(EmailProvider):
    """Fetch Gmail via a CLI wrapper (like gws)."""

    def __init__(self, cli_path: str = "gws", account: str = "me"):
        self.cli_path = cli_path
        self.account = account

    def _call(self, args: list, timeout: int = 30) -> Optional[dict]:
        try:
            r = subprocess.run(
                [self.cli_path] + args,
                capture_output=True, text=True, timeout=timeout, check=True,
            )
            return json.loads(r.stdout) if r.stdout.strip() else {}
        except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Provider error: {e}", file=sys.stderr)
            return None

    def list_unread(self, query: str, max_results: int = 50) -> List[dict]:
        res = self._call([
            "gmail", "users", "messages", "list", "--params",
            json.dumps({"userId": self.account, "q": query, "maxResults": max_results}),
        ])
        return res.get("messages", []) if res else []

    def get_message(self, msg_id: str) -> Optional[dict]:
        return self._call([
            "gmail", "users", "messages", "get", "--params",
            json.dumps({"userId": self.account, "id": msg_id, "format": "metadata"}),
        ])

    def mark_read(self, msg_id: str) -> bool:
        result = self._call([
            "gmail", "users", "messages", "modify", "--params",
            json.dumps({"userId": self.account, "id": msg_id}),
            "--json", json.dumps({"removeLabelIds": ["UNREAD"]}),
        ])
        return result is not None


def create_provider(config: dict) -> EmailProvider:
    """Create a provider from config."""
    provider_config = config.get("provider", {})
    provider_type = provider_config.get("type", "gmail_cli")

    if provider_type == "gmail_cli":
        return GmailCLIProvider(
            cli_path=provider_config.get("cli_path", "gws"),
            account=provider_config.get("account", "me"),
        )

    raise ValueError(f"Unknown provider type: {provider_type}")
