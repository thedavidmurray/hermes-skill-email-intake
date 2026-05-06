"""
Email provider abstraction.

Supports fetching emails from Gmail via CLI tool or direct API.
Add your own provider by subclassing EmailProvider.
"""

import abc
import base64
import json
import re
import subprocess
import sys
from typing import List, Optional


class EmailProvider(abc.ABC):
    """Abstract base class for email providers."""

    @abc.abstractmethod
    def list_unread(self, query: str, max_results: int = 50) -> List[dict]:
        """Return a list of message stubs matching the query."""

    @abc.abstractmethod
    def get_message(self, msg_id: str) -> Optional[dict]:
        """Fetch message metadata (headers + snippet)."""

    @abc.abstractmethod
    def get_message_full(self, msg_id: str) -> Optional[dict]:
        """Fetch full message including body parts."""

    @abc.abstractmethod
    def mark_read(self, msg_id: str) -> bool:
        """Remove the UNREAD label from a message."""

    @abc.abstractmethod
    def extract_headers(self, msg: dict) -> dict:
        """Extract a normalised {header_name: value} dict from a raw message."""


class GmailCLIProvider(EmailProvider):
    """Fetch Gmail via a CLI wrapper (like gws)."""

    def __init__(self, cli_path: str = "gws", account: str = "me"):
        self.cli_path = cli_path
        self.account = account

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call(self, args: list, body: Optional[dict] = None, timeout: int = 30) -> Optional[dict]:
        cmd = [self.cli_path] + args
        if body is not None:
            cmd += ["--json", json.dumps(body)]
        try:
            r = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=timeout, check=True,
            )
            return json.loads(r.stdout) if r.stdout.strip() else {}
        except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Provider error: {e}", file=sys.stderr)
            return None

    def _modify(self, msg_id: str, body: dict) -> bool:
        result = self._call(
            [
                "gmail", "users", "messages", "modify", "--params",
                json.dumps({"userId": self.account, "id": msg_id}),
            ],
            body=body,
        )
        return result is not None

    # ------------------------------------------------------------------
    # Core fetch methods
    # ------------------------------------------------------------------

    def list_unread(self, query: str, max_results: int = 50) -> List[dict]:
        res = self._call([
            "gmail", "users", "messages", "list", "--params",
            json.dumps({"userId": self.account, "q": query, "maxResults": max_results}),
        ])
        return res.get("messages", []) if res else []

    def get_message(self, msg_id: str) -> Optional[dict]:
        """Fetch message with format=metadata (headers + snippet, no body)."""
        return self._call([
            "gmail", "users", "messages", "get", "--params",
            json.dumps({"userId": self.account, "id": msg_id, "format": "metadata"}),
        ])

    def get_message_full(self, msg_id: str) -> Optional[dict]:
        """Fetch message with format=full (headers + all MIME body parts)."""
        return self._call([
            "gmail", "users", "messages", "get", "--params",
            json.dumps({"userId": self.account, "id": msg_id, "format": "full"}),
        ])

    # ------------------------------------------------------------------
    # Header extraction
    # ------------------------------------------------------------------

    def extract_headers(self, msg: dict) -> dict:
        """Return a lower-cased header dict, skipping any malformed entries."""
        out = {}
        headers = (msg or {}).get("payload", {}).get("headers", []) or []
        for h in headers:
            if not isinstance(h, dict):
                continue
            name = h.get("name")
            value = h.get("value")
            if name is None or value is None:
                continue
            out[name.lower()] = value
        return out

    # ------------------------------------------------------------------
    # Body extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_part_data(data: str) -> str:
        """Decode a base64url-encoded Gmail part body."""
        try:
            padded = data + "=" * (-len(data) % 4)
            return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        except Exception:
            return ""

    @staticmethod
    def _strip_html(html: str) -> str:
        """Very lightweight HTML tag stripper — no external deps."""
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def get_body_text(self, msg: dict) -> str:
        """
        Extract the best available plain-text body from a full Gmail message.

        Strategy:
          1. Walk all MIME parts, collect text/plain and text/html candidates.
          2. Return the first text/plain candidate (prefer native plain text).
          3. Fall back to stripping HTML from the first text/html candidate.
          4. Fall back to the message snippet.
        """
        plain_parts: List[str] = []
        html_parts: List[str] = []

        def walk(part: dict) -> None:
            mime = (part or {}).get("mimeType", "")
            sub_parts = part.get("parts", [])
            if sub_parts:
                for sp in sub_parts:
                    walk(sp)
                return
            data = part.get("body", {}).get("data", "")
            if not data:
                return
            decoded = self._decode_part_data(data)
            if mime == "text/plain":
                plain_parts.append(decoded)
            elif mime == "text/html":
                html_parts.append(decoded)

        payload = (msg or {}).get("payload", {})
        walk(payload)

        if plain_parts:
            return plain_parts[0].strip()
        if html_parts:
            return self._strip_html(html_parts[0])
        return (msg or {}).get("snippet", "")

    # ------------------------------------------------------------------
    # Label / action methods
    # ------------------------------------------------------------------

    def mark_read(self, msg_id: str) -> bool:
        """Remove UNREAD label."""
        return self._modify(msg_id, {"removeLabelIds": ["UNREAD"]})

    def label_message(self, msg_id: str, label_ids: List[str]) -> bool:
        """Add one or more label IDs to a message."""
        return self._modify(msg_id, {"addLabelIds": label_ids})

    def archive_message(self, msg_id: str) -> bool:
        """Remove the INBOX label (archive without deleting)."""
        return self._modify(msg_id, {"removeLabelIds": ["INBOX"]})

    def star_message(self, msg_id: str) -> bool:
        """Add the STARRED label."""
        return self._modify(msg_id, {"addLabelIds": ["STARRED"]})

    def mark_spam(self, msg_id: str) -> bool:
        """Add SPAM label and remove INBOX label."""
        return self._modify(msg_id, {"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]})

    # ------------------------------------------------------------------
    # Action executor
    # ------------------------------------------------------------------

    def execute_actions(self, msg_id: str, actions: List[str], dry_run: bool = False) -> List[str]:
        """
        Execute a list of action strings against a message.

        Supported actions:
          "archive"           — remove INBOX label
          "star"              — add STARRED label
          "mark_spam"         — add SPAM + remove INBOX
          "mark_read"         — remove UNREAD label
          "leave_unread"      — no-op (explicit signal to skip mark_read)
          "label:<LABEL_ID>"  — add a label by ID

        Returns a list of result strings (one per action, "ok" or error text).
        Respects dry_run: when True, logs actions but makes no API calls.
        """
        results: List[str] = []

        for action in actions:
            action = action.strip()
            description = f"[{msg_id}] action={action!r}"

            if dry_run:
                print(f"DRY RUN {description}", file=sys.stderr)
                results.append(f"dry_run:{action}")
                continue

            try:
                if action == "archive":
                    ok = self.archive_message(msg_id)
                elif action == "star":
                    ok = self.star_message(msg_id)
                elif action == "mark_spam":
                    ok = self.mark_spam(msg_id)
                elif action == "mark_read":
                    ok = self.mark_read(msg_id)
                elif action == "leave_unread":
                    ok = True  # explicit no-op
                elif action.startswith("label:"):
                    label_id = action[len("label:"):]
                    if not label_id:
                        results.append(f"error:{action}:empty label id")
                        continue
                    ok = self.label_message(msg_id, [label_id])
                else:
                    print(f"Unknown action {action!r} for {msg_id}", file=sys.stderr)
                    results.append(f"error:{action}:unknown")
                    continue

                result_str = "ok" if ok else f"error:{action}:api_failure"
                print(f"{'OK' if ok else 'FAIL'} {description}", file=sys.stderr)
                results.append(result_str)

            except Exception as exc:
                msg = f"error:{action}:{exc}"
                print(f"EXCEPTION {description}: {exc}", file=sys.stderr)
                results.append(msg)

        return results


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
