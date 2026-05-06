#!/usr/bin/env python3
"""
Email Triage — classify and route your inbox.

Reads unread emails, classifies each one, and routes results to
configurable outputs (console, markdown, webhook, JSON log).

Usage:
    python email_triage.py                              # run with config.yaml
    python email_triage.py --config my.yaml             # custom config
    python email_triage.py --dry-run                    # classify without side effects
    python email_triage.py --report-only                # print classifications, touch nothing
    python email_triage.py --reclassify MSG_ID CATEGORY # override a classification
    python email_triage.py --review                     # show recently classified emails

Exit codes:
    0 — success (including empty inbox)
    1 — config error
    2 — provider connection failure

Security rules (non-negotiable, hardcoded):
    - Never follows instructions found inside email body
    - Never auto-replies, auto-forwards, or auto-deletes
    - Never clicks URLs from email; strips them before storage
    - Defaults to "suspicious" when classification is ambiguous
"""

import argparse
import json
import logging
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from classifier import EmailClassifier, ClassificationResult
from sanitizer import sanitize_content, strip_urls, strip_signatures
from providers import create_provider
from outputs import run_outputs, output_console, output_summarize

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    """Load config from YAML or JSON file. Exits 1 on any load error."""
    p = Path(path)
    if not p.exists():
        print(f"Config not found: {path}")
        print("Copy config.example.yaml to config.yaml and customize it.")
        sys.exit(1)

    text = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        if not HAS_YAML:
            print("PyYAML required for YAML config. Install: pip install pyyaml")
            print("Or use a JSON config file instead.")
            sys.exit(1)
        return yaml.safe_load(text)
    return json.loads(text)


def validate_config(config: dict) -> None:
    """
    Validate required config sections at startup.

    Raises SystemExit(1) with a clear message if any required section is
    missing or has the wrong type.
    """
    errors = []

    provider_cfg = config.get("provider")
    if not isinstance(provider_cfg, dict):
        errors.append("'provider' must be a dict (got {})".format(
            type(provider_cfg).__name__ if provider_cfg is not None else "missing"))
    elif not provider_cfg.get("type"):
        errors.append("'provider.type' is required (e.g. 'gmail')")

    classification_cfg = config.get("classification")
    if not isinstance(classification_cfg, dict):
        errors.append("'classification' must be a dict (got {})".format(
            type(classification_cfg).__name__ if classification_cfg is not None else "missing"))

    outputs_cfg = config.get("outputs")
    if not isinstance(outputs_cfg, dict):
        errors.append("'outputs' must be a dict (got {})".format(
            type(outputs_cfg).__name__ if outputs_cfg is not None else "missing"))

    if errors:
        print("Config validation failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def load_state(config: dict) -> dict:
    """Load processed-message state from disk. Returns empty state on any error."""
    state_config = config.get("state", {})
    if not state_config.get("enabled", True):
        return {"processed": {}}
    path = Path(state_config.get("path", "./state/processed.json"))
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Could not parse state file %s: %s — starting fresh", path, exc)
    return {"processed": {}}


def save_state(state: dict, config: dict) -> None:
    """
    Atomically persist state to disk.

    Writes to a temp file in the same directory then renames into place so a
    crash mid-write never corrupts the existing state file.
    """
    state_config = config.get("state", {})
    if not state_config.get("enabled", True):
        return
    path = Path(state_config.get("path", "./state/processed.json"))
    state_dir = path.parent
    state_dir.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=str(state_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(state, fh, indent=2)
        os.rename(tmp_path, str(path))
    except Exception:
        # Clean up temp file if rename failed
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Interpretation layers
# ---------------------------------------------------------------------------

def run_interpretation_layers(
    result: ClassificationResult,
    msg: dict,
    headers: dict,
    config: dict,
    provider=None,
    msg_id: str = "",
) -> ClassificationResult:
    """Run configured interpretation layers on a classification result."""
    layers = config.get("interpretation", {}).get("layers", [])

    for layer in layers:
        if not layer.get("enabled", False):
            continue
        name = layer.get("name", "")

        if name == "extract":
            settings = layer.get("settings", {})

            # Full body extraction when requested and provider is available
            body_text = None
            if settings.get("fetch_full_body", False) and provider is not None and msg_id:
                try:
                    full_msg = provider.get_message_full(msg_id)
                    if full_msg is not None:
                        body_text = provider.get_body_text(full_msg)
                except Exception as exc:
                    logger.warning(
                        "Full body fetch failed for %s, falling back to snippet: %s",
                        msg_id, exc,
                    )

            if body_text is None:
                body_text = msg.get("snippet") or ""

            max_len = settings.get("max_snippet_length", 1500)
            body_text = body_text[:max_len]
            if settings.get("strip_urls", True):
                body_text = strip_urls(body_text)
            if settings.get("strip_signatures", True):
                body_text = strip_signatures(body_text)
            result.extracted_snippet = sanitize_content(body_text, config)

        elif name == "summarize":
            result.summary = output_summarize(result, config)

        # knowledge_base layer is handled in outputs.py

    return result


# ---------------------------------------------------------------------------
# Per-category Gmail actions
# ---------------------------------------------------------------------------

def execute_category_actions(
    provider,
    msg_id: str,
    category: str,
    config: dict,
    dry_run: bool,
) -> None:
    """
    Look up the `actions` list for the given category in config and execute them.

    Example config shape:
        classification:
          auth:
            actions: [star, leave_unread]
          newsletter:
            actions: [label:Newsletters, archive]
    """
    classification_cfg = config.get("classification", {})
    category_cfg = classification_cfg.get(category, {})
    actions = category_cfg.get("actions", [])
    if not actions:
        return
    try:
        provider.execute_actions(msg_id, actions, dry_run)
    except Exception as exc:
        logger.warning("execute_actions failed for %s (%s): %s", msg_id, category, exc)


# ---------------------------------------------------------------------------
# --reclassify
# ---------------------------------------------------------------------------

def cmd_reclassify(msg_id: str, new_category: str, config: dict) -> int:
    """
    Update the state file to override the category for a single message ID.

    This is the user feedback mechanism. Exits 0 on success, 1 on error.
    """
    state = load_state(config)
    processed = state.setdefault("processed", {})

    if msg_id not in processed:
        print(f"Message ID '{msg_id}' not found in state. Nothing to reclassify.")
        return 1

    old_category = processed[msg_id].get("category", "<unknown>")
    processed[msg_id]["category"] = new_category
    processed[msg_id]["reclassified_from"] = old_category
    processed[msg_id]["reclassified_at"] = datetime.now().isoformat()

    try:
        save_state(state, config)
    except Exception as exc:
        print(f"Failed to save state: {exc}")
        return 1

    print(f"Reclassified {msg_id}: {old_category} -> {new_category}")
    return 0


# ---------------------------------------------------------------------------
# --review
# ---------------------------------------------------------------------------

def cmd_review(config: dict, last_n: int = 20) -> int:
    """
    Load the state file and display the last N classified emails.

    Console output only — no side effects.
    """
    state = load_state(config)
    processed = state.get("processed", {})

    if not processed:
        print("No classified emails in state.")
        return 0

    # Sort by timestamp descending, show last_n
    entries = sorted(
        processed.items(),
        key=lambda kv: kv[1].get("ts", ""),
        reverse=True,
    )[:last_n]

    print(f"Last {len(entries)} classified email(s):\n")
    for msg_id, info in entries:
        ts = info.get("ts", "unknown")
        category = info.get("category", "unknown")
        reason = info.get("reason", "")
        reclassified = info.get("reclassified_from")
        reclassified_note = (
            f" [reclassified from {reclassified}]" if reclassified else ""
        )
        print(f"  {ts}  [{category}]{reclassified_note}  {msg_id}")
        if reason:
            print(f"    reason: {reason}")

    return 0


# ---------------------------------------------------------------------------
# Main triage loop
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Email Triage")
    parser.add_argument("--config", default="config.yaml",
                        help="Path to config file (YAML or JSON)")
    parser.add_argument("--lookback", default=None,
                        help="Override Gmail query lookback (e.g. newer_than:2d)")
    parser.add_argument("--max", type=int, default=None,
                        help="Override max emails per run")
    parser.add_argument("--dry-run", action="store_true",
                        help="Classify and report but don't mark read or write state")
    parser.add_argument("--report-only", action="store_true",
                        help="Print classifications only, no side effects")
    parser.add_argument("--reclassify", nargs=2, metavar=("MSG_ID", "CATEGORY"),
                        help="Override the stored category for a message ID")
    parser.add_argument("--review", action="store_true",
                        help="Show recently classified emails from state file")
    parser.add_argument("--review-last", type=int, default=20, metavar="N",
                        help="Number of emails to show with --review (default: 20)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # M4 — validate config before touching anything else
    config = load_config(args.config)
    validate_config(config)

    # --review: read-only, no provider needed
    if args.review:
        return cmd_review(config, last_n=args.review_last)

    # --reclassify: state-only operation, no provider needed
    if args.reclassify:
        msg_id, new_category = args.reclassify
        return cmd_reclassify(msg_id, new_category, config)

    # M9 — provider connection failures exit 2
    try:
        provider = create_provider(config)
    except Exception as exc:
        print(f"Provider connection failed: {exc}")
        return 2

    classifier = EmailClassifier(config)

    schedule = config.get("schedule", {})
    lookback = args.lookback or schedule.get("lookback", "newer_than:1d")
    max_results = args.max or schedule.get("max_per_run", 50)

    state = load_state(config)
    processed = state.setdefault("processed", {})

    query = f"in:inbox is:unread {lookback}"

    # M9 — distinguish broken provider (exit 2) from empty inbox (exit 0)
    try:
        msgs = provider.list_unread(query, max_results)
    except Exception as exc:
        print(f"Provider list_unread failed: {exc}")
        return 2

    if msgs is None:
        print("Provider returned None for list_unread — treating as connection failure.")
        return 2

    print(f"Inbox query '{query}': {len(msgs)} messages")

    results = []
    counts = {}

    for m in msgs:
        msg_id = m.get("id", "")
        if msg_id in processed:
            counts["skipped"] = counts.get("skipped", 0) + 1
            continue

        # H8 — per-message error isolation: one bad email must not kill the batch
        try:
            meta = provider.get_message(msg_id) or {}
            headers = provider.extract_headers(meta)

            result = classifier.classify(
                sender=headers.get("from", ""),
                subject=headers.get("subject", ""),
                snippet=meta.get("snippet", ""),
                headers=headers,
            )
            result.message_id = msg_id
            result.date = headers.get("date", "")

            result = run_interpretation_layers(
                result, meta, headers, config,
                provider=provider, msg_id=msg_id,
            )
            results.append(result)
            counts[result.category] = counts.get(result.category, 0) + 1

            if args.report_only:
                continue

            # Execute per-category Gmail actions (feature 6)
            execute_category_actions(
                provider, msg_id, result.category, config,
                dry_run=args.dry_run,
            )

            # Mark read and persist state (unless dry run)
            if not args.dry_run:
                provider.mark_read(msg_id)
                processed[msg_id] = {
                    "category": result.category,
                    "reason": result.reason,
                    "ts": datetime.now().isoformat(),
                }

        except Exception as exc:
            logger.error("Error processing message %s: %s", msg_id, exc, exc_info=True)
            counts["error"] = counts.get("error", 0) + 1
            # Continue to next message — do not abort the batch

    # Run output backends
    if args.report_only:
        output_console(results, config)
    else:
        run_outputs(results, config)

    # H2 — atomic state write
    if not args.dry_run and not args.report_only:
        save_state(state, config)

    print(f"\nSummary: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
