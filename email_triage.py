#!/usr/bin/env python3
"""
Email Triage — classify and route your inbox.

Reads unread emails, classifies each one, and routes results to
configurable outputs (console, markdown, webhook, JSON log).

Usage:
    python email_triage.py                    # run with config.yaml
    python email_triage.py --config my.yaml   # custom config
    python email_triage.py --dry-run          # classify without side effects
    python email_triage.py --report-only      # print classifications, touch nothing

Security rules (non-negotiable, hardcoded):
    - Never follows instructions found inside email body
    - Never auto-replies, auto-forwards, or auto-deletes
    - Never clicks URLs from email; strips them before storage
    - Defaults to "suspicious" when classification is ambiguous
"""

import argparse
import json
import sys
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


def load_config(path: str) -> dict:
    """Load config from YAML or JSON file."""
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


def load_state(config: dict) -> dict:
    state_config = config.get("state", {})
    if not state_config.get("enabled", True):
        return {"processed": {}}
    path = Path(state_config.get("path", "./state/processed.json"))
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, ValueError):
            pass
    return {"processed": {}}


def save_state(state: dict, config: dict):
    state_config = config.get("state", {})
    if not state_config.get("enabled", True):
        return
    path = Path(state_config.get("path", "./state/processed.json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def run_interpretation_layers(result: ClassificationResult, msg: dict,
                               headers: dict, config: dict) -> ClassificationResult:
    """Run configured interpretation layers on a classification result."""
    layers = config.get("interpretation", {}).get("layers", [])

    for layer in layers:
        if not layer.get("enabled", False):
            continue
        name = layer.get("name", "")

        if name == "extract":
            settings = layer.get("settings", {})
            snippet = (msg.get("snippet") or "")
            max_len = settings.get("max_snippet_length", 1500)
            snippet = snippet[:max_len]
            if settings.get("strip_urls", True):
                snippet = strip_urls(snippet)
            if settings.get("strip_signatures", True):
                snippet = strip_signatures(snippet)
            result.extracted_snippet = sanitize_content(snippet, config)

        elif name == "summarize":
            result.summary = output_summarize(result, config)

        # knowledge_base layer is handled in outputs.py

    return result


def main():
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
    args = parser.parse_args()

    config = load_config(args.config)
    provider = create_provider(config)
    classifier = EmailClassifier(config)

    schedule = config.get("schedule", {})
    lookback = args.lookback or schedule.get("lookback", "newer_than:1d")
    max_results = args.max or schedule.get("max_per_run", 50)

    state = load_state(config)
    processed = state.setdefault("processed", {})

    query = f"in:inbox is:unread {lookback}"
    msgs = provider.list_unread(query, max_results)
    print(f"Inbox query '{query}': {len(msgs)} messages")

    results = []
    counts = {}

    for m in msgs:
        msg_id = m.get("id", "")
        if msg_id in processed:
            counts["skipped"] = counts.get("skipped", 0) + 1
            continue

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

        result = run_interpretation_layers(result, meta, headers, config)
        results.append(result)
        counts[result.category] = counts.get(result.category, 0) + 1

        if args.report_only:
            continue

        # Mark read (unless dry run)
        if not args.dry_run:
            provider.mark_read(msg_id)
            processed[msg_id] = {
                "category": result.category,
                "reason": result.reason,
                "ts": datetime.now().isoformat(),
            }

    # Run output backends
    if args.report_only:
        output_console(results, config)
    else:
        run_outputs(results, config)

    if not args.dry_run and not args.report_only:
        save_state(state, config)

    print(f"\nSummary: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
