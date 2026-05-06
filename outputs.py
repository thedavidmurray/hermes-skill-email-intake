"""
Output backends for classified emails.

Each backend receives a list of ClassificationResults and writes them
to the configured destination (console, markdown files, webhook, JSON log).
"""

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List

from classifier import ClassificationResult


def output_console(results: List[ClassificationResult], config: dict):
    """Print results as a table or JSON."""
    fmt = config.get("outputs", {}).get("console", {}).get("format", "table")

    if fmt == "json":
        for r in results:
            print(json.dumps({
                "category": r.category,
                "sender": r.sender,
                "subject": r.subject,
                "reason": r.reason,
            }))
        return

    # Table format
    for r in results:
        sender = r.sender[:55] if r.sender else "?"
        subject = r.subject[:75] if r.subject else "?"
        print(f"  [{r.category:11}] {sender:55} | {subject}")


def output_markdown(results: List[ClassificationResult], config: dict):
    """Write results as markdown files."""
    md_config = config.get("outputs", {}).get("markdown", {})
    output_dir = Path(md_config.get("output_dir", "./inbox/triage"))
    mode = md_config.get("mode", "per_run")
    output_dir.mkdir(parents=True, exist_ok=True)

    if mode == "per_run":
        today = datetime.now().strftime("%Y-%m-%d-%H%M")
        path = output_dir / f"triage-{today}.md"
        lines = [f"# Email Triage — {today}\n"]
        for r in results:
            lines.append(f"## [{r.category}] {r.subject}\n")
            lines.append(f"- **From:** {r.sender}")
            lines.append(f"- **Reason:** {r.reason}")
            if r.extracted_snippet:
                lines.append(f"\n> {r.extracted_snippet[:500]}\n")
            lines.append("")
        path.write_text("\n".join(lines))
        print(f"  Wrote {path}")
    else:
        for r in results:
            slug = re.sub(r"[^a-z0-9-]+", "-", (r.subject or "untitled").lower())[:60]
            path = output_dir / f"{r.category}-{slug}.md"
            body = f"""---
type: email-triage
category: {r.category}
sender: "{r.sender}"
subject: "{r.subject}"
date: "{r.date}"
message_id: "{r.message_id}"
captured: "{datetime.now().strftime('%Y-%m-%d')}"
---

# {r.subject}

**From:** {r.sender}
**Category:** {r.category}
**Reason:** {r.reason}

{r.extracted_snippet if r.extracted_snippet else ''}
"""
            path.write_text(body)


def output_newsletter(result: ClassificationResult, config: dict):
    """Write a single newsletter to the configured newsletter directory."""
    layers = config.get("interpretation", {}).get("layers", [])
    kb_layer = next((l for l in layers if l.get("name") == "knowledge_base"), None)
    if not kb_layer or not kb_layer.get("enabled"):
        return

    settings = kb_layer.get("settings", {})
    newsletter_dir = Path(settings.get("newsletter_dir", "./inbox/newsletters"))

    # Slugify sender domain
    import re as _re
    m = _re.search(r"@([^>\s]+)", result.sender or "")
    domain = m.group(1).split(".")[0] if m else "unknown"
    domain = _re.sub(r"[^a-z0-9-]+", "-", domain.lower()).strip("-") or "unknown"

    slug = _re.sub(r"[^a-z0-9-]+", "-", (result.subject or "").lower()).strip("-")[:80] or "untitled"
    today = datetime.now().strftime("%Y-%m-%d")
    target = newsletter_dir / domain / f"{today}-{slug}.md"

    template = settings.get("frontmatter_template", "---\ntype: email-newsletter\n---\n")
    frontmatter = template.format(
        sender=result.sender or "",
        subject=result.subject or "",
        date=result.date or "",
        message_id=result.message_id or "",
        today=today,
    )

    target.parent.mkdir(parents=True, exist_ok=True)
    body = f"""{frontmatter}
# {result.subject}

{result.extracted_snippet if result.extracted_snippet else '(no content extracted)'}

---
*Auto-captured by email-triage. URLs stripped, content scrubbed.*
"""
    target.write_text(body)
    print(f"  Newsletter note: {target}")


def output_webhook(results: List[ClassificationResult], config: dict):
    """Post results to a webhook URL."""
    wh_config = config.get("outputs", {}).get("webhook", {})
    url = wh_config.get("url", "")
    if not url:
        return

    template = wh_config.get("payload_template", '{{"text": "[{category}] {sender}: {subject}"}}')

    for r in results:
        payload = template.format(
            category=r.category,
            sender=r.sender or "?",
            subject=r.subject or "?",
            reason=r.reason or "",
        )
        try:
            import urllib.request
            req = urllib.request.Request(
                url, data=payload.encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            print(f"  Webhook error: {e}", file=sys.stderr)


def output_json_log(results: List[ClassificationResult], config: dict):
    """Append results to a JSON log file."""
    log_config = config.get("outputs", {}).get("json_log", {})
    path = Path(log_config.get("path", "./logs/email_triage.json"))
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = []
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except (json.JSONDecodeError, ValueError):
            existing = []

    for r in results:
        existing.append({
            "category": r.category,
            "reason": r.reason,
            "sender": r.sender,
            "subject": r.subject,
            "message_id": r.message_id,
            "date": r.date,
            "ts": datetime.now().isoformat(),
        })

    path.write_text(json.dumps(existing, indent=2))


def output_summarize(result: ClassificationResult, config: dict) -> str:
    """Use an LLM to generate a summary (if configured)."""
    layers = config.get("interpretation", {}).get("layers", [])
    summarize = next((l for l in layers if l.get("name") == "summarize"), None)
    if not summarize or not summarize.get("enabled"):
        return ""

    llm_cmd = summarize.get("settings", {}).get("llm_command", "")
    if not llm_cmd:
        return ""

    prompt = (
        f"Summarize this email in 1-2 sentences. "
        f"Subject: {result.subject}\nFrom: {result.sender}\n"
        f"Content: {result.extracted_snippet[:1000]}"
    )

    try:
        r = subprocess.run(
            llm_cmd.split() + [prompt],
            capture_output=True, text=True, timeout=30,
        )
        return r.stdout.strip()[:300] if r.returncode == 0 else ""
    except Exception:
        return ""


def output_command(results: List[ClassificationResult], config: dict):
    """Pipe each result as JSON to a shell command.

    Use this to route emails into any system: vector DBs, databases,
    Notion, Airtable, custom scripts, etc. The command receives one
    JSON object per line on stdin.

    Config example:
        outputs:
          command:
            enabled: true
            cmd: "python3 my_vectorize.py"
            # Or pipe to jq, sqlite, curl, etc:
            # cmd: "jq -c . >> emails.jsonl"
            # cmd: "python3 -c 'import sys,json,chromadb; ...'"
            categories: [newsletter, actionable]  # optional filter
    """
    cmd_config = config.get("outputs", {}).get("command", {})
    cmd = cmd_config.get("cmd", "")
    if not cmd:
        return

    allowed = cmd_config.get("categories")  # None = all
    filtered = [r for r in results if not allowed or r.category in allowed]
    if not filtered:
        return

    payload = "\n".join(
        json.dumps({
            "category": r.category,
            "reason": r.reason,
            "sender": r.sender,
            "subject": r.subject,
            "message_id": r.message_id,
            "date": r.date,
            "snippet": r.extracted_snippet,
            "summary": r.summary,
            "confidence": r.confidence,
            "metadata": r.metadata,
        })
        for r in filtered
    )

    try:
        proc = subprocess.run(
            cmd, input=payload, shell=True,
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            print(f"  Command output error: {proc.stderr[:200]}", file=sys.stderr)
        else:
            print(f"  Command output: piped {len(filtered)} emails to: {cmd[:60]}")
    except Exception as e:
        print(f"  Command output error: {e}", file=sys.stderr)


def output_custom_script(results: List[ClassificationResult], config: dict):
    """Import and call a user-provided Python function per email.

    Config example:
        outputs:
          custom_script:
            enabled: true
            script: "./my_output.py"
            function: "handle_email"  # must accept (result_dict, config)
            categories: [newsletter]  # optional filter
    """
    script_config = config.get("outputs", {}).get("custom_script", {})
    script_path = script_config.get("script", "")
    func_name = script_config.get("function", "handle_email")
    if not script_path:
        return

    allowed = script_config.get("categories")
    filtered = [r for r in results if not allowed or r.category in allowed]
    if not filtered:
        return

    # Import the script dynamically
    import importlib.util
    spec = importlib.util.spec_from_file_location("custom_output", script_path)
    if not spec or not spec.loader:
        print(f"  Custom script not found: {script_path}", file=sys.stderr)
        return

    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        print(f"  Custom script import error: {e}", file=sys.stderr)
        return

    handler = getattr(mod, func_name, None)
    if not callable(handler):
        print(f"  Custom script: function '{func_name}' not found in {script_path}", file=sys.stderr)
        return

    for r in filtered:
        try:
            handler({
                "category": r.category,
                "reason": r.reason,
                "sender": r.sender,
                "subject": r.subject,
                "message_id": r.message_id,
                "date": r.date,
                "snippet": r.extracted_snippet,
                "summary": r.summary,
                "confidence": r.confidence,
                "metadata": r.metadata,
            }, config)
        except Exception as e:
            print(f"  Custom script error on {r.message_id}: {e}", file=sys.stderr)

    print(f"  Custom script: processed {len(filtered)} emails via {script_path}:{func_name}")


def run_outputs(results: List[ClassificationResult], config: dict):
    """Run all enabled output backends."""
    outputs = config.get("outputs", {})

    if outputs.get("console", {}).get("enabled", True):
        output_console(results, config)

    if outputs.get("markdown", {}).get("enabled", False):
        output_markdown(results, config)

    if outputs.get("webhook", {}).get("enabled", False):
        output_webhook(results, config)

    if outputs.get("json_log", {}).get("enabled", True):
        output_json_log(results, config)

    if outputs.get("command", {}).get("enabled", False):
        output_command(results, config)

    if outputs.get("custom_script", {}).get("enabled", False):
        output_custom_script(results, config)

    # Newsletter notes for newsletter-category results
    for r in results:
        if r.category == "newsletter":
            output_newsletter(r, config)
