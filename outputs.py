"""
Output backends for classified emails.

Each backend receives a list of ClassificationResults and writes them
to the configured destination (console, markdown files, webhook, JSON log).
"""

import importlib.util
import ipaddress
import json
import re
import shlex
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List

from classifier import ClassificationResult

# Private/internal IP networks to block for SSRF protection (H3)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_ip(host: str) -> bool:
    """Return True if the resolved host is a private/internal IP address."""
    try:
        addr_info = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Fail closed: if we cannot resolve, treat as blocked
        return True
    for _family, _type, _proto, _canonname, sockaddr in addr_info:
        raw_ip = sockaddr[0]
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        for network in _BLOCKED_NETWORKS:
            if addr in network:
                return True
    return False


def _validate_webhook_url(url: str) -> bool:
    """
    Validate webhook URL for SSRF safety (H3).

    - Only http:// and https:// schemes are allowed.
    - Resolves hostname and rejects private/internal IP ranges.
    Returns True if safe, False otherwise.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        print(
            f"  Webhook blocked: unsupported scheme in URL (only http/https allowed)",
            file=sys.stderr,
        )
        return False

    # Extract hostname
    try:
        # Strip scheme, take everything before first / or :
        after_scheme = url.split("://", 1)[1]
        host_port = after_scheme.split("/")[0]
        host = host_port.split(":")[0]
    except (IndexError, ValueError):
        print("  Webhook blocked: could not parse hostname", file=sys.stderr)
        return False

    if _is_private_ip(host):
        print(
            f"  Webhook blocked: hostname '{host}' resolves to a private/internal IP",
            file=sys.stderr,
        )
        return False

    return True


def _escape_yaml_string(value: str, max_len: int = 200) -> str:
    """
    Escape a string for safe embedding in YAML double-quoted scalar (C4).

    - Strips newlines to prevent YAML injection via multiline values.
    - Escapes double-quotes.
    - Truncates to max_len.
    """
    value = (value or "").replace("\r", "").replace("\n", " ")
    value = value.replace('"', '\\"')
    return value[:max_len]


def _escape_format_field(value: str) -> str:
    """
    Escape a user-supplied string so it is safe to use with str.format() (C3).

    Curly braces are escaped to prevent format-string injection.
    """
    value = value or ""
    return value.replace("{", "{{").replace("}", "}}")


def output_console(results: List[ClassificationResult], config: dict):
    """Print results as a table or JSON."""
    fmt = config.get("outputs", {}).get("console", {}).get("format", "table")

    if fmt == "json":
        for r in results:
            d = r.to_dict()
            print(json.dumps({
                "category": d["category"],
                "sender": d["sender"],
                "subject": d["subject"],
                "reason": d["reason"],
            }))
        return

    # Table format
    for r in results:
        d = r.to_dict()
        sender = (d["sender"] or "?")[:55]
        subject = (d["subject"] or "?")[:75]
        print(f"  [{d['category']:11}] {sender:55} | {subject}")


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
            d = r.to_dict()
            lines.append(f"## [{d['category']}] {d['subject']}\n")
            lines.append(f"- **From:** {d['sender']}")
            lines.append(f"- **Reason:** {d['reason']}")
            if d.get("extracted_snippet"):
                lines.append(f"\n> {d['extracted_snippet'][:500]}\n")
            lines.append("")
        path.write_text("\n".join(lines))
        print(f"  Wrote {path}")
    else:
        for r in results:
            d = r.to_dict()
            slug = re.sub(r"[^a-z0-9-]+", "-", (d["subject"] or "untitled").lower())[:60]
            path = output_dir / f"{d['category']}-{slug}.md"
            # C4: escape sender/subject for YAML
            safe_sender = _escape_yaml_string(d["sender"] or "", max_len=200)
            safe_subject = _escape_yaml_string(d["subject"] or "", max_len=200)
            body = f"""---
type: email-triage
category: {d['category']}
sender: "{safe_sender}"
subject: "{safe_subject}"
date: "{d.get('date') or ''}"
message_id: "{d.get('message_id') or ''}"
captured: "{datetime.now().strftime('%Y-%m-%d')}"
---

# {d['subject']}

**From:** {d['sender']}
**Category:** {d['category']}
**Reason:** {d['reason']}

{d.get('extracted_snippet') or ''}
"""
            path.write_text(body)


def output_newsletter(result: ClassificationResult, config: dict):
    """Write a single newsletter to the configured newsletter directory.

    Triggered via outputs.newsletter config (H9).
    """
    nl_config = config.get("outputs", {}).get("newsletter", {})
    if not nl_config.get("enabled", False):
        return

    newsletter_dir = Path(nl_config.get("output_dir", "./inbox/newsletters"))
    d = result.to_dict()

    # Slugify sender domain
    m = re.search(r"@([^>\s]+)", d.get("sender") or "")
    domain = m.group(1).split(".")[0] if m else "unknown"
    domain = re.sub(r"[^a-z0-9-]+", "-", domain.lower()).strip("-") or "unknown"

    slug = re.sub(r"[^a-z0-9-]+", "-", (d.get("subject") or "").lower()).strip("-")[:80] or "untitled"
    today = datetime.now().strftime("%Y-%m-%d")

    # M6: append first 8 chars of message_id to prevent same-day/same-subject overwrites
    msg_id_suffix = (d.get("message_id") or "")[:8]
    if msg_id_suffix:
        filename = f"{today}-{slug}-{msg_id_suffix}.md"
    else:
        filename = f"{today}-{slug}.md"

    target = newsletter_dir / domain / filename

    template = nl_config.get(
        "frontmatter_template",
        "---\ntype: email-newsletter\n---\n",
    )

    # C4: escape sender/subject for YAML before substitution
    safe_sender = _escape_yaml_string(d.get("sender") or "", max_len=200)
    safe_subject = _escape_yaml_string(d.get("subject") or "", max_len=200)

    # C3: use manual .replace() on the template instead of .format()
    frontmatter = (
        template
        .replace("{sender}", safe_sender)
        .replace("{subject}", safe_subject)
        .replace("{date}", d.get("date") or "")
        .replace("{message_id}", d.get("message_id") or "")
        .replace("{today}", today)
    )

    target.parent.mkdir(parents=True, exist_ok=True)
    body = f"""{frontmatter}
# {d.get('subject') or ''}

{d.get('extracted_snippet') or '(no content extracted)'}

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

    # H3: validate URL scheme and SSRF protection
    if not _validate_webhook_url(url):
        return

    template = wh_config.get("payload_template", '{{"text": "[{category}] {sender}: {subject}"}}')

    import urllib.request

    for r in results:
        d = r.to_dict()

        # C3: escape email-derived fields before substituting into the template
        safe_category = _escape_format_field(d.get("category") or "")
        safe_sender = _escape_format_field(d.get("sender") or "?")
        safe_subject = _escape_format_field(d.get("subject") or "?")
        safe_reason = _escape_format_field(d.get("reason") or "")

        payload = (
            template
            .replace("{category}", safe_category)
            .replace("{sender}", safe_sender)
            .replace("{subject}", safe_subject)
            .replace("{reason}", safe_reason)
        )

        try:
            req = urllib.request.Request(
                url, data=payload.encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # H3: disable redirect following to prevent redirect-based SSRF
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            print(f"  Webhook error: {e}", file=sys.stderr)


def output_json_log(results: List[ClassificationResult], config: dict):
    """Append results to a JSONL log file (H5: atomic append, no read-modify-write race)."""
    log_config = config.get("outputs", {}).get("json_log", {})
    path = Path(log_config.get("path", "./logs/email_triage.jsonl"))
    path.parent.mkdir(parents=True, exist_ok=True)

    # H1: use append mode + one JSON line per result (JSONL) instead of
    # read-modify-write on a JSON array, which races under concurrent writers.
    with open(path, "a", encoding="utf-8") as fh:
        for r in results:
            d = r.to_dict()
            record = {
                "category": d.get("category"),
                "reason": d.get("reason"),
                "sender": d.get("sender"),
                "subject": d.get("subject"),
                "message_id": d.get("message_id"),
                "date": d.get("date"),
                "ts": datetime.now().isoformat(),
            }
            fh.write(json.dumps(record) + "\n")


def output_summarize(result: ClassificationResult, config: dict) -> str:
    """Use an LLM to generate a summary (if configured)."""
    layers = config.get("interpretation", {}).get("layers", [])
    summarize = next((l for l in layers if l.get("name") == "summarize"), None)
    if not summarize or not summarize.get("enabled"):
        return ""

    llm_cmd = summarize.get("settings", {}).get("llm_command", "")
    if not llm_cmd:
        return ""

    d = result.to_dict()
    # H4: pass prompt via stdin to avoid argument injection; do not append to argv
    prompt = (
        f"Summarize this email in 1-2 sentences. "
        f"Subject: {d.get('subject') or ''}\nFrom: {d.get('sender') or ''}\n"
        f"Content: {(d.get('extracted_snippet') or '')[:1000]}"
    )

    try:
        # H4: use shlex.split instead of llm_cmd.split() for correct tokenisation
        proc = subprocess.run(
            shlex.split(llm_cmd),
            input=prompt,
            capture_output=True, text=True, timeout=30,
        )
        return proc.stdout.strip()[:300] if proc.returncode == 0 else ""
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
    filtered = [r for r in results if not allowed or r.to_dict().get("category") in allowed]
    if not filtered:
        return

    payload = "\n".join(
        json.dumps(r.to_dict())
        for r in filtered
    )

    try:
        # C2: use shlex.split + shell=False to avoid shell injection
        proc = subprocess.run(
            shlex.split(cmd), input=payload, shell=False,
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
    script_path_raw = script_config.get("script", "")
    func_name = script_config.get("function", "handle_email")
    if not script_path_raw:
        return

    allowed = script_config.get("categories")
    filtered = [r for r in results if not allowed or r.to_dict().get("category") in allowed]
    if not filtered:
        return

    # C5: validate custom script path before importing
    script_path = Path(script_path_raw).resolve()

    # Reject path traversal attempts
    if ".." in Path(script_path_raw).parts:
        print(
            f"  Custom script blocked: path contains '..': {script_path_raw}",
            file=sys.stderr,
        )
        return

    if not script_path.exists():
        print(f"  Custom script not found: {script_path}", file=sys.stderr)
        return

    if not script_path.is_file():
        print(
            f"  Custom script blocked: path is not a regular file: {script_path}",
            file=sys.stderr,
        )
        return

    # C5: warn about trust implications of executing arbitrary code
    print(
        f"  WARNING: importing and executing custom script '{script_path}'. "
        f"Only load scripts from trusted sources.",
        file=sys.stderr,
    )

    spec = importlib.util.spec_from_file_location("custom_output", script_path)
    if not spec or not spec.loader:
        print(f"  Custom script could not be loaded: {script_path}", file=sys.stderr)
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
        d = r.to_dict()
        try:
            handler(d, config)
        except Exception as e:
            print(f"  Custom script error on {d.get('message_id')}: {e}", file=sys.stderr)

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

    # H9: newsletter is now a proper output backend, not driven by interpretation.layers
    if outputs.get("newsletter", {}).get("enabled", False):
        for r in results:
            d = r.to_dict()
            if d.get("category") == "newsletter":
                output_newsletter(r, config)
