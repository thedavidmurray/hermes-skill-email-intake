# Email Triage

Rule-based email classifier that routes messages to the right handler. Pluggable providers, 7 output backends, configurable Gmail actions, and hardcoded security that blocks phishing.

## Features

**Classification**: 6-category priority-based rules engine (auth, actionable, suspicious, newsletter, social, noise). Exact domain matching with subdomain support. Weighted scoring with configurable signal thresholds.

**Interpretation layers**: Optional content extraction and LLM summarization. Strips URLs, signatures, and PII before storage.

**Output backends**: Console (table/JSON), markdown files, newsletter-organized archives, webhooks (SSRF-protected), JSONL logs, shell commands, and Python plugins.

**Per-category actions**: Configure Gmail operations per rule—star, archive, label, mark read.

**Extensible providers**: Gmail CLI out of the box. Add Outlook, FastMail, IMAP via ABC subclass.

**State tracking**: Atomic writes. User feedback loop: reclassify mismatches and review recent decisions.

## Install

Requires Python 3.8+ and PyYAML.

```bash
pip install pyyaml
```

Copy `config.example.yaml` to `config.yaml` and update the `provider.cli_path` to your Gmail CLI tool (e.g., `gws`, `gmail-cli`).

## Quick Start

1. **Configure your provider:**
   ```yaml
   provider:
     type: gmail_cli
     cli_path: gws
     account: me
   ```

2. **Add trusted domains to auth rules:**
   ```yaml
   classification:
     auth:
       priority: 10
       domains: [github.com, anthropic.com, stripe.com]
       terms: [two-factor, otp, security alert]
       require_both: true
       actions: [star, leave_unread]
   ```

3. **Run classification:**
   ```bash
   python email_triage.py
   ```

4. **Review and adjust:**
   ```bash
   python email_triage.py --review --review-last 30
   ```

5. **Correct a misclassification:**
   ```bash
   python email_triage.py --reclassify MSG_ID actionable
   ```

## Usage

```bash
# Run with config.yaml
python email_triage.py

# Custom config
python email_triage.py --config my.yaml

# Classify without Gmail side-effects
python email_triage.py --dry-run

# Print classifications only, no state/reads
python email_triage.py --report-only

# Show recently classified (default 20)
python email_triage.py --review --review-last 50

# Override classification
python email_triage.py --reclassify MSG_ID new_category

# Debug mode
python email_triage.py --verbose

# Custom Gmail query
python email_triage.py --lookback "newer_than:3d"

# Limit emails per run
python email_triage.py --max 100
```

Exit codes: 0 (success), 1 (config error), 2 (provider error).

## Classification Rules

Rules are evaluated in **priority order** (lower number = checked first). First clear winner wins.

### Rule Anatomy

```yaml
auth:                           # Category name
  priority: 10                  # Lower = higher priority
  domains: [github.com]         # Domain list (exact + subdomain match)
  terms: [two-factor, otp]      # Text patterns (case-insensitive)
  require_both: true            # Both domain AND term must match
  sender_patterns: []           # Regex patterns on sender email
  check_unsubscribe_header: false  # Trigger on List-Unsubscribe header
  min_matches: 1                # Suspicious rules need 2+
  inherit_domains_from: auth    # Reuse domain list from another rule
  actions: [star]               # Per-category Gmail actions (below)
```

### Domain Matching

- **Exact match**: `github.com` matches `noreply@github.com`
- **Subdomain match**: `github.com` also matches `mail.github.com`
- **No suffix match**: `github.com` does NOT match `github.com.evil.net`

### Special Rules

**Require both**: Set `require_both: true` to demand both a domain AND term match (used by auth to prevent false positives on spoofed headers).

**Inherit domains**: Set `inherit_domains_from: auth` to reuse the domain list from the auth rule. Saves duplication in actionable rules.

**Min matches**: Set `min_matches: 2` for suspicious rules to require 2+ term hits (not just 1).

**Noreply handling**: Mild positive signal (+1) for auth, mild negative (-1) for actionable. Distinguishes automated vendor emails from human-sent messages.

### Confidence Scoring

- Auth with domain + term = 1.0
- Auth with noreply = 0.8
- Actionable with trusted domain = 1.0
- Actionable with noreply = 0.7
- Suspicious scales 0.5–1.0 with term hits
- Newsletter/social/default = 0.5

## Output Backends

All enabled/disabled per config. Write results to multiple places simultaneously.

### Console

```yaml
console:
  enabled: true
  format: table  # or "json"
```

Prints a table or JSON to stdout.

### Markdown

```yaml
markdown:
  enabled: true
  output_dir: ./inbox/triage
  mode: per_run  # or "per_email"
```

Writes YAML frontmatter + body to file(s). `per_run` = one file per execution; `per_email` = one file per message.

### Newsletter

```yaml
newsletter:
  enabled: true
  output_dir: ./inbox/newsletters
  frontmatter_template: |
    ---
    type: email-newsletter
    sender: "{sender}"
    subject: "{subject}"
    date: "{date}"
    gmail_id: "{message_id}"
    captured: "{today}"
    ---
```

Routes only newsletter-classified emails to `output_dir/{sender_domain}/` with message-ID dedup in filenames.

### Webhook

```yaml
webhook:
  enabled: true
  url: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
  payload_template: |
    {
      "text": "[{category}] {sender}: {subject}"
    }
```

POSTs JSON to the URL. **SSRF-protected**: blocks requests to private IPs, link-local, localhost. Hostname resolution required; fails closed if resolution fails.

### JSON Log

```yaml
json_log:
  enabled: true
  path: ./logs/email_triage.jsonl
```

Appends one JSON object per line (JSONL, not JSON array). No read-modify-write race conditions.

### Command

```yaml
command:
  enabled: true
  cmd: "python3 vectorize.py"
  categories: []  # empty = all categories
```

Pipes each email as JSON to stdin of `cmd`. Use for ChromaDB, Qdrant, SQLite, PostgreSQL, Notion, Airtable, Linear, etc. Uses `shlex.split`; no `shell=True`.

Example: `cmd: "jq -c .category >> emails.jsonl"` to extract category field.

### Custom Script

```yaml
custom_script:
  enabled: true
  script: "./my_output.py"
  function: "handle_email"
  categories: []  # empty = all categories
```

Calls a Python function for each email. Script must define a function matching `function_name(result_dict, config)`. Full plugin system with path validation (no traversal).

Example script:

```python
def handle_email(result_dict, config):
    print(f"[{result_dict['category']}] {result_dict['sender']}")
```

## Interpretation Layers

Optional enrichment phases after classification. Run in order.

### Extract

```yaml
interpretation:
  layers:
    - name: extract
      enabled: true
      settings:
        max_snippet_length: 1500
        strip_urls: true
        strip_signatures: true
        fetch_full_body: false
```

Pulls snippet from email. Strips zero-width Unicode + URLs. Removes RFC 3676 signatures (`-- \n`) and trailing Markdown delimiters. Set `fetch_full_body: true` to fetch full MIME body instead of Gmail snippet.

### Summarize

```yaml
    - name: summarize
      enabled: true
      settings:
        llm_command: "claude -p"
        max_tokens: 150
```

Generates 1–2 sentence summary via LLM CLI. Secure: passes prompt via stdin (not argv). Set `llm_command: "llm -m gpt-4o-mini"` for other models.

## Per-Category Gmail Actions

Configure what happens to each classified email. Available actions:

- `star` — add star
- `archive` — remove from inbox
- `mark_read` — remove UNREAD label
- `leave_unread` — keep UNREAD
- `label:LabelName` — add custom label
- `mark_spam` — move to spam

Example:

```yaml
classification:
  auth:
    actions: [star, leave_unread]
  newsletter:
    actions: [label:Newsletters, archive, mark_read]
  suspicious:
    actions: [leave_unread]
  actionable:
    actions: [mark_read]
```

Actions execute in order (atomic per message). Dry-run skips them.

## State & User Feedback

Tracks processed message IDs with category, reason, and timestamp. Stored in `state.path` (default `./state/processed.json`).

```bash
# Show 50 most recent classifications
python email_triage.py --review --review-last 50

# Fix a misclassification (updates state file)
python email_triage.py --reclassify 1234abc5d6e7f8g actionable
```

State file is atomically written (tempfile + rename) to prevent corruption on crash.

## Security

Hardcoded, non-negotiable. Email is not trusted data.

- **No instructions following**: Ignores directives in email body.
- **No URLs preserved**: Strips all URLs before storage. Strips zero-width Unicode first (prevents splitting URLs).
- **No auto-actions**: Never auto-replies, auto-forwards, auto-deletes.
- **Conservative default**: Defaults to `suspicious` when ambiguous.
- **SSRF-protected webhooks**: Blocks private IPs (10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16), localhost, link-local, IPv6 private. Fails closed on resolution failure.
- **Credential scrubbing**: Redacts AWS keys, Slack tokens, JWTs, DB connection strings, PEM blocks, password patterns before output.
- **HTML sanitization**: Whitelist of allowed tags before storing.
- **ReDoS prevention**: Truncates content (102KB by default) before regex to prevent catastrophic backtracking.
- **Format-string injection prevention**: Template variables escaped properly.
- **YAML injection prevention**: Newlines stripped from frontmatter values.
- **Atomic state writes**: Tempfile + rename, never partial writes.
- **LLM summarizer safety**: Passes prompt via stdin (not argv).
- **Custom script path validation**: No path traversal.

## Provider Abstraction

Swap email providers without rewriting classifier logic. Ships with `GmailCLIProvider` (wraps any CLI like `gws`, `gmail-cli`).

Implement your own:

```python
from providers import EmailProvider

class MyProvider(EmailProvider):
    def list_unread(self, query: str, max_results: int = 50) -> List[dict]:
        """Return list of message stubs."""
        pass

    def get_message(self, msg_id: str) -> Optional[dict]:
        """Fetch metadata (headers + snippet)."""
        pass

    def get_message_full(self, msg_id: str) -> Optional[dict]:
        """Fetch full MIME message."""
        pass

    def mark_read(self, msg_id: str) -> bool:
        """Remove UNREAD label."""
        pass

    def extract_headers(self, msg: dict) -> dict:
        """Return normalized {header: value} dict."""
        pass

    def execute_actions(self, msg_id: str, actions: list, dry_run: bool) -> None:
        """Apply category actions (star, archive, etc.)."""
        pass

    def get_body_text(self, msg: dict) -> str:
        """Extract best-effort plain text from MIME."""
        pass
```

Then in config:

```yaml
provider:
  type: my_custom_provider
  # your provider-specific settings
```

## Examples

### Trap Phishing

```yaml
classification:
  suspicious:
    priority: 20
    terms:
      - verify your account
      - confirm your password
      - unusual activity
      - urgent action required
      - click here to confirm
    min_matches: 2
    actions: [leave_unread]  # Don't auto-mark read
```

### Route Newsletters to Archive

```yaml
classification:
  newsletter:
    priority: 50
    sender_patterns: [substack, beehiiv, mailchimp]
    check_unsubscribe_header: true
    actions: [label:Newsletters, archive, mark_read]
```

### Highlight Auth Emails

```yaml
classification:
  auth:
    priority: 10
    domains: [github.com, stripe.com, aws.amazon.com]
    terms: [two-factor, otp, security alert, new device]
    require_both: true
    actions: [star, leave_unread]
```

### Log Everything to ChromaDB

```yaml
command:
  enabled: true
  cmd: "python3 -c 'import json, sys; sys.stdin.read()'"  # just read stdin
  categories: []  # all categories
```

## License

MIT

Author: thedavidmurray
