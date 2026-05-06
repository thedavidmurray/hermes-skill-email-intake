"""
Email content sanitizer.

Strips URLs, scrubs sensitive patterns, and sanitizes HTML
before content is stored or forwarded anywhere.
"""

import re
import html as _html_stdlib

# ---------------------------------------------------------------------------
# Zero-width and invisible Unicode characters that can be inserted before
# URLs to defeat naive regex matching.
# ---------------------------------------------------------------------------
_ZERO_WIDTH_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u180e\u00a0]"
)

# ---------------------------------------------------------------------------
# Expanded URL pattern (M1)
# Covers:
#   - Full-scheme URLs: https://, http://, ftp://, data:, javascript:
#   - Protocol-relative URLs: //example.com/path
#   - Bare hostnames with paths: example.com/phish  (must contain a slash
#     to reduce false positives on plain words)
# ---------------------------------------------------------------------------
_URL_PATTERN = re.compile(
    r"""
    (?:
        # Schemes that always use ://, including ftp
        (?:https?|ftp|file)://\S+
        |
        # Schemes that do NOT require // (data:, javascript:, vbscript:)
        # Match scheme: followed by any non-whitespace
        (?:data|javascript|vbscript):[^\s"'<>]+
        |
        # Protocol-relative URLs: //host/path
        //[A-Za-z0-9\-\.]+(?:\.[A-Za-z]{2,})\S*
        |
        # Bare domain with path (must have a dot-TLD and a slash to
        # avoid false positives on plain words)
        [A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+/\S*
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def strip_urls(text: str) -> str:
    """Replace URLs with [URL stripped] markers.

    Strips zero-width Unicode characters first so they cannot be used to
    split a URL and bypass the regex.
    """
    text = _ZERO_WIDTH_CHARS.sub("", text)
    return _URL_PATTERN.sub("[URL stripped]", text)


# ---------------------------------------------------------------------------
# Signature stripping (M3)
# ---------------------------------------------------------------------------
# RFC 3676 / email convention: "-- \n" (dash dash space newline) is the only
# truly standard email signature delimiter.  "\n---\n" is a Markdown
# horizontal rule and must NOT be treated as a signature delimiter
# unconditionally.
#
# Strategy: honour "-- \n" anywhere in the message; only treat "---" style
# separators when they appear in the last 30 % of the content (where a
# footer/signature is plausible).  The "Sent from my" heuristic is also
# restricted to the trailing 30 %.
# ---------------------------------------------------------------------------

_RFC_SIG_DELIMITER = "\n-- \n"  # RFC-standard, valid anywhere

_TRAILING_DELIMITERS = [
    "\n---\n",
    "\n___\n",
    "\nSent from my ",
]


def strip_signatures(text: str) -> str:
    """Remove common email signature blocks.

    The RFC-standard '-- \\n' delimiter is recognised anywhere in the body.
    Markdown-style horizontal rules ('---') and device footers ('Sent from my
    ...') are only treated as signature separators when they appear in the
    last 30 % of the message, to avoid false positives on inline Markdown.
    """
    # RFC-standard delimiter: respected wherever it appears.
    idx = text.find(_RFC_SIG_DELIMITER)
    if idx > 0:
        text = text[:idx]
        return text

    # Heuristic delimiters: only in the trailing 30 %.
    cutoff = max(0, int(len(text) * 0.70))
    trailing = text[cutoff:]
    for marker in _TRAILING_DELIMITERS:
        local_idx = trailing.find(marker)
        if local_idx >= 0:
            text = text[: cutoff + local_idx]
            break

    return text


# ---------------------------------------------------------------------------
# Sensitive-data scrubbing (M7)
# ---------------------------------------------------------------------------
# Each tuple is (pattern_string, replacement, re_flags).
# Order matters: more specific patterns should appear before generic ones.
# ---------------------------------------------------------------------------
_SENSITIVE_PATTERNS: list[tuple[str, str, int]] = [
    # SSH / PEM private keys (may span lines — use re.DOTALL-free approach,
    # just strip the header line which is the canary).
    (r"-----BEGIN [\w\s]+PRIVATE KEY-----[\s\S]*?-----END [\w\s]+PRIVATE KEY-----",
     "[REDACTED PRIVATE KEY]", re.IGNORECASE),

    # AWS access key IDs
    (r"\bAKIA[A-Z0-9]{16}\b", "[REDACTED AWS KEY]", 0),

    # Slack tokens
    (r"\bxox[bpas]-[A-Za-z0-9\-]{10,}\b", "[REDACTED SLACK TOKEN]", re.IGNORECASE),

    # JWT tokens (header.payload[.signature])
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]+)?\b",
     "[REDACTED JWT]", 0),

    # Database / service connection strings
    (r"\b(?:postgres(?:ql)?|mysql|mongodb|redis|amqp|mssql)://\S+",
     "[REDACTED CONNECTION STRING]", re.IGNORECASE),

    # Generic password assignments: password=secret, password: secret
    (r"(?:password|passwd|pwd)\s*[=:]\s*\S+",
     "[REDACTED PASSWORD]", re.IGNORECASE),

    # Generic API keys / tokens (kept broad but after more specific patterns)
    (r"\b(?:sk|pk|ghp|glpat|Bearer)\s*[=_-]?\s*[A-Za-z0-9]{10,}",
     "[REDACTED]", re.IGNORECASE),

    # File paths
    (r"/(?:Users|home)/\w+/[^\s]+", "[PATH]", 0),
    (r"~/[^\s]+", "[PATH]", 0),
]

# Pre-compile for performance
_COMPILED_SENSITIVE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pat, flags), repl)
    for pat, repl, flags in _SENSITIVE_PATTERNS
]


def scrub_sensitive(text: str) -> str:
    """Remove patterns that look like credentials or internal references."""
    if not text:
        return text
    for pattern, replacement in _COMPILED_SENSITIVE:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# HTML sanitisation (M2) — whitelist approach
# ---------------------------------------------------------------------------
# If `nh3` or `bleach` is available, delegate to them (they use a real HTML
# parser and are much more robust).  Otherwise fall back to the regex-based
# whitelist defined below.
# ---------------------------------------------------------------------------

# Safe tags and the attributes permitted on each (None = no attributes).
_SAFE_TAGS: dict[str, set[str] | None] = {
    "p": None,
    "br": None,
    "b": None,
    "i": None,
    "em": None,
    "strong": None,
    "ul": None,
    "ol": None,
    "li": None,
    "h1": None,
    "h2": None,
    "h3": None,
    "h4": None,
    "h5": None,
    "h6": None,
    "blockquote": None,
    "pre": None,
    "code": None,
    "table": None,
    "thead": None,
    "tbody": None,
    "tr": None,
    "td": {"colspan", "rowspan", "class", "title"},
    "th": {"colspan", "rowspan", "class", "title"},
    "div": {"class"},
    "span": {"class"},
    # href only allowed with http/https scheme (validated separately)
    "a": {"href", "title", "class"},
    # src only allowed with http/https scheme (validated separately)
    "img": {"src", "alt", "title", "class"},
}

# Globally safe attributes (allowed on any whitelisted tag)
_GLOBALLY_SAFE_ATTRS: frozenset[str] = frozenset()

# Pattern matching an opening or self-closing HTML tag and its attributes
_TAG_RE = re.compile(
    r"<(?P<slash>/?)(?P<tag>[A-Za-z][A-Za-z0-9]*)(?P<attrs>[^>]*)>",
    re.DOTALL,
)

# Individual attribute scanner
_ATTR_RE = re.compile(
    r"""(?P<name>[A-Za-z][A-Za-z0-9_-]*)"""
    r"""\s*=\s*(?P<quote>["\'])(?P<value>[^"\']*?)(?P=quote)"""
    r"""|(?P<bare>[A-Za-z][A-Za-z0-9_-]*)""",
    re.DOTALL | re.IGNORECASE,
)

_SAFE_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def _safe_attr_value(tag: str, attr_name: str, attr_value: str) -> str | None:
    """Return the sanitised attribute value, or None to drop the attribute."""
    attr_lower = attr_name.lower()

    # href on <a>: must be http/https
    if tag == "a" and attr_lower == "href":
        if _SAFE_URL_RE.match(attr_value.strip()):
            return attr_value
        return None

    # src on <img>: must be http/https
    if tag == "img" and attr_lower == "src":
        if _SAFE_URL_RE.match(attr_value.strip()):
            return attr_value
        return None

    # alt / title / class — safe to pass through (HTML-escaped)
    if attr_lower in {"alt", "title", "class"}:
        return attr_value

    # colspan / rowspan on table cells
    if attr_lower in {"colspan", "rowspan"} and tag in {"td", "th"}:
        if re.match(r"^\d+$", attr_value.strip()):
            return attr_value
        return None

    return None


def _rebuild_tag(tag_name: str, attrs_str: str, closing_slash: str) -> str:
    """Rebuild a whitelisted opening/self-closing tag keeping only safe attrs."""
    tag_lower = tag_name.lower()
    allowed_attrs = _SAFE_TAGS.get(tag_lower)
    parts = [tag_lower]

    for m in _ATTR_RE.finditer(attrs_str):
        if m.group("bare"):
            # Boolean attribute — skip (no value to validate)
            continue
        name = m.group("name")
        value = m.group("value")
        if allowed_attrs is not None and name.lower() not in allowed_attrs:
            continue
        safe_value = _safe_attr_value(tag_lower, name, value)
        if safe_value is None:
            continue
        escaped = _html_stdlib.escape(safe_value, quote=True)
        parts.append(f'{name}="{escaped}"')

    rebuilt = "<" + " ".join(parts)
    if closing_slash:
        rebuilt += " /"
    rebuilt += ">"
    return rebuilt


def _sanitize_html_regex(html: str) -> str:
    """Whitelist-based HTML sanitiser using stdlib regex (no parser)."""
    # Strip HTML comments first
    html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)

    # Strip <style> blocks entirely
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)

    # Strip <script> blocks entirely
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)

    # Strip other wholesale-forbidden elements: svg, math, object, embed,
    # applet, link, meta, iframe, frame, frameset, form, input, button,
    # select, textarea
    _FORBIDDEN_BLOCK = re.compile(
        r"<(?P<t>svg|math|object|embed|applet|link|meta|iframe|frame|frameset"
        r"|form|input|button|select|textarea)"
        r"(?:[^>]*)>.*?</(?P=t)>",
        re.DOTALL | re.IGNORECASE,
    )
    html = _FORBIDDEN_BLOCK.sub("", html)

    # Also strip self-closing / void versions of forbidden elements
    html = re.sub(
        r"<(?:svg|math|object|embed|applet|link|meta|iframe|frame"
        r"|input|button)[^>]*/?>",
        "",
        html,
        flags=re.IGNORECASE,
    )

    def _replace_tag(m: re.Match[str]) -> str:
        slash = m.group("slash")
        tag = m.group("tag").lower()
        if tag not in _SAFE_TAGS:
            return ""  # strip unknown / disallowed tags entirely
        if slash:  # closing tag — no attributes needed
            return f"</{tag}>"
        return _rebuild_tag(tag, m.group("attrs"), "")

    html = _TAG_RE.sub(_replace_tag, html)
    return html


def sanitize_html(html: str) -> str:
    """Sanitise HTML using a whitelist of safe tags and attributes.

    Uses `nh3` if available, then `bleach`, then falls back to the built-in
    regex whitelist.  The regex fallback is deliberately conservative: unknown
    tags are stripped entirely rather than passed through.
    """
    if not html:
        return ""

    try:
        import nh3  # type: ignore[import]
        allowed_tags = set(_SAFE_TAGS.keys())
        allowed_attributes: dict[str, set[str]] = {}
        for tag, attrs in _SAFE_TAGS.items():
            if attrs:
                allowed_attributes[tag] = set(attrs)
        return nh3.clean(
            html,
            tags=allowed_tags,
            attributes=allowed_attributes,
            link_rel=None,
        )
    except ImportError:
        pass

    try:
        import bleach  # type: ignore[import]
        from bleach.linkifier import LinkifyFilter  # noqa: F401
        allowed_tags_list = list(_SAFE_TAGS.keys())
        allowed_attrs: dict[str, list[str]] = {}
        for tag, attrs in _SAFE_TAGS.items():
            if attrs:
                allowed_attrs[tag] = list(attrs)
        return bleach.clean(
            html,
            tags=allowed_tags_list,
            attributes=allowed_attrs,
            strip=True,
            strip_comments=True,
        )
    except ImportError:
        pass

    return _sanitize_html_regex(html)


# ---------------------------------------------------------------------------
# Main entry point (M10: truncate BEFORE regex operations)
# ---------------------------------------------------------------------------

def sanitize_content(text: str, config: dict) -> str:
    """Apply all sanitization steps based on config.

    Truncation is applied first (M10) so that subsequent regex operations
    never operate on unbounded input, preventing ReDoS on crafted payloads.
    """
    if not text:
        return text or ""

    security = config.get("security", {})

    # M10: Truncate FIRST, before any regex work.
    max_size = security.get("max_body_size", 102400)
    if len(text) > max_size:
        text = text[:max_size] + "\n[TRUNCATED]"

    if security.get("strip_urls", True):
        text = strip_urls(text)
    if security.get("scrub_content", True):
        text = scrub_sensitive(text)

    return text
