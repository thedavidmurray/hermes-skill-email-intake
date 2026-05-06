"""
Email content sanitizer.

Strips URLs, scrubs sensitive patterns, and sanitizes HTML
before content is stored or forwarded anywhere.
"""

import re


def strip_urls(text: str) -> str:
    """Replace URLs with [URL stripped] markers."""
    return re.sub(r"https?://\S+", "[URL stripped]", text)


def strip_signatures(text: str) -> str:
    """Remove common email signature blocks."""
    # Cut at common signature delimiters
    for marker in ["\n-- \n", "\n---\n", "\nSent from my "]:
        idx = text.find(marker)
        if idx > 0:
            text = text[:idx]
    return text


def scrub_sensitive(text: str) -> str:
    """Remove patterns that look like credentials or internal references."""
    if not text:
        return text

    patterns = [
        # API keys / tokens
        (r'\b(?:sk|pk|ghp|glpat|Bearer)\s*[=_-]?\s*[A-Za-z0-9]{10,}',
         '[REDACTED]', re.IGNORECASE),
        # File paths
        (r'/(?:Users|home)/\w+/[^\s]+', '[PATH]', 0),
        (r'~\/[^\s]+', '[PATH]', 0),
    ]

    for pattern, replacement, flags in patterns:
        text = re.sub(pattern, replacement, text, flags=flags)

    return text


def sanitize_html(html: str) -> str:
    """Aggressively strip dangerous HTML elements."""
    if not html:
        return ""

    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<script[^>]*/?>', '', html, flags=re.IGNORECASE)
    html = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)
    html = re.sub(r'href\s*=\s*["\']\s*javascript:', 'href="#" ', html, flags=re.IGNORECASE)
    html = re.sub(r'<iframe[^>]*>.*?</iframe>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<form[^>]*>.*?</form>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)

    return html


def sanitize_content(text: str, config: dict) -> str:
    """Apply all sanitization steps based on config."""
    security = config.get("security", {})

    if security.get("strip_urls", True):
        text = strip_urls(text)
    if security.get("scrub_content", True):
        text = scrub_sensitive(text)

    max_size = security.get("max_body_size", 102400)
    if len(text) > max_size:
        text = text[:max_size] + "\n[TRUNCATED]"

    return text
