"""
Email classifier with configurable rules and interpretation layers.

Classification categories (default, all customizable via config.yaml):
  auth       - Authentication/security from known vendors
  actionable - Trusted vendor communication requiring response
  suspicious - Probable phishing or scam (2+ suspicious signals)
  newsletter - Bulk sender or has List-Unsubscribe header
  social     - Chat/social platform digest
  noise      - Unrecognized sender, no clear signal
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ClassificationResult:
    category: str
    reason: str
    confidence: float = 1.0
    extracted_snippet: str = ""
    summary: str = ""
    sender: str = ""
    subject: str = ""
    message_id: str = ""
    date: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "reason": self.reason,
            "confidence": self.confidence,
            "sender": self.sender,
            "subject": self.subject,
            "message_id": self.message_id,
            "date": self.date,
            "extracted_snippet": self.extracted_snippet,
            "summary": self.summary,
            "metadata": self.metadata,
        }


# Matches the domain portion of an email address.
# Handles bare addresses ("foo@example.com") and display names
# ("Foo Bar <foo@example.com>").
_EMAIL_RE = re.compile(r"@([\w.-]+)", re.IGNORECASE)


def _extract_domain(sender: str) -> str:
    """Return the lowercased domain of the first address found in sender."""
    match = _EMAIL_RE.search(sender)
    if not match:
        return ""
    return match.group(1).lower()


def _domain_matches(sender_domain: str, trusted_domain: str) -> bool:
    """
    Return True when sender_domain exactly equals trusted_domain or is an
    immediate subdomain of it (e.g. mail.github.com matches github.com).
    Does NOT match github.com.evil.net against github.com.
    """
    trusted = trusted_domain.lower()
    dom = sender_domain.lower()
    return dom == trusted or dom.endswith("." + trusted)


class _RuleConfig:
    """Parsed, validated view of a single classification rule block."""

    def __init__(self, name: str, raw: dict, all_rules: dict):
        self.name = name
        self.priority: int = raw.get("priority", 50)
        self.require_both: bool = raw.get("require_both", False)

        # Domain inheritance
        inherit_from = raw.get("inherit_domains_from")
        if inherit_from and inherit_from in all_rules:
            self.domains: set = set(all_rules[inherit_from].get("domains", []))
        else:
            self.domains = set(raw.get("domains", []))

        self.terms: list = raw.get("terms", [])
        self.sender_patterns: list = raw.get("sender_patterns", [])
        self.check_unsubscribe: bool = raw.get("check_unsubscribe_header", False)
        self.min_matches: int = raw.get("min_matches", 1)


# Score weights
_W_DOMAIN = 3
_W_TERM = 3
_W_NOREPLY_AUTH = 1       # noreply is a mild positive for auth
_W_NOREPLY_ACTIONABLE = -1  # noreply is a mild negative for actionable
_W_SUSPICIOUS_TERM = 2
_W_LIST_UNSUB = 5
_W_SOCIAL_PATTERN = 5
_W_NEWSLETTER_PATTERN = 3


class EmailClassifier:
    """Rule-based email classifier driven by config."""

    def __init__(self, config: dict):
        raw_rules = config.get("classification", {})
        self.default_category: str = config.get("security", {}).get(
            "default_category", "suspicious"
        )

        # Build _RuleConfig objects keyed by rule name
        self._rules: dict[str, _RuleConfig] = {
            name: _RuleConfig(name, raw, raw_rules)
            for name, raw in raw_rules.items()
        }

        # Convenience shortcuts used in scoring
        auth_cfg = self._rules.get("auth")
        self._auth_domains: set = auth_cfg.domains if auth_cfg else set()
        self._auth_terms: list = auth_cfg.terms if auth_cfg else []

        suspicious_cfg = self._rules.get("suspicious")
        self._suspicious_terms: list = (
            suspicious_cfg.terms if suspicious_cfg else []
        )
        self._suspicious_min: int = (
            suspicious_cfg.min_matches if suspicious_cfg else 2
        )

        social_cfg = self._rules.get("social")
        self._social_patterns: list = (
            social_cfg.sender_patterns if social_cfg else []
        )

        newsletter_cfg = self._rules.get("newsletter")
        self._newsletter_patterns: list = (
            newsletter_cfg.sender_patterns if newsletter_cfg else []
        )
        self._check_unsubscribe: bool = (
            newsletter_cfg.check_unsubscribe if newsletter_cfg else True
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(
        self,
        sender: str,
        subject: str,
        snippet: str,
        headers: Optional[dict] = None,
    ) -> ClassificationResult:
        headers = headers or {}
        sender_lower = sender.lower()
        sender_domain = _extract_domain(sender)
        text = f"{subject} {snippet}".lower()
        list_unsub = headers.get("list-unsubscribe")
        is_noreply = "noreply" in sender_lower or "no-reply" in sender_lower

        # --- Signal booleans ---
        domain_hit = any(
            _domain_matches(sender_domain, d) for d in self._auth_domains
        )
        term_hit = any(t in text for t in self._auth_terms)
        suspicious_hits = sum(
            1 for t in self._suspicious_terms if t in text
        )
        social_hit = any(p in sender_lower for p in self._social_patterns)
        newsletter_hit = any(
            p in sender_lower for p in self._newsletter_patterns
        )

        # --- Weighted scoring per category ---
        scores: dict[str, float] = {
            "auth": 0.0,
            "actionable": 0.0,
            "suspicious": 0.0,
            "social": 0.0,
            "newsletter": 0.0,
            "noise": 0.0,
        }

        if domain_hit:
            scores["auth"] += _W_DOMAIN
            scores["actionable"] += _W_DOMAIN
        if term_hit:
            scores["auth"] += _W_TERM
        if is_noreply:
            scores["auth"] += _W_NOREPLY_AUTH
            scores["actionable"] += _W_NOREPLY_ACTIONABLE
        if suspicious_hits > 0:
            scores["suspicious"] += suspicious_hits * _W_SUSPICIOUS_TERM
        if list_unsub:
            scores["newsletter"] += _W_LIST_UNSUB
        if social_hit:
            scores["social"] += _W_SOCIAL_PATTERN
        if newsletter_hit:
            scores["newsletter"] += _W_NEWSLETTER_PATTERN

        # --- Rule-engine: evaluate in priority order, first clear winner wins ---
        # Build an ordered list of rule names sorted by ascending priority value
        # (lower number = higher priority, like cron/systemd conventions).
        ordered_rules = sorted(
            (rc for rc in self._rules.values()),
            key=lambda rc: rc.priority,
        )

        for rc in ordered_rules:
            name = rc.name
            if name not in scores:
                continue

            if rc.require_both:
                # Both domain AND term must match
                rule_domain_hit = any(
                    _domain_matches(sender_domain, d) for d in rc.domains
                ) if rc.domains else domain_hit
                rule_term_hit = any(t in text for t in rc.terms) if rc.terms else term_hit
                if not (rule_domain_hit and rule_term_hit):
                    continue
            else:
                # Any positive score suffices
                if scores[name] <= 0:
                    continue

            # Category-specific thresholds and confidence computation
            if name == "auth":
                if domain_hit and term_hit:
                    confidence = 0.8 if is_noreply else 1.0
                    reason = (
                        f"auth signal from automated sender ({sender[:60]})"
                        if is_noreply
                        else f"auth signal from trusted domain ({sender[:60]})"
                    )
                    return ClassificationResult(
                        "auth", reason,
                        confidence=confidence,
                        sender=sender,
                        subject=subject,
                    )

            elif name == "actionable":
                if domain_hit and not is_noreply:
                    return ClassificationResult(
                        "actionable",
                        f"trusted vendor: {sender[:60]}",
                        confidence=1.0,
                        sender=sender,
                        subject=subject,
                    )
                # H5 fix: trusted domain + noreply + not caught by auth
                if domain_hit and is_noreply:
                    return ClassificationResult(
                        "actionable",
                        f"trusted vendor (automated): {sender[:60]}",
                        confidence=0.7,
                        sender=sender,
                        subject=subject,
                    )

            elif name == "suspicious":
                if suspicious_hits >= self._suspicious_min:
                    return ClassificationResult(
                        "suspicious",
                        f"matched {suspicious_hits} suspicious terms",
                        confidence=min(1.0, 0.5 + suspicious_hits * 0.1),
                        sender=sender,
                        subject=subject,
                    )

            elif name == "social":
                if social_hit:
                    return ClassificationResult(
                        "social",
                        "social/chat digest",
                        confidence=1.0,
                        sender=sender,
                        subject=subject,
                    )

            elif name == "newsletter":
                if list_unsub or newsletter_hit:
                    return ClassificationResult(
                        "newsletter",
                        "unsubscribe header or newsletter sender pattern",
                        confidence=1.0,
                        sender=sender,
                        subject=subject,
                    )

        # --- Default fallback ---
        return ClassificationResult(
            self.default_category,
            "no recognizable signal",
            confidence=0.5,
            sender=sender,
            subject=subject,
        )
