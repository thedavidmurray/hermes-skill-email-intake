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


class EmailClassifier:
    """Rule-based email classifier driven by config."""

    def __init__(self, config: dict):
        rules = config.get("classification", {})
        self.auth_domains = set(rules.get("auth", {}).get("domains", []))
        self.auth_terms = rules.get("auth", {}).get("terms", [])
        self.suspicious_terms = rules.get("suspicious", {}).get("terms", [])
        self.suspicious_min = rules.get("suspicious", {}).get("min_matches", 2)
        self.social_patterns = rules.get("social", {}).get("sender_patterns", [])
        self.newsletter_patterns = rules.get("newsletter", {}).get("sender_patterns", [])
        self.check_unsubscribe = rules.get("newsletter", {}).get("check_unsubscribe_header", True)
        self.default_category = config.get("security", {}).get("default_category", "suspicious")

    def classify(self, sender: str, subject: str, snippet: str,
                 headers: Optional[dict] = None) -> ClassificationResult:
        headers = headers or {}
        sender_lower = sender.lower()
        text = f"{subject} {snippet}".lower()
        list_unsub = headers.get("list-unsubscribe")

        # Auth: trusted domain + auth term
        domain_hit = any(d in sender_lower for d in self.auth_domains)
        term_hit = any(t in text for t in self.auth_terms)

        if domain_hit and term_hit:
            return ClassificationResult("auth",
                f"auth signal from trusted domain ({sender[:60]})",
                sender=sender, subject=subject)

        if term_hit and "noreply" in sender_lower:
            return ClassificationResult("auth",
                f"auth signal from automated sender ({sender[:60]})",
                confidence=0.8, sender=sender, subject=subject)

        # Actionable: trusted domain, no auth signal
        if domain_hit and "noreply" not in sender_lower:
            return ClassificationResult("actionable",
                f"trusted vendor: {sender[:60]}",
                sender=sender, subject=subject)

        # Suspicious: multiple phishing terms
        hits = sum(1 for t in self.suspicious_terms if t in text)
        if hits >= self.suspicious_min:
            return ClassificationResult("suspicious",
                f"matched {hits} suspicious terms",
                sender=sender, subject=subject)

        # Social digest
        if any(s in sender_lower for s in self.social_patterns):
            return ClassificationResult("social",
                "social/chat digest",
                sender=sender, subject=subject)

        # Newsletter
        if list_unsub or any(p in sender_lower for p in self.newsletter_patterns):
            return ClassificationResult("newsletter",
                "unsubscribe header or newsletter sender pattern",
                sender=sender, subject=subject)

        # Default
        return ClassificationResult(self.default_category,
            "no recognizable signal",
            confidence=0.5, sender=sender, subject=subject)
