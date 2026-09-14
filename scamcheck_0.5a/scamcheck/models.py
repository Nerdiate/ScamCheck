"""Shared data structures used across all analysis modules."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    INFO = "info"          # neutral/positive signal, shown for transparency
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    """A single, explainable signal produced by one rule.

    `weight` is added to the overall suspicion score (0-100 scale, can be
    negative for signals that indicate legitimacy, e.g. SPF/DKIM/DMARC all
    passing).
    """

    id: str
    category: str            # "headers" | "domain" | "urls" | "language"
    severity: Severity
    weight: float
    summary: str              # short, human-readable statement of what was found
    evidence: str              # the specific detail backing the summary
    advice: str = ""           # optional specific action for the recipient

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity.value,
            "weight": self.weight,
            "summary": self.summary,
            "evidence": self.evidence,
            "advice": self.advice,
        }


@dataclass
class ParsedEmail:
    """Normalized view of an .eml file that every analysis module reads from."""

    raw_headers: dict = field(default_factory=dict)
    from_addr: str = ""
    from_display_name: str = ""
    reply_to_addr: str = ""
    return_path_addr: str = ""
    sender_addr: str = ""
    to_addrs: list = field(default_factory=list)
    subject: str = ""
    date: str = ""
    received_chain: list = field(default_factory=list)
    authentication_results: str = ""
    body_text: str = ""
    body_html: str = ""
    links: list = field(default_factory=list)  # list of dicts: {"display": str, "href": str}
    attachments: list = field(default_factory=list)  # list of dicts: {"filename": str, "content_type": str}
