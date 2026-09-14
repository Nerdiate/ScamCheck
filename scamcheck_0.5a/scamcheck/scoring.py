"""Combines findings from all analysis modules into one report:
a 0-100 suspicion score, a risk label, and a plain-language explanation
built directly from the specific rules that fired.
"""

from dataclasses import dataclass, field

from . import attachments as attachments_module
from . import domain as domain_module
from . import headers as headers_module
from . import language as language_module
from . import urls as urls_module
from .models import Finding, Severity
from .parser import parse_eml_bytes, parse_eml_file


@dataclass
class Report:
    score: int
    risk_level: str
    findings: list = field(default_factory=list)
    summary_line: str = ""
    limited_headers: bool = False

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "risk_level": self.risk_level,
            "summary_line": self.summary_line,
            "limited_headers": self.limited_headers,
            "findings": [f.to_dict() for f in self.findings],
        }


# Headers that only appear on a real, fully-intact message source -- if
# none of these are present, the user most likely pasted just the visible
# body text rather than the full "show original" source, and a large chunk
# of the analysis (auth, mismatches, spoofing, domain checks) could not run.
_FULL_SOURCE_INDICATOR_HEADERS = (
    "Received", "Authentication-Results", "Return-Path", "Message-ID", "Message-Id",
)


_RISK_THRESHOLDS = (
    (70, "High risk — very likely a scam or phishing attempt"),
    (35, "Medium risk — several suspicious signals, proceed with caution"),
    (10, "Low risk — minor signals only"),
    (0, "Minimal risk — no significant suspicious signals found"),
)


def _domain_of(addr: str) -> str:
    return addr.split("@")[-1].lower() if "@" in addr else ""


def analyze_file(path: str, skip_whois: bool = False) -> Report:
    parsed = parse_eml_file(path)
    return _analyze_parsed(parsed, skip_whois=skip_whois)


def analyze_bytes(raw: bytes, skip_whois: bool = False) -> Report:
    parsed = parse_eml_bytes(raw)
    return _analyze_parsed(parsed, skip_whois=skip_whois)


def _analyze_parsed(parsed, skip_whois: bool = False) -> Report:
    findings: list = []

    findings.extend(headers_module.analyze_headers(parsed))
    findings.extend(domain_module.analyze_domain(_domain_of(parsed.from_addr), skip_whois=skip_whois))
    findings.extend(urls_module.analyze_urls(parsed.links))
    findings.extend(language_module.analyze_language(parsed.subject, parsed.body_text))
    findings.extend(attachments_module.analyze_attachments(parsed.attachments))

    score = _compute_score(findings)
    risk_level = _risk_label(score)
    summary_line = _build_summary_line(findings, risk_level)
    limited_headers = not any(h in parsed.raw_headers for h in _FULL_SOURCE_INDICATOR_HEADERS)

    # Most severe / highest-weight findings first, for report readability
    findings.sort(key=lambda f: f.weight, reverse=True)

    return Report(
        score=score,
        risk_level=risk_level,
        findings=findings,
        summary_line=summary_line,
        limited_headers=limited_headers,
    )


def _compute_score(findings: list) -> int:
    raw = sum(f.weight for f in findings)
    return max(0, min(100, round(raw)))


def _risk_label(score: int) -> str:
    for threshold, label in _RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return _RISK_THRESHOLDS[-1][1]


def _build_summary_line(findings: list, risk_level: str) -> str:
    concerning = [f for f in findings if f.weight > 0 and f.severity != Severity.INFO]
    if not concerning:
        return "No suspicious signals were found in this message."
    top = sorted(concerning, key=lambda f: f.weight, reverse=True)[:3]
    highlights = "; ".join(f.summary for f in top)
    return f"{risk_level}. Top signals: {highlights}."
