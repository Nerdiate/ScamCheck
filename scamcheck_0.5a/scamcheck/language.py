"""Language and formatting heuristics.

Pure keyword/regex/statistics -- no model calls, runs instantly, costs
nothing per email. Weighted so that a single common word never triggers a
flag; it takes a cluster of pressure-tactic language to score meaningfully.
"""

import re

from .models import Finding, Severity

_URGENCY_PHRASES = [
    "act now", "immediate action required", "urgent", "verify your account",
    "your account has been suspended", "your account will be closed",
    "confirm your identity", "unusual activity", "unauthorized access",
    "final notice", "failure to respond", "within 24 hours", "within 48 hours",
    "limited time", "expire", "avoid suspension", "restricted",
]

_MONEY_PRESSURE_PHRASES = [
    "gift card", "wire transfer", "western union", "moneygram", "bitcoin",
    "cryptocurrency", "processing fee", "claim your prize", "you have won",
    "lottery", "inheritance", "tax refund", "social security number",
    "bank account number", "routing number", "cvv", "one time password",
    "send payment", "release your funds", "unclaimed funds",
]

_GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear account holder", "dear valued customer",
    "dear sir/madam", "dear sir or madam", "valued member", "dear winner",
]

_EXCESSIVE_PUNCT_RE = re.compile(r"[!?]{2,}")
_WORD_RE = re.compile(r"[A-Za-z]{3,}")


def analyze_language(subject: str, body_text: str) -> list:
    findings = []
    full_text = f"{subject}\n{body_text}".lower()

    findings.extend(_check_phrase_cluster(full_text, _URGENCY_PHRASES, "urgency_language", "urgency/pressure language", 4))
    findings.extend(_check_phrase_cluster(full_text, _MONEY_PRESSURE_PHRASES, "money_pressure_language", "requests for money, gift cards, or sensitive financial info", 6))
    findings.extend(_check_generic_greeting(full_text))
    findings.extend(_check_formatting_anomalies(subject, body_text))

    return findings


def _check_phrase_cluster(text, phrases, finding_id, label, weight_per_hit) -> list:
    hits = [p for p in phrases if p in text]
    if not hits:
        return []
    # Weight grows with number of distinct phrases matched, capped so one
    # extremely long email can't runaway-score.
    weight = min(len(hits) * weight_per_hit, 30)
    severity = Severity.HIGH if len(hits) >= 3 else (Severity.MEDIUM if len(hits) >= 2 else Severity.LOW)
    example_list = ", ".join(f'"{h}"' for h in hits[:5])
    return [
        Finding(
            id=finding_id,
            category="language",
            severity=severity,
            weight=weight,
            summary=f"Message contains {label}",
            evidence=f"Found {len(hits)} matching phrase(s): {example_list}.",
            advice="Slow down. Legitimate organizations rarely demand immediate action through email alone.",
        )
    ]


def _check_generic_greeting(text) -> list:
    for greeting in _GENERIC_GREETINGS:
        if greeting in text:
            return [
                Finding(
                    id="generic_greeting",
                    category="language",
                    severity=Severity.LOW,
                    weight=5,
                    summary="Email uses a generic greeting instead of your name",
                    evidence=f'The message opens with "{greeting}" rather than a personal name, common in mass scam mailings.',
                )
            ]
    return []


def _check_formatting_anomalies(subject, body_text) -> list:
    findings = []
    combined = f"{subject} {body_text}"

    words = _WORD_RE.findall(combined)
    if len(words) >= 15:
        caps_words = [w for w in words if w.isupper()]
        caps_ratio = len(caps_words) / len(words)
        if caps_ratio > 0.15:
            findings.append(
                Finding(
                    id="excessive_caps",
                    category="language",
                    severity=Severity.LOW,
                    weight=5,
                    summary="Unusually high use of ALL CAPS text",
                    evidence=f"{len(caps_words)} of {len(words)} words ({caps_ratio:.0%}) are fully capitalized, a common attention-grabbing tactic in scam email.",
                )
            )

    excess_punct = _EXCESSIVE_PUNCT_RE.findall(combined)
    if len(excess_punct) >= 2:
        findings.append(
            Finding(
                id="excessive_punctuation",
                category="language",
                severity=Severity.LOW,
                weight=5,
                summary="Unusual repeated punctuation (e.g. \"!!!\" or \"???\")",
                evidence=f"Found {len(excess_punct)} instance(s) of repeated ! or ? marks, often used to create urgency.",
            )
        )

    return findings
