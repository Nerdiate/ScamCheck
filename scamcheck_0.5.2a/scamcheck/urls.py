"""Link analysis: display-text mismatches, shorteners, IP-literal links,
suspicious TLDs, and credential-harvesting patterns in the URL path.
"""

import ipaddress
import re
from urllib.parse import urlparse

from .models import Finding, Severity

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
}

# TLDs disproportionately used in phishing/scam campaigns per multiple
# public abuse reports. Not proof of malice by itself -- scored low.
_SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "ga", "cam", "icu", "rest"}

_BRAND_WORDS = [
    "paypal", "amazon", "apple", "microsoft", "netflix", "bank", "chase",
    "irs", "usps", "fedex", "ups", "docusign", "venmo", "zelle", "linkedin",
    "google", "facebook", "instagram", "wellsfargo", "citibank",
]

_DOMAIN_IN_TEXT_RE = re.compile(
    r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,})\b", re.IGNORECASE
)


def analyze_urls(links: list) -> list:
    findings = []
    seen_ids = set()

    for link in links:
        href = link.get("href", "")
        display = link.get("display", "")
        try:
            parsed = urlparse(href if "://" in href else f"http://{href}")
            host = (parsed.hostname or "").lower()
        except ValueError:
            # Malformed URL (e.g. a stray bracket that urlparse mistakes for
            # IPv6 literal syntax). Skip this one link rather than aborting
            # the whole report -- it's not analyzable, not a crash.
            continue
        if not host:
            continue

        findings.extend(_check_display_mismatch(host, display, seen_ids))
        findings.extend(_check_ip_literal(host, seen_ids))
        findings.extend(_check_shortener(host, seen_ids))
        findings.extend(_check_suspicious_tld(host, seen_ids))
        findings.extend(_check_credential_path(href, seen_ids))

    return findings


def _add_once(findings, seen_ids, finding):
    if finding.id in seen_ids:
        return
    seen_ids.add(finding.id)
    findings.append(finding)


def _check_display_mismatch(host, display, seen_ids) -> list:
    findings = []
    match = _DOMAIN_IN_TEXT_RE.search(display or "")
    if not match:
        return findings
    displayed_domain = match.group(1).lower()
    if displayed_domain != host and not host.endswith("." + displayed_domain) and not displayed_domain.endswith("." + host):
        _add_once(
            findings,
            seen_ids,
            Finding(
                id="link_text_mismatch",
                category="urls",
                severity=Severity.HIGH,
                weight=20,
                summary="A link's visible text does not match where it actually goes",
                evidence=f'The email shows a link that reads "{displayed_domain}" but it actually points to "{host}".',
                advice="Do not click this link. Hover over links (or long-press on mobile) to see the real destination before clicking.",
            ),
        )
    return findings


def _check_ip_literal(host, seen_ids) -> list:
    findings = []
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return findings
    _add_once(
        findings,
        seen_ids,
        Finding(
            id="ip_literal_link",
            category="urls",
            severity=Severity.HIGH,
            weight=20,
            summary="Email contains a link to a raw IP address instead of a domain name",
            evidence=f'One link points directly to "{host}" rather than a named website. Legitimate businesses do not link to raw IP addresses.',
            advice="Do not click this link.",
        ),
    )
    return findings


def _check_shortener(host, seen_ids) -> list:
    findings = []
    if host not in _SHORTENERS:
        return findings
    _add_once(
        findings,
        seen_ids,
        Finding(
            id="url_shortener",
            category="urls",
            severity=Severity.MEDIUM,
            weight=10,
            summary="Email uses a link-shortening service to hide the real destination",
            evidence=f'A link uses "{host}", which hides the real destination address until you click it.',
            advice="Don't click shortened links from unsolicited email. If you must check one, use a link-expander website first.",
        ),
    )
    return findings


def _check_suspicious_tld(host, seen_ids) -> list:
    findings = []
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld not in _SUSPICIOUS_TLDS:
        return findings
    _add_once(
        findings,
        seen_ids,
        Finding(
            id="suspicious_tld",
            category="urls",
            severity=Severity.LOW,
            weight=5,
            summary=f'Link uses the ".{tld}" domain ending, which is disproportionately used for scams',
            evidence=f'One link\'s domain, "{host}", ends in ".{tld}", a TLD commonly abused in phishing campaigns. This alone is not proof of a scam.',
        ),
    )
    return findings


def _check_credential_path(href, seen_ids) -> list:
    findings = []
    lower = href.lower()
    for brand in _BRAND_WORDS:
        if brand in lower and any(
            kw in lower for kw in ("login", "signin", "verify", "update", "secure", "account", "confirm")
        ):
            try:
                parsed = urlparse(href if "://" in href else f"http://{href}")
                host = (parsed.hostname or "").lower()
            except ValueError:
                continue  # malformed URL -- not analyzable, skip rather than crash
            if brand in host:
                continue  # the brand name legitimately appears in its own domain
            _add_once(
                findings,
                seen_ids,
                Finding(
                    id="credential_harvest_pattern",
                    category="urls",
                    severity=Severity.MEDIUM,
                    weight=15,
                    summary=f'Link path references "{brand}" and account/login terms, but is hosted elsewhere',
                    evidence=f'A link mentions "{brand}" and words like "login" or "verify" in its address, but is hosted on "{host}", not an official {brand} domain.',
                    advice=f"Don't enter any credentials here. Go to {brand}'s site directly by typing the address yourself.",
                ),
            )
            break
    return findings
