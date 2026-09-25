"""Domain reputation checks: brand lookalikes and WHOIS registration age.

Both checks are free, public-data lookups (no LLM, no per-call API cost).
"""

import re
import unicodedata
from datetime import datetime, timezone

from .models import Finding, Severity

try:
    import whois as _whois

    _WHOIS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _WHOIS_AVAILABLE = False

try:
    import dns.resolver

    _DNS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _DNS_AVAILABLE = False

# Popular brands frequently impersonated in scam email, with their real
# registrable domain. Used for lookalike-domain detection.
_KNOWN_BRANDS = {
    "paypal.com", "amazon.com", "apple.com", "microsoft.com", "netflix.com",
    "bankofamerica.com", "wellsfargo.com", "chase.com", "irs.gov", "ssa.gov",
    "usps.com", "fedex.com", "ups.com", "docusign.com", "venmo.com",
    "zellepay.com", "linkedin.com", "google.com", "facebook.com", "instagram.com",
    "citibank.com", "capitalone.com", "americanexpress.com", "coinbase.com",
    "walmart.com", "target.com", "bestbuy.com", "geico.com", "progressive.com",
}

# Visually similar character substitutions used to normalize a domain before
# comparing it to known brands (catches 0/o, 1/l, rn/m style tricks).
_HOMOGLYPH_MAP = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e", "@": "a"})

_NEW_DOMAIN_THRESHOLD_DAYS = 30


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def _normalize(domain: str) -> str:
    d = domain.lower().translate(_HOMOGLYPH_MAP)
    d = d.replace("rn", "m")  # common two-character lookalike for "m"
    return d


def analyze_domain(from_domain: str, skip_whois: bool = False) -> list:
    findings = []
    if not from_domain:
        return findings

    findings.extend(_check_lookalike(from_domain))
    findings.extend(_check_idn_homograph(from_domain))
    findings.extend(_check_domain_resolves(from_domain))
    if not skip_whois:
        findings.extend(_check_registration_age(from_domain))
    return findings


def _check_idn_homograph(domain: str) -> list:
    """Flags internationalized domains: raw punycode labels (xn--...) and
    domains that mix Latin letters with another alphabet -- the classic IDN
    homograph attack (e.g. a Cyrillic "a" that renders identically to the
    Latin "a" but is a completely different domain to a browser/mail server).
    """
    labels = domain.split(".")

    if any(label.startswith("xn--") for label in labels):
        return [
            Finding(
                id="punycode_domain",
                category="domain",
                severity=Severity.MEDIUM,
                weight=12,
                summary="Sending domain uses internationalized (punycode) encoding",
                evidence=(
                    f'"{domain}" contains a punycode-encoded label (xn--...), used to represent '
                    "non-English characters. This is sometimes legitimate, but is also a known "
                    "technique for building domains that visually mimic a trusted brand."
                ),
                advice="Inspect this domain carefully before trusting it, ideally by typing the real site's address yourself instead of clicking through.",
            )
        ]

    if not domain.isascii():
        has_latin = any(_char_script(c) == "LATIN" for c in domain if c.isalpha())
        has_other_script = any(
            _char_script(c) not in ("LATIN", None) for c in domain if c.isalpha()
        )
        if has_latin and has_other_script:
            return [
                Finding(
                    id="mixed_script_domain",
                    category="domain",
                    severity=Severity.HIGH,
                    weight=25,
                    summary="Sending domain mixes letters from different alphabets",
                    evidence=(
                        f'"{domain}" combines standard Latin letters with characters from another '
                        "alphabet that can look nearly identical. This is a known technique (an IDN "
                        "homograph attack) for creating a fake domain that appears identical to a "
                        "trusted one."
                    ),
                    advice="Treat this domain as untrustworthy. Do not click any links or reply.",
                )
            ]
    return []


def _char_script(c: str):
    try:
        name = unicodedata.name(c)
    except ValueError:
        return None
    return name.split(" ")[0] if name else None


def _check_domain_resolves(domain: str) -> list:
    """Confirms the sending domain has any DNS presence at all. A domain
    with zero A/AAAA/MX records cannot legitimately run a mail system and is
    a strong sign of a throwaway or spoofed domain. Only flags when every
    record type comes back as a definite NXDOMAIN, to avoid false positives
    from transient lookup failures.
    """
    if not _DNS_AVAILABLE:
        return []

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0

    nxdomain_count = 0
    checked = 0
    for record_type in ("A", "AAAA", "MX"):
        try:
            resolver.resolve(domain, record_type)
            return []  # resolves via at least one record type -- domain is real
        except dns.resolver.NXDOMAIN:
            nxdomain_count += 1
            checked += 1
        except Exception:
            checked += 1
            continue

    if checked > 0 and nxdomain_count == checked:
        return [
            Finding(
                id="domain_does_not_exist",
                category="domain",
                severity=Severity.HIGH,
                weight=30,
                summary="Sending domain does not exist",
                evidence=(
                    f'"{domain}" has no DNS records at all (A, AAAA, or MX) -- this domain cannot '
                    "even receive a reply. Real organizations do not send mail from domains that "
                    "don't exist; this strongly suggests a spoofed or fabricated sender address."
                ),
                advice="Do not trust anything about this message's claimed sender.",
            )
        ]
    return []


def _check_lookalike(domain: str) -> list:
    if domain in _KNOWN_BRANDS:
        return []  # exact match to a known-good domain, nothing to flag

    normalized = _normalize(domain)
    root = _registrable_root(domain)

    for brand in _KNOWN_BRANDS:
        brand_normalized = _normalize(brand)
        brand_root = _registrable_root(brand)

        # Skip if it's a legitimate subdomain of the real brand
        if domain.endswith("." + brand) or domain == brand:
            return []

        # Compare both the raw domains and their homoglyph-normalized forms.
        # A normalized distance of 0 (e.g. "paypa1.com" -> "paypal.com") is
        # itself the strongest possible signal, since the domain is *not*
        # actually equal to the brand (checked above) but reads as identical.
        raw_distance = _levenshtein(domain, brand)
        normalized_distance = _levenshtein(normalized, brand_normalized)
        # Also compare bare registrable roots (without TLD) to catch
        # different-TLD lookalikes, e.g. "paypal-secure.com" vs "paypal.com"
        root_distance = _levenshtein(root, brand_root)

        # Token-based check: does the brand name appear as its own
        # hyphen/dot/digit-separated token inside a longer domain, e.g.
        # "paypal-secure-alerts.com" or "arnazon-support.com" (after
        # homoglyph normalization turns "arnazon" into "amazon")?
        normalized_root = _normalize(root)
        tokens = [t for t in re.split(r"[^a-z]+", normalized_root) if t]
        is_root_substring = root != brand_root and brand_root in tokens

        is_close_edit = 0 < raw_distance <= 2
        is_homoglyph_match = normalized_distance == 0 and raw_distance > 0

        if is_close_edit or is_homoglyph_match or is_root_substring:
            display_distance = raw_distance if (is_close_edit or is_homoglyph_match) else root_distance
            reason = (
                "uses look-alike characters for" if is_homoglyph_match
                else "is a near-exact spelling of" if is_close_edit
                else "embeds the brand name inside a longer domain that impersonates"
            )
            return [
                Finding(
                    id="lookalike_domain",
                    category="domain",
                    severity=Severity.HIGH,
                    weight=25,
                    summary=f'Sending domain closely resembles "{brand}"',
                    evidence=(
                        f'The sending domain "{domain}" {reason} the real domain '
                        f'"{brand}" (character difference: {display_distance}). This is a common '
                        "tactic to make a fake address look legitimate at a glance."
                    ),
                    advice=f"This is very likely not really from {brand}. Do not click links or reply; go to {brand} directly in your browser instead.",
                )
            ]
    return []


def _registrable_root(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) <= 2:
        return parts[0] if parts else domain
    return parts[-2]


def _check_registration_age(domain: str) -> list:
    if not _WHOIS_AVAILABLE:
        return [
            Finding(
                id="whois_unavailable",
                category="domain",
                severity=Severity.INFO,
                weight=0,
                summary="Could not check domain registration age",
                evidence="The WHOIS lookup library was not available in this environment.",
            )
        ]

    try:
        w = _whois.whois(domain)
    except Exception:
        return [
            Finding(
                id="whois_lookup_failed",
                category="domain",
                severity=Severity.INFO,
                weight=2,
                summary="Domain registration lookup failed",
                evidence=f"A WHOIS lookup for {domain} did not return usable data, which can itself indicate a very new or privacy-shielded registration.",
            )
        ]

    creation_date = w.creation_date if hasattr(w, "creation_date") else None
    if isinstance(creation_date, list):
        creation_date = creation_date[0] if creation_date else None

    if not creation_date:
        return []

    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)

    age_days = (datetime.now(timezone.utc) - creation_date).days

    if age_days < _NEW_DOMAIN_THRESHOLD_DAYS:
        return [
            Finding(
                id="newly_registered_domain",
                category="domain",
                severity=Severity.HIGH,
                weight=20,
                summary="Sending domain was registered very recently",
                evidence=(
                    f"{domain} was registered {age_days} day(s) ago "
                    f"({creation_date.date().isoformat()}). Legitimate businesses "
                    "almost never send from a domain that new."
                ),
                advice="Treat this domain as unverified. Newly registered domains are heavily used in scam campaigns.",
            )
        ]
    elif age_days < 365:
        return [
            Finding(
                id="young_domain",
                category="domain",
                severity=Severity.LOW,
                weight=5,
                summary="Sending domain is less than a year old",
                evidence=f"{domain} was registered on {creation_date.date().isoformat()} ({age_days} days ago).",
            )
        ]
    return []
