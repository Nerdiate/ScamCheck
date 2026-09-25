"""Header and authentication analysis.

Primary source of truth is the Authentication-Results header added by the
receiving mail server (this is what real mailboxes already computed and is
free to read). When that header is missing -- e.g. the user pasted a raw
.eml exported without it -- we fall back to a live SPF/DMARC DNS lookup for
the claimed sending domain. DKIM cannot be verified after the fact without
the original signing key, so a missing Authentication-Results header means
DKIM is reported as "unknown", not "fail".
"""

import re
from email.utils import parseaddr

from .models import Finding, Severity

try:
    import dns.resolver

    _DNS_AVAILABLE = True
except ImportError:  # pragma: no cover - degrade gracefully without dnspython
    _DNS_AVAILABLE = False

_AUTH_RESULT_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)

# Common display-name brand strings paired with the domain(s) they actually
# belong to. If the display name claims one of these brands but the sending
# address domain doesn't match, that's a strong spoofing signal.
_BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "netflix": ["netflix.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "chase": ["chase.com"],
    "irs": ["irs.gov"],
    "social security administration": ["ssa.gov"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "venmo": ["venmo.com"],
    "zelle": ["zellepay.com"],
    "linkedin": ["linkedin.com"],
    "google": ["google.com", "gmail.com"],
}

# Free consumer webmail providers. A message claiming to be an official
# notice from a bank, government agency, or major company but sent from one
# of these is a very strong spoofing signal on its own -- real organizations
# essentially never send official account/security notices from a personal
# free-mail address.
_FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "icloud.com", "mail.com", "protonmail.com", "gmx.com",
    "yandex.com", "zoho.com",
}


def _domain_of(addr: str) -> str:
    return addr.split("@")[-1].lower() if "@" in addr else ""


def _domains_related(a: str, b: str) -> bool:
    """True if domain `a` and `b` are the same or one is a subdomain of the other."""
    if not a or not b:
        return False
    a, b = a.lower(), b.lower()
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def analyze_headers(parsed) -> list:
    from_domain = _domain_of(parsed.from_addr)
    reply_domain = _domain_of(parsed.reply_to_addr)
    return_path_domain = _domain_of(parsed.return_path_addr)

    # Identity findings first: these say whether the claimed sender identity
    # (display name, reply address, bounce address) is trustworthy.
    identity_findings = []
    identity_findings.extend(_check_from_reply_to_mismatch(from_domain, reply_domain, parsed))
    identity_findings.extend(_check_return_path_mismatch(from_domain, return_path_domain, parsed))
    identity_findings.extend(_check_display_name_spoofing(parsed, from_domain))

    # SPF/DKIM/DMARC only prove that the *technical sending domain*
    # (from_domain here) was authorized to send -- e.g. a scammer using a
    # real Gmail account will pass all three, because Gmail really did send
    # it. That's not evidence the claimed identity (a bank, a brand) is
    # truthful, so once a spoofed-identity signal already fired, an
    # authentication "pass" is not treated as a reassuring/offsetting signal.
    identity_already_suspicious = bool(identity_findings)
    auth_findings = _check_authentication_results(
        parsed, from_domain, suppress_pass_reward=identity_already_suspicious
    )

    findings = auth_findings + identity_findings
    findings.extend(_check_received_chain(parsed))

    return findings


def _check_authentication_results(parsed, from_domain, suppress_pass_reward: bool = False) -> list:
    findings = []
    auth_header = parsed.authentication_results

    results = {}
    if auth_header:
        for mechanism, result in _AUTH_RESULT_RE.findall(auth_header):
            results[mechanism.lower()] = result.lower()

    if results:
        for mechanism in ("spf", "dkim", "dmarc"):
            result = results.get(mechanism, "none")
            if result in ("pass",):
                if suppress_pass_reward:
                    findings.append(
                        Finding(
                            id=f"auth_{mechanism}_pass_but_identity_suspicious",
                            category="headers",
                            severity=Severity.INFO,
                            weight=0,
                            summary=f"{mechanism.upper()} passed, but that doesn't vouch for the claimed identity",
                            evidence=(
                                f"Receiving mail server reported {mechanism.upper()}=pass for "
                                f'"{from_domain}" -- meaning that domain was really authorized to send this. '
                                "It does NOT mean the sender is who they claim to be in the display name, "
                                "since anyone can send authenticated mail from their own real account."
                            ),
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            id=f"auth_{mechanism}_pass",
                            category="headers",
                            severity=Severity.INFO,
                            weight=-4,
                            summary=f"{mechanism.upper()} passed",
                            evidence=f"Receiving mail server reported {mechanism.upper()}=pass in Authentication-Results.",
                        )
                    )
            elif result in ("fail", "softfail", "permerror", "temperror"):
                findings.append(
                    Finding(
                        id=f"auth_{mechanism}_fail",
                        category="headers",
                        severity=Severity.HIGH,
                        weight=25,
                        summary=f"{mechanism.upper()} failed",
                        evidence=(
                            f"Receiving mail server reported {mechanism.upper()}={result}. "
                            "This means the sending server was not authorized to send "
                            f"mail for this domain, or the message was altered in transit."
                        ),
                        advice="Do not trust this message's claimed sender. Verify through a separate, known channel.",
                    )
                )
            # "none" / not present: no finding, treated as unknown rather than penalized
        return findings

    # No Authentication-Results header at all -- fall back to a live DNS check
    findings.extend(_dns_fallback_check(from_domain))
    return findings


def _dns_fallback_check(domain: str) -> list:
    findings = []
    if not domain:
        return findings
    if not _DNS_AVAILABLE:
        findings.append(
            Finding(
                id="auth_unavailable",
                category="headers",
                severity=Severity.INFO,
                weight=0,
                summary="Could not verify sender authentication",
                evidence=(
                    "This email had no Authentication-Results header and the DNS "
                    "checking library was not available, so SPF/DMARC could not be verified."
                ),
            )
        )
        return findings

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0

    spf_found = False
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace") if hasattr(rdata, "strings") else str(rdata)
            if txt.startswith("v=spf1"):
                spf_found = True
                if "+all" in txt:
                    findings.append(
                        Finding(
                            id="spf_permissive",
                            category="headers",
                            severity=Severity.HIGH,
                            weight=15,
                            summary="Sending domain's SPF record allows any server to send mail",
                            evidence=f'{domain} publishes "{txt.strip()}", which ends in +all (allow all).',
                            advice="Treat sender identity on this domain as unverifiable.",
                        )
                    )
    except Exception:
        pass

    if not spf_found:
        findings.append(
            Finding(
                id="spf_missing",
                category="headers",
                severity=Severity.MEDIUM,
                weight=10,
                summary="Sending domain has no SPF record",
                evidence=f"No v=spf1 TXT record was found for {domain}, so anyone can forge mail claiming to be from it.",
            )
        )

    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_txt = ""
        for rdata in dmarc_answers:
            dmarc_txt = b"".join(rdata.strings).decode("utf-8", errors="replace") if hasattr(rdata, "strings") else str(rdata)
            if dmarc_txt.startswith("v=DMARC1"):
                break
        if dmarc_txt and "p=none" in dmarc_txt:
            findings.append(
                Finding(
                    id="dmarc_policy_none",
                    category="headers",
                    severity=Severity.LOW,
                    weight=5,
                    summary="Sending domain's DMARC policy takes no action on failures",
                    evidence=f'{domain} publishes a DMARC policy of p=none, so spoofed mail is not blocked or quarantined.',
                )
            )
    except Exception:
        findings.append(
            Finding(
                id="dmarc_missing",
                category="headers",
                severity=Severity.MEDIUM,
                weight=10,
                summary="Sending domain has no DMARC record",
                evidence=f"No _dmarc.{domain} TXT record was found, so there is no policy telling mail servers what to do with spoofed mail from this domain.",
            )
        )

    return findings


def _check_from_reply_to_mismatch(from_domain, reply_domain, parsed) -> list:
    if not reply_domain or _domains_related(from_domain, reply_domain):
        return []
    return [
        Finding(
            id="reply_to_mismatch",
            category="headers",
            severity=Severity.HIGH,
            weight=20,
            summary="Reply-To address does not match the From address",
            evidence=(
                f'This message claims to be from "{parsed.from_addr}" but any reply '
                f'would actually go to "{parsed.reply_to_addr}", a different domain.'
            ),
            advice="Do not reply to this email. If you need to contact the sender, look up their contact info independently.",
        )
    ]


def _check_return_path_mismatch(from_domain, return_path_domain, parsed) -> list:
    if not return_path_domain or _domains_related(from_domain, return_path_domain):
        return []
    return [
        Finding(
            id="return_path_mismatch",
            category="headers",
            severity=Severity.MEDIUM,
            weight=10,
            summary="Return-Path domain differs from the From address domain",
            evidence=(
                f'The technical bounce address ("{parsed.return_path_addr}") does not match '
                f'the claimed sender domain ("{from_domain}"). This is common in bulk/spoofed mail '
                "sent through a third-party relay."
            ),
        )
    ]


def _check_display_name_spoofing(parsed, from_domain) -> list:
    if not parsed.from_display_name:
        return []
    name_lower = parsed.from_display_name.lower()
    findings = []
    for brand, domains in _BRAND_DOMAINS.items():
        if brand in name_lower and not any(_domains_related(from_domain, d) for d in domains):
            is_freemail = from_domain in _FREE_WEBMAIL_DOMAINS
            if is_freemail:
                findings.append(
                    Finding(
                        id=f"display_name_spoof_freemail_{brand.replace(' ', '_')}",
                        category="headers",
                        severity=Severity.HIGH,
                        weight=28,
                        summary=f'Claims to be "{brand.title()}" but was sent from a free personal email account',
                        evidence=(
                            f'The sender name shown is "{parsed.from_display_name}", but the message '
                            f'was actually sent from "{parsed.from_addr}", a free consumer email address '
                            f"(not a company-owned domain). Legitimate organizations essentially never "
                            f"send official notices from personal {from_domain} addresses."
                        ),
                        advice=f"This is almost certainly not really from {brand.title()}. Do not reply or click anything; contact {brand.title()} directly using a number or site you already know is real.",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=f"display_name_spoof_{brand.replace(' ', '_')}",
                        category="headers",
                        severity=Severity.HIGH,
                        weight=20,
                        summary=f'Display name claims to be "{brand.title()}" but the address is not',
                        evidence=(
                            f'The sender name shown is "{parsed.from_display_name}", but the actual '
                            f'email address domain is "{from_domain}", not an official {brand.title()} domain.'
                        ),
                        advice=f"Do not trust this as being from {brand.title()}. Contact {brand.title()} directly using a number or site you already know is real.",
                    )
                )
            break  # one match is enough signal
    return findings


def _check_received_chain(parsed) -> list:
    if not parsed.received_chain:
        return [
            Finding(
                id="no_received_headers",
                category="headers",
                severity=Severity.INFO,
                weight=3,
                summary="Message has no Received headers",
                evidence=(
                    "No Received headers were present to trace the delivery path. "
                    "This can happen with exported/forwarded copies, but is also seen "
                    "in hand-crafted or injected messages."
                ),
            )
        ]
    return []
