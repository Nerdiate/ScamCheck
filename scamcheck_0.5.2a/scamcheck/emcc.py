"""EMCC: Email Misconfiguration & Config Checker.

Checks whether a DOMAIN's own published email authentication records are
sound -- the flip side of ScamCheck, which checks a specific MESSAGE.
A small business or nonprofit can run this on their own domain to find out
whether someone else could successfully spoof "you@yourcompany.com" to
their customers.

Everything here is a public DNS TXT-record lookup. No mail server access,
no credentials, no cost per check -- a domain owner (or anyone) can run
this against any domain's already-public records.
"""

import re
from dataclasses import dataclass, field

from .models import Finding, Severity

try:
    import dns.resolver

    _DNS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _DNS_AVAILABLE = False

# Common DKIM selectors used by major email platforms. DKIM selectors are
# not discoverable from public DNS in general -- the sending platform
# defines them -- so this is a best-effort probe, not exhaustive.
_COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2",  # Google Workspace, Microsoft 365
    "k1", "k2", "k3",                    # Mailchimp/Mandrill, SendGrid-style
    "default", "dkim", "mail", "smtp", "s1", "s2",
    "mandrill", "sendgrid", "mailgun", "amazonses",
]

_DEFAULT_TIMEOUT = 4.0


def _resolver():
    r = dns.resolver.Resolver()
    r.lifetime = _DEFAULT_TIMEOUT
    return r


def _txt_strings(rdata) -> str:
    if hasattr(rdata, "strings"):
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    return str(rdata).strip('"')


@dataclass
class DomainConfigReport:
    domain: str
    score: int              # 0-100: how exposed this domain is to spoofing (higher = worse)
    risk_level: str
    findings: list = field(default_factory=list)
    summary_line: str = ""

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "score": self.score,
            "risk_level": self.risk_level,
            "summary_line": self.summary_line,
            "findings": [f.to_dict() for f in self.findings],
        }


_EXPOSURE_THRESHOLDS = (
    (60, "High exposure — this domain can likely be spoofed convincingly"),
    (30, "Medium exposure — some protections in place, but gaps remain"),
    (10, "Low exposure — mostly well configured, minor improvements available"),
    (0, "Well configured — strong anti-spoofing protections in place"),
)


def _exposure_label(score: int) -> str:
    for threshold, label in _EXPOSURE_THRESHOLDS:
        if score >= threshold:
            return label
    return _EXPOSURE_THRESHOLDS[-1][1]


def analyze_domain_config(domain: str, resolver=None) -> DomainConfigReport:
    """Runs all EMCC checks for `domain`. `resolver` is injectable for
    testing; production callers should leave it as None.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    findings = []

    if not domain:
        return DomainConfigReport(domain=domain, score=0, risk_level="No domain provided", findings=[])

    if not _DNS_AVAILABLE:
        findings.append(
            Finding(
                id="dns_unavailable",
                category="email_config",
                severity=Severity.INFO,
                weight=0,
                summary="Could not check DNS records",
                evidence="The DNS lookup library was not available in this environment.",
            )
        )
        return DomainConfigReport(domain=domain, score=0, risk_level="Could not check", findings=findings)

    resolver = resolver or _resolver()

    if not _domain_exists(domain, resolver):
        findings.append(
            Finding(
                id="domain_not_found",
                category="email_config",
                severity=Severity.HIGH,
                weight=60,
                summary="Domain has no DNS presence at all",
                evidence=f'"{domain}" does not resolve (NXDOMAIN) for A, AAAA, or MX records. No email configuration can exist for a domain that does not exist.',
            )
        )
        score = max(0, min(100, round(sum(f.weight for f in findings))))
        risk_level = _exposure_label(score)
        return DomainConfigReport(
            domain=domain, score=score, risk_level=risk_level, findings=findings,
            summary_line=f"{risk_level}. This domain could not be found in DNS at all.",
        )

    findings.extend(_check_spf(domain, resolver))
    findings.extend(_check_dmarc(domain, resolver))
    findings.extend(_check_dkim(domain, resolver))
    findings.extend(_check_mx(domain, resolver))

    score = max(0, min(100, round(sum(f.weight for f in findings))))
    risk_level = _exposure_label(score)

    concerning = [f for f in findings if f.weight > 0 and f.severity != Severity.INFO]
    if concerning and score > 0:
        top = sorted(concerning, key=lambda f: f.weight, reverse=True)[:3]
        summary_line = f"{risk_level}. Top issues: " + "; ".join(f.summary for f in top) + "."
    else:
        summary_line = f"{risk_level}. No significant email-configuration gaps found."

    findings.sort(key=lambda f: f.weight, reverse=True)

    return DomainConfigReport(domain=domain, score=score, risk_level=risk_level, findings=findings, summary_line=summary_line)


# --------------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------------

def _domain_exists(domain, resolver) -> bool:
    """Cheap existence check so a nonexistent domain produces one clear
    finding instead of every individual check independently reporting
    "missing"."""
    for record_type in ("A", "AAAA", "MX", "TXT"):
        try:
            resolver.resolve(domain, record_type)
            return True
        except dns.resolver.NXDOMAIN:
            continue
        except Exception:
            return True  # inconclusive (timeout etc.) -- assume it exists rather than false-flag
    return False


def _check_spf(domain, resolver) -> list:
    findings = []
    try:
        answers = resolver.resolve(domain, "TXT")
        spf_records = [_txt_strings(r) for r in answers if _txt_strings(r).startswith("v=spf1")]
    except Exception:
        spf_records = None  # lookup failed/timed out -- inconclusive, don't guess

    if spf_records is None:
        findings.append(
            Finding(
                id="spf_lookup_failed",
                category="email_config",
                severity=Severity.INFO,
                weight=0,
                summary="Could not check SPF (DNS lookup failed or timed out)",
                evidence=f"A TXT lookup for {domain} did not complete. Try again, or check manually.",
            )
        )
        return findings

    if not spf_records:
        findings.append(
            Finding(
                id="spf_missing",
                category="email_config",
                severity=Severity.HIGH,
                weight=30,
                summary="No SPF record published",
                evidence=(
                    f"{domain} has no v=spf1 TXT record. Without SPF, mail servers have no list of "
                    f"which servers are allowed to send mail as @{domain}, making it easy for anyone "
                    "to forge mail that appears to come from this domain."
                ),
                advice=f'Publish a TXT record on {domain} listing your real mail servers, e.g. "v=spf1 include:_spf.google.com -all" (adjust for your actual provider).',
            )
        )
        return findings

    if len(spf_records) > 1:
        findings.append(
            Finding(
                id="spf_multiple_records",
                category="email_config",
                severity=Severity.HIGH,
                weight=20,
                summary="Multiple SPF records found (only one is allowed)",
                evidence=(
                    f"{domain} publishes {len(spf_records)} separate v=spf1 TXT records. "
                    "The SPF standard requires exactly one; having more than one causes mail "
                    "servers to treat SPF as a hard failure for legitimate mail."
                ),
                advice="Merge all SPF includes into a single v=spf1 TXT record.",
            )
        )

    spf = spf_records[0]

    if re.search(r"[+]?all\b", spf) and "+all" in spf.replace(" ", ""):
        findings.append(
            Finding(
                id="spf_plus_all",
                category="email_config",
                severity=Severity.HIGH,
                weight=30,
                summary='SPF record ends in "+all" (allows literally any server)',
                evidence=f'"{spf}" explicitly allows any server on the internet to send mail as @{domain}. This makes SPF provide no protection at all.',
                advice='Change the final mechanism to "-all" (hard fail) once you have confirmed all your real sending servers are listed.',
            )
        )
    elif spf.rstrip().endswith("?all"):
        findings.append(
            Finding(
                id="spf_neutral_all",
                category="email_config",
                severity=Severity.MEDIUM,
                weight=15,
                summary='SPF record ends in "?all" (neutral -- provides little protection)',
                evidence=f'"{spf}" tells receiving mail servers to treat unlisted senders as neutral rather than suspicious, which undermines SPF\'s purpose.',
                advice='Change the final mechanism to "-all" (hard fail) once you have confirmed all your real sending servers are listed.',
            )
        )
    elif spf.rstrip().endswith("~all"):
        findings.append(
            Finding(
                id="spf_softfail",
                category="email_config",
                severity=Severity.LOW,
                weight=8,
                summary='SPF record uses "~all" (softfail) rather than a hard fail',
                evidence=f'"{spf}" asks receiving servers to mark unlisted senders as suspicious but still deliver them, rather than rejecting them outright.',
                advice='Consider moving to "-all" (hard fail) once you\'re confident all legitimate senders are listed in the record.',
            )
        )
    elif not spf.rstrip().endswith("-all"):
        findings.append(
            Finding(
                id="spf_no_all_mechanism",
                category="email_config",
                severity=Severity.MEDIUM,
                weight=15,
                summary="SPF record has no catch-all (\"all\") mechanism",
                evidence=f'"{spf}" does not end with an all mechanism, so its behavior for unlisted senders is undefined/implementation-dependent.',
                advice='Add "-all" at the end of the record once all legitimate senders are listed.',
            )
        )

    lookup_count = len(re.findall(r"\b(include|a|mx|ptr|exists|redirect)\b[:=]?", spf))
    if lookup_count > 10:
        findings.append(
            Finding(
                id="spf_too_many_lookups",
                category="email_config",
                severity=Severity.MEDIUM,
                weight=15,
                summary="SPF record likely exceeds the 10 DNS-lookup limit",
                evidence=(
                    f"The SPF record for {domain} appears to use roughly {lookup_count} lookup-triggering "
                    'mechanisms (include/a/mx/ptr/exists/redirect). SPF has a hard limit of 10; going over '
                    'causes receiving servers to treat the record as a permanent error ("permerror"), which '
                    "can cause legitimate mail to fail SPF entirely."
                ),
                advice="Flatten or reduce the number of includes in your SPF record.",
            )
        )

    return findings


# --------------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------------

def _check_dmarc(domain, resolver) -> list:
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [_txt_strings(r) for r in answers if _txt_strings(r).startswith("v=DMARC1")]
    except Exception:
        dmarc_records = []

    if not dmarc_records:
        return [
            Finding(
                id="dmarc_missing",
                category="email_config",
                severity=Severity.HIGH,
                weight=30,
                summary="No DMARC record published",
                evidence=(
                    f"{domain} has no _dmarc TXT record. Without DMARC, there is no domain-level policy "
                    "telling receiving mail servers what to do with mail that fails SPF/DKIM -- and no "
                    "reporting to alert you when someone is spoofing your domain."
                ),
                advice=f'Publish a DMARC record, e.g. "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}" as a starting point, moving to p=reject once you\'ve reviewed reports.',
            )
        ]

    dmarc = dmarc_records[0]
    findings = []

    policy_match = re.search(r"p=(\w+)", dmarc)
    policy = policy_match.group(1).lower() if policy_match else None

    if policy == "none":
        findings.append(
            Finding(
                id="dmarc_policy_none",
                category="email_config",
                severity=Severity.MEDIUM,
                weight=20,
                summary='DMARC policy is "none" (monitor only, takes no action)',
                evidence=f'"{dmarc}" tells receiving servers to take no action on mail that fails authentication -- spoofed mail using this domain is not blocked or quarantined.',
                advice='Once you\'ve reviewed DMARC reports and confirmed legitimate senders pass, move to "p=quarantine" and eventually "p=reject".',
            )
        )
    elif policy == "quarantine":
        findings.append(
            Finding(
                id="dmarc_policy_quarantine",
                category="email_config",
                severity=Severity.LOW,
                weight=5,
                summary='DMARC policy is "quarantine" (partial protection)',
                evidence=f'"{dmarc}" sends failing mail to spam rather than blocking it outright. This is a reasonable middle step, but "p=reject" offers stronger protection once you\'re confident in your setup.',
            )
        )
    elif policy is None:
        findings.append(
            Finding(
                id="dmarc_no_policy",
                category="email_config",
                severity=Severity.MEDIUM,
                weight=15,
                summary="DMARC record has no policy (p=) tag",
                evidence=f'"{dmarc}" is missing the required p= policy tag, which may cause receiving servers to ignore it entirely.',
            )
        )

    if "rua=" not in dmarc:
        findings.append(
            Finding(
                id="dmarc_no_reporting",
                category="email_config",
                severity=Severity.LOW,
                weight=8,
                summary="DMARC record has no aggregate reporting address (rua)",
                evidence=f'"{dmarc}" does not include an rua= address, so you will not receive reports showing who is sending mail (legitimately or fraudulently) as your domain.',
                advice=f"Add an rua= address, e.g. rua=mailto:dmarc-reports@{domain}, to start receiving visibility into your domain's mail traffic.",
            )
        )

    pct_match = re.search(r"pct=(\d+)", dmarc)
    if pct_match and int(pct_match.group(1)) < 100 and policy in ("quarantine", "reject"):
        pct = int(pct_match.group(1))
        findings.append(
            Finding(
                id="dmarc_partial_pct",
                category="email_config",
                severity=Severity.LOW,
                weight=5,
                summary=f"DMARC policy only applies to {pct}% of mail",
                evidence=f'"{dmarc}" includes pct={pct}, meaning the enforcement policy only applies to a fraction of failing mail.',
            )
        )

    return findings


# --------------------------------------------------------------------------
# DKIM (best-effort -- selectors are not publicly discoverable in general)
# --------------------------------------------------------------------------

def _check_dkim(domain, resolver) -> list:
    found_selectors = []
    for selector in _COMMON_DKIM_SELECTORS:
        try:
            resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            found_selectors.append(selector)
        except Exception:
            continue

    if found_selectors:
        return [
            Finding(
                id="dkim_selector_found",
                category="email_config",
                severity=Severity.INFO,
                weight=-5,
                summary=f"Found a DKIM record (selector: {found_selectors[0]})",
                evidence=f"A DKIM public key was found at {found_selectors[0]}._domainkey.{domain}, indicating at least one mail platform is set up to sign mail for this domain.",
            )
        ]

    return [
        Finding(
            id="dkim_not_found",
            category="email_config",
            severity=Severity.INFO,
            weight=5,
            summary="No DKIM record found among common selectors (inconclusive)",
            evidence=(
                f"None of {len(_COMMON_DKIM_SELECTORS)} commonly used DKIM selector names had a record "
                f"under _domainkey.{domain}. DKIM selectors are chosen by your email provider and are not "
                "fully discoverable from outside, so this is a hint, not proof DKIM is absent -- check your "
                "email provider's admin panel to confirm DKIM is enabled."
            ),
        )
    ]


# --------------------------------------------------------------------------
# MX
# --------------------------------------------------------------------------

def _check_mx(domain, resolver) -> list:
    try:
        answers = resolver.resolve(domain, "MX")
        mx_hosts = [str(r.exchange).rstrip(".") for r in answers]
    except dns.resolver.NoAnswer:
        mx_hosts = []
    except Exception:
        return []  # inconclusive, stay silent rather than guess

    if not mx_hosts:
        return [
            Finding(
                id="mx_missing",
                category="email_config",
                severity=Severity.LOW,
                weight=5,
                summary="No MX record found",
                evidence=(
                    f"{domain} has no MX record, meaning it cannot receive email at all. If this domain "
                    "is not meant to send or receive mail, consider publishing a null MX (RFC 7505) "
                    'record ("0 .") to explicitly declare that and strengthen anti-spoofing posture.'
                ),
            )
        ]

    if mx_hosts == ["."] or (len(mx_hosts) == 1 and mx_hosts[0] == ""):
        return [
            Finding(
                id="mx_null",
                category="email_config",
                severity=Severity.INFO,
                weight=-5,
                summary="Domain explicitly declares it does not accept mail (null MX)",
                evidence=f"{domain} publishes a null MX record, an explicit, well-supported way to declare a domain sends/receives no mail -- good practice for parked or non-email domains.",
            )
        ]

    return []
