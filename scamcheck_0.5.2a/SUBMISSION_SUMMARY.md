## ScamCheck — Submission Summary

ScamCheck is two free, rule-based security tools in one lightweight app: an
email scam checker and a domain email-configuration checker (EMCC).

**Functionality.** *Check an Email* analyzes a pasted or uploaded email and
produces a 0–100 suspicion score with plain-language evidence for every
finding: mismatched Reply-To/Return-Path addresses, lookalike or homoglyph
domains, a brand name sent from a free webmail account, spoofed display
names, dangerous or disguised attachments, phishing-style language, and
more. *Check a Domain's Email Setup (EMCC)* takes any domain name and
audits its public SPF, DKIM, DMARC, and MX records, flagging exactly what
would let someone spoof mail as that domain and how to fix it.

**Audience.** Nonprofits, small businesses, schools, and individuals with
no security background who need a fast, trustworthy answer to "is this
email safe?" The same tool doubles as a lightweight audit an IT volunteer
can run on an organization's domain to catch spoofing gaps before an
attacker does.

**Mechanics.** Both tools are entirely rule-based — no AI model, no
per-check cost, and no data sent anywhere except public DNS/WHOIS lookups,
the same kind any "check this domain" website performs. Email analysis
parses the raw message with Python's standard email library and runs five
independent checks: authentication (reads `Authentication-Results`, or
falls back to a live SPF/DMARC DNS lookup), domain reputation
(edit-distance lookalike detection, IDN homograph/punycode detection,
NXDOMAIN checks, WHOIS registration age), link analysis (display-text vs.
destination mismatches, IP-literal links, shorteners, suspicious TLDs),
attachment metadata (dangerous or double file extensions, macro-enabled
Office documents), and weighted language heuristics (urgency phrases,
generic greetings, formatting anomalies). Findings combine into one score,
with a deliberate nuance: a passing SPF/DKIM/DMARC result never offsets an
already-found identity-spoofing signal, since a scammer using their own
real Gmail account passes authentication trivially — that pass says
nothing about whether the claimed brand is truthful. EMCC runs the
equivalent checks against a domain's own DNS records instead of a message,
scoring "spoofing exposure" the same way. Every finding names the specific
rule or record that fired and, where relevant, the exact action to take —
never just a bare score.

Both tools share one small web app (two tabs) and a command-line
interface. Double-click launcher scripts (Windows/Mac/Linux) let a
non-technical person run it with no coding knowledge — Python and all
dependencies install automatically and a browser opens on its own — while
`pyproject.toml`/`requirements.txt` support `uv` or `pip` for technical
users. The repository includes an automated test suite for the domain
checker (a fake DNS resolver, so results don't depend on any real domain's
records) and sample emails covering phishing, brand spoofing from free
webmail, a malicious attachment, and a clean baseline, so every score in
this summary can be reproduced immediately after cloning.
