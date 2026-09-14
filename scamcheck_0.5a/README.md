# ScamCheck

## Quick Start (no coding required)

1. **Download this whole project** as a folder on your computer (if you got
   it as a .zip, unzip it first — right-click it and choose "Extract All"
   on Windows, or just double-click it on Mac).
2. **Make sure Python is installed.** Mac and Linux almost always already
   have it. On Windows, if you're not sure, just try step 3 — the launcher
   will tell you if it's missing and link you straight to the download
   (https://www.python.org/downloads/). During that install, check the box
   that says "Add python.exe to PATH."
3. **Double-click the launcher for your computer:**
   - Windows: `run_windows.bat`
   - Mac: `run_mac.command` (first time only: if macOS says it's from an
     "unidentified developer," right-click the file and choose **Open**
     instead of double-clicking — you only need to do this once)
   - Linux: open a terminal in this folder and run `bash run_linux.sh`
     (double-clicking often just opens the file in a text editor instead of
     running it, depending on your file manager)
4. **Wait a few seconds.** The first run installs a few small Python
   packages automatically; every run after that starts in a couple of
   seconds. Your web browser will open by itself to the ScamCheck page —
   you don't need to type anything.
5. **To stop it,** just close the black window/terminal that opened (or
   press Ctrl+C in it).

Nothing here talks to an outside server except public DNS/WHOIS lookups
(the same kind of lookup any "check this domain" website does) — your
emails and the domains you check are never sent anywhere else.

---

**Category:** Community-focused tools (submitted for consideration in this
category; the second tool below, EMCC, may also fit this category or be
considered separately at the organizers' discretion — both checks live in
one repo because they share the same audience and a lot of underlying code)

ScamCheck is two rule-based, no-AI security tools built for people who
aren't security professionals — a small business owner, a nonprofit staffer,
a school IT volunteer, a parent:

1. **Check an Email** — analyzes a suspicious email and explains, in plain
   language, exactly why it looks like a scam (or why it doesn't), with
   specific next steps ("don't reply to this address," "call the business
   directly instead of clicking this link").
2. **Check a Domain's Email Setup (EMCC)** — checks whether a domain's own
   published SPF/DKIM/DMARC/MX records would let someone else send
   convincing spoofed mail *as* that domain, and tells you exactly what to
   fix. Point it at your own organization's domain to find the gap before a
   scammer does.

Both are available from the same command-line tool and the same small web
app (two tabs), because they're really the same underlying problem — "can
this email be trusted?" — looked at from the message side and the domain
side.

## Why no LLM?

We deliberately built this as a **rule-based / heuristic engine, not an LLM
wrapper**. That was a design choice, not a shortcut:

- **Zero per-check cost.** A community tool that a school district or small
  nonprofit runs on every suspicious email (or every vendor domain) it
  encounters can't carry a per-call API bill, and a local LLM good enough to
  be trustworthy here is not something most of the intended users can run.
- **Explainability.** Every finding comes from a specific, inspectable rule
  or public DNS record (an SPF failure, a Reply-To mismatch, a lookalike
  domain, a phrase match, a missing DMARC policy). That's a stronger basis
  for telling someone "don't trust this" than a paraphrased LLM impression,
  and it means the reasoning can be audited, tested, and trusted by
  non-experts.
- **Speed and reliability.** Everything runs in well under a second, fully
  offline except for a handful of public DNS/WHOIS lookups, with no rate
  limits or outages to worry about.

This does mean ScamCheck won't catch a novel, perfectly-worded scam with no
technical tells. A natural extension (noted for future work, not attempted
here given the contest timeline) would be a small, purpose-trained
classifier — e.g. logistic regression or a lightweight transformer
fine-tuned on public phishing-email corpora (the Nazario corpus, Enron+
phishing sets) — that runs locally with no per-call cost and adds a
model-based signal alongside the deterministic ones, rather than replacing
them.

## Tool 1: Check an Email

| Category | Signals |
|---|---|
| **Headers & authentication** | SPF/DKIM/DMARC results (reads `Authentication-Results` if present; falls back to a live SPF/DMARC DNS lookup for the sending domain if not), From/Reply-To mismatch, From/Return-Path mismatch, display-name brand spoofing (e.g. "PayPal Security" from a non-PayPal domain) — including the specific, very common case of a brand name paired with a free consumer webmail address (`wellsfargo.alerts@gmail.com`), missing Received headers |
| **Domain reputation** | Lookalike/homoglyph domains against a list of commonly impersonated brands (`paypa1.com`, `arnazon-support.com`, `paypal-secure-alerts.com`), IDN homograph attacks (mixed-alphabet or raw punycode domains), domains with no DNS records at all (NXDOMAIN), domain registration age via WHOIS (very new domains are a strong signal) |
| **Links** | Display text vs. actual destination mismatches, raw IP-address links, URL shorteners, suspicious TLDs, brand+login/verify wording hosted on an unrelated domain |
| **Attachments** | Dangerous executable extensions (`.exe`, `.scr`, `.js`, `.vbs`, ...), disguised double extensions (`invoice.pdf.exe`), macro-enabled Office documents (`.docm`, `.xlsm`), archive attachments — filename/metadata only, files are never opened or scanned |
| **Language** | Weighted phrase clustering for urgency/pressure tactics and money/financial-info requests, generic greetings ("Dear Customer"), excessive capitalization or punctuation |

Every finding carries: what was found, the specific evidence backing it, and
(where applicable) a concrete action — never just a score.

One deliberate scoring nuance: a message can pass SPF/DKIM/DMARC and *still*
be flagged as high risk. Authentication only proves which domain technically
sent the mail — a scammer using their own real Gmail account will pass all
three, because Gmail really did send it. It says nothing about whether the
claimed identity in the display name ("Wells Fargo Account Services") is
truthful. When a display-name brand mismatch is already found, ScamCheck
reports the auth pass as a neutral note explaining this, rather than letting
it offset the score — see `tests/sample_emails/freemail_bank_spoof.eml` for
a worked example.

## Tool 2: Check a Domain's Email Setup (EMCC)

Give it any domain name and it checks the same public DNS records a real
attacker would check before trying to spoof that domain:

| Check | What it catches |
|---|---|
| **SPF** | Missing entirely, multiple conflicting records (invalid per spec), a permissive `+all`/`?all` ending that authorizes anyone, `~all` softfail vs. `-all` hard fail, and an approximate DNS-lookup count against SPF's hard 10-lookup limit |
| **DMARC** | Missing entirely, `p=none` (monitor-only, blocks nothing), missing policy tag, no `rua=` reporting address (no visibility into who's sending as your domain), partial `pct=` enforcement |
| **DKIM** | Best-effort probe of common selectors used by major platforms (Google Workspace, Microsoft 365, SendGrid, Mailgun, Mailchimp, Amazon SES, etc.) — DKIM selectors aren't publicly enumerable in general, so this is reported as a hint, not a guarantee, when nothing is found |
| **MX** | Missing MX (can't receive mail) vs. an explicit null MX (RFC 7505 — correct practice for a domain that intentionally sends no mail) |
| **Existence** | A domain with zero DNS records at all short-circuits to one clear finding instead of a pile of "missing X" repeats |

Findings are worded for a domain owner to act on directly — e.g. "Add an
rua= address to your DMARC record" rather than jargon alone.

## Try it

Non-technical users: see **Quick Start** at the top of this file — just
double-click a launcher script and a browser window opens by itself.

For anyone comfortable with a terminal:

```bash
pip install -r requirements.txt

# --- Check an email ---
python -m scamcheck email tests/sample_emails/phishing_paypal.eml
python -m scamcheck email tests/sample_emails/legit_newsletter.eml
python -m scamcheck email path/to/email.eml --no-whois   # skip the network WHOIS lookup
python -m scamcheck email path/to/email.eml --json        # machine-readable output

# --- Check a domain's email config (EMCC) ---
python -m scamcheck domain example.com
python -m scamcheck domain example.com --json

# --- Web UI (both tools, tabbed) ---
python webapp/app.py
# then open http://localhost:5000
```

Sample emails are included under `tests/sample_emails/`: an obvious
phishing attempt, a bank-brand scam sent from a free Gmail account (a good
example of why passing SPF/DKIM/DMARC doesn't mean much on its own), a
malicious-attachment example, and a legitimate newsletter with proper
SPF/DKIM/DMARC — covering the full score range.

EMCC has its own automated test suite (`tests/test_emcc.py`) using an
injected fake DNS resolver, so its weak-config and strong-config detection
is verified deterministically rather than depending on any particular real
domain's records staying the same over time. Run it with
`python3 tests/test_emcc.py -v`.

## How to get a `.eml` file

Most email clients support "Download message" / "Show original" /
"Save as..." which exports the raw `.eml` source, headers included — that's
what the email checker needs (a screenshot or forwarded copy loses the
headers that most of its checks depend on). The web UI has a built-in,
per-provider cheat sheet (Gmail/Outlook/Apple Mail) for this, and flags
clearly when it only received the visible body rather than the full source.

## Project layout

```
run_windows.bat, run_mac.command, run_linux.sh   # double-click launchers (see Quick Start)
scamcheck/
  parser.py       # .eml -> normalized ParsedEmail (stdlib email package only)
  headers.py      # SPF/DKIM/DMARC, Reply-To/Return-Path mismatches, display-name spoofing
  domain.py       # lookalike-domain detection, IDN homograph, NXDOMAIN, WHOIS registration age
  urls.py         # link display/destination mismatches, shorteners, IP links, suspicious TLDs
  attachments.py  # dangerous/double extensions, macro-enabled Office files
  language.py     # urgency/pressure phrase scoring, generic greetings, formatting anomalies
  scoring.py      # combines email findings into a 0-100 score + plain-language summary
  emcc.py         # domain SPF/DKIM/DMARC/MX configuration checks + scoring
  cli.py          # command-line interface (email + domain subcommands)
webapp/
  app.py, templates/index.html   # tabbed Flask front-end for both tools
tests/
  sample_emails/    # example phishing, spoofed-brand, malicious-attachment, and legitimate .eml files
  test_emcc.py       # automated tests for the domain-config checker (fake resolver, no network needed)
```

## Limitations & honest caveats

- WHOIS and DNS lookups require network access and a small amount of time
  per check (typically well under a second); both fail gracefully (with a
  note in the report) if unavailable.
- The brand and phrase lists in the email checker are a useful starting
  set, not exhaustive — extending them is the highest-leverage next step
  for real-world use.
- DKIM cannot be fully verified in either tool without either the original
  signing key (email checker) or a known selector (domain checker) — both
  are reported as best-effort/inconclusive rather than guessed at.
- These are decision-support tools, not guarantees. They're designed to
  give someone the specific, correct question to ask ("why does this
  reply-to address not match?", "why is DMARC set to p=none?") — not to
  replace their own judgment or a real security team for high-stakes
  situations.

## Team / submission

Built for the OUPI Cyber Clinic Contest 2026 by Ryan King