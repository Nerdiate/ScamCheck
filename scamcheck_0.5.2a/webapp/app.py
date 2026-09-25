"""Minimal Flask front-end for the two ScamCheck tools:

- Check an Email: paste/upload a suspicious message, get a plain-language
  scam-likelihood report.
- Check a Domain's Email Setup (EMCC): enter a domain, get a plain-language
  report on whether its SPF/DKIM/DMARC/MX configuration would let someone
  spoof mail from it.

No LLM calls in either tool -- everything is rule-based and/or a public DNS
lookup, so there's no per-check cost and every result traces back to a
specific, inspectable rule.

Run with:
    pip install -r requirements.txt
    python webapp/app.py
Then open http://localhost:5000 (or just double-click one of the
run_windows.bat / run_mac.command / run_linux.sh launchers in the project
root, which do all of the above and open the browser for you).
"""

import os
import re
import sys
import threading
import webbrowser

from flask import Flask, render_template, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scamcheck.emcc import analyze_domain_config  # noqa: E402
from scamcheck.scoring import analyze_bytes  # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB upload limit

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", re.IGNORECASE)


@app.route("/", methods=["GET", "POST"])
def index():
    active_tab = request.form.get("tab", "email")

    email_report = None
    email_error = None
    domain_report = None
    domain_error = None

    if request.method == "POST" and active_tab == "email":
        email_report, email_error = _handle_email_submission()
    elif request.method == "POST" and active_tab == "domain":
        domain_report, domain_error = _handle_domain_submission()

    return render_template(
        "index.html",
        active_tab=active_tab,
        email_report=email_report,
        email_error=email_error,
        domain_report=domain_report,
        domain_error=domain_error,
    )


def _handle_email_submission():
    raw_bytes = None
    uploaded = request.files.get("eml_file")
    pasted = request.form.get("raw_email", "").strip()

    if uploaded and uploaded.filename:
        raw_bytes = uploaded.read()
    elif pasted:
        raw_bytes = pasted.encode("utf-8", errors="replace")
    else:
        return None, "Upload a .eml file or paste the raw email source below."

    try:
        skip_whois = request.form.get("skip_whois") == "on"
        return analyze_bytes(raw_bytes, skip_whois=skip_whois), None
    except Exception as exc:
        return None, f"Could not analyze this message: {exc}"


def _handle_domain_submission():
    domain = request.form.get("domain", "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]

    if not domain:
        return None, "Enter a domain name to check, e.g. example.com."
    if not _DOMAIN_RE.match(domain):
        return None, f'"{domain}" doesn\'t look like a valid domain name (expected something like example.com).'

    try:
        return analyze_domain_config(domain), None
    except Exception as exc:
        return None, f"Could not analyze {domain}: {exc}"


if __name__ == "__main__":
    # Hosting platforms (Render, Railway, etc.) set PORT and expect the app
    # to bind 0.0.0.0. Running locally via a launcher script, PORT is unset,
    # we bind to localhost only, and we auto-open the browser so a
    # non-technical user never has to type a URL.
    is_hosted = "PORT" in os.environ
    port = int(os.environ.get("PORT", 5000))

    def _open_browser():
        try:
            webbrowser.open(f"http://127.0.0.1:{port}/")
        except Exception:
            pass  # headless environment or no default browser configured -- non-fatal

    if not is_hosted:
        threading.Timer(1.25, _open_browser).start()

    app.run(
        debug=os.environ.get("SCAMCHECK_DEBUG") == "1",
        host="0.0.0.0" if is_hosted else "127.0.0.1",
        port=port,
    )
