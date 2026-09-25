"""Parses a raw .eml file into a ParsedEmail structure.

Uses only the Python standard library (email package) so there is no
dependency risk in this step.
"""

import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr

from .models import ParsedEmail

_HTML_LINK_RE = re.compile(
    r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")
_BARE_URL_RE = re.compile(r'(https?://[^\s<>"\']+)', re.IGNORECASE)


def parse_eml_file(path: str) -> ParsedEmail:
    with open(path, "rb") as f:
        raw = f.read()
    return parse_eml_bytes(raw)


def parse_eml_bytes(raw: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    parsed = ParsedEmail()
    parsed.raw_headers = {k: v for k, v in msg.items()}

    from_name, from_addr = parseaddr(msg.get("From", ""))
    parsed.from_display_name = from_name
    parsed.from_addr = from_addr.lower()

    _, reply_to = parseaddr(msg.get("Reply-To", ""))
    parsed.reply_to_addr = reply_to.lower()

    _, return_path = parseaddr(msg.get("Return-Path", ""))
    parsed.return_path_addr = return_path.lower()

    _, sender = parseaddr(msg.get("Sender", ""))
    parsed.sender_addr = sender.lower()

    parsed.to_addrs = [addr.lower() for _, addr in getaddresses(msg.get_all("To", []))]
    parsed.subject = msg.get("Subject", "") or ""
    parsed.date = msg.get("Date", "") or ""
    parsed.received_chain = msg.get_all("Received", []) or []
    parsed.authentication_results = " ".join(msg.get_all("Authentication-Results", []) or [])

    body_text_parts = []
    body_html_parts = []
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = part.get_content_disposition()
            filename = part.get_filename()
            if disposition == "attachment" or (filename and disposition != "inline"):
                attachments.append({"filename": filename or "", "content_type": ctype})
                continue
            if ctype == "text/plain":
                body_text_parts.append(_get_payload_text(part))
            elif ctype == "text/html":
                body_html_parts.append(_get_payload_text(part))
    else:
        ctype = msg.get_content_type()
        if ctype == "text/html":
            body_html_parts.append(_get_payload_text(msg))
        else:
            body_text_parts.append(_get_payload_text(msg))

    parsed.body_text = "\n".join(body_text_parts)
    parsed.body_html = "\n".join(body_html_parts)
    parsed.links = _extract_links(parsed.body_html, parsed.body_text)
    parsed.attachments = attachments

    return parsed


def _get_payload_text(part) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else str(content)
    except Exception:
        try:
            payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            return ""


_TRAILING_PUNCTUATION = ").,];:!?\"'"


def _strip_trailing_punctuation(url: str) -> str:
    """Bare URLs picked up by regex often carry trailing punctuation that's
    part of the surrounding sentence, not the link itself -- "see
    http://example.com]." or "(http://example.com)." A trailing bracket in
    particular can make urllib.parse.urlparse raise ValueError("Invalid
    IPv6 URL"), so this also prevents that class of crash at the source.
    """
    while url and url[-1] in _TRAILING_PUNCTUATION:
        url = url[:-1]
    return url


def _extract_links(html: str, text: str) -> list:
    links = []
    seen = set()

    for href, display_html in _HTML_LINK_RE.findall(html or ""):
        href = _strip_trailing_punctuation(href)
        display = _TAG_RE.sub("", display_html).strip()
        key = (href, display)
        if key in seen:
            continue
        seen.add(key)
        links.append({"display": display, "href": href})

    # Bare URLs in either html (outside anchors) or plain text body
    for source in (text or "", _TAG_RE.sub(" ", html or "")):
        for url in _BARE_URL_RE.findall(source):
            url = _strip_trailing_punctuation(url)
            if not url:
                continue
            key = (url, url)
            if key in seen:
                continue
            seen.add(key)
            links.append({"display": url, "href": url})

    return links
