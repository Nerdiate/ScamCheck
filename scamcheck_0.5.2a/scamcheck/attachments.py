"""Attachment filename/type analysis.

Only looks at filenames and declared content-types (both are free metadata
already present in the parsed .eml) -- it never opens, scans, or executes
attachment content, so it stays fast and safe to run on untrusted mail.
"""

import re

from .models import Finding, Severity

_DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "psm1", "msi", "msp", "jar", "hta", "lnk", "reg",
    "dll", "cpl", "gadget", "apk",
}

_MACRO_ENABLED_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm"}

_ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "iso", "img"}

_FILENAME_RE = re.compile(r"^(.*)\.([A-Za-z0-9]+)$")


def analyze_attachments(attachments: list) -> list:
    findings = []
    seen_ids = set()

    for att in attachments:
        filename = (att.get("filename") or "").strip()
        if not filename:
            continue

        extensions = _all_extensions(filename)
        if not extensions:
            continue

        final_ext = extensions[-1]

        if final_ext in _DANGEROUS_EXTENSIONS:
            _add_once(
                findings, seen_ids,
                Finding(
                    id="dangerous_attachment",
                    category="attachments",
                    severity=Severity.HIGH,
                    weight=25,
                    summary="Email includes a potentially dangerous attachment",
                    evidence=f'"{filename}" is a .{final_ext} file, a type that can run code on your computer when opened.',
                    advice="Do not open this attachment. Legitimate businesses do not send executable files by email.",
                ),
            )

        if len(extensions) >= 2 and extensions[-2] not in (final_ext,) and _looks_like_document_extension(extensions[-2]) and final_ext in _DANGEROUS_EXTENSIONS:
            _add_once(
                findings, seen_ids,
                Finding(
                    id="double_extension_attachment",
                    category="attachments",
                    severity=Severity.HIGH,
                    weight=25,
                    summary="Attachment uses a disguised double file extension",
                    evidence=(
                        f'"{filename}" is named to look like a .{extensions[-2]} file at a glance, but its real '
                        f"extension is .{final_ext}. This is a common trick to disguise a program as a document."
                    ),
                    advice="Do not open this attachment under any circumstances.",
                ),
            )

        if final_ext in _MACRO_ENABLED_EXTENSIONS:
            _add_once(
                findings, seen_ids,
                Finding(
                    id="macro_enabled_attachment",
                    category="attachments",
                    severity=Severity.MEDIUM,
                    weight=15,
                    summary="Email includes a macro-enabled Office document",
                    evidence=f'"{filename}" is a .{final_ext} file, an Office format that can contain macros (small programs) that run automatically when you enable editing.',
                    advice='If you were not expecting this file, do not open it, and never click "Enable Content" or "Enable Macros" in an unexpected document.',
                ),
            )

        if final_ext in _ARCHIVE_EXTENSIONS:
            _add_once(
                findings, seen_ids,
                Finding(
                    id="archive_attachment",
                    category="attachments",
                    severity=Severity.LOW,
                    weight=5,
                    summary="Email includes a compressed archive attachment",
                    evidence=f'"{filename}" is a .{final_ext} archive. Archives are sometimes used to hide dangerous files from email security scanners.',
                ),
            )

    return findings


def _add_once(findings, seen_ids, finding):
    if finding.id in seen_ids:
        return
    seen_ids.add(finding.id)
    findings.append(finding)


def _all_extensions(filename: str) -> list:
    """Returns every dot-separated extension-looking suffix, lowercased,
    e.g. "invoice.pdf.exe" -> ["pdf", "exe"].
    """
    parts = filename.lower().split(".")
    if len(parts) < 2:
        return []
    return [p for p in parts[1:] if p and len(p) <= 5]


def _looks_like_document_extension(ext: str) -> bool:
    return ext in {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif"}
