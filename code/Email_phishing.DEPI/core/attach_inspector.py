# core/attach_inspector.py
"""
Attachment checks.
- suspicious extensions
- double extensions (invoice.pdf.exe)
"""
from typing import List

SUSPICIOUS = {".exe", ".scr", ".bat", ".js", ".vbs", ".cmd", ".ps1"}


def analyze_attachments(attachments) -> List[str]:
    reasons = []
    for a in attachments or []:
        fn = (a.filename or "").lower()
        if not fn:
            continue
        # simple extension check
        for ext in SUSPICIOUS:
            if fn.endswith(ext):
                reasons.append("suspicious_attachment")
                break
        # double extension
        parts = fn.split(".")
        if len(parts) >= 3:
            last = parts[-1]
            if last in [e.strip(".") for e in SUSPICIOUS]:
                reasons.append("suspicious_attachment")
    return reasons
