# core/mail_parser.py
"""
mail_pars.py
مُحلل .eml خفيف الوزن يُرجع كائن MailObject.
يستخدم مكتبة email القياسية في بايثون ويُرجع كائن dataclass بسيط.
"""
from email import policy
from email.parser import BytesParser
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Attachment:
    filename: str
    content_type: str
    data: bytes


@dataclass
class MailObject:
    subject: str = ""
    sender: str = ""
    recipient: str = ""
    date: str = ""
    headers: dict = None
    body_text: str = ""
    body_html: str = ""
    attachments: List[Attachment] = None


def parse_eml_bytes(raw: bytes) -> MailObject:
    """
    يُحلل بايتات .eml الأولية ويُرجع MailObject.
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    m = MailObject(headers=dict(msg.items()), attachments=[])

    m.subject = msg.get("Subject", "") or ""
    m.sender = msg.get("From", "") or ""
    m.recipient = msg.get("To", "") or ""
    m.date = msg.get("Date", "") or ""

    # استخراج نص الرسالة: يفضل النص العادي، وإلا HTML
    try:
        body = msg.get_body(preferencelist=("plain", "html"))
        if body:
            if body.get_content_type().startswith("text/html"):
                m.body_html = body.get_content()
            else:
                m.body_text = body.get_content()
        else:
            # تجميع أجزاء النص العادي كخطة بديلة
            parts = []
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    parts.append(part.get_content())
            if parts:
                m.body_text = "\n".join(parts)
    except Exception:
        # خطة بديلة لفك تشفير الحمولة بأكملها كنص
        try:
            m.body_text = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
        except Exception:
            m.body_text = ""

    # المرفقات
    for part in msg.iter_attachments():
        fn = part.get_filename() or ""
        ctype = part.get_content_type()
        data = part.get_payload(decode=True) or b""
        m.attachments.append(Attachment(filename=fn, content_type=ctype, data=data))

    return m


def parse_eml_file(path: str) -> MailObject:
    """يقرأ ملف .eml من المسار."""
    with open(path, "rb") as f:
        raw = f.read()
    return parse_eml_bytes(raw)
