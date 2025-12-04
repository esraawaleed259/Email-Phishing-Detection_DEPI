# core/engine.py
"""
engine.py
محرك التحليل المركزي: يُنسق عمليات الفحص ويُرجع تقريراً مُنظماً.
يتضمن 'explanations' لتقديم أسباب واضحة ومقروءة للأعلام المرفوعة.
"""
from .mail_parser import MailObject
from .link_inspector import analyze_urls
from .hdr_inspector import parse_authentication_results, replyto_mismatch
# يفترض وجود text_inspector
from .text_inspector import find_keywords, contains_urgent_language 
from .attach_inspector import analyze_attachments

# الأوزان الافتراضية لعوامل الخطر (قابلة للتعديل)
DEFAULT_WEIGHTS = {
    "spf_fail": 3, "dkim_fail": 3, "dmarc_fail": 3,
    "host_is_ip": 2, "contains_at": 2, "many_subdomains": 1,
    "suspicious_extension": 3, "keyword": 1, "replyto_mismatch": 2,
    "suspicious_attachment": 3, "urgent_language": 1
}


def analyze_mail(mail: MailObject, weights=None):
    """
    يُجري تحليل شامل لكائن MailObject ويُرجع تقرير مفصل.
    """
    w = weights or DEFAULT_WEIGHTS
    flags = []
    explanations = []
    score = 0

    # 1. فحص ترويسات المصادقة (Auth Headers)
    auth = parse_authentication_results((mail.headers or {}).get("Authentication-Results", ""))
    if auth.get("spf") == "fail":
        flags.append("spf_fail"); score += w.get("spf_fail", 3)
        explanations.append({"flag": "spf_fail", "weight": w.get("spf_fail", 3), "explain": "SPF reported fail — sending IP is not authorized for this domain."})
    if auth.get("dkim") == "fail":
        flags.append("dkim_fail"); score += w.get("dkim_fail", 3)
        explanations.append({"flag": "dkim_fail", "weight": w.get("dkim_fail", 3), "explain": "DKIM signature invalid — message may be forged."})
    if auth.get("dmarc") == "fail":
        flags.append("dmarc_fail"); score += w.get("dmarc_fail", 3)
        explanations.append({"flag": "dmarc_fail", "weight": w.get("dmarc_fail", 3), "explain": "DMARC policy failure — domain alignment issue."})

    # 2. فحص عدم تطابق الرد (Reply-To Mismatch)
    reply_to = (mail.headers or {}).get("Reply-To", "")
    if replyto_mismatch(mail.sender, reply_to):
        flags.append("replyto_mismatch"); score += w.get("replyto_mismatch", 2)
        explanations.append({"flag": "replyto_mismatch", "weight": w.get("replyto_mismatch", 2), "explain": "Reply-To domain differs from From — possible impersonation."})

    # 3. فحص الروابط (URLs)
    combined = (mail.body_text or "") + "\n" + (mail.body_html or "")
    urls = analyze_urls(combined)
    for u in urls:
        for c in u.get("checks", []):
            flag = f"url:{c}"
            flags.append(flag)
            score += w.get(c, 1)
            explanations.append({"flag": flag, "weight": w.get(c, 1), "explain": f"URL {u.get('url')} flagged for {c}."})

    # 4. فحص الكلمات المفتاحية (Keywords) واللغة العاجلة
    # يفترض وجود text_inspector
    keywords = find_keywords((mail.body_text or "") + " " + (mail.subject or ""))
    for k in keywords:
        flag = f"keyword:{k}"
        flags.append(flag)
        score += w.get("keyword", 1)
        explanations.append({"flag": flag, "weight": w.get("keyword", 1), "explain": f"Message contains suspicious keyword '{k}'."})

    if contains_urgent_language(mail.body_text):
        flags.append("urgent_language"); score += w.get("urgent_language", 1)
        explanations.append({"flag": "urgent_language", "weight": w.get("urgent_language", 1), "explain": "Message uses urgent language encouraging immediate action."})

    # 5. فحص المرفقات (Attachments)
    att_reasons = analyze_attachments(mail.attachments)
    for r in att_reasons:
        flags.append(r); score += w.get("suspicious_attachment", 3)
        explanations.append({"flag": r, "weight": w.get("suspicious_attachment", 3), "explain": "Attachment has suspicious extension or pattern."})

    # 6. تحديد الحكم النهائي (Verdict Thresholds)
    if score >= 8:
        verdict = "High risk (likely phishing)"
    elif score >= 4:
        verdict = "Suspicious (possible phishing)"
    elif score >= 1:
        verdict = "Low risk (watchful)"
    else:
        verdict = "No obvious signs"

    # تجميع التقرير
    report = {
        "subject": mail.subject,
        "from": mail.sender,
        "to": mail.recipient,
        "date": mail.date,
        "score": score,
        "verdict": verdict,
        "flags": flags,
        "explanations": explanations,
        "urls": urls,
        "keywords": keywords,
        "attachments": [a.filename for a in (mail.attachments or [])],
        "body_text": mail.body_text,
        "body_html": mail.body_html,
        "headers": mail.headers or {}
    }
    return report
