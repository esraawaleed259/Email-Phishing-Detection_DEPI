# core/hdr_inspector.py
"""
hdr_inspector.py
أدوات فحص الترويسات:
- تحليل ترويسة Authentication-Results لحالات SPF/DKIM/DMARC (بسيط).
- فحص عدم تطابق Reply-To مقابل From.
"""
from typing import Dict


def parse_authentication_results(header_value: str) -> Dict:
    """
    مُحلل بسيط جداً: يبحث عن 'spf=pass/fail', 'dkim=pass/fail', 'dmarc=pass/fail'.
    يُرجع قاموساً مثل {"spf":"pass","dkim":"fail"}.
    """
    res = {}
    if not header_value:
        return res
    v = header_value.lower()
    
    # فحص SPF
    if "spf=pass" in v or "spf pass" in v:
        res["spf"] = "pass"
    elif "spf=fail" in v or "spf fail" in v:
        res["spf"] = "fail"
        
    # فحص DKIM
    if "dkim=pass" in v or "dkim pass" in v:
        res["dkim"] = "pass"
    elif "dkim=fail" in v or "dkim fail" in v:
        res["dkim"] = "fail"
        
    # فحص DMARC
    if "dmarc=pass" in v or "dmarc pass" in v:
        res["dmarc"] = "pass"
    elif "dmarc=fail" in v or "dmarc fail" in v:
        res["dmarc"] = "fail"
        
    return res


def replyto_mismatch(from_header: str, reply_to: str) -> bool:
    """
    خوارزمية بسيطة: إذا لم يكن نطاق (Domain) الرد (Reply-To) موجوداً في ترويسة المُرسل (From)، يتم رفع علم عدم التطابق.
    """
    if not from_header or not reply_to:
        return False
    try:
        lo_from = from_header.lower()
        lo_reply = reply_to.lower()
        # استخراج النطاق من عنوان الرد
        if "@" in lo_reply:
            reply_domain = lo_reply.split("@", 1)[1]
            # التحقق مما إذا كان نطاق الرد غير موجود في ترويسة المُرسل بالكامل
            return reply_domain not in lo_from
    except Exception:
        return False
    return False
