# core/link_inspector.py
"""
link_inspector.py
أدوات فحص الروابط/عناوين URL.
- استخراج عناوين URL من النص.
- عمليات فحص: المضيف كعنوان IP، يحتوي على رمز @، العديد من النطاقات الفرعية، امتداد مشبوه.
"""
import re
from typing import List, Dict
from urllib.parse import urlparse

# التعبير النمطي الأساسي لعنوان URL (يغطي http/https)
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)

# الامتدادات المشبوهة التي قد تظهر في مسار URL
SUSPICIOUS_EXTS = {".exe", ".scr", ".bat", ".js", ".vbs", ".cmd"}


def extract_urls(text: str) -> List[str]:
    """يستخرج جميع الروابط من النص."""
    if not text:
        return []
    return _URL_RE.findall(text)


def analyze_url(url: str) -> Dict:
    """
    يُحلل رابط واحد ويُرجع قاموساً بـ:
      {"url": url, "checks": ["host_is_ip", ...], "host": "..."}
    """
    checks = []
    host = ""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        host_plain = host.strip("[]") if host else ""
        
        if host_plain:
            # 1. فحص المضيف كعنوان IPv4 (فحص سريع)
            if all(c.isdigit() or c == "." for c in host_plain) and host_plain.count(".") >= 1:
                checks.append("host_is_ip")
                
            # 2. فحص وجود رمز @ داخل الرابط (قد يشير إلى ترميز)
            if "@" in url:
                checks.append("contains_at")
                
            # 3. خوارزمية النطاقات الفرعية المتعددة
            if host.count(".") >= 4:
                checks.append("many_subdomains")
                
        # 4. فحص الامتداد المشبوه في المسار
        path = parsed.path or ""
        for ext in SUSPICIOUS_EXTS:
            if path.lower().endswith(ext):
                checks.append("suspicious_extension")
                break
                
    except Exception:
        host = ""
        
    return {"url": url, "checks": checks, "host": host}


def analyze_urls(text: str) -> List[Dict]:
    """يستخرج ويُحلل جميع الروابط الموجودة في النص."""
    urls = extract_urls(text)
    return [analyze_url(u) for u in urls]
