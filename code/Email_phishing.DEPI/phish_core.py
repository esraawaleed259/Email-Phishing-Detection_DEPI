# phish_core.py
"""
Core Phishing Analysis Logic.

Provides essential methods for data processing, analysis, and report saving.
NOTE: This file contains an 'Enhanced Fallback' analysis used when advanced
inspection modules (like header_checker, link_inspector) are not available.
"""
from pathlib import Path
from datetime import datetime
import json
import re
from email import message_from_bytes
import tldextract 
from typing import Dict, List, Any

# --- Core Analyzer Logic (Enhanced Fallback) ---
def _enhanced_analysis(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Enhanced fallback analysis function.
    Parses email, checks keywords, counts URLs, and performs basic domain checks.
    """
    
    # 1. Parse Email Content (تحليل محتوى البريد الإلكتروني)
    try:
        msg = message_from_bytes(raw_bytes)
    except:
        return {
            "error": "Failed to parse raw EML bytes.",
            "score": 100.0,
            "verdict": "ERROR/HIGH_RISK",
            "flags": ["PARSING_FAILED"]
        }
        
    subject = msg.get('Subject', '(No Subject)')
    from_header = msg.get('From', '(Unknown Sender)')
    to_header = msg.get('To', '(Unknown Recipient)')
    
    # Extract body text (استخلاص النص العادي من جسم الرسالة)
    body_text = ""
    for part in msg.walk():
        ctype = part.get_content_type()
        cdispo = str(part.get("Content-Disposition"))
        
        if ctype == 'text/plain' and 'attachment' not in cdispo:
            try:
                # Robust decoding with error ignore
                body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                break
            except:
                pass

    # 2. Analysis & Scoring (التحليل وحساب النقاط)
    report: Dict[str, Any] = {
        "subject": subject,
        "from": from_header,
        "to": to_header,
        "score": 0.0, # Raw score (0-10)
        "verdict": "Likely Safe (Low Risk)",
        "flags": [],
        "keywords": [],
        "urls": [],
        "body_text": body_text.strip(),
        "headers": dict(msg.items())
    }

    text_to_analyze = (subject + " " + body_text).lower()
    
    # 2.1 Keyword Check (فحص الكلمات المفتاحية)
    suspicious_keywords = {
        "password": 2.5, "update payment": 2.0, "account suspended": 2.0,
        "immediate action": 2.0, "urgent": 1.5, "click here": 1.5,
        "verify": 1.0, "login": 1.0
    }
    
    for kw, weight in suspicious_keywords.items():
        if kw in text_to_analyze:
            report["keywords"].append(kw)
            report["score"] += weight
            report["flags"].append(f"KW:{kw.replace(' ', '_')}")

    # 2.2 URL Check (فحص الروابط)
    url_pattern = re.compile(r'https?://[^\s\'"]+')
    found_urls = list(set(url_pattern.findall(body_text)))
    
    for url in found_urls:
        url_info = {"url": url, "checks": []}
        try:
            ext = tldextract.extract(url)
            full_domain = f"{ext.domain}.{ext.suffix}"
            
            # Check 1: IP address in hostname (عنوان IP في اسم المضيف)
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ext.domain):
                url_info["checks"].append("URL uses IP address")
                report["score"] += 3.0
            
            # Check 2: Domain name length (طول اسم النطاق)
            if len(full_domain) > 30 and ext.domain not in ["google", "microsoft"]:
                url_info["checks"].append("Long domain name")
                report["score"] += 1.0

            if url_info["checks"]:
                report["flags"].append(f"URL: {full_domain} is suspicious")
                
            report["urls"].append(url_info)
        except Exception:
             # Handle malformed URLs that tldextract can't handle
             url_info["checks"].append("Malformed URL")
             report["urls"].append(url_info)
             report["score"] += 1.5
             report["flags"].append("Malformed_URL")


    # 2.3 Subject urgency check (فحص إلحاح الموضوع)
    if any(word in subject.lower() for word in ['urgent', 'immediate', 'alert', 'action required']):
        report["score"] += 1.0
        report["flags"].append("Subject_High_Urgency")


    # 3. Final Score and Verdict (النتيجة النهائية والقرار)
    final_score_0_10 = min(report["score"], 10.0) # Cap raw score
    # Normalize to 0-100 range (use a max raw score of 10 for normalization)
    final_score_0_100 = round(final_score_0_10 * 10, 1) 
    
    report["score"] = final_score_0_100 
    
    if final_score_0_100 >= 70.0:
        report["verdict"] = "PHISHING (High Risk)"
    elif final_score_0_100 >= 40.0:
        report["verdict"] = "SUSPICIOUS (Medium Risk)"
    else:
        report["verdict"] = "CLEAN (Low Risk)"

    return report

# ----------------------------------------------------------------------
# Public API Wrappers (مغلفات الواجهة البرمجية العامة)
# ----------------------------------------------------------------------

def analyze_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Analyze raw .eml content (bytes) using the enhanced fallback analysis."""
    if not raw_bytes:
        return _enhanced_analysis(b"") 
    
    return _enhanced_analysis(raw_bytes)


def analyze_file(path: str | Path) -> Dict[str, Any]:
    """Analyze an .eml file from disk. (تحليل ملف EML من القرص)"""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        raw = p.read_bytes()
        return analyze_bytes(raw)
    except Exception as e:
        return {
            "error": "Failed to read file bytes",
            "details": str(e),
            "score": 100.0, 
            "verdict": "READ_ERROR/HIGH_RISK"
        }

def save_report(report: Dict[str, Any], outdir: str = "reports", as_html: bool = False) -> str:
    """
    Save report dict to JSON and optionally HTML.
    """
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = outdir_p / f"report_{ts}.json"
    
    # 1. Save JSON
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # 2. Save HTML (Simple and Clean)
    if as_html:
        html_path = outdir_p / f"report_{ts}.html"
        
        # Build HTML content
        flags_html = ''.join([f'<li>{f}</li>' for f in report.get('flags', []) + report.get('keywords', [])])
        
        html_content = f"""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Phishing Analysis Report</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; background-color: #f4f7f6; color: #333; }}
        .container {{ max-width: 800px; margin: auto; background: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
        h1, h2 {{ color: #007bff; border-bottom: 2px solid #e9ecef; padding-bottom: 5px; }}
        .verdict-high {{ color: #dc3545; font-weight: bold; }}
        .verdict-medium {{ color: #ffc107; font-weight: bold; }}
        .verdict-low {{ color: #28a745; font-weight: bold; }}
        pre {{ background-color: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; border-radius: 5px; white-space: pre-wrap; }}
        ul {{ padding-left: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Phishing Analysis Report</h1>
        <p><strong>Subject:</strong> {report.get('subject', 'N/A')}</p>
        <p><strong>From:</strong> {report.get('from', 'N/A')}</p>
        <p><strong>To:</strong> {report.get('to', 'N/A')}</p>
        <p><strong>Score (0-100):</strong> {report.get('score', 'N/A')}</p>
        <p><strong>Verdict:</strong> <span class="verdict-{report.get('verdict', 'CLEAN (Low Risk)').lower().split(' ')[0]}">{report.get('verdict', 'N/A')}</span></p>

        <h2>Risk Factors & Flags</h2>
        <ul>{flags_html or '<li>No specific flags found.</li>'}</ul>

        <h2>Body Preview (Text)</h2>
        <pre>{report.get('body_text', 'N/A')}</pre>

        <p><a href="./{json_path.name}">Download Raw JSON Report</a></p>
    </div>
</body>
</html>
"""
        with html_path.open("w", encoding="utf-8") as f:
            f.write(html_content)
            
        report["_saved_html"] = html_path.name

        return str(html_path)

    return str(json_path)
