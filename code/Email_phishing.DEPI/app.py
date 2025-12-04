#!/usr/bin/env python3
"""
main.py - Command Line Interface (CLI) for the Phishing Analyzer.

Supports local analysis (using phish_core) or remote API calls.
(أداة سطر الأوامر - تدعم التحليل المحلي أو عبر API)
"""
from pathlib import Path
import argparse
import datetime
import json
import sys
from typing import Dict, Any

# Attempt to import core functions for local mode
# محاولة استيراد وظائف النواة (phish_core) للتحليل المحلي
try:
    from phish_core import analyze_file, save_report
    CORE_IMPORTED = True
except Exception:
    analyze_file = None
    save_report = None
    CORE_IMPORTED = False

# Optional requests library for API mode
# مكتبة requests اختيارية لوضع API
try:
    import requests
except ImportError:
    requests = None

def pretty_print_report(report: Dict[str, Any]):
    """Prints the analysis report in a formatted console view. (طباعة التقرير بشكل منسق)"""
    
    # Define colors for better console output (ANSI escape codes)
    C_RED = '\033[91m'
    C_YELLOW = '\033[93m'
    C_GREEN = '\033[92m'
    C_BLUE = '\033[94m'
    C_END = '\033[0m'
    
    verdict = report.get('verdict', 'N/A')
    
    # Color based on verdict
    if 'HIGH' in verdict.upper():
        V_COLOR = C_RED
    elif 'SUSPICIOUS' in verdict.upper():
        V_COLOR = C_YELLOW
    else:
        V_COLOR = C_GREEN

    print("\n" + "="*75)
    print(f"{C_BLUE} Email Phishing Analysis Report {C_END}".center(85))
    print("="*75)
    
    print(f"  {C_BLUE}Subject:{C_END}  {report.get('subject')}")
    print(f"  {C_BLUE}From:{C_END}     {report.get('from')}")
    print(f"  {C_BLUE}To:{C_END}       {report.get('to')}")
    print("-" * 75)
    print(f"  {C_BLUE}SCORE:{C_END}    {report.get('score', 'N/A')} / 100")
    print(f"  {C_BLUE}VERDICT:{C_END}  {V_COLOR}{verdict}{C_END}")
    print("-" * 75)

    # Risk Flags
    flags = report.get("flags", [])
    if flags:
        print(f"  {C_BLUE}RISK FLAGS ({len(flags)}):{C_END}")
        for f in flags:
            print(f"    - {C_RED}{f}{C_END}")
    else:
        print(f"  {C_GREEN}No specific risk flags detected.{C_END}")
        
    # Keywords
    keywords = report.get("keywords", [])
    if keywords:
        print(f"\n  {C_BLUE}SUSPICIOUS KEYWORDS:{C_END}")
        print(f"    {C_YELLOW}{', '.join(keywords)}{C_END}")

    # URLs
    urls = report.get("urls", [])
    if urls:
        print(f"\n  {C_BLUE}SUSPICIOUS URLS:{C_END}")
        for u in urls:
            checks = ", ".join(u.get("checks", [])) or "No checks failed"
            print(f"    * {C_BLUE}{u.get('url')}{C_END} -> {C_YELLOW}{checks}{C_END}")
            
    print("\n" + "="*75)


def analyze_via_api(path: Path, api_url: str, timeout: int = 30) -> Dict[str, Any]:
    """Sends the EML file to the remote API for analysis. (يرسل الملف إلى الواجهة البرمجية للتحليل)"""
    if requests is None:
        raise RuntimeError("The 'requests' library is required for API mode. Please install it.")
    
    with path.open("rb") as fh:
        # Prepare file for multipart form data
        files = {"file": (path.name, fh, "message/rfc822")}
        try:
            resp = requests.post(api_url, files=files, timeout=timeout)
        except requests.exceptions.Timeout:
            raise RuntimeError(f"API request timed out after {timeout} seconds.")
        except Exception as e:
            raise RuntimeError(f"Failed to contact API at {api_url}: {e}")
    
    if resp.status_code != 200:
        # Raise error with detailed message from API if available
        try:
            detail = resp.json().get('detail', resp.text)
        except:
            detail = resp.text
        raise RuntimeError(f"API returned {resp.status_code}: {detail}")
        
    try:
        return resp.json()
    except Exception as e:
        raise RuntimeError(f"API returned non-JSON response: {e}")

def parse_args():
    """Parses command line arguments. (يحلل وسائط سطر الأوامر)"""
    ap = argparse.ArgumentParser(description="Email Phishing CLI - local or API mode (uses phish_core)",
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--file", "-f", required=True, help="Path to .eml file to analyze.")
    ap.add_argument("--out", "-o", default=None, help="Output directory or path for JSON/HTML reports (e.g., reports/report_name).")
    ap.add_argument("--html", action="store_true", help="Also generate an HTML report file.")
    ap.add_argument("--api", help="If provided, send file to this API URL (e.g. http://127.0.0.1:8000/analyze).")
    ap.add_argument("--timeout", type=int, default=30, help="Timeout seconds for API requests.")
    return ap.parse_args()

def main():
    args = parse_args()
    eml_path = Path(args.file)
    if not eml_path.exists():
        print(f"Error: file not found: {eml_path}")
        sys.exit(1)

    # 1. Choose analysis mode (API or local)
    try:
        if args.api:
            print(f"Analyzing via API: {args.api}...")
            report = analyze_via_api(eml_path, args.api, timeout=args.timeout)
        else:
            if not CORE_IMPORTED or analyze_file is None:
                raise RuntimeError("Local analysis requires 'phish_core.py' and its dependencies. Please check import status.")
            print("Analyzing locally...")
            report = analyze_file(str(eml_path))
    except Exception as e:
        print(f"\n[FATAL ERROR] Analysis failed: {e}")
        sys.exit(1)

    # 2. Save report
    if args.out:
        try:
            if save_report:
                # save_report handles path creation and extension setting
                saved_path = save_report(report, outdir=args.out, as_html=args.html)
                print(f"\n[SUCCESS] Report saved to: {saved_path}")
            else:
                 print("\n[WARNING] Could not save report. 'save_report' function is unavailable.")
        except Exception as e:
            print(f"\n[ERROR] Failed to save report: {e}")
    
    # 3. Print summary
    pretty_print_report(report)

if __name__ == "__main__":
    main()
