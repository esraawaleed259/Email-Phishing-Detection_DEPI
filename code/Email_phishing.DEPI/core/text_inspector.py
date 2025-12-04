# core/text_inspector.py
"""
Text analysis utilities: find suspicious keywords and urgency language.
"""
from typing import List

DEFAULT_KEYWORDS = [
    "urgent", "verify", "verify your account", "click here",
    "immediately", "password", "suspend", "update your", "confirm your", "login"
]


def find_keywords(text: str, keywords=None) -> List[str]:
    if not text:
        return []
    t = text.lower()
    ks = keywords or DEFAULT_KEYWORDS
    found = []
    for k in ks:
        if k in t and k not in found:
            found.append(k)
    return found


def contains_urgent_language(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    urgent_terms = ["urgent", "immediately", "asap", "now", "attention required"]
    return any(w in t for w in urgent_terms)
