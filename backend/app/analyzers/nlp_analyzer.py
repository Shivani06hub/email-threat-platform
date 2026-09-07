"""
NLP Phishing Analyzer.

Scans email body text for phishing-style language patterns across
several categories: urgency, credential harvesting, threats/fear,
financial requests, and prize/scam language.

IMPORTANT LIMITATION: This is keyword/phrase-based detection, not
true NLP understanding. It can miss cleverly-worded phishing that
avoids these exact phrases, and can occasionally flag legitimate
urgent emails as suspicious. This is one signal among several in
the Correlation Engine (Phase 11), not a standalone verdict.
"""

import re


PHRASE_CATEGORIES = {
    "urgency": {
        "weight": 15,
        "phrases": [
            "immediately", "urgent", "within 24 hours", "act now",
            "as soon as possible", "expire", "final notice", "last chance",
            "time sensitive", "right away",
        ],
    },
    "credential_harvesting": {
        "weight": 30,
        "phrases": [
            "verify your identity", "verify your account", "confirm your password",
            "confirm your identity", "update your information", "click here to login",
            "re-enter your password", "validate your account", "sign in to confirm",
        ],
    },
    "threat_fear": {
        "weight": 25,
        "phrases": [
            "account will be suspended", "account suspended", "unauthorized access",
            "suspicious activity", "your account has been locked", "legal action",
            "account will be closed", "permanent suspension", "security breach",
        ],
    },
    "financial_request": {
        "weight": 25,
        "phrases": [
            "wire transfer", "gift card", "payment required", "bank details",
            "credit card information", "processing fee", "transfer funds",
            "invoice attached", "urgent payment",
        ],
    },
    "prize_scam": {
        "weight": 20,
        "phrases": [
            "you have won", "claim your reward", "congratulations you", "lottery",
            "free gift", "you are selected", "claim now",
        ],
    },
}


class NLPAnalyzer:
    """Analyzes email body text for phishing-style language patterns."""

    def __init__(self, body_text: str):
        self.body_text = (body_text or "").lower()
        self.reasons = []
        self.matched_phrases = {}
        self.score = 0

    def analyze(self) -> dict:
        for category, config in PHRASE_CATEGORIES.items():
            matches = [
                phrase for phrase in config["phrases"]
                if phrase in self.body_text
            ]
            if matches:
                self.matched_phrases[category] = matches
                self.score += config["weight"]
                readable_category = category.replace("_", " ").title()
                self.reasons.append(
                    f"{readable_category} language detected: {', '.join(matches[:3])}"
                )

        final_score = min(self.score, 100)

        if final_score >= 70:
            risk_level = "HIGH"
        elif final_score >= 40:
            risk_level = "MEDIUM"
        elif final_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        return {
            "nlp_risk_score": final_score,
            "risk_level": risk_level,
            "reasons": self.reasons,
            "matched_phrases": self.matched_phrases,
            "limitation_note": (
                "This is keyword/phrase-based detection, not true language "
                "understanding. It can miss cleverly-worded phishing and can "
                "occasionally flag legitimate urgent emails. Treat this as one "
                "signal among several, not a standalone verdict."
            ),
        }