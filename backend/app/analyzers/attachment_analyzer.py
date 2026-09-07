"""
Attachment Analyzer.

Performs STATIC analysis only on attachment metadata -- filename,
extension, MIME type, size, and SHA-256 hash (computed in the parser).
Attachments are NEVER executed or opened by this platform.
"""

SUSPICIOUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "jar",
    "msi", "com", "pif", "hta", "wsf",
}

MACRO_ENABLED_EXTENSIONS = {
    "docm", "xlsm", "pptm", "dotm", "xltm", "potm",
}


class AttachmentAnalyzer:
    """Analyzes a single attachment's metadata for suspicious characteristics."""

    def __init__(self, attachment: dict):
        self.attachment = attachment
        self.reasons = []
        self.score = 0

    def analyze(self) -> dict:
        extension = (self.attachment.get("extension") or "").lower()
        filename = self.attachment.get("filename", "unknown")

        is_suspicious_extension = extension in SUSPICIOUS_EXTENSIONS
        is_macro_enabled = extension in MACRO_ENABLED_EXTENSIONS

        if is_suspicious_extension:
            self.score += 60
            self.reasons.append(
                f"Attachment '{filename}' has a high-risk executable extension (.{extension})"
            )

        if is_macro_enabled:
            self.score += 40
            self.reasons.append(
                f"Attachment '{filename}' is a macro-enabled Office document (.{extension}), "
                "which can run embedded code if macros are allowed"
            )

        name_parts = filename.lower().split(".")
        if len(name_parts) > 2 and name_parts[-1] in SUSPICIOUS_EXTENSIONS:
            self.score += 20
            self.reasons.append(
                f"Attachment '{filename}' uses a double extension, a common disguise trick"
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
            "filename": filename,
            "extension": extension,
            "mime_type": self.attachment.get("mime_type"),
            "size_bytes": self.attachment.get("size_bytes"),
            "sha256": self.attachment.get("sha256"),
            "is_suspicious": final_score > 0,
            "risk_score": final_score,
            "risk_level": risk_level,
            "reasons": self.reasons,
        }


def analyze_attachments(attachments: list) -> list:
    """Convenience function: analyzes a list of attachments."""
    return [AttachmentAnalyzer(a).analyze() for a in attachments]