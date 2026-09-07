"""
Email Parser.

Takes raw .eml bytes (or raw email text) and extracts structured data:
headers, sender/recipient info, body text, attachments metadata,
and any URLs / IP addresses found in the headers or body.

This module ONLY parses and extracts -- it does not judge anything
as safe or malicious. That judgment happens in later phases
(header analyzer, NLP analyzer, ML model, correlation engine).
"""

import re
import hashlib
import email
from email import policy
from email.parser import BytesParser


URL_PATTERN = re.compile(r'https?://[^\s\'"<>]+')
IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')


class EmailParser:
    """Parses a raw .eml file into structured, easy-to-use data."""

    def __init__(self, raw_bytes: bytes):
        self.raw_bytes = raw_bytes
        self.message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    def get_headers(self) -> dict:
        return {key: str(value) for key, value in self.message.items()}

    def get_basic_fields(self) -> dict:
        return {
            "from": self.message.get("From", ""),
            "to": self.message.get("To", ""),
            "cc": self.message.get("Cc", ""),
            "reply_to": self.message.get("Reply-To", ""),
            "subject": self.message.get("Subject", ""),
            "date": self.message.get("Date", ""),
            "message_id": self.message.get("Message-ID", ""),
            "return_path": self.message.get("Return-Path", ""),
        }

    def get_authentication_results(self) -> dict:
        return {
            "authentication_results": self.message.get("Authentication-Results", ""),
            "received_spf": self.message.get("Received-SPF", ""),
        }

    def get_received_chain(self) -> list:
        return self.message.get_all("Received", [])

    def get_body_text(self) -> str:
        if self.message.is_multipart():
            for part in self.message.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        return part.get_content()
                    except Exception:
                        continue
            for part in self.message.walk():
                if part.get_content_type() == "text/html":
                    try:
                        html = part.get_content()
                        return re.sub(r'<[^>]+>', ' ', html)
                    except Exception:
                        continue
            return ""
        else:
            try:
                return self.message.get_content()
            except Exception:
                return ""

    def get_attachments(self) -> list:
        """Returns metadata about each attachment -- never the file's raw content here."""
        attachments = []
        if self.message.is_multipart():
            for part in self.message.walk():
                content_disposition = part.get_content_disposition()
                if content_disposition == "attachment":
                    filename = part.get_filename() or "unknown"
                    payload = part.get_payload(decode=True) or b""
                    attachments.append({
                        "filename": filename,
                        "extension": filename.split(".")[-1].lower() if "." in filename else "",
                        "mime_type": part.get_content_type(),
                        "size_bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
                    })
        return attachments

    def extract_urls(self) -> list:
        body = self.get_body_text()
        return list(set(URL_PATTERN.findall(body)))

    def extract_ips(self) -> list:
        all_headers_text = "\n".join(self.get_received_chain())
        return list(set(IP_PATTERN.findall(all_headers_text)))

    def parse(self) -> dict:
        return {
            "basic_fields": self.get_basic_fields(),
            "authentication": self.get_authentication_results(),
            "received_chain": self.get_received_chain(),
            "headers": self.get_headers(),
            "body_text": self.get_body_text(),
            "attachments": self.get_attachments(),
            "urls": self.extract_urls(),
            "ips": self.extract_ips(),
        }