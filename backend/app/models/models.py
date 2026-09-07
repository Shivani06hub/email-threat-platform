"""
Core database models for the Email Threat Intelligence Platform.

These map directly to the schema we designed in Phase 0:
Case -> Email -> (IPAddress, Domain, URL, Attachment) -> IOC -> AnalysisResult

Kept in one file for now since the model set is still small.
"""

from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, Boolean, Float, Text, DateTime, ForeignKey
)
from sqlalchemy.orm import relationship

from app.database.session import Base
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="analyst")
    created_at = Column(DateTime, default=datetime.utcnow)


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, unique=True, index=True)  # human-readable e.g. CASE-0001
    status = Column(String, default="OPEN")  # OPEN, INVESTIGATING, CONFIRMED, FALSE POSITIVE, CLOSED
    threat_level = Column(String, nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    emails = relationship("Email", back_populates="case", cascade="all, delete-orphan")


class Email(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"))

    subject = Column(String, nullable=True)
    sender = Column(String, nullable=True)
    recipient = Column(String, nullable=True)
    reply_to = Column(String, nullable=True)
    date = Column(String, nullable=True)
    message_id = Column(String, nullable=True)
    raw_eml_path = Column(String, nullable=True)
    analysis_json = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="emails")
    ip_addresses = relationship("IPAddress", back_populates="email", cascade="all, delete-orphan")
    domains = relationship("Domain", back_populates="email", cascade="all, delete-orphan")
    urls = relationship("URLModel", back_populates="email", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="email", cascade="all, delete-orphan")
    analysis_results = relationship("AnalysisResult", back_populates="email", cascade="all, delete-orphan")


class IPAddress(Base):
    __tablename__ = "ip_addresses"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))

    ip = Column(String, index=True)
    ip_type = Column(String, nullable=True)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    lat = Column(Float, nullable=True)
    lon = Column(Float, nullable=True)
    isp = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    is_public = Column(Boolean, default=True)

    email = relationship("Email", back_populates="ip_addresses")


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))

    domain = Column(String, index=True)
    is_sender_domain = Column(Boolean, default=False)
    age_days = Column(Integer, nullable=True)
    registrar = Column(String, nullable=True)

    email = relationship("Email", back_populates="domains")


class URLModel(Base):
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))

    url = Column(Text)
    domain = Column(String, nullable=True)
    is_shortened = Column(Boolean, default=False)
    is_https = Column(Boolean, default=False)
    risk_score = Column(Integer, nullable=True)
    reasons_json = Column(Text, nullable=True)

    email = relationship("Email", back_populates="urls")


class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))

    filename = Column(String, nullable=True)
    extension = Column(String, nullable=True)
    mime_type = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=True)
    sha256 = Column(String, nullable=True)
    is_suspicious = Column(Boolean, default=False)

    email = relationship("Email", back_populates="attachments")


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"))

    type = Column(String)
    value = Column(String)
    risk_level = Column(String, nullable=True)
    source_module = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"))

    module_name = Column(String)
    score = Column(Integer, nullable=True)
    verdict = Column(String, nullable=True)
    details_json = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    email = relationship("Email", back_populates="analysis_results")