from datetime import datetime, timezone
import uuid
from typing import Any, Dict, Optional
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    url = Column(Text, nullable=False)
    url_hash = Column(String(64), nullable=False, index=True)
    url_redacted = Column(Text, nullable=False)
    verdict = Column(String(20), nullable=False)  # Safe, Suspicious, Phishing
    risk_score = Column(Float, nullable=False)  # 0 to 100
    confidence = Column(String(20), nullable=False)  # low, medium, high
    layer_scores = Column(JSON, nullable=False)
    red_flags = Column(JSON, nullable=False)
    explanation = Column(Text, nullable=True)
    processing_time_ms = Column(Float, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True)

    feedbacks = relationship("Feedback", back_populates="scan", cascade="all, delete-orphan")


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    is_correct = Column(Boolean, nullable=False)
    user_comment = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    scan = relationship("Scan", back_populates="feedbacks")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    owner_email = Column(String(255), nullable=False)
    rate_limit_per_day = Column(Integer, default=1000)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    url_hash = Column(String(64), nullable=False, index=True)
    source = Column(String(50), nullable=False)
    result = Column(JSON, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
