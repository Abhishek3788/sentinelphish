from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl


class URLCheckRequest(BaseModel):
    url: str = Field(..., description="The target URL to scan for phishing threat indicators.")


class BatchCheckRequest(BaseModel):
    urls: List[str] = Field(..., max_length=50, description="List of up to 50 URLs to scan concurrently.")


class RedFlagSchema(BaseModel):
    severity: str  # 'high', 'medium', 'low'
    flag: str


class ScanResponse(BaseModel):
    id: str
    url: str
    verdict: str  # 'Safe', 'Suspicious', 'Phishing'
    risk_score: float  # 0 to 100
    confidence: str  # 'low', 'medium', 'high'
    red_flags: List[RedFlagSchema]
    explanation: Optional[str] = None
    layer_scores: Dict[str, float]
    processing_time_ms: float
    cached: bool = False
    created_at: Optional[str] = None


class FeedbackRequest(BaseModel):
    scan_id: str
    is_correct: bool
    user_comment: Optional[str] = None


class StatsResponse(BaseModel):
    total_scans: int
    phishing_detected: int
    suspicious_detected: int
    safe_detected: int
    avg_processing_time_ms: float
    feedback_accuracy_percentage: float


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    redis: str
    environment: str
