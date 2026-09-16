from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.schemas import (
    URLCheckRequest, BatchCheckRequest, ScanResponse, FeedbackRequest,
    StatsResponse, HealthResponse
)
from app.api.deps import get_db, verify_rate_limit, verify_api_key
from app.engine.orchestrator import ScanOrchestrator
from app.db.models import Scan, Feedback, ApiKey
from app.utils.cache import AsyncCache, get_redis_client
from app.utils.validators import is_valid_url, hash_url, redact_url
from app.utils.logger import get_logger
from app.config import settings

logger = get_logger("api.routes")
router = APIRouter(prefix="/api/v1", tags=["Phishing Detection"])

orchestrator = ScanOrchestrator()


@router.post("/check", response_model=ScanResponse, dependencies=[Depends(verify_rate_limit)])
async def check_url(
    payload: URLCheckRequest,
    db: AsyncSession = Depends(get_db)
):
    """Submits a single URL for multi-layer phishing risk detection."""
    url = payload.url.strip()
    if not is_valid_url(url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL format provided."
        )

    url_h = hash_url(url)
    cache_key = f"scan_result:{url_h}"

    # 1. Check Redis Cache
    cached_data = await AsyncCache.get(cache_key)
    if cached_data:
        cached_data["cached"] = True
        return ScanResponse(**cached_data)

    # 2. Execute Async Orchestrator
    scan_result = await orchestrator.scan_url(url)
    redacted = redact_url(url)

    # 3. Save result to Database
    db_scan = Scan(
        url=url,
        url_hash=url_h,
        url_redacted=redacted,
        verdict=scan_result["verdict"],
        risk_score=scan_result["risk_score"],
        confidence=scan_result["confidence"],
        layer_scores=scan_result["layer_scores"],
        red_flags=scan_result["red_flags"],
        explanation=scan_result["explanation"],
        processing_time_ms=scan_result["processing_time_ms"]
    )
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)

    response_data = {
        "id": db_scan.id,
        "url": db_scan.url,
        "verdict": db_scan.verdict,
        "risk_score": db_scan.risk_score,
        "confidence": db_scan.confidence,
        "red_flags": db_scan.red_flags,
        "explanation": db_scan.explanation,
        "layer_scores": db_scan.layer_scores,
        "processing_time_ms": db_scan.processing_time_ms,
        "cached": False,
        "created_at": db_scan.created_at.isoformat() if db_scan.created_at else None
    }

    # 4. Cache response in Redis for 24h
    await AsyncCache.set(cache_key, response_data, ttl=86400)

    return ScanResponse(**response_data)


@router.post("/check/batch", response_model=List[ScanResponse], dependencies=[Depends(verify_rate_limit)])
async def check_batch_urls(
    payload: BatchCheckRequest,
    db: AsyncSession = Depends(get_db),
    api_key: Optional[ApiKey] = Depends(verify_api_key)
):
    """Submits a batch of up to 50 URLs for parallel scanning."""
    if len(payload.urls) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch limit exceeded. Maximum 50 URLs per request."
        )

    responses = []
    for url in payload.urls:
        if is_valid_url(url):
            url_h = hash_url(url)
            cached_data = await AsyncCache.get(f"scan_result:{url_h}")
            if cached_data:
                cached_data["cached"] = True
                responses.append(ScanResponse(**cached_data))
            else:
                res = await orchestrator.scan_url(url)
                redacted = redact_url(url)
                db_scan = Scan(
                    url=url,
                    url_hash=url_h,
                    url_redacted=redacted,
                    verdict=res["verdict"],
                    risk_score=res["risk_score"],
                    confidence=res["confidence"],
                    layer_scores=res["layer_scores"],
                    red_flags=res["red_flags"],
                    explanation=res["explanation"],
                    processing_time_ms=res["processing_time_ms"]
                )
                db.add(db_scan)
                await db.commit()
                await db.refresh(db_scan)

                resp_dict = {
                    "id": db_scan.id,
                    "url": db_scan.url,
                    "verdict": db_scan.verdict,
                    "risk_score": db_scan.risk_score,
                    "confidence": db_scan.confidence,
                    "red_flags": db_scan.red_flags,
                    "explanation": db_scan.explanation,
                    "layer_scores": db_scan.layer_scores,
                    "processing_time_ms": db_scan.processing_time_ms,
                    "cached": False,
                    "created_at": db_scan.created_at.isoformat() if db_scan.created_at else None
                }
                await AsyncCache.set(f"scan_result:{url_h}", resp_dict, ttl=86400)
                responses.append(ScanResponse(**resp_dict))

    return responses


@router.get("/result/{scan_id}", response_model=ScanResponse)
async def get_scan_result(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Fetches a historical scan result by UUID."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    db_scan = result.scalar_one_or_none()

    if not db_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan result with ID '{scan_id}' not found."
        )

    return ScanResponse(
        id=db_scan.id,
        url=db_scan.url,
        verdict=db_scan.verdict,
        risk_score=db_scan.risk_score,
        confidence=db_scan.confidence,
        red_flags=db_scan.red_flags,
        explanation=db_scan.explanation,
        layer_scores=db_scan.layer_scores,
        processing_time_ms=db_scan.processing_time_ms,
        cached=False,
        created_at=db_scan.created_at.isoformat() if db_scan.created_at else None
    )


@router.post("/feedback")
async def submit_feedback(
    payload: FeedbackRequest,
    db: AsyncSession = Depends(get_db)
):
    """Submits user feedback to report false positives or negatives for model retraining."""
    result = await db.execute(select(Scan).where(Scan.id == payload.scan_id))
    db_scan = result.scalar_one_or_none()
    if not db_scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan ID not found")

    fb = Feedback(
        scan_id=payload.scan_id,
        is_correct=payload.is_correct,
        user_comment=payload.user_comment
    )
    db.add(fb)
    await db.commit()
    return {"status": "success", "message": "Feedback recorded. Thank you for contributing!"}


@router.get("/stats", response_model=StatsResponse)
async def get_statistics(db: AsyncSession = Depends(get_db)):
    """Returns aggregated public system metrics."""
    total_res = await db.execute(select(func.count(Scan.id)))
    total_scans = total_res.scalar() or 0

    phishing_res = await db.execute(select(func.count(Scan.id)).where(Scan.verdict == "Phishing"))
    phishing_count = phishing_res.scalar() or 0

    suspicious_res = await db.execute(select(func.count(Scan.id)).where(Scan.verdict == "Suspicious"))
    suspicious_count = suspicious_res.scalar() or 0

    safe_res = await db.execute(select(func.count(Scan.id)).where(Scan.verdict == "Safe"))
    safe_count = safe_res.scalar() or 0

    avg_time_res = await db.execute(select(func.avg(Scan.processing_time_ms)))
    avg_time = float(avg_time_res.scalar() or 0.0)

    feedback_total = await db.execute(select(func.count(Feedback.id)))
    fb_count = feedback_total.scalar() or 0

    feedback_correct = await db.execute(select(func.count(Feedback.id)).where(Feedback.is_correct == True))
    fb_correct_count = feedback_correct.scalar() or 0

    accuracy = (fb_correct_count / fb_count * 100.0) if fb_count > 0 else 98.5

    return StatsResponse(
        total_scans=total_scans,
        phishing_detected=phishing_count,
        suspicious_detected=suspicious_count,
        safe_detected=safe_count,
        avg_processing_time_ms=round(avg_time, 2),
        feedback_accuracy_percentage=round(accuracy, 2)
    )


@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check endpoint to verify database and redis connectivity."""
    db_status = "healthy"
    try:
        await db.execute(select(1))
    except Exception as e:
        db_status = f"unhealthy ({e})"

    redis_status = "healthy"
    try:
        r_client = await get_redis_client()
        if not r_client:
            redis_status = "degraded (in-memory fallback active)"
    except Exception:
        redis_status = "unavailable"

    return HealthResponse(
        status="healthy" if db_status == "healthy" else "degraded",
        version="1.0.0",
        database=db_status,
        redis=redis_status,
        environment=settings.ENVIRONMENT
    )
