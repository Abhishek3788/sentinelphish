import asyncio
from typing import Dict, Any, List, Optional

import httpx

from app.config import settings
from app.layers.base import BaseLayer, LayerResult, RedFlag
from app.utils.logger import get_logger
from app.utils.api_clients import (
    check_google_safe_browsing,
    scan_virustotal,
    check_phishtank,
)

logger = get_logger("layers.api_intel")


class APIIntelLayer(BaseLayer):
    @property
    def name(self) -> str:
        return "api_intel"

    async def analyze(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        red_flags: List[RedFlag] = []
        risk_score = 0.0
        details: Dict[str, Any] = {}

        try:
            # Run all API checks concurrently
            tasks = [
                check_google_safe_browsing(url),
                scan_virustotal(url),
                check_phishtank(url),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Google Safe Browsing result
            sb_result = results[0]
            details["google_safe_browsing"] = sb_result
            if isinstance(sb_result, dict) and sb_result.get("threats"):
                risk_score += 30
                red_flags.append(RedFlag(severity="high", flag="Google Safe Browsing flagged URL as malicious"))

            # VirusTotal result
            vt_result = results[1]
            details["virustotal"] = vt_result
            if isinstance(vt_result, dict):
                positives = vt_result.get("positives", 0)
                total = vt_result.get("total", 0)
                if total and positives / total > 0.2:
                    risk_score += 25
                    red_flags.append(RedFlag(severity="medium", flag=f"VirusTotal detection ratio {positives}/{total}"))

            # PhishTank result
            pt_result = results[2]
            details["phishtank"] = pt_result
            if isinstance(pt_result, dict) and pt_result.get("in_database"):
                risk_score += 35
                red_flags.append(RedFlag(severity="high", flag="URL present in PhishTank database"))

            final_risk = min(100.0, float(risk_score))
            confidence = 0.85

            return LayerResult(
                layer_name=self.name,
                risk_score=final_risk,
                confidence=confidence,
                red_flags=red_flags,
                details=details,
            )
        except Exception as e:
            logger.error(f"APIIntel layer error for {url}: {e}")
            return LayerResult(
                layer_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                error=str(e),
            )
