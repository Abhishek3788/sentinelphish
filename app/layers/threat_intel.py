import asyncio
from typing import Dict, Any, List, Optional
import httpx
from app.config import settings
from app.layers.base import BaseLayer, LayerResult, RedFlag
from app.utils.cache import AsyncCache
from app.utils.validators import hash_url
from app.utils.logger import get_logger

logger = get_logger("layers.threat_intel")


class ThreatIntelLayer(BaseLayer):
    @property
    def name(self) -> str:
        return "threat_intel"

    async def analyze(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        red_flags: List[RedFlag] = []
        risk_score = 0.0
        details: Dict[str, Any] = {}

        url_h = hash_url(url)
        cache_key = f"threat_intel:{url_h}"
        cached_result = await AsyncCache.get(cache_key)
        if cached_result:
            logger.info("Returning cached Threat Intel result.")
            return LayerResult(**cached_result)

        # Concurrently query available threat intel services
        results = await asyncio.gather(
            self._check_urlhaus(url),
            self._check_openphish(url),
            self._check_google_safe_browsing(url),
            self._check_virustotal(url),
            return_exceptions=True
        )

        sources = ["urlhaus", "openphish", "google_safe_browsing", "virustotal"]
        hits = []

        for idx, res in enumerate(results):
            source_name = sources[idx]
            if isinstance(res, dict) and res.get("is_phishing"):
                hits.append(source_name)
                details[source_name] = res
                red_flags.append(RedFlag(severity="high", flag=f"Flagged as malicious by {source_name.upper()}"))
            elif isinstance(res, dict):
                details[source_name] = res

        if hits:
            # Overriding rule: any threat intel hit means >= 95 risk score
            risk_score = 98.0
            confidence = 0.99
        else:
            risk_score = 0.0
            confidence = 0.85

        final_res = LayerResult(
            layer_name=self.name,
            risk_score=risk_score,
            confidence=confidence,
            red_flags=red_flags,
            details=details
        )

        # Cache for 24 hours
        await AsyncCache.set(cache_key, final_res.model_dump(), ttl=86400)
        return final_res

    async def _check_urlhaus(self, url: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("query_status")
                    if status == "ok" and data.get("url_status") == "online":
                        return {"is_phishing": True, "threat": data.get("threat")}
        except Exception as e:
            logger.debug(f"URLhaus lookup error: {e}")
        return {"is_phishing": False}

    async def _check_openphish(self, url: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get("https://openphish.com/feed.txt")
                if resp.status_code == 200:
                    if url in resp.text:
                        return {"is_phishing": True, "source": "openphish_feed"}
        except Exception as e:
            logger.debug(f"OpenPhish feed error: {e}")
        return {"is_phishing": False}

    async def _check_google_safe_browsing(self, url: str) -> Dict[str, Any]:
        if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
            return {"is_phishing": False, "skipped": "No API key"}
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
            body = {
                "client": {"clientId": "sentinelphish", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(endpoint, json=body)
                if resp.status_code == 200 and resp.json().get("matches"):
                    return {"is_phishing": True, "matches": resp.json()["matches"]}
        except Exception as e:
            logger.debug(f"Google Safe Browsing error: {e}")
        return {"is_phishing": False}

    async def _check_virustotal(self, url: str) -> Dict[str, Any]:
        if not settings.VIRUSTOTAL_API_KEY:
            return {"is_phishing": False, "skipped": "No API key"}
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
                if resp.status_code == 200:
                    stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    if malicious > 0:
                        return {"is_phishing": True, "malicious_count": malicious}
        except Exception as e:
            logger.debug(f"VirusTotal error: {e}")
        return {"is_phishing": False}
