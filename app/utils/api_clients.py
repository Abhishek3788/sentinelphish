import httpx
import asyncio
from typing import Dict, Any, Optional

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger("utils.api_clients")


async def check_google_safe_browsing(url: str) -> Dict[str, Any]:
    """Check URL against Google Safe Browsing.
    Returns the JSON response or empty dict on failure.
    """
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        logger.debug("Google Safe Browsing API key not configured.")
        return {}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "sentinelphish", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(endpoint, json=payload)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.debug(f"Google Safe Browsing request failed {resp.status_code}: {resp.text}")
                return {}
    except Exception as e:
        logger.debug(f"Google Safe Browsing error: {e}")
        return {}


async def scan_virustotal(url: str) -> Dict[str, Any]:
    """Submit URL to VirusTotal and retrieve analysis summary.
    Returns a dict with 'positives' and 'total' counts or empty dict.
    """
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key:
        logger.debug("VirusTotal API key not configured.")
        return {}
    # Encode URL for VT endpoint
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(analysis_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())
                return {"positives": positives, "total": total, "details": data.get("last_analysis_results", {})}
            else:
                logger.debug(f"VirusTotal request failed {resp.status_code}: {resp.text}")
                return {}
    except Exception as e:
        logger.debug(f"VirusTotal error: {e}")
        return {}


async def check_phishtank(url: str) -> Dict[str, Any]:
    """Check URL against PhishTank public feed.
    Returns dict with 'in_database' flag.
    """
    # Use the public CSV feed (no API key required)
    feed_url = "https://data.phishtank.com/data/online-valid.csv"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(feed_url)
            if resp.status_code == 200:
                # Simple substring check – not efficient but works for demo
                in_db = url in resp.text
                return {"in_database": in_db}
            else:
                logger.debug(f"PhishTank feed fetch failed {resp.status_code}")
                return {"in_database": False}
    except Exception as e:
        logger.debug(f"PhishTank error: {e}")
        return {"in_database": False}
