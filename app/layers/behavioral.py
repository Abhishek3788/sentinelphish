import hashlib
from typing import Dict, Any, List, Optional
import httpx
import tldextract
from app.layers.base import BaseLayer, LayerResult, RedFlag
from app.utils.logger import get_logger

logger = get_logger("layers.behavioral")


class BehavioralLayer(BaseLayer):
    @property
    def name(self) -> str:
        return "behavioral"

    async def analyze(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        red_flags: List[RedFlag] = []
        risk_score = 0.0
        details: Dict[str, Any] = {}

        try:
            # 1. User-Agent Cloaking Check (Browser UA vs Bot UA diff)
            cloaking_detected = await self._check_ua_cloaking(url)
            details["cloaking_detected"] = cloaking_detected
            if cloaking_detected:
                risk_score += 40.0
                red_flags.append(RedFlag(
                    severity="high",
                    flag="User-Agent cloaking detected (server serving different content to web bots vs browsers)"
                ))

            # 2. Campaign pattern hash (URL structure fingerprinting)
            extracted = tldextract.extract(url)
            pattern_str = f"{len(extracted.subdomain)}.{len(extracted.domain)}.{extracted.suffix}:{url.count('/')}:{url.count('?')}"
            pattern_hash = hashlib.md5(pattern_str.encode()).hexdigest()[:12]
            details["campaign_pattern_hash"] = pattern_hash

            # 3. Shortener expanded target verification
            if context and context.get("is_shortener"):
                expanded_target = await self._expand_shortener(url)
                details["expanded_target"] = expanded_target
                if expanded_target and expanded_target != url:
                    red_flags.append(RedFlag(
                        severity="medium",
                        flag=f"Shortened URL expands to: {expanded_target}"
                    ))
                    risk_score += 15.0

            final_risk = min(100.0, float(risk_score))
            confidence = 0.8

            return LayerResult(
                layer_name=self.name,
                risk_score=final_risk,
                confidence=confidence,
                red_flags=red_flags,
                details=details
            )

        except Exception as e:
            logger.error(f"Behavioral layer error for {url}: {e}")
            return LayerResult(
                layer_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                error=str(e)
            )

    async def _check_ua_cloaking(self, url: str) -> bool:
        browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36"
        bot_ua = "Googlebot/2.1 (+http://www.google.com/bot.html)"
        
        try:
            async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
                res_browser = await client.get(url, headers={"User-Agent": browser_ua})
                res_bot = await client.get(url, headers={"User-Agent": bot_ua})
                
                # If status code differs dramatically (e.g. 200 vs 403/404) or length ratio > 3x
                if res_browser.status_code == 200 and res_bot.status_code in [403, 404, 401]:
                    return True
                
                len_b = len(res_browser.text)
                len_bot = len(res_bot.text)
                if len_b > 1000 and len_bot > 0 and (len_b / max(1, len_bot) > 3.0 or len_bot / max(1, len_b) > 3.0):
                    return True
        except Exception:
            pass
        return False

    async def _expand_shortener(self, url: str) -> Optional[str]:
        try:
            async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
                res = await client.head(url)
                return str(res.url)
        except Exception:
            return None
