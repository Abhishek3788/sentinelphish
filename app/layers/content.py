from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import imagehash
from PIL import Image
import io
import httpx
import trafilatura
from app.layers.base import BaseLayer, LayerResult, RedFlag
from app.utils.sandbox import safe_fetch_page_content, extract_page_features
from app.utils.logger import get_logger

logger = get_logger("layers.content")


class ContentLayer(BaseLayer):
    @property
    def name(self) -> str:
        return "content"

    async def analyze(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        red_flags: List[RedFlag] = []
        risk_score = 0.0
        details: Dict[str, Any] = {}

        try:
            page_data = await safe_fetch_page_content(url, timeout=8.0)
            html = page_data.get("html", "")
            status_code = page_data.get("status_code")
            redirects = page_data.get("redirect_chain", [])

            details["status_code"] = status_code
            details["redirect_chain_length"] = len(redirects)

            if not html or status_code in [404, 500, 502, 503]:
                return LayerResult(
                    layer_name=self.name,
                    risk_score=15.0,
                    confidence=0.5,
                    details={"error": f"Page failed to load properly (Status: {status_code})"}
                )

            # 1. Structural features extraction
            features = extract_page_features(html)
            details["forms_found"] = features["form_count"]
            details["has_password_field"] = features["has_password_field"]

            # 2. Cross-domain form submission check
            target_domain = urlparse(url).netloc.lower()
            cross_domain_forms = []
            for action in features["form_action_urls"]:
                if action.startswith("http"):
                    action_domain = urlparse(action).netloc.lower()
                    if action_domain and action_domain != target_domain:
                        cross_domain_forms.append(action)

            if cross_domain_forms:
                risk_score += 40
                red_flags.append(RedFlag(severity="high", flag=f"Cross-domain form submission detected (submitting to: {cross_domain_forms[0]})"))
                details["cross_domain_actions"] = cross_domain_forms

            # 3. Password field on non-HTTPS or suspicious site
            if features["has_password_field"]:
                if not url.startswith("https://"):
                    risk_score += 40
                    red_flags.append(RedFlag(severity="high", flag="Password form present on insecure HTTP connection"))
                else:
                    risk_score += 15

            # 4. JS Obfuscation
            if features["has_js_obfuscation"]:
                risk_score += 25
                red_flags.append(RedFlag(severity="medium", flag="Obfuscated JavaScript code detected"))

            # 5. Multiple redirects check
            if len(redirects) > 2:
                risk_score += 20
                red_flags.append(RedFlag(severity="medium", flag=f"Excessive HTTP redirects ({len(redirects)} hops)"))

            # 6. Hidden iframes check
            if features["iframe_count"] > 2:
                risk_score += 15
                red_flags.append(RedFlag(severity="low", flag=f"Multiple hidden iframes detected ({features['iframe_count']})"))

            # 7. Text extraction using trafilatura
            extracted_text = trafilatura.extract(html) or features["text_content"]
            details["extracted_text_snippet"] = extracted_text[:300] if extracted_text else ""
            
            # Check for credential harvesting prompt phrases
            phishing_phrases = ["confirm your account", "verify your identity", "suspended due to unusual activity", "update payment info", "account locked"]
            matched_phrases = [p for p in phishing_phrases if p in extracted_text.lower()]
            if matched_phrases:
                risk_score += 20
                red_flags.append(RedFlag(severity="medium", flag=f"Urgency/credential harvesting language found: '{matched_phrases[0]}'"))

            final_risk = min(100.0, float(risk_score))
            confidence = 0.85

            return LayerResult(
                layer_name=self.name,
                risk_score=final_risk,
                confidence=confidence,
                red_flags=red_flags,
                details=details
            )

        except Exception as e:
            logger.error(f"Content layer error for {url}: {e}")
            return LayerResult(
                layer_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                error=str(e)
            )
