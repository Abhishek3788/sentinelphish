import json
from typing import Dict, Any, List, Optional
import httpx
from app.config import settings
from app.layers.base import BaseLayer, LayerResult, RedFlag
from app.utils.logger import get_logger

logger = get_logger("layers.llm_reasoning")


class LLMReasoningLayer(BaseLayer):
    @property
    def name(self) -> str:
        return "ai_analysis"

    async def analyze(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        red_flags: List[RedFlag] = []
        details: Dict[str, Any] = {}

        if not settings.GROQ_API_KEY:
            logger.info("Groq API key not provided. Executing local LLM heuristic model.")
            return self._heuristic_fallback(url, context)

        # Prepare context payload for LLM prompt
        snippet = context.get("extracted_text_snippet", "") if context else ""
        lexical_flags = context.get("lexical_flags", []) if context else []
        domain_info = context.get("domain_info", {}) if context else {}

        prompt = f"""You are an expert cybersecurity threat analyst specializing in phishing URL detection.
Analyze the following URL and telemetry details:

URL: {url}
Extracted Page Text (first 300 chars): {snippet}
Lexical Red Flags: {lexical_flags}
Domain Info: {domain_info}

Perform step-by-step security reasoning. Evaluate typosquatting, deceptive brand usage, credential harvesting intent, and URL obfuscation.
Output strict JSON matching this exact structure:
{{
    "verdict": "Phishing" | "Suspicious" | "Safe",
    "risk_score": <number between 0 and 100>,
    "confidence": <number between 0.0 and 1.0>,
    "red_flags": ["flag 1", "flag 2"],
    "reasoning": "<concise explanation>"
}}
Do NOT output markdown backticks or any conversational text around the JSON object.
"""

        try:
            from groq import AsyncGroq
            client = AsyncGroq(api_key=settings.GROQ_API_KEY)
            
            chat_completion = await client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are a cybersecurity AI. Respond ONLY with raw valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                model="llama-3.3-70b-versatile",
                temperature=0.1,
                max_tokens=400,
                response_format={"type": "json_object"}
            )

            raw_response = chat_completion.choices[0].message.content or "{}"
            data = json.loads(raw_response)

            score = float(data.get("risk_score", 0.0))
            confidence = float(data.get("confidence", 0.85))
            reasoning = data.get("reasoning", "")
            
            for f in data.get("red_flags", []):
                red_flags.append(RedFlag(severity="high" if score > 70 else "medium", flag=f))

            details["reasoning"] = reasoning
            details["verdict"] = data.get("verdict", "Safe")

            return LayerResult(
                layer_name=self.name,
                risk_score=min(100.0, max(0.0, score)),
                confidence=confidence,
                red_flags=red_flags,
                details=details
            )

        except Exception as e:
            logger.warning(f"Groq API execution failed ({e}). Falling back to heuristic reasoning.")
            return self._heuristic_fallback(url, context)

    def _heuristic_fallback(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        """Local AI heuristic fallback when Groq API key is not present."""
        red_flags: List[RedFlag] = []
        score = 0.0
        reasoning_parts = []

        url_lower = url.lower()
        if any(b in url_lower for b in ["paypal", "bank", "login", "verify", "secure", "account"]):
            score += 45.0
            reasoning_parts.append("URL contains high-risk brand/credential target terms.")
            red_flags.append(RedFlag(severity="medium", flag="Brand target keywords found in URL path"))

        if "@" in url or "xn--" in url:
            score += 35.0
            reasoning_parts.append("Deceptive URL structure detected.")
            red_flags.append(RedFlag(severity="high", flag="Obfuscated URL structure"))

        if score == 0.0:
            score = 5.0
            reasoning_parts.append("URL exhibits standard structural patterns.")

        return LayerResult(
            layer_name=self.name,
            risk_score=score,
            confidence=0.7,
            red_flags=red_flags,
            details={"reasoning": " ".join(reasoning_parts), "fallback_mode": True}
        )
