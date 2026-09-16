import asyncio
import time
from typing import Dict, Any, Optional
from app.config import settings
from app.layers.base import LayerResult
from app.layers.lexical import LexicalLayer
from app.layers.domain_intel import DomainIntelLayer
from app.layers.content import ContentLayer
from app.layers.threat_intel import ThreatIntelLayer
from app.layers.visual import VisualSimilarityLayer
from app.layers.api_intel import APIIntelLayer
from app.layers.llm_reasoning import LLMReasoningLayer
from app.layers.ml_ensemble import MLEnsembleLayer
from app.layers.behavioral import BehavioralLayer
from app.engine.fusion import fuse_layer_results, FusionResult
from app.utils.logger import get_logger

logger = get_logger("engine.orchestrator")


class ScanOrchestrator:
    def __init__(self):
        self.lexical_layer = LexicalLayer()
        self.domain_layer = DomainIntelLayer()
        self.api_intel_layer = APIIntelLayer()
        self.content_layer = ContentLayer()
        self.threat_layer = ThreatIntelLayer()
        self.visual_layer = VisualSimilarityLayer()
        self.ai_layer = LLMReasoningLayer()
        self.ml_layer = MLEnsembleLayer()
        self.behavioral_layer = BehavioralLayer()

    async def scan_url(self, url: str) -> Dict[str, Any]:
        start_time = time.time()
        logger.info(f"Starting orchestration scan for URL: {url}")

        # Dictionary to gather layer outcomes
        results: Dict[str, Optional[LayerResult]] = {}

        async def run_with_timeout(layer_name: str, coroutine, timeout: float) -> tuple[str, Optional[LayerResult]]:
            try:
                result = await asyncio.wait_for(coroutine, timeout=timeout)
                return layer_name, result
            except asyncio.TimeoutError:
                logger.warning(f"Layer '{layer_name}' timed out after {timeout}s.")
                return layer_name, LayerResult(
                    layer_name=layer_name,
                    risk_score=0.0,
                    confidence=0.0,
                    error=f"Layer timed out after {timeout}s"
                )
            except Exception as e:
                logger.error(f"Layer '{layer_name}' unhandled exception: {e}")
                return layer_name, LayerResult(
                    layer_name=layer_name,
                    risk_score=0.0,
                    confidence=0.0,
                    error=str(e)
                )

        # Build execution tasks with per-layer timeouts
        tasks = [
            run_with_timeout("lexical", self.lexical_layer.analyze(url), settings.LEXICAL_TIMEOUT),
            run_with_timeout("domain_intel", self.domain_layer.analyze(url), settings.DOMAIN_INTEL_TIMEOUT),
            run_with_timeout("api_intel", self.api_intel_layer.analyze(url), settings.DOMAIN_INTEL_TIMEOUT),
            run_with_timeout("content", self.content_layer.analyze(url), settings.CONTENT_TIMEOUT),
            run_with_timeout("threat_intel", self.threat_layer.analyze(url), settings.THREAT_INTEL_TIMEOUT),
            run_with_timeout("visual", self.visual_layer.analyze(url), settings.VISUAL_TIMEOUT),
            run_with_timeout("ai_analysis", self.ai_layer.analyze(url), settings.AI_TIMEOUT),
            run_with_timeout("ml_ensemble", self.ml_layer.analyze(url), settings.ML_TIMEOUT),
            run_with_timeout("behavioral", self.behavioral_layer.analyze(url), settings.BEHAVIORAL_TIMEOUT),
        ]

        # Concurrently execute all layers
        layer_outcomes = await asyncio.gather(*tasks)

        for name, outcome in layer_outcomes:
            results[name] = outcome

        # Fuse layer scores into final verdict
        fusion: FusionResult = fuse_layer_results(results)

        processing_time_ms = round((time.time() - start_time) * 1000, 2)

        return {
            "url": url,
            "verdict": fusion.verdict,
            "risk_score": fusion.risk_score,
            "confidence": fusion.confidence,
            "red_flags": [rf.model_dump() for rf in fusion.red_flags],
            "explanation": fusion.explanation,
            "layer_scores": fusion.layer_scores,
            "processing_time_ms": processing_time_ms
        }
