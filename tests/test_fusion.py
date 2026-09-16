import pytest
from app.engine.fusion import fuse_layer_results
from app.layers.base import LayerResult, RedFlag

def test_fusion_threat_intel_override():
    results = {
        "threat_intel": LayerResult(
            layer_name="threat_intel",
            risk_score=95.0,
            confidence=0.99,
            red_flags=[RedFlag(severity="high", flag="Flagged by URLhaus")]
        ),
        "lexical": LayerResult(layer_name="lexical", risk_score=10.0, confidence=0.8)
    }
    fusion = fuse_layer_results(results)
    assert fusion.verdict == "Phishing"
    assert fusion.risk_score >= 95.0

def test_fusion_safe_url():
    results = {
        "lexical": LayerResult(layer_name="lexical", risk_score=5.0, confidence=0.9),
        "domain_intel": LayerResult(layer_name="domain_intel", risk_score=0.0, confidence=0.9),
        "ai_analysis": LayerResult(layer_name="ai_analysis", risk_score=0.0, confidence=0.9)
    }
    fusion = fuse_layer_results(results)
    assert fusion.verdict == "Safe"
    assert fusion.risk_score <= 15.0
