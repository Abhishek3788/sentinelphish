from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from app.layers.base import LayerResult, RedFlag
from app.utils.logger import get_logger

logger = get_logger("engine.fusion")

WEIGHTS = {
    "threat_intel": 0.30,
    "ai_analysis": 0.25,
    "ml_ensemble": 0.20,
    "visual": 0.10,
    "content": 0.08,
    "domain_intel": 0.05,
    "lexical": 0.02,
}


class FusionResult(BaseModel):
    verdict: str  # Safe, Suspicious, Phishing
    risk_score: float  # 0 to 100
    confidence: str  # low, medium, high
    red_flags: List[RedFlag]
    explanation: str
    layer_scores: Dict[str, float]


def fuse_layer_results(results: Dict[str, Optional[LayerResult]]) -> FusionResult:
    valid_results = {k: v for k, v in results.items() if v is not None and v.error is None}
    
    total_weight = 0.0
    weighted_score = 0.0
    layer_scores: Dict[str, float] = {}
    all_red_flags: List[RedFlag] = []

    for layer_name, result in valid_results.items():
        layer_scores[layer_name] = round(result.risk_score, 2)
        all_red_flags.extend(result.red_flags)
        
        weight = WEIGHTS.get(layer_name, 0.0)
        if weight > 0:
            weighted_score += result.risk_score * weight
            total_weight += weight

    # Base weighted risk score
    if total_weight > 0:
        calculated_score = weighted_score / total_weight
    else:
        calculated_score = 0.0

    risk_score = float(calculated_score)

    # --- Apply Strict Override Rules in Order ---
    
    # 1. Any threat-intel source flags the URL -> risk_score = max(risk_score, 95)
    threat_intel_res = valid_results.get("threat_intel")
    if threat_intel_res and threat_intel_res.risk_score >= 90:
        risk_score = max(risk_score, 95.0)

    # 2. AI and ML both agree on phishing with >0.9 confidence -> risk_score = max(risk_score, 90)
    ai_res = valid_results.get("ai_analysis")
    ml_res = valid_results.get("ml_ensemble")
    if (ai_res and ai_res.risk_score >= 70 and ai_res.confidence >= 0.85 and
            ml_res and ml_res.risk_score >= 70 and ml_res.confidence >= 0.85):
        risk_score = max(risk_score, 90.0)

    # 3. Domain age < 7 days AND visual brand match -> risk_score = max(risk_score, 85)
    domain_res = valid_results.get("domain_intel")
    visual_res = valid_results.get("visual")
    is_new_domain = False
    if domain_res and domain_res.details.get("whois", {}).get("age_days") is not None:
        if domain_res.details["whois"]["age_days"] < 7:
            is_new_domain = True
            
    is_visual_match = bool(visual_res and visual_res.details.get("matched_brand_logo"))
    if is_new_domain and is_visual_match:
        risk_score = max(risk_score, 85.0)

    # 4. Only lexical layer is suspicious, everything else clean -> risk_score = min(risk_score, 40)
    lexical_res = valid_results.get("lexical")
    other_layers = [v for k, v in valid_results.items() if k != "lexical"]
    if lexical_res and lexical_res.risk_score > 30 and all(l.risk_score < 25 for l in other_layers):
        risk_score = min(risk_score, 40.0)

    # Determine Verdict
    if risk_score >= 70.0:
        verdict = "Phishing"
    elif risk_score >= 40.0:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    # Confidence calculation: high if >= 3 layers agree with >0.8 confidence, medium if 2 agree, else low
    high_conf_agreements = sum(1 for v in valid_results.values() if v.confidence >= 0.8 and v.risk_score >= 40)
    if high_conf_agreements >= 3 or (verdict == "Safe" and len(valid_results) >= 4):
        confidence = "high"
    elif high_conf_agreements >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    # Narrative explanation generator
    explanation = _generate_explanation(verdict, risk_score, confidence, valid_results, all_red_flags)

    # Deduplicate red flags
    unique_red_flags: List[RedFlag] = []
    seen_flags = set()
    for rf in all_red_flags:
        if rf.flag not in seen_flags:
            seen_flags.add(rf.flag)
            unique_red_flags.append(rf)

    return FusionResult(
        verdict=verdict,
        risk_score=round(risk_score, 2),
        confidence=confidence,
        red_flags=unique_red_flags,
        explanation=explanation,
        layer_scores=layer_scores
    )


def _generate_explanation(verdict: str, score: float, confidence: str, results: Dict[str, LayerResult], flags: List[RedFlag]) -> str:
    ai_res = results.get("ai_analysis")
    if ai_res and ai_res.details.get("reasoning"):
        return f"AI Analysis: {ai_res.details['reasoning']}"
    
    if verdict == "Phishing":
        flag_summary = ", ".join([f.flag for f in flags[:3]])
        return f"High risk URL ({round(score, 1)}/100). Critical threat indicators detected: {flag_summary}."
    elif verdict == "Suspicious":
        return f"URL exhibits suspicious characteristics ({round(score, 1)}/100). Exercise caution before proceeding or submitting credentials."
    else:
        return f"URL evaluated as safe with {confidence} confidence ({round(score, 1)}/100). No significant threat vectors found."
