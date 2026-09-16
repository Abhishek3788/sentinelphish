import pytest
from app.layers.lexical import LexicalLayer

@pytest.mark.asyncio
async def test_lexical_phishing_url():
    layer = LexicalLayer()
    phishing_url = "http://paypal-secure-login-verify.xyz/auth/account"
    result = await layer.analyze(phishing_url)
    
    assert result.layer_name == "lexical"
    assert result.risk_score > 30.0
    assert len(result.red_flags) > 0
    assert any(rf.flag for rf in result.red_flags if "TLD" in rf.flag or "keywords" in rf.flag or "length" in rf.flag)

@pytest.mark.asyncio
async def test_lexical_safe_url():
    layer = LexicalLayer()
    safe_url = "https://www.google.com"
    result = await layer.analyze(safe_url)
    
    assert result.layer_name == "lexical"
    assert result.risk_score <= 15.0
    assert len(result.red_flags) == 0
