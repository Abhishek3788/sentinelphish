import pytest
from app.layers.domain_intel import DomainIntelLayer

@pytest.mark.asyncio
async def test_domain_intel_analysis():
    layer = DomainIntelLayer()
    url = "https://www.wikipedia.org"
    result = await layer.analyze(url)
    
    assert result.layer_name == "domain_intel"
    assert "dns" in result.details
    assert result.risk_score < 40.0
