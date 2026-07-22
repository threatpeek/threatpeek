import httpx
import pytest
import respx

from routes.scan import _inspect_redirect_chain, _risk_assessment


@pytest.mark.asyncio
@respx.mock
async def test_redirect_inspection_records_hops_and_cross_domain_change():
    respx.get("https://example.com/start").mock(
        return_value=httpx.Response(302, headers={"location": "https://other.example/final"})
    )
    respx.get("https://other.example/final").mock(return_value=httpx.Response(200))

    chain, factors = await _inspect_redirect_chain("https://example.com/start")

    assert [hop["status_code"] for hop in chain] == [302, 200]
    assert any("Followed 1 redirect" in factor for factor in factors)
    assert any("Redirected from example.com to other.example" in factor for factor in factors)


def test_risk_assessment_includes_vendor_and_redirect_evidence():
    score, factors = _risk_assessment(
        "suspicious",
        base_factors=["Followed 1 redirect hop(s)", "Redirected from example.com to other.example"],
        vendors={"Vendor A": "malicious", "Vendor B": "suspicious"},
    )

    assert score == 72
    assert any("marked it malicious" in factor for factor in factors)
    assert any("marked it suspicious" in factor for factor in factors)
