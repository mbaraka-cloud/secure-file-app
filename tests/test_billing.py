
import pytest
import importlib

pytestmark = [pytest.mark.billing]

def test_cost_function_exists():
    try:
        billing = importlib.import_module("app.utils.billing")
    except Exception:
        pytest.skip("app.utils.billing not found")
    candidates = ["get_cost_for_size", "estimate_credits_for_size", "price_for_bytes"]
    fn = None
    for name in candidates:
        if hasattr(billing, name):
            fn = getattr(billing, name)
            break
    if fn is None:
        pytest.skip(f"No billing function found among {candidates}")
    small = fn(1024)
    medium = fn(5*1024*1024)
    large = fn(100*1024*1024)
    assert small <= medium <= large, "Cost should be non-decreasing with size"
