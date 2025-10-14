
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.stripe]

def test_stripe_webhook_minimal(client):
    for path in ("/stripe/webhook", "/webhook/stripe", "/billing/webhook"):
        r = client.post(path, data="{}", content_type="application/json")
        if r.status_code != 404:
            break
    else:
        pytest.skip("Stripe webhook route not found (tried /stripe/webhook, /webhook/stripe, /billing/webhook).")
    assert r.status_code in (200, 202, 204, 400, 401)
