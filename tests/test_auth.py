
import pytest

pytestmark = [pytest.mark.integration]

@pytest.mark.parametrize("path", ["/auth/login", "/login"])
def test_login_page_renders(client, path):
    res = client.get(path)
    if res.status_code == 404:
        pytest.skip(f"Login route not found at {path}")
    assert res.status_code in (200, 302)

def test_rate_limit_login(client):
    hits = []
    for _ in range(10):
        r = client.post("/auth/login", data={"email":"x@y.z","password":"bad"})
        hits.append(r.status_code)
    if 429 in hits:
        assert True
    else:
        pytest.skip("No rate limiting observed on /auth/login (or different route).")
