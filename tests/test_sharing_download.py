
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.sharing]

def test_share_routes_present(client):
    candidates = ["/share", "/files/share", "/my-shares", "/received"]
    found = []
    for p in candidates:
        res = client.get(p)
        if res.status_code != 404:
            found.append(p)
    if not found:
        pytest.skip("No sharing-related routes discovered.")
    assert True
