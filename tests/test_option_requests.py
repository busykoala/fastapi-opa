from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def mock_opa_response():
    with patch("fastapi_opa.opa.opa_middleware.requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"result": {"allow": True}}
        yield mock_post


def test_options_request_with_auth(
    client_multiple_authentications, api_key_auth, mock_opa_response
):
    client: TestClient = client_multiple_authentications

    # Test OPTIONS request for an existing item with authentication
    response = client.options(
        "/items/1",
        headers={api_key_auth["header_key"]: api_key_auth["api_key"]},
    )
    assert response.status_code == 200
    assert response.headers["Allow"] == "OPTIONS, GET, POST"
    assert response.json() == {}

    # Test OPTIONS request for a non-existing item with authentication
    response = client.options(
        "/items/3",
        headers={api_key_auth["header_key"]: api_key_auth["api_key"]},
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_options_request_without_auth(
    client_multiple_authentications, mock_opa_response
):
    client: TestClient = client_multiple_authentications

    # Test OPTIONS request for an existing item without authentication
    response = client.options("/items/1")
    assert response.status_code == 401
    assert response.json() == {"message": "Unauthorized"}

    # Test OPTIONS request for a non-existing item without authentication
    response = client.options("/items/3")
    assert response.status_code == 401
    assert response.json() == {"message": "Unauthorized"}
