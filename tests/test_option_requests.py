from fastapi.testclient import TestClient


def test_options_request_with_auth(
    client_multiple_authentications, api_key_auth, opa_client
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
    assert len(opa_client.calls) == 1  # OPTIONS is authorized like any method

    # Test OPTIONS request for a non-existing item with authentication
    response = client.options(
        "/items/3",
        headers={api_key_auth["header_key"]: api_key_auth["api_key"]},
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_options_request_without_auth(
    client_multiple_authentications, opa_client
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
    assert (
        opa_client.calls == []
    )  # OPA is never asked about the unauthenticated
