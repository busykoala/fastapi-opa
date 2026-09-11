"""The OPA decision request is awaited, through a client the caller may inject."""

import asyncio
from unittest.mock import AsyncMock
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import fastapi_opa.opa.opa_middleware as opa_middleware
from fastapi_opa import OPAConfig
from fastapi_opa import OPAMiddleware
from tests.utils import AuthenticationDummy
from tests.utils import FakeOPAClient

SCOPE = {
    "type": "http",
    "method": "GET",
    "path": "/api/resource",
    "headers": [],
    "query_string": b"",
    "state": {},
}


@pytest.mark.asyncio
async def test_the_decision_is_awaited_from_the_configured_client() -> None:
    """An injected client receives the OPA input and is awaited on the loop."""
    loops: list[asyncio.AbstractEventLoop] = []

    class RecordingClient(FakeOPAClient):
        async def post(self, url: str, *, json: object) -> Mock:
            loops.append(asyncio.get_running_loop())
            return await super().post(url, json=json)

    client = RecordingClient()
    config = OPAConfig(
        authentication=AuthenticationDummy(),
        opa_host="http://localhost:8181",
        opa_client=client,
    )
    app = AsyncMock()
    middleware = OPAMiddleware(app=app, config=config)

    await middleware(dict(SCOPE), AsyncMock(), AsyncMock())

    assert loops == [asyncio.get_running_loop()]
    url, body = client.calls[0]
    assert url == "http://localhost:8181/v1/data/httpapi/authz"
    assert body == {
        "input": {
            "stuff": "some info",
            "username": "John Doe",
            "role": "Administrator",
            "request_method": "GET",
            "request_path": ["api", "resource"],
        }
    }
    app.assert_called_once()


@pytest.mark.asyncio
async def test_the_default_client_is_httpx_with_a_five_second_timeout() -> (
    None
):
    config = OPAConfig(
        authentication=AuthenticationDummy(), opa_host="http://localhost:8181"
    )
    middleware = OPAMiddleware(app=AsyncMock(), config=config)

    client = middleware.opa_client
    assert isinstance(client, httpx.AsyncClient)
    assert client.timeout == httpx.Timeout(5.0)
    assert middleware.opa_client is client  # created once, then reused

    await middleware.aclose()
    assert client.is_closed


def test_the_middleware_no_longer_imports_requests() -> None:
    assert not hasattr(opa_middleware, "requests")


def test_a_failing_client_surfaces_as_a_server_error() -> None:
    """Transport errors propagate, as they did with the blocking client."""
    config = OPAConfig(
        authentication=AuthenticationDummy(),
        opa_host="http://localhost:8181",
        opa_client=FakeOPAClient(error=httpx.ConnectError("OPA is down")),
    )
    app = FastAPI()
    app.add_middleware(OPAMiddleware, config=config)

    @app.get("/")
    async def root() -> dict[str, str]:
        return {"msg": "success"}

    response = TestClient(app, raise_server_exceptions=False).get("/")
    assert response.status_code == 500
