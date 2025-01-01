from typing import Any
from typing import AsyncGenerator
from typing import Callable
from typing import Dict

import nest_asyncio
import pytest
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response
from fastapi.testclient import TestClient

from fastapi_opa import OPAConfig
from fastapi_opa import OPAMiddleware
from fastapi_opa.auth.auth_api_key import APIKeyAuthentication
from fastapi_opa.auth.auth_api_key import APIKeyConfig
from fastapi_opa.opa.enrichment.graphql_enrichment import GraphQLInjectable
from tests.utils import AuthenticationDummy
from tests.utils import OPAInjectableExample

nest_asyncio.apply()

# Sample data for the test
WRITABLE_ITEMS = {
    1: True,
    2: False,
}


@pytest.fixture
def client():
    opa_host = "http://localhost:8181"
    oidc_auth = AuthenticationDummy()
    opa_config = OPAConfig(authentication=oidc_auth, opa_host=opa_host)

    app = FastAPI()
    app.add_middleware(OPAMiddleware, config=opa_config)

    @app.get("/")
    async def root() -> Dict:
        return {"msg": "success"}

    @app.get("/items/{item_id}")
    async def read_item(item_id: int):
        if item_id not in WRITABLE_ITEMS:
            raise HTTPException(status_code=404)
        return {"item_id": item_id}

    @app.options("/items/{item_id}")
    async def read_item_options(response: Response, item_id: int) -> Dict:
        if item_id not in WRITABLE_ITEMS:
            raise HTTPException(status_code=404)
        response.headers["Allow"] = "OPTIONS, GET" + (
            ", POST" if WRITABLE_ITEMS[item_id] else ""
        )
        return {}

    @app.post("/items")
    async def create_item(request: Request):
        data = await request.json()
        return {"msg": f"Received {len(str(data))} bytes"}

    yield TestClient(app)


@pytest.fixture
def large_body() -> Callable[[], AsyncGenerator[Dict[str, Any], None]]:
    """Fixture to generate a large request body in chunks."""

    async def generate():
        body = (
            b'{"input": {"item_id": 1, "data": "'
            + b"a" * 5 * 1024 * 1024
            + b'"}}'
        )
        for i in range(0, len(body), 1024):
            yield {
                "type": "http.request",
                "body": body[i : i + 1024],
                "more_body": i + 1024 < len(body),
            }
        yield {"type": "http.request", "body": b"", "more_body": False}

    return generate


@pytest.fixture
def injected_client():
    opa_host = "http://localhost:8181"
    oidc_auth = AuthenticationDummy()
    injectable = OPAInjectableExample("example_injectable")
    opa_config = OPAConfig(
        authentication=oidc_auth, opa_host=opa_host, injectables=[injectable]
    )

    app = FastAPI()
    app.add_middleware(OPAMiddleware, config=opa_config)

    @app.post("/")
    async def root() -> Dict:
        return {"msg": "success"}

    yield TestClient(app)


@pytest.fixture
def api_key_auth():
    header_key = "API"
    api_key = "1234"
    config = APIKeyConfig(header_key=header_key, api_key=api_key)
    auth = APIKeyAuthentication(config)
    yield {"auth": auth, "header_key": header_key, "api_key": api_key}


@pytest.fixture
def client_multiple_authentications(api_key_auth):
    opa_host = "http://localhost:8181"
    oidc_auth = AuthenticationDummy(accept_all=False)

    opa_config = OPAConfig(
        authentication=[oidc_auth, api_key_auth["auth"]], opa_host=opa_host
    )

    app = FastAPI()
    app.add_middleware(OPAMiddleware, config=opa_config)

    @app.get("/")
    async def root() -> Dict:
        return {"msg": "success"}

    @app.get("/items/{item_id}")
    async def read_item(item_id: int):
        if item_id not in WRITABLE_ITEMS:
            raise HTTPException(status_code=404)
        return {"item_id": item_id}

    @app.options("/items/{item_id}")
    async def read_item_options(response: Response, item_id: int) -> Dict:
        if item_id not in WRITABLE_ITEMS:
            raise HTTPException(status_code=404)
        response.headers["Allow"] = "OPTIONS, GET" + (
            ", POST" if WRITABLE_ITEMS[item_id] else ""
        )
        return {}

    yield TestClient(app)


@pytest.fixture
def gql_injected_client():
    opa_host = "http://localhost:8181"
    oidc_auth = AuthenticationDummy()
    injectable = GraphQLInjectable("gql_injectable")
    opa_config = OPAConfig(
        authentication=oidc_auth, opa_host=opa_host, injectables=[injectable]
    )

    app = FastAPI()
    app.add_middleware(OPAMiddleware, config=opa_config)

    @app.post("/")
    @pytest.mark.asyncio
    async def root() -> Dict:
        return {"msg": "success"}

    yield TestClient(app)
