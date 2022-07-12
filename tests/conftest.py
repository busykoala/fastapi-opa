from typing import Dict

import nest_asyncio
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_opa import OPAConfig
from fastapi_opa import OPAMiddleware
from fastapi_opa.auth.auth_api_key import APIKeyAuthentication
from fastapi_opa.auth.auth_api_key import APIKeyConfig
from fastapi_opa.opa.enrichment.graphql_enrichment import GraphQLInjectable
from tests.utils import AuthenticationDummy
from tests.utils import OPAInjectableExample

nest_asyncio.apply()


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

    yield TestClient(app)


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

    @app.get("/")
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

    yield TestClient(app)


@pytest.fixture
async def gql_injected_client():
    opa_host = "http://localhost:8181"
    oidc_auth = AuthenticationDummy()
    injectable = GraphQLInjectable("gql_injectable")
    opa_config = OPAConfig(
        authentication=oidc_auth, opa_host=opa_host, injectables=[injectable]
    )

    app = FastAPI()
    app.add_middleware(OPAMiddleware, config=opa_config)

    @app.get("/")
    @pytest.mark.asyncio
    async def root() -> Dict:
        return {"msg": "success"}

    yield TestClient(app)
