from typing import Dict

import nest_asyncio
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_opa import OPAConfig
from fastapi_opa import OPAMiddleware
from fastapi_opa.opa.enrichment.graphql_enrichment import GraphQLInjectable
from fastapi_opa.opa.opa_middleware import ShouldSkip
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


def should_skip_client(should_skip: ShouldSkip):
    # Configure OPA
    opa_host = "http://localhost:8181"
    oidc_auth = AuthenticationDummy()
    opa_config = OPAConfig(authentication=oidc_auth, opa_host=opa_host)

    # Setup app
    app = FastAPI()
    app.add_middleware(
        OPAMiddleware,
        config=opa_config,
        should_skip_authorization=[should_skip],
    )

    @app.get("/")
    async def root() -> Dict:
        return {"msg": "success"}

    # Create client
    return TestClient(app)
