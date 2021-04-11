from typing import Dict

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_opa import OPAConfig
from fastapi_opa import OPAMiddleware
from tests.utils import AuthenticationDummy


@pytest.fixture
def client():
    opa_host = "http://localhost:8181"
    oidc_auth = AuthenticationDummy()
    opa_config = OPAConfig(authentication=oidc_auth, opa_host=opa_host)

    app = FastAPI()
    app.add_middleware(OPAMiddleware, config=opa_config)

    @app.get("/")
    async def root() -> Dict:
        return {
            "msg": "success",
        }

    yield TestClient(app)
