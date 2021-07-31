# fastapi_opa/main.py
from typing import Dict

import uvicorn as uvicorn
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request

from fastapi_opa import OPAConfig
from fastapi_opa import OPAMiddleware
from fastapi_opa.auth.auth_saml import SAMLAuthentication
from fastapi_opa.auth.auth_saml import SAMLConfig

opa_host = "http://localhost:8181"
# In this example we use OIDC authentication flow (using Keycloak)
saml_config = SAMLConfig(settings_directory="./tests/test_data/saml")
saml_auth = SAMLAuthentication(saml_config)

opa_config = OPAConfig(authentication=saml_auth, opa_host=opa_host)

app = FastAPI()
app.add_middleware(OPAMiddleware, config=opa_config)
app.add_middleware(SessionMiddleware, secret_key="secret", max_age=24 * 60 * 60)


@app.get("/")
async def root(request: Request) -> Dict:
    return {
        "msg": request.session.get("foo"),
    }

if __name__ == '__main__':
    uvicorn.run(app, debug=True)
