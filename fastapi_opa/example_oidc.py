from typing import Dict
from fastapi import FastAPI, Request
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.common.security import generate_token

from fastapi_opa import OPAConfig
from fastapi_opa.auth import OIDCAuthentication
from fastapi_opa.auth import OIDCConfig
from fastapi_opa.opa.cookie_middleware import CookieAuthMiddleware
from fastapi_opa.models import TokenCookieConfig

# Generate PKCE values using Authlib's built-in functions
code_verifier = generate_token(128)
code_challenge = create_s256_code_challenge(code_verifier)

# The hostname of your Open Policy Agent instance
opa_host = "http://localhost:8181"

# OIDC configuration with PKCE
oidc_config = OIDCConfig(
    # well known endpoint
    well_known_endpoint="http://localhost:8000/auth/realms/example-realm/.well-known/openid-configuration",  # noqa
    # host where this app is running
    app_uri="http://localhost:5000",
    # client id of your app configured in the identity provider
    client_id="example-client",
    # the client secret retrieved from your identity provider
    client_secret="bbb4857c-21ba-44a3-8843-1364984a36906",
    # the scope of the token
    scope="openid profile email",
    # Obtain the user info of when the user is authenticated
    get_user_info=True,
    # Add PKCE parameters
    code_challenge_method="S256",
    response_type="code",  # Required for PKCE
    grant_type="authorization_code",  # Required for PKCE
    # Customisable authentication parameters for the token request
    use_auth_header=False,
    is_public_client=False
)

oidc_auth = OIDCAuthentication(oidc_config)
opa_config = OPAConfig(
    authentication=oidc_auth,
    opa_host=opa_host,
    accepted_methods=["id_token", "access_token"],
)

app = FastAPI()
# Add CookieAuthMiddleware to the fastapi app
app.add_middleware(
    CookieAuthMiddleware,
    config=opa_config,
    force_authorization=True,
    cookie_config=TokenCookieConfig(
        cookie_name="access_token",
        cookie_secure=True
    )
)

@app.get("/")
async def root(request: Request) -> Dict:
    return {"msg": "success"}
