from typing import Dict

from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.common.security import generate_token

from fastapi import FastAPI
from fastapi_opa import OPAConfig
from fastapi_opa import OPAMiddleware
from fastapi_opa.auth import OIDCAuthentication
from fastapi_opa.auth import OIDCConfig

# Generate PKCE values using Authlib's built-in functions
code_verifier = generate_token(128)
code_challenge = create_s256_code_challenge(code_verifier)

# The hostname of your Open Policy Agent instance
opa_host = "http://localhost:8181"
# In this example we use OIDC authentication flow (using Keycloak)
oidc_config = OIDCConfig(
    well_known_endpoint="http://localhost:8000/"
    + ("auth/realms/example-realm/.well-known/openid-configuration"),
    # well known endpoint
    app_uri="http://localhost:4000",  # host where this app is running
    # client id of your app configured in the identity provider
    client_id="example-client",
    # the client secret retrieved from your identity provider
    client_secret="bbb4857c-21ba-44a3-8843-1364984a36906",
    # client PKCE code challenge method
    code_challenge_method="S256",
    # client PKCE response type
    response_type="code",
    # client PKCE grant type flow
    grant_type="authorization_code",
    # client PKCE configuration for getting the token
    use_auth_header=False,
    # client PKCE configuration type: confidential | public
    is_public_client=False
)
oidc_auth = OIDCAuthentication(oidc_config)
opa_config = OPAConfig(authentication=oidc_auth, opa_host=opa_host)

app = FastAPI()
# Add OPAMiddleware to the fastapi app
app.add_middleware(OPAMiddleware, config=opa_config)


@app.get("/")
async def root() -> Dict:
    return {"msg": "success"}
