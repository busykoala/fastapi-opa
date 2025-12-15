"""
Example: OIDC Authentication with PKCE for Public Clients

This example demonstrates how to configure OIDC authentication using
PKCE (Proof Key for Code Exchange) as defined in RFC 7636.

PKCE is recommended for:
- Public clients (SPAs, mobile apps, CLI tools) that cannot securely store secrets
- Confidential clients as an additional security layer

Key features shown:
- Public client configuration (no client_secret required)
- Configurable code_verifier_length (43-128 chars per RFC 7636)
- Cookie-based token storage for session management
"""

from typing import Dict

from fastapi import FastAPI
from fastapi import Request

from fastapi_opa import OPAConfig
from fastapi_opa.auth import OIDCAuthentication
from fastapi_opa.auth import OIDCConfig
from fastapi_opa.auth.auth_oidc import PKCE_CODE_VERIFIER_DEFAULT_LENGTH
from fastapi_opa.models import TokenCookieConfig
from fastapi_opa.opa.cookie_middleware import CookieAuthMiddleware

# The hostname of your Open Policy Agent instance
opa_host = "http://localhost:8181"

# OIDC configuration with PKCE for a PUBLIC client
# Public clients don't require a client_secret - PKCE provides the security
oidc_config = OIDCConfig(
    # Well-known endpoint for auto-discovery of OIDC endpoints
    well_known_endpoint="http://localhost:8080/realms/example-realm/.well-known/openid-configuration",  # noqa
    # Host where this app is running
    app_uri="http://localhost:5000",
    # Client ID configured in the identity provider
    client_id="example-public-client",
    # PUBLIC CLIENT: No client_secret needed when using PKCE
    is_public_client=True,
    # Scopes to request
    scope="openid profile email",
    # PKCE Configuration (RFC 7636)
    code_challenge_method="S256",  # S256 is required by most IdPs
    response_type="code",
    grant_type="authorization_code",
    # code_verifier_length: Length of the PKCE code_verifier (43-128 chars)
    # Default is 128 for maximum entropy, but can be customized if needed
    code_verifier_length=PKCE_CODE_VERIFIER_DEFAULT_LENGTH,
    # Skip user info endpoint call (faster, uses only id_token claims)
    get_user_info=False,
    # Keep raw tokens available in request state for downstream use
    preserve_tokens=True,
)

oidc_auth = OIDCAuthentication(oidc_config)

opa_config = OPAConfig(
    authentication=oidc_auth,
    opa_host=opa_host,
    accepted_methods=["id_token", "access_token"],
)

app = FastAPI(
    title="PKCE Example",
    description="Example FastAPI app with OIDC PKCE authentication",
)

# Add CookieAuthMiddleware for session-based authentication
app.add_middleware(
    CookieAuthMiddleware,
    config=opa_config,
    force_authorization=True,
    cookie_config=TokenCookieConfig(
        cookie_name="access_token",
        cookie_secure=True,  # Set to False for local development without HTTPS
        cookie_httponly=True,
        cookie_samesite="lax",
    ),
)


@app.get("/")
async def root(request: Request) -> Dict:
    """Public endpoint that requires authentication via PKCE flow."""
    return {"msg": "success", "user": "authenticated via PKCE"}


@app.get("/profile")
async def profile(request: Request) -> Dict:
    """
    Example endpoint showing how to access token claims.

    The validated token is available in request.state after authentication.
    """
    # Access the authentication result from request state
    auth_result = getattr(request.state, "auth_result", None)
    if auth_result and auth_result.validated_token:
        return {
            "sub": auth_result.validated_token.get("sub"),
            "email": auth_result.validated_token.get("email"),
            "name": auth_result.validated_token.get("name"),
        }
    return {"error": "No token available"}
