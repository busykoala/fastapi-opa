# Authentication

`fastapi-opa` supports three built-in authentication methods, and you can add your
own by subclassing `AuthInterface`. The authentication result feeds the OPA policy
evaluation—every claim in the validated token becomes available as `input.<claim>`
in your Rego policy.

## AuthInterface

All authentication handlers follow this contract:

```python
from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.models import AuthenticationResult
from starlette.requests import Request
from starlette.responses import RedirectResponse


class MyAuth(AuthInterface):
    async def authenticate(
        self,
        request: Request,
        accepted_methods: list[str] | None = None,
    ) -> RedirectResponse | AuthenticationResult:
        ...
```

Return `RedirectResponse` to send the user to an identity provider, or
`AuthenticationResult` once authentication is complete.

## API key authentication

`APIKeyAuthentication` validates a request header value using a constant-time
comparison to prevent timing attacks.

```python
from fastapi_opa.auth.auth_api_key import APIKeyAuthentication
from fastapi_opa.auth.auth_api_key import APIKeyConfig

api_key_config = APIKeyConfig(header_key="X-API-Key", api_key="my-secret")
api_key_auth = APIKeyAuthentication(api_key_config)

opa_config = OPAConfig(authentication=api_key_auth, opa_host=opa_host)
```

The OPA input sets:
- `user` → `"APIKey"`
- `client` → the client IP address

`APIKeyConfig` parameters:

| Parameter | Description |
|-----------|-------------|
| `header_key` | Name of the request header; for example, `"X-API-Key"` |
| `api_key` | Expected header value |

## OIDC authentication

`OIDCAuthentication` implements the OpenID Connect authorization code flow with
PKCE support. It handles the redirect to the identity provider, the callback,
token exchange, and JWT validation.

```python
from fastapi_opa.auth import OIDCAuthentication
from fastapi_opa.auth import OIDCConfig

oidc_config = OIDCConfig(
    well_known_endpoint="https://idp.example.com/realms/myrealm/.well-known/openid-configuration",
    app_uri="https://app.example.com",
    client_id="my-client",
    client_secret="my-secret",
)
oidc_auth = OIDCAuthentication(oidc_config)
```

### OIDCConfig reference

| Option | Default | Description |
|--------|---------|-------------|
| `well_known_endpoint` | `""` | OIDC discovery URL; auto-populates `token_endpoint`, `jwks_uri`, and `userinfo_endpoint` |
| `app_uri` | — | Absolute URL of this app; used as the base for the redirect URI |
| `client_id` | — | Client ID configured in the identity provider |
| `client_secret` | `None` | Required for confidential clients; omit for public clients using PKCE |
| `scope` | `"openid email profile"` | Space-separated scopes to request |
| `get_user_info` | `False` | Call the Userinfo endpoint after token validation to fetch extra claims |
| `preserve_tokens` | `False` | Include raw tokens in `AuthenticationResult`; required for `CookieAuthMiddleware` |
| `trust_x_headers` | `False` | Trust `X-Forwarded-*` headers when building the redirect URI; enable behind a reverse proxy |
| `is_public_client` | `False` | Public client mode—no `client_secret` required; use together with PKCE |
| `use_auth_header` | `True` | Send client credentials in the `Authorization` header; set `False` to send in the request body |
| `code_challenge_method` | `"S256"` | PKCE challenge method; most identity providers require `S256` |
| `code_verifier_length` | `128` | Length of the PKCE code verifier (43 to 128, per RFC 7636) |
| `pkce_store` | `None` | PKCE store instance; `None` uses the default in-memory store |

Manual endpoint configuration (if no `well_known_endpoint`):

| Option | Default | Description |
|--------|---------|-------------|
| `authorization_endpoint` | `""` | Identity provider authorization URL |
| `token_endpoint` | `""` | Token exchange URL |
| `jwks_uri` | `""` | JWKS URL for public key retrieval |
| `userinfo_endpoint` | `""` | Userinfo URL; required when `get_user_info=True` |
| `issuer` | `""` | Expected `iss` claim value for token validation |

### Client types

Confidential clients authenticate with a `client_secret`. Public clients (SPAs,
CLIs, mobile apps) use PKCE instead—see [the PKCE guide](pkce.md).

### Cookie-based sessions

After OIDC authentication succeeds, use `CookieAuthMiddleware` to persist the
session in a cookie so users aren't redirected on every request—see
[docs/cookie-auth.md](cookie-auth.md). Set `preserve_tokens=True` on `OIDCConfig`
for this to work.

### Security: `preserve_tokens`

`preserve_tokens=False` (the default) follows the principle of least privilege—raw
tokens after validation. Set it to `True` when a downstream
component needs the token:

- `CookieAuthMiddleware` needs the access token to store it in a cookie.
- A proxy that forwards tokens to another service.

Risks when `preserve_tokens=True`:
- Logging `AuthenticationResult` exposes raw tokens in logs.
- Without `cookie_httponly=True`, JavaScript can read the token from the cookie.
- Without `cookie_secure=True`, the cookie travels over plain HTTP.

The middleware logs a security warning when `preserve_tokens=True`.

## SAML authentication

`SAMLAuthentication` implements SAML 2.0 SP-initiated SSO.

### Generate certificates

```bash
openssl req -new -x509 -days 3652 -nodes -out sp.crt -keyout sp.key
```

Add the private key and certificate to the `sp` section of `settings.json`. See
`tests/test_data/saml/*.json` for the expected structure. Don't use the test
certificates in production.

### Configure the middleware

```python
from fastapi_opa import OPAConfig
from fastapi_opa.auth.auth_saml import SAMLAuthentication
from fastapi_opa.auth.auth_saml import SAMLConfig

saml_config = SAMLConfig(settings_directory="./saml")
saml_auth = SAMLAuthentication(saml_config)

opa_config = OPAConfig(
    authentication=saml_auth,
    opa_host=opa_host,
    accepted_methods=["id_token", "access_token"],
)
```

Install the SAML extra and rebuild its binary dependencies:

```bash
uv add "fastapi-opa[saml]"
PIP_NO_BINARY="lxml,xmlsec" uv run pip install --force-reinstall --no-binary=lxml --no-binary=xmlsec lxml xmlsec
```

### Configure Keycloak

When using Keycloak as the SAML identity provider, create a SAML client and enable:

- **Encrypt assertion**
- **Client signature required**
- **Force POST bindings**

Under **Client Scopes → role_list (SAML) → Mappers → role list**, enable
**Single Role Attribute**.

Upload `sp.crt` as the client's signing certificate.

## Custom authentication handlers

Create a custom handler by subclassing `AuthInterface`. Return `RedirectResponse` to start an
external login, or `AuthenticationResult` with `success=True` and a `user_info`
dict once authentication succeeds:

```python
from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.models import AuthenticationResult
from starlette.requests import Request
from starlette.responses import RedirectResponse


class HeaderAuth(AuthInterface):
    async def authenticate(
        self,
        request: Request,
        accepted_methods: list[str] | None = None,
    ) -> RedirectResponse | AuthenticationResult:
        user = request.headers.get("X-Remote-User")
        if not user:
            return AuthenticationResult(
                success=False,
                error="No X-Remote-User header",
            )
        return AuthenticationResult(
            success=True,
            user_info={"user": user},
        )
```

Register it on `OPAConfig` like any other handler.
