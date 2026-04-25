# Cookie session management

`CookieAuthMiddleware` extends `OPAMiddleware` with cookie-based session management.
On the first authenticated request it stores the access token in an `HttpOnly` cookie.
On later requests it reads the cookie and injects an `Authorization` header before
passing the request through to OPA, so users aren't redirected to the identity provider
on every page load.

## How the flow works

1. **First visit**—no cookie present. The middleware passes the request to
   `OPAMiddleware`, which redirects the browser to the identity provider.
2. **After login**—the identity provider redirects back with an authorization code.
   `OPAMiddleware` exchanges it for tokens and validates the ID token. On a
   successful response, `CookieAuthMiddleware` adds a `Set-Cookie` header with
   the access token.
3. **Later visits**—the browser sends the cookie. The middleware extracts
   the token and injects `Authorization: Bearer <token>` before passing the request
   to `OPAMiddleware` for validation. The identity provider isn't contacted again.
4. **Token expiry**—if OPA or token validation returns a 401 and the token came
   from the cookie, the middleware clears the cookie and redirects to the same
   URL, restarting the login flow from step 1.

## Setup

```python
from fastapi import FastAPI

from fastapi_opa import OPAConfig
from fastapi_opa.auth import OIDCAuthentication
from fastapi_opa.auth import OIDCConfig
from fastapi_opa.models import TokenCookieConfig
from fastapi_opa.opa.cookie_middleware import CookieAuthMiddleware

oidc_config = OIDCConfig(
    well_known_endpoint="https://idp.example.com/realms/myrealm/.well-known/openid-configuration",
    app_uri="https://app.example.com",
    client_id="my-client",
    client_secret="my-secret",
    preserve_tokens=True,  # required: middleware needs the raw token to store it
)
oidc_auth = OIDCAuthentication(oidc_config)
opa_config = OPAConfig(authentication=oidc_auth, opa_host="http://localhost:8181")

app = FastAPI()
app.add_middleware(
    CookieAuthMiddleware,
    config=opa_config,
    cookie_config=TokenCookieConfig(
        cookie_name="access_token",
        cookie_secure=True,
        cookie_httponly=True,
        cookie_samesite="lax",
    ),
)
```

Set `preserve_tokens=True` on `OIDCConfig`. Without it, `CookieAuthMiddleware`
has no token to store and cookie sessions don't work.

## Cookie configuration

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `True` | Set `False` to turn off cookie handling entirely |
| `cookie_name` | `"access_token"` | Name of the cookie |
| `cookie_domain` | `None` | Restrict the cookie to a specific domain (for example, `.example.com`) |
| `cookie_path` | `"/"` | Path scope for the cookie |
| `cookie_secure` | `True` | Restricts the cookie to HTTPS; set `False` for local development |
| `cookie_httponly` | `True` | Block JavaScript from reading the cookie; prevents XSS token theft |
| `cookie_samesite` | `"lax"` | `"strict"`, `"lax"`, or `"none"` |

### Choosing a `SameSite` value

| Value | When to use |
|-------|-------------|
| `"lax"` | Default. Cookies sent on top-level navigations (clicking a link) but not on cross-site sub-requests. Good balance for most apps. |
| `"strict"` | Restricts cookies to same-site requests. Most restrictive; users lose their session when arriving from an external link. |
| `"none"` | Cookies sent on all cross-site requests. **Requires `cookie_secure=True`.** Needed for embedded iframes or APIs called from a different origin. |

## middleware options

`CookieAuthMiddleware` accepts the same options as `OPAMiddleware`:

| Option | Default | Description |
|--------|---------|-------------|
| `config` | — | `OPAConfig` instance |
| `cookie_config` | `TokenCookieConfig()` | Cookie configuration |
| `skip_endpoints` | `["/openapi.json", "/docs", "/redoc"]` | Paths that bypass authentication |
| `enable_authorization` | `True` | Set `False` to skip OPA policy checks; authentication still runs |
| `max_buffer_size` | `None` | Request body size limit for buffering in bytes; `None` sets no limit |

## Skipping endpoints

Pass `skip_endpoints` to bypass authentication on specific paths. Values are exact
strings or regular expressions:

```python
app.add_middleware(
    CookieAuthMiddleware,
    config=opa_config,
    skip_endpoints=["/health", "/metrics", "/api/public/.*"],
)
```

Providing `skip_endpoints` replaces the default list (`/openapi.json`, `/docs`, `/redoc`)
entirely. Include those paths explicitly to still expose the OpenAPI docs without
authentication.

## Skipping authorization

Set `enable_authorization=False` to skip OPA policy checks. Every authenticated user
reaches every endpoint. The middleware still handles the full OIDC flow and cookie
lifecycle.

```python
app.add_middleware(
    CookieAuthMiddleware,
    config=opa_config,
    enable_authorization=False,
)
```

The middleware logs a warning at startup when `enable_authorization=False`. Use this mode
when your app handles authorization internally, or during development.

## Security checklist

- Set `cookie_secure=True` in production (HTTPS).
- Keep `cookie_httponly=True` (default) to prevent JavaScript from reading the token.
- Use `cookie_samesite="lax"` or `"strict"` unless cross-origin cookie delivery is
  required.
- Use `preserve_tokens=True` together with the preceding settings—never log `AuthenticationResult`
  when `preserve_tokens=True`, as it contains raw tokens.
