# Public clients and PKCE

PKCE (Proof Key for Code Exchange, RFC 7636) is an OAuth 2.0 extension that lets
public clients—SPAs, mobile apps, command-line tools, or any client that can't securely
store a secret—complete the authorization code flow without a `client_secret`.

Instead of a shared secret, the client generates a random `code_verifier`, derives
a `code_challenge` from it, and sends the challenge to the identity provider at the
start of the flow. When exchanging the authorization code for tokens, it sends the
original verifier. The identity provider checks that the verifier matches the
challenge it received earlier, proving the token request came from the same party
that initiated the login.

`fastapi-opa` handles this automatically. Configure `OIDCConfig` to get started.

## Client types

| | Confidential client | Public client |
|---|---|---|
| Has a `client_secret` | Yes | No |
| Secret stored securely | On the server | Has no secure storage |
| Needs PKCE | Optional (extra security) | Required |
| Use case | Server-side web app | SPA, mobile app, command-line tool |

## Setup

### Public client (no secret)

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
    client_id="my-public-client",
    # No client_secret for public clients
    is_public_client=True,
    code_challenge_method="S256",   # S256 required by most identity providers
    preserve_tokens=True,           # needed for CookieAuthMiddleware
)
oidc_auth = OIDCAuthentication(oidc_config)
opa_config = OPAConfig(authentication=oidc_auth, opa_host="http://localhost:8181")

app = FastAPI()
app.add_middleware(
    CookieAuthMiddleware,
    config=opa_config,
    cookie_config=TokenCookieConfig(cookie_secure=True),
)
```

Configure the client in your identity provider as a public client (no client
authentication). In Keycloak, set **Client authentication** to off when creating
the client.

### Confidential client with PKCE (added security layer)

PKCE adds a second layer of protection for confidential clients. The `client_secret`
still authenticates the token request; PKCE also prevents authorization code
interception:

```python
oidc_config = OIDCConfig(
    well_known_endpoint="https://idp.example.com/realms/myrealm/.well-known/openid-configuration",
    app_uri="https://app.example.com",
    client_id="my-confidential-client",
    client_secret="my-secret",
    is_public_client=False,         # default; client_secret is sent
    code_challenge_method="S256",
    preserve_tokens=True,
)
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `code_challenge_method` | `"S256"` | Hash method. Most identity providers require S256; strongly recommended for all deployments. |
| `code_verifier_length` | `128` | Length of the random verifier string in characters. RFC 7636 allows 43 to 128; 128 gives the highest entropy. |
| `response_type` | `"code"` | Must be `"code"` for the authorization code flow. |
| `grant_type` | `"authorization_code"` | Grant type for the token request. |

## Code verifier store

The middleware generates a code verifier at the start of the authorization flow and
retrieves it when the identity provider redirects back with the authorization code. The
middleware stores it in a `PKCEStore`.

### In-memory store

`InMemoryPKCEStore` serves as the default. It's thread-safe and suitable for
single-process deployments.

```python
# Default: in-memory store, no configuration needed
oidc_config = OIDCConfig(
    ...,
    pkce_store=None,  # None uses InMemoryPKCEStore
)
```

Customize TTL and size limits if needed:

```python
from fastapi_opa.auth.pkce_store import InMemoryPKCEStore

oidc_config = OIDCConfig(
    ...,
    pkce_store=InMemoryPKCEStore(
        ttl_seconds=300,   # default: 600 (10 minutes)
        max_entries=5000,  # default: 10000
    ),
)
```

### Multi-process deployments

When running several workers (Gunicorn, `uvicorn --workers`, Kubernetes replicas),
the callback after login may arrive at a different process than the one that started
the flow. The in-memory store doesn't work in this case.

Create a `PKCEStoreProtocol` backed by a shared store. The `retrieve` operation
**must** be atomic (fetch + delete) to prevent replay attacks.

```python
from typing import Optional
from fastapi_opa.auth.pkce_store import PKCEStoreProtocol


class RedisPKCEStore:
    """Redis-backed PKCE store for multi-process deployments."""

    def __init__(self, redis_client, ttl: int = 600) -> None:
        self.redis = redis_client
        self.ttl = ttl

    def store(self, state: str, code_verifier: str) -> None:
        self.redis.setex(f"pkce:{state}", self.ttl, code_verifier)

    def retrieve(self, state: str) -> Optional[str]:
        key = f"pkce:{state}"
        pipe = self.redis.pipeline()
        pipe.get(key)
        pipe.delete(key)
        value, _ = pipe.execute()
        return value.decode() if value else None
```

Pass the store to `OIDCConfig`:

```python
import redis

redis_client = redis.Redis(host="redis", port=6379, db=0)
pkce_store = RedisPKCEStore(redis_client, ttl=300)

oidc_config = OIDCConfig(
    ...,
    pkce_store=pkce_store,
)
```

### PKCEStoreProtocol

```python
class PKCEStoreProtocol(Protocol):
    def store(self, state: str, code_verifier: str) -> None:
        """Store code_verifier for the given state parameter."""
        ...

    def retrieve(self, state: str) -> str | None:
        """Retrieve and *remove* code_verifier for the given state.

        This operation must be atomic. Returns None if not found or expired.
        """
        ...
```

## Authlib extra

By default, `fastapi-opa` generates the code verifier and S256 challenge using
the Python standard library. Optionally install Authlib to use its implementation:

```bash
uv add "fastapi-opa[authlib]"
```

The behavior is identical. The stdlib fallback is production-ready; the extra exists
for environments that already depend on Authlib.

## Security notes

- Keep `code_verifier_length` at 128 (the default) for the highest entropy.
- Always use `S256` as the challenge method. The `plain` method provides no
  protection against interception.
- In multi-process deployments, use a Redis store with an appropriate TTL. The
- The verifier needs to survive the round-trip to the identity provider
  (typically seconds to a couple of minutes).
- Combine PKCE with `cookie_httponly=True` and `cookie_secure=True` to protect
  the resulting token once it's stored.
