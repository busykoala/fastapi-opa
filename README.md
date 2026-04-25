# Open Policy Agent (OPA) middleware for FastAPI

## Table of contents

- [About](#about)
- [Installation](#installation)
- [Quick start](#getting-started)
- [Documentation](#documentation)
- [Development](#development)
- [Contributors](#contributors)

<a name="about"/>

## About

`fastapi-opa` adds authentication and authorization middleware to FastAPI. It handles
the login flow with an identity provider, validates the returned token, and forwards
the user's claims to [Open Policy Agent](https://www.openpolicyagent.org/) for
policy-based access control.

![Flow Diagram](https://raw.githubusercontent.com/busykoala/fastapi-opa/master/assets/diagram.png)

Every request passes through the middleware. Unauthenticated requests redirect to the
identity provider. Once OPA validates the token, it evaluates the request against your
policy and either allows or rejects it with a 403.

<a name="installation"/>

## Installation

```bash
uv add fastapi-opa
```

Optional extras:

| Extra | Adds |
|-------|------|
| `graphql` | `GraphQLInjectable` for GraphQL payload enrichment |
| `saml` | SAML 2.0 authentication support |
| `authlib` | Authlib-backed PKCE token generation (stdlib fallback used otherwise) |

```bash
uv add "fastapi-opa[graphql,saml]"
```

For SAML, you may need to install the binary dependencies without wheels:

```bash
PIP_NO_BINARY="lxml,xmlsec" uv run pip install --force-reinstall --no-binary=lxml --no-binary=xmlsec lxml xmlsec
```

<a name="getting-started"/>

## Quick start

:bulb: see [docs/getting-started.md](docs/getting-started.md) for a complete local
setup with Keycloak and OPA, including Docker Compose configuration and a working
policy.

Add the middleware to your FastAPI app:

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
    preserve_tokens=True,  # required for CookieAuthMiddleware
)
oidc_auth = OIDCAuthentication(oidc_config)
opa_config = OPAConfig(authentication=oidc_auth, opa_host="http://localhost:8181")

app = FastAPI()
app.add_middleware(
    CookieAuthMiddleware,
    config=opa_config,
    cookie_config=TokenCookieConfig(cookie_secure=True),
)


@app.get("/finance/salary/{name}")
async def salary(name: str) -> dict[str, str]:
    return {"msg": "success", "name": name}
```

<a name="documentation"/>

## Documentation

### Introduction and tutorials

| Doc | Description |
|-----|-------------|
| [docs/getting-started.md](docs/getting-started.md) | Full local setup with Keycloak and OPA: Docker Compose, Rego policy, Keycloak configuration |

### Open Policy Agent

| Doc | Description |
|-----|-------------|
| [docs/opa.md](docs/opa.md) | OPA input format, policy examples, `OPAConfig` reference, skipping endpoints, body buffering |
| [docs/token-enrichment.md](docs/token-enrichment.md) | Custom injectables and GraphQL enrichment to add extra fields to the OPA input |

### Authentication

| Doc | Description |
|-----|-------------|
| [docs/authentication.md](docs/authentication.md) | All authentication methods: API key, OIDC (full configuration reference), SAML, custom handlers |
| [docs/cookie-auth.md](docs/cookie-auth.md) | Cookie-based sessions with `CookieAuthMiddleware`: flow, `TokenCookieConfig` options, security checklist |
| [docs/pkce.md](docs/pkce.md) | Public clients and PKCE: setup, `PKCEStoreProtocol`, example Redis store for multi-process deployments |

<a name="development"/>

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide. In brief:

```bash
# Install all dev dependencies
uv sync

# Full QA pipeline: lint, type check, tests, security scan
make qa

# Tests only
uv run pytest

# Tests against the lowest allowed dependency versions
make qa-lowest
```

<a name="contributors"/>

## Contributors

Thanks to all the contributors below. Furthermore thanks for raising issues.

<a href="https://github.com/morestanna"><img src="https://avatars.githubusercontent.com/morestanna" width="60" height="60" /></a><a href="https://github.com/busykoala"><img src="https://avatars.githubusercontent.com/busykoala" width="60" height="60" /></a><a href="https://github.com/TracyWR"><img src="https://avatars.githubusercontent.com/TracyWR" width="60" height="60" /></a><a href="https://github.com/loikki"><img src="https://avatars.githubusercontent.com/loikki" width="60" height="60" /></a><a href="https://github.com/ejsyx"><img src="https://avatars.githubusercontent.com/ejsyx" width="60" height="60" /></a><a href="https://github.com/JimFawkes"><img src="https://avatars.githubusercontent.com/JimFawkes" width="60" height="60" /></a><a href="https://github.com/DiamondJoseph"><img src="https://avatars.githubusercontent.com/DiamondJoseph" width="60" height="60" /></a><a href="https://github.com/miceg"><img src="https://avatars.githubusercontent.com/miceg" width="60" height="60" /></a><a href="https://github.com/JulianSprung"><img src="https://avatars.githubusercontent.com/JulianSprung" width="60" height="60" /></a><a href="https://github.com/francbartoli"><img src="https://avatars.githubusercontent.com/francbartoli" width="60" height="60" /></a>