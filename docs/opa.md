# Open Policy Agent integration

`fastapi-opa` sends each authenticated request to OPA for policy evaluation. OPA
receives the user's validated token claims plus two fields added by the middleware,
evaluates your Rego policy, and returns an `allow` decision. The middleware either
forwards the request to your handler or responds with 403.

## OPA input

The middleware builds the OPA input from the validated token (ID token or access
token claims) and appends:

| Added field | Value |
|-------------|-------|
| `request_method` | HTTP method, for example `"GET"` |
| `request_path` | URL path split into segments, for example `["finance", "salary", "alice"]` |

Example input document sent to OPA:

```json
{
    "input": {
        "exp": 1617466243,
        "iss": "https://idp.example.com/realms/example-realm",
        "aud": "example-client",
        "preferred_username": "david",
        "user": "david",
        "hr": "true",
        "subordinates": [],
        "request_method": "GET",
        "request_path": ["finance", "salary", "david"]
    }
}
```

The exact set of token claims depends on your identity provider and the scopes
requested. The middleware appends custom claims automatically—see
[docs/token-enrichment.md](token-enrichment.md) to add extra fields from the
request context.

## Writing policies

OPA evaluates the input against a package whose name matches `OPAConfig.package_name`
(default `httpapi.authz`). The middleware looks for an `allow` rule and permits the
request only when `allow` evaluates to the boolean value `true`; non-boolean values
are rejected with 403.

Example policy (Rego v1):

```rego
package httpapi.authz

import rego.v1

subordinates := {
  "alice":   [],
  "charlie": [],
  "bob":     ["alice"],
  "betty":   ["charlie"],
}

default allow := false

# Allow users to view their own salary.
allow if {
  some username
  input.request_method == "GET"
  input.request_path = ["finance", "salary", username]
  input.user == username
}

# Allow managers to view their reports' salaries.
allow if {
  some username
  input.request_method == "GET"
  input.request_path = ["finance", "salary", username]
  subordinates[input.user][_] == username
}
```

Use `import rego.v1` for all new policies. It enables strict mode and the modern
`if`/`contains` keywords. See the
[OPA documentation](https://www.openpolicyagent.org/docs/latest/policy-language/)
for a full language reference.

## OPAConfig reference

`OPAConfig` holds every setting the middleware needs.

```python
from fastapi_opa import OPAConfig

opa_config = OPAConfig(
    authentication=oidc_auth,
    opa_host="http://localhost:8181",
    injectables=[tenant_inj],
    accepted_methods=["id_token", "access_token"],
    package_name="httpapi.authz",
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `authentication` | — | `AuthInterface` instance, or a list of instances for fallback chains |
| `opa_host` | — | Base URL of your OPA instance, for example `"http://localhost:8181"` |
| `injectables` | `[]` | `Injectable` instances to add extra fields to the OPA input |
| `accepted_methods` | `["id_token", "access_token"]` | Token types the middleware accepts during authentication |
| `package_name` | `"httpapi.authz"` | Rego package name; must match the `package` declaration in your policy |
| `opa_client` | `httpx.AsyncClient` | Asynchronous HTTP client for the decision request; see [Bringing your own HTTP client](#bringing-your-own-http-client) |

The `package_name` maps to the OPA REST API path by replacing dots with slashes:
`"httpapi.authz"` → `/v1/data/httpapi/authz`.

### Bringing your own HTTP client

The middleware asks OPA for a decision with an asynchronous request, so the
event loop keeps serving other requests while OPA answers. By default it
creates an `httpx.AsyncClient` with a five-second timeout on first use and
keeps it for connection pooling; `await middleware.aclose()` releases it.

Pass `opa_client` to use a client of your own, for example one with custom
TLS settings, a different timeout, or another library. Any object with an
`async post(url, *, json)` method that returns something exposing
`status_code` and `json()` works:

```python
import httpx

opa_config = OPAConfig(
    authentication=oidc_auth,
    opa_host="http://localhost:8181",
    opa_client=httpx.AsyncClient(timeout=2.0, verify="/etc/ssl/opa-ca.pem"),
)
```

The same hook is the seam for tests: an in-memory client records the input
documents and answers as told, and nothing needs patching.

### Authentication handler chains

Pass a list to `authentication` to support fallback chains. The middleware tries
each handler in order and uses the first successful result:

```python
opa_config = OPAConfig(
    authentication=[oidc_auth, api_key_auth],
    opa_host="http://localhost:8181",
)
```

### Accepted methods

`accepted_methods` controls which token types count as valid for a request.
The default `["id_token", "access_token"]` works for OIDC flows. Change it when
using SAML or a custom flow:

```python
# SAML typically uses assertion-based tokens
opa_config = OPAConfig(
    authentication=saml_auth,
    opa_host=opa_host,
    accepted_methods=["id_token", "access_token"],
)
```

## Skipping endpoints

Both `OPAMiddleware` and `CookieAuthMiddleware` skip authentication and
authorization on `/openapi.json`, `/docs`, and `/redoc` by default. Override with
`skip_endpoints`—values are exact strings or regular expressions:

```python
from fastapi_opa.opa.cookie_middleware import CookieAuthMiddleware

app.add_middleware(
    CookieAuthMiddleware,
    config=opa_config,
    skip_endpoints=["/health", "/metrics", "/api/public/.*"],
)
```

Providing `skip_endpoints` replaces the default list entirely. Include `/docs`
explicitly if you still want to serve the OpenAPI UI without authentication.

## Disabling authorization

Set `enable_authorization=False` to run authentication without OPA policy checks.
Every authenticated user reaches every endpoint; OPA isn't contacted. The middleware
logs a warning at startup.

```python
app.add_middleware(
    CookieAuthMiddleware,
    config=opa_config,
    enable_authorization=False,  # authentication only, no policy checks
)
```

Use this mode when your app handles its own authorization logic, or when
testing the authentication flow without a running OPA instance.

## Buffering large request bodies

`OPAMiddleware` buffers the request body so both the enrichment layer and your handler
can access it. Set `max_buffer_size` to limit memory use:

```python
app.add_middleware(
    CookieAuthMiddleware,
    config=opa_config,
    max_buffer_size=1_048_576,  # 1 MB
)
```

Requests with a body larger than `max_buffer_size` raise a `ValueError` before
reaching your handler. The default (`None`) sets no limit.
