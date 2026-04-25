# OPA token enrichment

The OPA payload contains the authenticated user's token claims plus `request_method` and
`request_path`. You can inject extra data into that payload using the `Injectable`
interface—useful when a policy decision depends on request context beyond the token.

## Custom injectables

Subclass `Injectable` and override `extract`. The return value must be JSON-serializable.
Register instances on `OPAConfig`.

```python
from starlette.requests import Request

from fastapi_opa import OPAConfig
from fastapi_opa.auth import OIDCAuthentication
from fastapi_opa.auth import OIDCConfig
from fastapi_opa.opa.opa_config import Injectable
from fastapi_opa.opa.cookie_middleware import CookieAuthMiddleware

oidc_config = OIDCConfig(
    well_known_endpoint="https://idp.example.com/realms/myrealm/.well-known/openid-configuration",
    app_uri="https://app.example.com",
    client_id="my-client",
    client_secret="my-secret",
    preserve_tokens=True,
)
oidc_auth = OIDCAuthentication(oidc_config)
opa_host = "http://localhost:8181"


class TenantInjectable(Injectable):
    async def extract(self, request: Request) -> list[object]:
        tenant = request.headers.get("X-Tenant-ID", "default")
        return [{"tenant": tenant}]


tenant_inj = TenantInjectable("tenant_info")

opa_config = OPAConfig(
    authentication=oidc_auth,
    opa_host=opa_host,
    injectables=[tenant_inj],
)
```

The key passed to the constructor (`"tenant_info"` in the preceding example) becomes the key in the OPA input:

```json
{
  "input": {
    "user": "alice",
    "request_method": "GET",
    "request_path": ["finance", "salary", "alice"],
    "tenant_info": [{"tenant": "acme"}]
  }
}
```

## Skip endpoints

Pass `skip_endpoints` to prevent the injectable from running on specific paths. Values can be
exact strings or regular expressions.

```python
tenant_inj = TenantInjectable(
    "tenant_info",
    skip_endpoints=["/health", "/api/[^/]*/test"],
)
```

## GraphQL enrichment

`GraphQLInjectable` parses GraphQL operation payloads and exposes operation names, types,
variables, and selection sets to OPA—without requiring your policy to parse raw query strings.

```python
from fastapi_opa.opa.enrichment.graphql_enrichment import GraphQLInjectable

gql_inj = GraphQLInjectable("gql_info")

opa_config = OPAConfig(
    authentication=oidc_auth,
    opa_host=opa_host,
    injectables=[gql_inj],
)
```

Install the `graphql` extra to use it:

```bash
uv add "fastapi-opa[graphql]"
```

### Example

For a request with this GraphQL payload:

```json
{
  "operationName": "getStudents",
  "variables": {"subject": "Physics", "enrolled": true},
  "query": "query getStudents($subject: String, $enrolled: Boolean) { students(subject: $subject, enrolled: $enrolled) { Student { name subject enrolled } } }"
}
```

The OPA input receives:

```json
{
  "input": {
    "user": "alice",
    "request_method": "POST",
    "request_path": ["graphql"],
    "gql_info": [
      {
        "name": "getStudents",
        "operation": "query",
        "variables": {"subject": "String", "enrolled": "Boolean"},
        "selection_set": [["students", ["Student", ["name", "subject", "enrolled"]]]]
      }
    ]
  }
}
```

You can then write OPA rules that restrict which operations or fields a user can query:

```rego
import rego.v1

default allow := false

allow if {
  op := input.gql_info[_]
  op.operation == "query"
  not forbidden_operation(op.name)
}

forbidden_operation(name) if {
  name in {"adminUsers", "deleteStudent"}
}
```
