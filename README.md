# Open Policy Agent middleware for FastAPI

## Table of contents
- [Contributors](#contributors)
- [What does fastapi-opa do](#about)
- [Installation](#installation)
- [How to get started](#getting-started)
- [Open Policy Agent](#opa)
- [Authentication flow](#auth-flow)
  - [API key authentication](#api-key-auth)
  - [OIDC authentication](#oidc-auth)
  - [SAML authentication](#saml-auth)
- [Custom payload enrichment](#custom-payload-enrichment)
  - [GraphQL enrichment](#gql-enrichment)

<a name="contributors"/>

## Contributors

Thanks to all the contributors below and everybody helping with issuing
suggestions and problems.

<a href="https://github.com/morestanna">
  <img src="https://avatars.githubusercontent.com/morestanna" width="60" height="60" />
</a>
<a href="https://github.com/busykoala">
  <img src="https://avatars.githubusercontent.com/busykoala" width="60" height="60" />
</a>
<a href="https://github.com/TracyWR">
  <img src="https://avatars.githubusercontent.com/TracyWR" width="60" height="60" />
</a>
<a href="https://github.com/loikki">
  <img src="https://avatars.githubusercontent.com/loikki" width="60" height="60" />
</a>
<a href="https://github.com/ejsyx">
  <img src="https://avatars.githubusercontent.com/ejsyx" width="60" height="60" />
</a>

<a name="about"/>

## What does fastapi-opa do

The FastAPI extension `fastapi-opa` that allows you to add a login flow
to your app within minutes using Open Policy Agent and your favourite
identity provider.

![Flow Diagram](https://raw.githubusercontent.com/busykoala/fastapi-opa/master/assets/diagram.png)

The middleware redirects the initial user request to the identity provider for
authentication. After the authentication the app validates the token provided.
Using the users validated token Open Policy Agent decides whether the response
has success or failure status.

<a name="installation"/>

## Installation

```bash
poetry add [--extras "graphql"] [--extras "saml"] fastapi-opa 
```

<a name="getting-started"/>

## How to get started

:bulb: checkout the wiki for a complete environment setup with Keycloak and Open Policy Agent:  
[Getting Started with FastAPI app with Authentication and Authorization](https://github.com/busykoala/fastapi-opa/wiki#dev-setup)

The package provides allows to integrate authentication and authorization with
FastAPI. Depending on your authentication flow you can inject different
configuration into the `OPAMiddleware`.

For the most frequently used flows checkout the examples: 
 - an example for OIDC : fastapi_opa.example_oidc.py,
 - an example for SAML: fastapi_opa.example_saml.py

## Open Policy Agent

The middleware sends the validated and authenticated user token to the Open
Policy Agent with the extra attributes `request_method` and
`request_path`.

```json
{
    "input": {
        "exp": 1617466243,
        "iat": 1617465943,
        "auth_time": 1617465663,
        "jti": "9aacb638-70c6-4f0a-b0c8-dbc67f92e3d1",
        "iss": "http://localhost:8080/auth/realms/example-realm",
        "aud": "example-client",
        "sub": "ccf78dc0-e1d6-4606-99d4-9009e74e3ab4",
        "typ": "ID",
        "azp": "david",
        "session_state": "41640fe7-39d2-44bc-818c-a3360b36fb87",
        "at_hash": "2IGw-B9f5910Sll1tnfQRg",
        "acr": "0",
        "email_verified": false,
        "hr": "true",
        "preferred_username": "david",
        "user": "david",
        "subordinates": [],
        "request_method": "GET",
        "request_path": ["finance", "salary", "david"]
    }
}
```

In Open Policy Agent you can now create policies using user roles,
routes, or request methods etc.

An example policy (from [the official Open Policy Agent
docs](https://www.openpolicyagent.org/docs/v0.11.0/http-api-authorization/))
for this setup could look like this:

```rego
package httpapi.authz

# bob is alice's manager, and betty is charlie's.
subordinates = {"alice": [], "charlie": [], "bob": ["alice"], "betty": ["charlie"]}

# HTTP API request
import input

default allow = false

# Allow users to get their own salaries.
allow {
  some username
  input.request_method == "GET"
  input.request_path = ["finance", "salary", username]
  input.user == username
}

# Allow managers to get their subordinates' salaries.
allow {
  some username
  input.request_method == "GET"
  input.request_path = ["finance", "salary", username]
  subordinates[input.user][_] == username
}
```

<a name="auth-flow"/>

## Authentication flow

Set up the desired authentication flow with the interface provided and inject
it into `OPAMiddleware` (`fastapi_opa.auth.auth_interface.AuthInterface`), or
open a pull request if you would like to contribute to the package.

Possibly you can make use of the ready to use implementations below.

<a name="api-key-auth"/>

### API key authentication

In the API key authentication a request header needs to match a given value.

```python
# Configure API keys
api_key_config = APIKeyConfig(
    header_key="test",
    api_key="1234"
)
api_key_auth = APIKeyAuthentication(api_key_config)
```

In the example the header `header["test"] = "1234"` authenticates the request.
For Open Policy Agent, set user to `APIKey` and the variable `client` to the
client address.

<a name="oidc-auth"/>

### OIDC authentication

The example in [How to get started](#getting-started) provides an example for
the implementation of the OIDC Authentication.

<a name="saml-auth"/>

### SAML authentication

For the saml implementation create your certs using
`openssl req -new -x509 -days 3652 -nodes -out sp.crt -keyout sp.key` and
add the keys to the sp section of your `settings.json`. Checkout the test
settings to get an idea (`tests/test_data/saml/*.json`).
Provide the path to your own `settings.json` and `advanced_settings.json`
in the `SAMLAuthConfig` like in the example below (don't use the test data in
production).

```python
from fastapi_opa import OPAConfig
from fastapi_opa.auth.auth_saml import SAMLAuthentication
from fastapi_opa.auth.auth_saml import SAMLConfig

opa_host = "http://localhost:8181"

saml_config = SAMLConfig(settings_directory="./tests/test_data/saml")
saml_auth = SAMLAuthentication(saml_config)

opa_config = OPAConfig(authentication=saml_auth, opa_host=opa_host,
                       accepted_methods=["id_token", "access_token"])
```

Upload the certificate to your identity provider. Using Keycloak as an
identity provider you need to configure `encrypt assertion`,
`client signature required`, `force POST bindings` on creating the client.
Also configure: `Client Scopes` -> `role_list (saml)` -> `Mappers tab` ->
`role list` -> `Single Role Attribute`

<a name="custom-payload-enrichment"/>

## Custom payload enrichment

Use the interface `fastapi_opa.opa.opa_config.Injectable` to add
more information to the payload sent to Open Policy Agent.

Configure the injectables in the `OPAConfig`:

```python
class FancyInjectable(Injectable):
    async def extract(self, request: Request) -> List:
        return ["some", "custom", "stuff"]

fancy_inj = FancyInjectable("fancy_key", skip_endpoints=["/health", "/api/[^/]*/test])

opa_config = OPAConfig(
    authentication=oidc_auth, opa_host=opa_host, injectables=[fancy_inj]
)
```

With `skip_endpoints`, you can define some endpoints where the injectable
has no effect.
To define an endpoint either use an exact string or a regular expression.


<a name="gql-enrichment"/>

### GraphQL enrichment

For GraphQL you can use the ready to go injectable:

```python
from fastapi_opa.opa.enrichment.graphql_enrichment import GraphQLInjectable`

graphql = GraphQLInjectable("gql_injectable")
opa_config = OPAConfig(authentication=oidc_auth, opa_host=opa_host, injectables=[graphql])
```
