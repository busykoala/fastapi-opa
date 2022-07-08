# Open Policy Agent Middleware for FastAPI

## Table of Contents
- [Contributors](#contributors)
- [What does fastapi-opa do](#about)
- [Installation](#installation)
- [How to get started](#getting-started)
- [Open Policy Agent](#opa)
- [Authentication Flow](#auth-flow)
  - [API Key Authentication](#api-key-auth)
  - [OIDC Authentication](#oidc-auth)
  - [SAML Authentication](#saml-auth)
- [Custom Payload Enrichment](#custom-payload-enrichment)
  - [Graphql Enrichment](#gql-enrichment)

<a name="contributors"/>

## Contributors

Thanks to all our contributors! There is no specific order and hopefully nobody was left out.

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

<a name="about"/>

## What does fastapi-opa do

`fastapi-opa` is an extension to FastAPI that allows you to add a login flow
to your application within minutes using open policy agent and your favourite
identity provider.

![Flow Diagram](https://raw.githubusercontent.com/busykoala/fastapi-opa/master/assets/diagram.png)

When a user tries to get a response from an endpoint he/she will be redirected
to the identity provider for authorization.
After the authentication the app validates the token provided. Once it was
validated the user information is used to get an OPA decision whether
the user is allowed to get any information from the endpoint.

<a name="installation"/>

## Installation

```bash
poetry add [--extras "graphql"] [--extras "saml"] fastapi-opa 
```

<a name="getting-started"/>

## How to get started

:bulb: Checkout the wiki for a complete environment setup with Keycloak and Open Policy Agent:  
[Getting Started with FastAPI app with Authentication and Authorization](https://github.com/busykoala/fastapi-opa/wiki#dev-setup)

The package provides a very easy way to integrate authentication and
authorization. We can decide what authentication flow we inject into the
OPAMiddleware to be able choosing between different flows.

There are 
 - one example for oidc : fastapi_opa.example_oidc.py,
 - one example for saml: fastapi_opa.example_saml.py

## Open Policy Agent

The (validated/authenticated) user token is sent to the Open Policy Agent
with the additional attributes `request_method` and `request_path`.

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

In open policy agent you can now easily create policies using user roles,
routes, or request methods etc.

An example policy (from [the official OPA docs](https://www.openpolicyagent.org/docs/v0.11.0/http-api-authorization/))
for this setup could be like:

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

## Authentication Flow

There is an interface provided to easily implement the desired authentication
flow and inject it into OPAMiddleware
(`fastapi_opa.auth.auth_interface.AuthInterface`), or you can open a pull
request if you would like to contribute to the package.

Also there are implementations ready to use.

<a name="api-key-auth"/>

### API Key Authentication

The API key authentication is the simplest authentication system where you simply needs to match
a given value in the request header:
```python
# Configure API keys
api_key_config = APIKeyConfig(
    header_key="test",
    api_key="1234"
)
api_key_auth = APIKeyAuthentication(api_key_config)
```
Here sending a request with the `header["test"] = "1234"` would be considered as a successful authentication.
For OPA, the user is `APIKey` and the variable `client` is set with the client address.

<a name="oidc-auth"/>

### OIDC Authentication

The example in [How to get started](#getting-started) provides an example for
the implementation of the OIDC Authentication.

<a name="saml-auth"/>

### SAML Authentication

For the saml implementation create your certs using
`openssl req -new -x509 -days 3652 -nodes -out sp.crt -keyout sp.key` and
add the keys to the sp section of your `settings.json`. Checkout the test
settings to get an idea (`tests/test_data/saml/*.json`). The path to your
own `settings.json` and `advanced_settings.json` has to be provided in the
`SAMLAuthConfig` like in the example below (do not use the test data in
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

The cert has to be uploaded to your identity provider. Using Keycloak as an
idp you need to configure `encrypt assertion`, `client signature required`,
`force POST bindings` on creating the client.
Also configure: `Client Scopes` -> `role_list (saml)` -> `Mappers tab` ->
`role list` -> `Single Role Attribute`

<a name="custom-payload-enrichment"/>

## Custom Payload Enrichment

In `fastapi_opa.opa.opa_config.Injectable` an interface is provided to add
more information to the payload sent to OPA.

The injectables can be added to the `OPAConfig`. Let's look at an example:

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
will not be applied. The endpoints can be defined either directly or through some
regex.


<a name="gql-enrichment"/>

### Graphql Enrichment

For GraphQL there is a ready to use injectable:

```python
from fastapi_opa.opa.enrichment.graphql_enrichment import GraphQLInjectable`

graphql = GraphQLInjectable("gql_injectable")
opa_config = OPAConfig(authentication=oidc_auth, opa_host=opa_host, injectables=[graphql])
```
