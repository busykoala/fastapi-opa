# Getting started: FastAPI with authentication and authorization

This guide walks through a minimal local setup with:

- A FastAPI app using `fastapi-opa` for authentication and authorization
- [Keycloak](https://www.keycloak.org/) as the identity provider (OIDC)
- [Open Policy Agent](https://www.openpolicyagent.org/) (OPA) for policy enforcement

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) with the Compose plugin
- [uv](https://docs.astral.sh/uv/)

## Set up the app

Create `app.py`:

```python
from fastapi import FastAPI

from fastapi_opa import OPAConfig
from fastapi_opa import OPAMiddleware
from fastapi_opa.auth import OIDCAuthentication
from fastapi_opa.auth import OIDCConfig

opa_host = "http://localhost:8181"

oidc_config = OIDCConfig(
    well_known_endpoint="http://localhost:8080/realms/example-realm/.well-known/openid-configuration",
    app_uri="http://localhost:4000",
    client_id="example-client",
    client_secret="<your-client-secret>",
)
oidc_auth = OIDCAuthentication(oidc_config)
opa_config = OPAConfig(authentication=oidc_auth, opa_host=opa_host)

app = FastAPI()
app.add_middleware(OPAMiddleware, config=opa_config)


@app.get("/finance/salary/{name}")
async def salary(name: str) -> dict[str, str]:
    return {"msg": "success", "name": name}
```

Install dependencies and start the app on port 4000:

```bash
uv add fastapi-opa uvicorn
uv run uvicorn app:app --port 4000
```

Visiting `http://localhost:4000/finance/salary/alice` redirects you to Keycloak (not yet running).

## Set up Keycloak and OPA

Create the OPA policy at `policy/auth.rego`:

```rego
package httpapi.authz

# bob is alice's manager, and betty is charlie's.
subordinates := {
  "alice": [],
  "charlie": [],
  "bob": ["alice"],
  "betty": ["charlie"],
}

import rego.v1

default allow := false

# Allow users to get their own salaries.
allow if {
  some username
  input.request_method == "GET"
  input.request_path = ["finance", "salary", username]
  input.user == username
}

# Allow managers to get their subordinates' salaries.
allow if {
  some username
  input.request_method == "GET"
  input.request_path = ["finance", "salary", username]
  subordinates[input.user][_] == username
}
```

Create `compose.yaml`:

```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:26.2
    command: start-dev
    ports:
      - "8080:8080"
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin

  opa:
    image: openpolicyagent/opa:1.4.0
    ports:
      - "8181:8181"
    command:
      - run
      - --server
      - --log-level=debug
      - /policy/auth.rego
    volumes:
      - ./policy:/policy
```

Your project layout should look like this:

```
.
├── app.py
├── compose.yaml
└── policy
    └── auth.rego
```

Start both services:

```bash
docker compose up -d
```

- Keycloak administrator panel: `http://localhost:8080`
- OPA playground: `http://localhost:8181`

## Configure Keycloak

Open the administrator panel at `http://localhost:8080` and log in as `admin` / `admin`.

### Create a realm

In the top-left dropdown select **Create realm** and name it `example-realm`.

### Create a client

Under **Clients** select **Create client**, set:

- **Client ID**: `example-client`
- **Client authentication**: on (confidential)
- **Root URL**: `http://localhost:4000`
- **Valid redirect URIs**: `http://localhost:4000/*`
- **Web origins**: `http://localhost:4000`

Save, then go to the **Credentials** tab and copy the generated secret into `app.py` as `client_secret`.

### Create users

Under **Users** create these five users: `alice`, `betty`, `bob`, `charlie`, `david`.

For each user add the following attributes under the **Attributes** tab:

| User    | `user`    | `subordinates`     | `hr`    | `azp`     |
|---------|-----------|--------------------|---------|-----------|
| alice   | alice     | `[]`               | `false` | alice     |
| betty   | betty     | `["charlie"]`      | `false` | betty     |
| bob     | bob       | `["alice"]`        | `false` | bob       |
| charlie | charlie   | `[]`               | `false` | charlie   |
| david   | david     | `[]`               | `true`  | david     |

Under the **Credentials** tab set a password for each user and turn off **Temporary**.

### Create attribute mappers

The token claims need mappers to carry the custom user attributes. For each attribute
(`user`, `subordinates`, `hr`, `azp`):

1. Go to **Clients** → `example-client` → **Client scopes**.
2. Click the scope listed as `example-client-dedicated` (created automatically).
3. Open the **Mappers** tab and select **Add mapper** → **By configuration** →
   **User Attribute**.
4. Set both **Name** and **User Attribute** to the attribute name (for example, `user`).
5. Enable **Add to ID token** and save.

## Test the setup

Visit `http://localhost:4000/finance/salary/alice` and log in as `alice`. You should see:

```json
{"msg": "success", "name": "alice"}
```

Try these scenarios to verify the policy works:

- Log in as `bob` and visit `/finance/salary/alice`—fails (bob manages alice but can't see alice's salary in this policy).
- Log in as `bob` and visit `/finance/salary/alice` with the allow-managers rule active—succeeds.
- Log in as `david` (`hr=true`) and visit `/finance/salary/alice`—succeeds if you add an HR rule to the policy.

The middleware validates your ID token and sends it to OPA. OPA evaluates `auth.rego` and returns
`allow: true` or `false`. The middleware lets the request through or returns 403 accordingly.
