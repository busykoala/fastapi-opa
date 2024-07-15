# Change Log

## [2.0.2] - 2024-07-15
- Replace linting and formatting with ruff.
- Fix deprecation warnings in tests.

## [2.0.1] - 2024-07-15
- Security Improvement: Added authentication and authorization checks for HTTP
  OPTIONS requests in OpaMiddleware. This ensures that OPTIONS requests are
  subjected to the same security policies as other HTTP methods, preventing
  potential information leaks.
  [See advisory for more details](https://github.com/advisories/GHSA-5f5c-8rvc-j8wf)
- Update dependencies due to multiple vulnerabilities.

## [2.0.0] - 2024-02-07
- Drop Python 3.7 support due to FastAPI update
- Update dependencies due to vulnerabilities:
  - [fastapi](https://github.com/advisories/GHSA-qf9m-vfgh-m389)

## [1.4.8] - 2024-01-12
- Optionally use `x-forwarded-` cookies when reconstructing redirect path for OIDC

## [1.4.7] - 2023-10-12
- Add option to define package name parameter in OPA Config

## [1.4.6] - 2023-08-15
- Update dependencies due to vulnerabilities
  - [certifi](https://github.com/advisories/GHSA-xqr8-7jwr-rhp7)
  - [cryptography](https://github.com/advisories/GHSA-cf7p-gm2m-833m)
  - [cryptography](https://github.com/advisories/GHSA-jm77-qphf-c4w8)
  - [GitPython](https://github.com/advisories/GHSA-pr76-5cm5-w9cj)

## [1.4.5] - 2023-06-04
- Use flake8 instead of flake9 to enable removing transitive override.

## [1.4.4] - 2023-05-24
- Update dependencies due to vulnerabilities.
  - requests: [CVE-2023-32681](https://github.com/advisories/GHSA-j8r2-6x86-q33q)
  - starlette: [no CVE](https://github.com/advisories/GHSA-v5gw-mw7f-84px)
- Add timeout to requests calls [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

## [1.4.3] - 2023-03-01
- Add documentation guidelines enforced with vale.
- Update packages due to vulnerability [CVE-2023-0286](https://github.com/advisories/GHSA-x4qr-2fvf-3mr5) and others.

## [1.4.2] - 2023-01-02
- Bump GitPython due to vulnerability [CVE-2022-24439](https://github.com/advisories/GHSA-hcpj-qp55-gfph)
- Drop Python 3.6 support due to incompatibility with GitPython > 3.1.29.
- Change method from get to post in testing to fix parameter issue.

## [1.4.1] - 2022-08-04
- Fix a bug with oidc redirect login

## [1.4.0] - 2022-07-12
- Add API Key authentication
- Add options to allow multiple authentication methods
- Bump lxml (transitive dependency) due to vulnerability [CVE-2022-2309](https://github.com/advisories/GHSA-wrxv-2j5q-m38w)

## [1.3.7] - 2022-05-26
- Bump pyjwt due to vulnerability [CVE-2022-29217](https://github.com/advisories/GHSA-ffqj-6fqr-9h24)

## [1.3.6] - 2022-05-23
- Fix multiple usage of the request body

## [1.3.5] - 2022-05-16
- Skip lifespan requests (server startup / shutdown)

## [1.3.4] - 2022-05-11
- Improve type extraction for graphql

## [1.3.3] - 2022-04-09
- Uses regex to skip endpoints
- Properly implement the usage of access tokens
- Add an option to allow id tokens or access tokens
- Replace contrib.rocks img with manual list

## [1.3.2] - 2022-03-10
- Add the option to skip some given endpoints (middleware + injectable).
- Allow authentication through bearer token
- Fix a bug with graphql injectable
- Update versions and fix python version range

## [1.3.1] - 2021-09-19

- Allow updating fastapi >= 0.66 and force updating because of CVE in
  versions < 0.65.2.
- Stop protecting the openapi endpoints by this middleware.
- Skip CORS "OPTIONS" requests.
- Change redirect to OIDC identity provider from 307 to 303.

## [1.3.0] - 2021-08-08

- Add session middleware and single log out for auth_saml
- Remove fixed versions of dependencies.

## [1.2.1] - 2021-05-30

- Add readme flow diagram with absolute link to be displayed on pypi.

## [1.2.0] - 2021-05-29

- Add saml authentication as an authentication method.
- Adapt authentication interface (backwards compatible) to allow async and
  request usage within the authentication method.

## [1.1.0] - 2021-05-06

- Allow custom injectables to enrich the payload sent to OPA.
- Add GraphQLAnalysis to parse raw GraphQL payloads and add an injectable to
  send additional data to OPA allowing fine-grained authorization policies.

## [1.0.1] - 2021-04-25

- Remove uvicorn as a pkg dependency.
- Make OIDC jkws endpoint optional (not necessary for the HS256 algorithm).

## [1.0.0] - 2021-04-22

- Allow non-keycloak well_known endpoints and usage without a well_known
  endpoint. This changes the interface of the OIDC config object.
- Add support for python versions > 3.6.

## [0.1.1] - 2021-04-11

- Testing of OPA middleware and OIDC authentication as well as the
  pipeline setup for executing tests, style checks and dependency audit.
  ([#4](https://github.com/busykoala/fastapi-opa/pull/4))
  
## [0.1.0] - 2021-04-03

- Initial implementation of OPA middleware and OIDC authentication.
- Package documentation and usage instructions.
