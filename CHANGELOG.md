# Change Log

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
