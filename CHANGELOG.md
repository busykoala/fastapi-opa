# Change Log

## [1.0.1] - 2021-04-25

- Remove uvicorn as a pkg dependency.

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
