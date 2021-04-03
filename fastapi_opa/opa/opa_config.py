from fastapi_opa.auth.auth_interface import AuthInterface


class OPAConfig:
    def __init__(self, authentication: AuthInterface, opa_host: str) -> None:
        self.authentication = authentication
        self.opa_url = f"{opa_host.rstrip('/')}/v1/data/httpapi/authz"
