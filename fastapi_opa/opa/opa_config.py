import re
from abc import ABC
from abc import abstractmethod
from typing import TypeGuard

from starlette.requests import Request

from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.opa.opa_client import OPAClient


class Injectable(ABC):
    def __init__(
        self, key: str, skip_endpoints: list[str] | None = None
    ) -> None:
        self.key = key
        if skip_endpoints is None:
            skip_endpoints = []
        self.skip_endpoints = [re.compile(skip) for skip in skip_endpoints]

    @abstractmethod
    async def extract(self, request: Request) -> list[object]:
        pass


def _is_authentication_list(
    authentication: AuthInterface | list[AuthInterface],
) -> TypeGuard[list[AuthInterface]]:
    return isinstance(authentication, list)


def _as_single_authentication(
    authentication: AuthInterface | list[AuthInterface],
) -> AuthInterface:
    if isinstance(authentication, list):
        raise TypeError("Expected a single authentication handler")
    return authentication


class OPAConfig:
    def __init__(
        self,
        authentication: AuthInterface | list[AuthInterface],
        opa_host: str,
        injectables: list[Injectable] | None = None,
        accepted_methods: list[str] | None = None,
        package_name: str | None = "httpapi.authz",
        opa_client: OPAClient | None = None,
    ) -> None:
        """
        Configuration container for the OPAMiddleware.

        PARAMETERS
        ----------
        authentication: [AuthInterface, List[AuthInterface]]
            Authentication Implementations to be used for the
            request authentication.
        opa_host: str
            URL to the OPA instance/server.
        injectables: List[Injectable], default=None
            List of injectables to be used to add informtation to the
            OPA request payload.
        accepted_methods: List[str], default=["id_token", "access_token"]
            List of accepted authentication methods.
        package_name: str, default="httpapi.authz
            Name of the OPA package to be used (specified in the policy).
        opa_client: OPAClient, default=None
            Asynchronous HTTP client used for the decision request. Any
            object with ``async post(url, *, json)`` returning
            ``status_code`` and ``json()`` works; ``httpx.AsyncClient``
            does as is. Defaults to an ``httpx.AsyncClient`` with a
            five-second timeout, created by the middleware on first use.
        """

        if accepted_methods is None:
            accepted_methods = ["id_token", "access_token"]

        authentication_list: list[AuthInterface]
        if _is_authentication_list(authentication):
            authentication_list = authentication
        else:
            authentication_list = [_as_single_authentication(authentication)]
        self.authentication = authentication_list
        if package_name is None:
            package_name = "httpapi.authz"
        self.opa_url = (
            f"{opa_host.rstrip('/')}/v1/data/{package_name.replace('.', '/')}"
        )
        self.injectables = injectables
        self.accepted_methods = accepted_methods
        self.package_name = package_name
        self.opa_client = opa_client
