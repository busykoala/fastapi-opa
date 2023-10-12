import re
from abc import ABC
from abc import abstractmethod
from typing import List
from typing import Optional

from starlette.requests import Request

from fastapi_opa.auth.auth_interface import AuthInterface


class Injectable(ABC):
    def __init__(
        self, key: str, skip_endpoints: Optional[List[str]] = []
    ) -> None:
        self.key = key
        self.skip_endpoints = [re.compile(skip) for skip in skip_endpoints]

    @abstractmethod
    async def extract(self, request: Request) -> List:
        pass


class OPAConfig:
    def __init__(
        self,
        authentication: [AuthInterface, List[AuthInterface]],
        opa_host: str,
        injectables: Optional[List[Injectable]] = None,
        accepted_methods: Optional[List[str]] = ["id_token", "access_token"],
        package_name: Optional[str] = "httpapi.authz",
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
        """

        if not isinstance(authentication, list):
            authentication = [authentication]
        self.authentication = authentication
        self.opa_url = (
            f"{opa_host.rstrip('/')}/v1/data/{package_name.replace('.', '/')}"
        )
        self.injectables = injectables
        self.accepted_methods = accepted_methods
        self.package_name = package_name
