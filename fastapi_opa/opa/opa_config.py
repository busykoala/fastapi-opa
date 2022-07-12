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
    ) -> None:
        if not isinstance(authentication, list):
            authentication = [authentication]
        self.authentication = authentication
        self.opa_url = f"{opa_host.rstrip('/')}/v1/data/httpapi/authz"
        self.injectables = injectables
        self.accepted_methods = accepted_methods
