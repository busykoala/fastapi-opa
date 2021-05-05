from abc import ABC
from abc import abstractmethod
from typing import List
from typing import Optional

from starlette.requests import Request

from fastapi_opa.auth.auth_interface import AuthInterface


class Injectable(ABC):
    def __init__(self, key: str) -> None:
        self.key = key

    @abstractmethod
    async def extract(self, request: Request) -> List:
        pass


class OPAConfig:
    def __init__(
        self,
        authentication: AuthInterface,
        opa_host: str,
        injectables: Optional[List[Injectable]] = None,
    ) -> None:
        self.authentication = authentication
        self.opa_url = f"{opa_host.rstrip('/')}/v1/data/httpapi/authz"
        self.injectables = injectables
