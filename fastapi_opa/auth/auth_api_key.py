import logging
from dataclasses import dataclass
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from starlette.requests import Request
from starlette.responses import Response

from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.auth.exceptions import AuthenticationException

logger = logging.getLogger(__name__)


@dataclass
class APIKeyConfig:
    header_key: str
    api_key: str


class APIKeyAuthentication(AuthInterface):
    def __init__(self, config: APIKeyConfig) -> None:
        self.config = config

    async def authenticate(
        self,
        request: Request,
        accepted_methods: Optional[List[str]] = [],
    ) -> Union[Response, Dict]:
        key = request.headers.get(self.config.header_key, None)
        if key is None or key != self.config.api_key:
            raise AuthenticationException("Unauthorized")
        return {
            "user": "APIKey",
            "client": request.client.host if request.client else "",
        }
