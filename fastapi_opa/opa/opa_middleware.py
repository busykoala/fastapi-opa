import json
import logging
from json.decoder import JSONDecodeError

import requests
from fastapi.responses import JSONResponse
from starlette.requests import HTTPConnection
from starlette.responses import RedirectResponse
from starlette.types import ASGIApp
from starlette.types import Receive
from starlette.types import Scope
from starlette.types import Send

from fastapi_opa.auth.exceptions import AuthenticationException
from fastapi_opa.opa.opa_config import OPAConfig

logger = logging.getLogger(__name__)


class OPAMiddleware:
    def __init__(self, app: ASGIApp, config: OPAConfig) -> None:
        self.config = config
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        # authenticate user or get redirect to identity provider
        try:
            user_info_or_auth_redirect = (
                self.config.authentication.authenticate(  # noqa
                    HTTPConnection(scope)
                )
            )
        except AuthenticationException:
            logger.error("AuthenticationException raised on login")
            return await self.get_unauthorized_response(scope, receive, send)
        # Some authentication flows require a prior redirect to id provider
        if isinstance(user_info_or_auth_redirect, RedirectResponse):
            return await user_info_or_auth_redirect.__call__(
                scope, receive, send
            )

        # Check OPA decision for info provided in user_info
        is_authorized = False
        user_info_or_auth_redirect["request_method"] = scope.get("method")
        # fmt: off
        user_info_or_auth_redirect["request_path"] = scope.get("path").split("/")[1:]  # noqa
        # fmt: on
        data = {"input": user_info_or_auth_redirect}
        opa_decision = requests.post(
            self.config.opa_url, data=json.dumps(data)
        )
        if opa_decision.status_code != 200:
            logger.error(f"Returned with status {opa_decision.status_code}.")
            return await self.get_unauthorized_response(scope, receive, send)
        try:
            is_authorized = opa_decision.json().get("result", {}).get("allow")
        except JSONDecodeError:
            logger.error("Unable to decode OPA response.")
            return await self.get_unauthorized_response(scope, receive, send)
        if not is_authorized:
            return await self.get_unauthorized_response(scope, receive, send)

        return await self.app(scope, receive, send)

    @staticmethod
    async def get_unauthorized_response(
        scope: Scope, receive: Receive, send: Send
    ) -> None:
        response = JSONResponse(
            status_code=401, content={"message": "Unauthorized"}
        )
        return await response(scope, receive, send)
