import asyncio
import json
import logging
from json.decoder import JSONDecodeError
from typing import List
from typing import Optional
from unittest.mock import patch

import requests
from fastapi.responses import JSONResponse
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.types import ASGIApp
from starlette.types import Receive
from starlette.types import Scope
from starlette.types import Send

from fastapi_opa.auth.exceptions import AuthenticationException
from fastapi_opa.opa.opa_config import OPAConfig

logger = logging.getLogger(__name__)


class OPAMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        config: OPAConfig,
        skip_endpoints: Optional[List[str]] = [
            "/openapi.json",
            "/docs",
            "/redoc",
        ],
    ) -> None:
        self.config = config
        self.app = app
        self.skip_endpoints = skip_endpoints

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:

        request = Request(scope, receive, send)

        if request.method == "OPTIONS":
            return await self.app(scope, receive, send)

        # allow openapi endpoints without authentication
        if any(
            request.url.path == endpoint for endpoint in self.skip_endpoints
        ):
            return await self.app(scope, receive, send)

        # authenticate user or get redirect to identity provider
        try:
            user_info_or_auth_redirect = (
                self.config.authentication.authenticate(request)
            )
            if asyncio.iscoroutine(user_info_or_auth_redirect):
                user_info_or_auth_redirect = await user_info_or_auth_redirect
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
        # Enrich user_info if injectables are provided
        if self.config.injectables:
            for injectable in self.config.injectables:
                # Skip endpoints if needed
                if request.url.path in injectable.skip_endpoints:
                    continue
                user_info_or_auth_redirect[
                    injectable.key
                ] = await injectable.extract(request)
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

        # Small hack to avoid reading twice the request's body in the
        # middleware stack
        # See https://github.com/tiangolo/fastapi/issues/394 for more details
        with patch.object(Request, "body", request.body):
            return await self.app(scope, receive, send)

    @staticmethod
    async def get_unauthorized_response(
        scope: Scope, receive: Receive, send: Send
    ) -> None:
        response = JSONResponse(
            status_code=401, content={"message": "Unauthorized"}
        )
        return await response(scope, receive, send)
