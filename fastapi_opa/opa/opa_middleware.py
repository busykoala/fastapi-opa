import asyncio
import json
import logging
import re
from json.decoder import JSONDecodeError
from typing import List
from typing import Optional

import requests
from fastapi.responses import JSONResponse
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.types import ASGIApp
from starlette.types import Receive
from starlette.types import Scope
from starlette.types import Send

from fastapi_opa.auth.exceptions import AuthenticationException
from fastapi_opa.models import AuthenticationResult
from fastapi_opa.opa.opa_config import OPAConfig

Pattern = re.Pattern
logger = logging.getLogger(__name__)


def should_skip_endpoint(endpoint: str, skip_endpoints: List[Pattern]) -> bool:
    for skip in skip_endpoints:
        if skip.match(endpoint):
            return True
    return False


class OwnReceive:
    """
    This class is required in order to access the request
    body multiple times, e.g. once in the middleware and once in the endpoint implementation.
    See https://github.com/fastapi/fastapi/issues/394 for more details.
    """

    def __init__(
        self, receive: Receive, max_buffer_size: Optional[int] = None
    ):
        self.receive = receive
        self.buffer = []
        self._complete = False
        self.max_buffer_size = max_buffer_size
        self._buffer_size = 0

    async def __call__(self):
        if self._complete and self.buffer:
            return self.buffer.pop(0)

        data = await self.receive()

        # Calculate buffer size for body messages
        if data["type"] == "http.request":
            body_len = len(data.get("body", b""))
            if (
                self.max_buffer_size
                and self._buffer_size + body_len > self.max_buffer_size
            ):
                raise ValueError("Request body too large for buffering")
            self._buffer_size += body_len

        if data["type"] == "http.request" and not data.get("more_body", False):
            self._complete = True

        self.buffer.append(data)
        return data


class OPAMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        config: OPAConfig,
        skip_endpoints: Optional[List[str]] = None,
        force_authorization: Optional[bool] = False,
        max_buffer_size: Optional[int] = None,
    ) -> None:
        if skip_endpoints is None:
            skip_endpoints = [
                "/openapi.json",
                "/docs",
                "/redoc",
            ]
        self.config = config
        self.app = app
        self.skip_endpoints = [re.compile(skip) for skip in skip_endpoints]
        self.force_authorization = force_authorization
        self.max_buffer_size = max_buffer_size

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        try:
            if scope["type"] == "lifespan":
                return await self.app(scope, receive, send)

            # Small hack to ensure that later we can still receive the body
            own_receive = OwnReceive(
                receive, max_buffer_size=self.max_buffer_size
            )
            request = Request(scope, own_receive, send)

            # allow openapi endpoints without authentication
            if should_skip_endpoint(request.url.path, self.skip_endpoints):
                return await self.app(scope, receive, send)

            # Initialize state in scope
            if "state" not in scope:
                scope["state"] = {}

            # authenticate user or get redirect to identity provider
            successful = False
            auth_result = None
            user_info = None
            for auth in self.config.authentication:
                try:
                    auth_result = auth.authenticate(
                        request, self.config.accepted_methods
                    )
                    if asyncio.iscoroutine(auth_result):
                        auth_result = await auth_result

                    # Handle AuthenticationResult (new style)
                    if isinstance(auth_result, AuthenticationResult):
                        successful = auth_result.success
                        if successful:
                            # Store auth_result in scope for cookie middleware
                            scope["state"]["auth_result"] = auth_result
                            # Extract user info from the result
                            user_info = auth_result.model_dump()
                            if auth_result.user_info:
                                user_info = auth_result.user_info.copy()
                            elif auth_result.validated_token:
                                user_info = auth_result.validated_token.copy()
                            break
                    # Handle dict (legacy style for backwards compatibility)
                    elif isinstance(auth_result, dict):
                        successful = True
                        user_info = auth_result.copy()
                        break
                except AuthenticationException:
                    logger.error("AuthenticationException raised on login")

            # Some authentication flows require a prior redirect to id provider
            if isinstance(auth_result, RedirectResponse):
                return await auth_result(scope, receive, send)

            if not successful or user_info is None:
                return await self.get_unauthorized_response(
                    scope, receive, send
                )

            # Check OPA decision for info provided in user_info
            # Enrich user_info if injectables are provided
            if self.config.injectables:
                for injectable in self.config.injectables:
                    # Skip endpoints if needed
                    if should_skip_endpoint(
                        request.url.path, injectable.skip_endpoints
                    ):
                        continue
                    user_info[injectable.key] = await injectable.extract(
                        request
                    )

            user_info["request_method"] = scope.get("method")
            user_info["request_path"] = scope.get("path").split("/")[1:]
            data = {"input": user_info}

            if not self.force_authorization:
                opa_decision = requests.post(
                    self.config.opa_url, data=json.dumps(data), timeout=5
                )
                return await self.get_decision(
                    scope, own_receive, receive, send, opa_decision
                )
            else:
                scope["state"]["user_info"] = data["input"]
                return await self.get_decision(
                    scope, own_receive, receive, send
                )

        except ValueError as e:
            if "Request body too large" in str(e):
                response = JSONResponse(
                    status_code=413,
                    content={"message": "Request body too large"},
                )
                return await response(scope, receive, send)
            raise e

    def get_decision(
        self,
        scope: Scope,
        own_receive: OwnReceive,
        receive: Receive,
        send: Send,
        opa_decision=None,
    ):
        is_authorized = self.force_authorization
        if not is_authorized:
            if opa_decision.status_code != 200:
                logger.error(
                    f"Returned with status {opa_decision.status_code}."
                )
                return self.get_unauthorized_response(scope, receive, send)
            try:
                is_authorized = (
                    opa_decision.json().get("result", {}).get("allow")
                )
            except JSONDecodeError:
                logger.error("Unable to decode OPA response.")
                return self.get_unauthorized_response(scope, receive, send)
            if not is_authorized:
                return self.get_unauthorized_response(scope, receive, send)
        else:
            logger.info("OPA decision skipped from the configuration.")

        return self.app(scope, own_receive, send)

    @staticmethod
    async def get_unauthorized_response(
        scope: Scope, receive: Receive, send: Send
    ) -> None:
        response = JSONResponse(
            status_code=401, content={"message": "Unauthorized"}
        )
        return await response(scope, receive, send)
