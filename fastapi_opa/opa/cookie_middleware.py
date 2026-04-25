"""Cookie-based authentication middleware implementation"""

import logging
from http.cookies import SimpleCookie

from starlette.responses import RedirectResponse
from starlette.types import ASGIApp
from starlette.types import Message
from starlette.types import Receive
from starlette.types import Scope
from starlette.types import Send

from fastapi_opa.auth.auth_oidc import skip_user_info_for_request
from fastapi_opa.models import AuthenticationResult
from fastapi_opa.models import TokenCookieConfig
from fastapi_opa.opa.opa_config import OPAConfig
from fastapi_opa.opa.opa_middleware import OPAMiddleware

logger = logging.getLogger(__name__)


class CookieAuthMiddleware:
    """Middleware for cookie-based authentication that extends OPA functionality"""

    def __init__(
        self,
        app: ASGIApp,
        config: OPAConfig,
        cookie_config: TokenCookieConfig | None = None,
        skip_endpoints: list[str] | None = None,
        enable_authorization: bool = True,
        max_buffer_size: int | None = None,
    ) -> None:
        self.app = app
        self.config = config
        self.cookie_config = cookie_config or TokenCookieConfig()
        self.opa: ASGIApp = OPAMiddleware(
            app=app,
            config=config,
            skip_endpoints=skip_endpoints,
            enable_authorization=enable_authorization,
            max_buffer_size=max_buffer_size,
        )

    def _create_cookie_header(self, token: str) -> tuple[bytes, bytes]:
        """Create Set-Cookie header value"""
        if not token:  # Removing cookie case
            cookie_parts = [
                f"{self.cookie_config.cookie_name}=",
                "Path=/",
                "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                "Max-Age=0",
            ]
            logger.debug("Creating cookie removal header")
        else:  # Setting cookie case
            cookie_parts = [
                f"{self.cookie_config.cookie_name}={token}",
                f"Path={self.cookie_config.cookie_path}",
            ]

            if self.cookie_config.cookie_domain:
                cookie_parts.append(
                    f"Domain={self.cookie_config.cookie_domain}"
                )
            if self.cookie_config.cookie_secure:
                cookie_parts.append("Secure")
            if self.cookie_config.cookie_httponly:
                cookie_parts.append("HttpOnly")
            if self.cookie_config.cookie_samesite:
                cookie_parts.append(
                    f"SameSite={self.cookie_config.cookie_samesite}"
                )

            logger.debug("Creating cookie header for token")

        return b"set-cookie", "; ".join(cookie_parts).encode("latin-1")

    def _extract_token_from_response(
        self, auth_result: AuthenticationResult
    ) -> str | None:
        """Extract token from authentication result"""
        if not auth_result.raw_tokens:
            logger.debug("No raw tokens in auth result")
            return None

        # Try access_token first
        token = auth_result.raw_tokens.get("access_token")
        if isinstance(token, str) and token:
            logger.debug("Found access_token in auth result")
            return token

        # Try other token types
        for key in ["id_token", "token"]:
            if key in auth_result.raw_tokens:
                logger.debug("Found %s in auth result", key)
                token_value = auth_result.raw_tokens[key]
                if isinstance(token_value, str):
                    return token_value

        logger.debug("No suitable token found in auth result")
        return None

    def _extract_token_from_cookie(
        self, headers: list[tuple[bytes, bytes]]
    ) -> str | None:
        """Extract token from cookie header"""
        if not self.cookie_config.enabled:
            logger.debug("Cookie handling is disabled")
            return None

        for name, value in headers:
            if name.lower() == b"cookie":
                sc: SimpleCookie = SimpleCookie()
                sc.load(value.decode("latin-1"))
                if self.cookie_config.cookie_name in sc:
                    logger.debug("Found token in cookie")
                    return sc[self.cookie_config.cookie_name].value

        logger.debug("No token found in cookies")
        return None

    def _add_auth_header(
        self, headers: list[tuple[bytes, bytes]], token: str
    ) -> None:
        """Add authorization header"""
        if not any(name.lower() == b"authorization" for name, _ in headers):
            headers.append((b"authorization", f"Bearer {token}".encode()))
            logger.debug("Added Authorization header")

    @staticmethod
    def _should_handle_expired_token(
        scope: Scope, cookie_token: str | None
    ) -> bool:
        """Handle cookie re-auth only for explicit authentication failures."""
        if not cookie_token:
            return False

        auth_result = scope.get("state", {}).get("auth_result")
        if not isinstance(auth_result, AuthenticationResult):
            return False
        if auth_result.success:
            return False

        error = (auth_result.error or "").lower()
        indicators = ["token", "expired", "invalid", "jwt", "unauthorized"]
        return any(indicator in error for indicator in indicators)

    async def handle_token_expired(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Handle expired token by redirecting to authentication"""
        logger.info(
            "Handling expired token - redirecting to request path to restart auth flow"
        )

        # Redirect to the same path/query with the cookie removed.
        # The subsequent request goes through the normal auth flow (PKCE/state).
        path = scope.get("path") or "/"
        query_string = scope.get("query_string", b"")
        if query_string:
            redirect_url = f"{path}?{query_string.decode('latin-1')}"
        else:
            redirect_url = path

        # Create response with cookie removal
        response = RedirectResponse(
            url=redirect_url,
            status_code=303,
        )
        response.delete_cookie(
            key=self.cookie_config.cookie_name,
            path=self.cookie_config.cookie_path,
            domain=self.cookie_config.cookie_domain,
            secure=self.cookie_config.cookie_secure,
            httponly=self.cookie_config.cookie_httponly,
            samesite=self.cookie_config.cookie_samesite,
        )

        await response(scope, receive, send)

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        logger.debug(
            "Processing request to: %s", scope.get("path", "unknown path")
        )

        # Prepare request with cookie handling
        original_headers = scope.get("headers", [])
        scope["headers"] = list(original_headers)
        cookie_token = None

        # Initialize scope state if needed
        if "state" not in scope:
            scope["state"] = {}

        # Check for token in cookie if no Authorization header present
        skip_user_info_token = None
        if not any(
            name.lower() == b"authorization" for name, _ in scope["headers"]
        ):
            cookie_token = self._extract_token_from_cookie(scope["headers"])
            if cookie_token:
                self._add_auth_header(scope["headers"], cookie_token)
                # Use thread-safe context variable to skip get_user_info for this request
                # This avoids race conditions from modifying global config state
                skip_user_info_token = skip_user_info_for_request.set(True)

        # Wrap send to intercept response
        response_hijacked = (
            False  # Flag to track if we've taken over the response
        )

        async def send_wrapper(message: Message) -> None:
            nonlocal response_hijacked

            # If we've hijacked the response (sent our own redirect),
            # ignore all subsequent messages from the original response
            if response_hijacked:
                return

            if message["type"] == "http.response.start":
                status = message.get("status", 200)

                # Handle 401 (expired/invalid token)
                if status == 401 and self._should_handle_expired_token(
                    scope, cookie_token
                ):
                    logger.warning("Token in cookie is invalid or expired")
                    response_hijacked = True  # Mark that we're taking over
                    await self.handle_token_expired(scope, receive, send)
                    return

                # Handle successful response
                headers = list(message.get("headers", []))
                auth_result = scope.get("state", {}).get("auth_result")

                if (
                    auth_result
                    and isinstance(auth_result, AuthenticationResult)
                    and auth_result.success
                    and auth_result.raw_tokens
                ):
                    token = self._extract_token_from_response(auth_result)
                    if token:
                        cookie_header = self._create_cookie_header(token)
                        headers.append(cookie_header)
                        message["headers"] = headers
                        logger.info("New token set in cookie")

                await send(message)
            else:
                await send(message)

        try:
            # Process through OPA middleware
            await self.opa(scope, receive, send_wrapper)
        finally:
            # Restore original headers
            scope["headers"] = original_headers
            # Reset context variable if it was set (thread-safe cleanup)
            if skip_user_info_token is not None:
                skip_user_info_for_request.reset(skip_user_info_token)
