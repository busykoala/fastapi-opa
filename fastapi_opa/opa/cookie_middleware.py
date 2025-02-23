"""Cookie-based authentication middleware implementation"""
import logging
from typing import Optional, List, Tuple
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import RedirectResponse

from fastapi_opa.opa.opa_middleware import OPAMiddleware
from fastapi_opa.opa.opa_config import OPAConfig
from fastapi_opa.models import AuthenticationResult, TokenCookieConfig

logger = logging.getLogger(__name__)


class CookieAuthMiddleware:
    """Middleware for cookie-based authentication that extends OPA functionality"""

    def __init__(
        self,
        app: ASGIApp,
        config: OPAConfig,
        cookie_config: Optional[TokenCookieConfig] = None,
        skip_endpoints: Optional[list[str]] = None,
        force_authorization: Optional[bool] = False,
        max_buffer_size: Optional[int] = None,
    ):
        self.app = app
        self.config = config
        self.cookie_config = cookie_config or TokenCookieConfig()
        self.opa = OPAMiddleware(
            app=app,
            config=config,
            skip_endpoints=skip_endpoints,
            force_authorization=force_authorization,
            max_buffer_size=max_buffer_size
        )

    def _create_cookie_header(self, token: str) -> Tuple[bytes, bytes]:
        """Create Set-Cookie header value"""
        if not token:  # Removing cookie case
            cookie_parts = [
                f"{self.cookie_config.cookie_name}=",
                "Path=/",
                "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                "Max-Age=0"
            ]
            logger.debug("Creating cookie removal header")
        else:  # Setting cookie case
            cookie_parts = [
                f"{self.cookie_config.cookie_name}={token}",
                f"Path={self.cookie_config.cookie_path}",
            ]

            if self.cookie_config.cookie_domain:
                cookie_parts.append(f"Domain={self.cookie_config.cookie_domain}")
            if self.cookie_config.cookie_secure:
                cookie_parts.append("Secure")
            if self.cookie_config.cookie_httponly:
                cookie_parts.append("HttpOnly")
            if self.cookie_config.cookie_samesite:
                cookie_parts.append(f"SameSite={self.cookie_config.cookie_samesite}")

            logger.debug(f"Creating cookie header for token: {token[:10]}...")

        return b"set-cookie", "; ".join(cookie_parts).encode("latin-1")

    def _extract_token_from_response(self, auth_result: AuthenticationResult) -> Optional[str]:
        """Extract token from authentication result"""
        if not auth_result.raw_tokens:
            logger.debug("No raw tokens in auth result")
            return None

        # Try access_token first
        token = auth_result.raw_tokens.get("access_token")
        if token:
            logger.debug("Found access_token in auth result")
            return token

        # Try other token types
        for key in ["id_token", "token"]:
            if key in auth_result.raw_tokens:
                logger.debug(f"Found {key} in auth result")
                return auth_result.raw_tokens[key]

        logger.debug("No suitable token found in auth result")
        return None

    def _extract_token_from_cookie(self, headers: List[Tuple[bytes, bytes]]) -> Optional[str]:
        """Extract token from cookie header"""
        if not self.cookie_config.enabled:
            logger.debug("Cookie handling is disabled")
            return None

        for name, value in headers:
            if name.lower() == b"cookie":
                cookies = value.decode("latin-1").split("; ")
                for cookie in cookies:
                    if cookie.startswith(f"{self.cookie_config.cookie_name}="):
                        token = cookie.split("=", 1)[1]
                        logger.debug(f"Found token in cookie: {token[:10]}...")
                        return token

        logger.debug("No token found in cookies")
        return None

    def _add_auth_header(self, headers: List[Tuple[bytes, bytes]], token: str) -> None:
        """Add authorization header"""
        if not any(name.lower() == b"authorization" for name, _ in headers):
            headers.append(
                (b"authorization", f"Bearer {token}".encode())
            )
            logger.debug(f"Added Authorization header with token: {token[:10]}...")

    async def handle_token_expired(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle expired token by redirecting to authentication"""
        logger.info("Handling expired token - redirecting to authentication")

        # Create response with cookie removal
        response = RedirectResponse(
            url=self.config.authentication[0].authorization_endpoint,
            status_code=303
        )
        response.delete_cookie(
            key=self.cookie_config.cookie_name,
            path=self.cookie_config.cookie_path,
            domain=self.cookie_config.cookie_domain,
            secure=self.cookie_config.cookie_secure,
            httponly=self.cookie_config.cookie_httponly,
            samesite=self.cookie_config.cookie_samesite
        )

        await response(scope, receive, send)

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        logger.debug(f"Processing request to: {scope.get('path', 'unknown path')}")

        # Prepare request with cookie handling
        original_headers = scope.get("headers", [])
        scope["headers"] = list(original_headers)
        cookie_token = None

        # Initialize scope state if needed
        if "state" not in scope:
            scope["state"] = {}

        # Check for token in cookie if no Authorization header present
        original_get_user_info = None
        if not any(name.lower() == b"authorization" for name, _ in scope["headers"]):
            cookie_token = self._extract_token_from_cookie(scope["headers"])
            if cookie_token:
                self._add_auth_header(scope["headers"], cookie_token)
                # Temporarily disable get_user_info if token comes from cookie
                original_get_user_info = self.config.authentication[0].config.get_user_info
                self.config.authentication[0].config.get_user_info = False

        # Wrap send to intercept response
        response_started = False

        async def send_wrapper(message):
            nonlocal response_started

            if message["type"] == "http.response.start":
                response_started = True
                status = message.get("status", 200)

                # Handle 401 (expired/invalid token)
                if status == 401 and cookie_token:
                    logger.warning("Token in cookie is invalid or expired")
                    await self.handle_token_expired(scope, receive, send)
                    return

                # Handle successful response
                headers = list(message.get("headers", []))
                auth_result = scope.get("state", {}).get("auth_result")

                if auth_result and isinstance(auth_result, AuthenticationResult):
                    if auth_result.success and auth_result.raw_tokens:
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
            if cookie_token and original_get_user_info is not None:
                # Restore original get_user_info value
                self.config.authentication[0].config.get_user_info = original_get_user_info
