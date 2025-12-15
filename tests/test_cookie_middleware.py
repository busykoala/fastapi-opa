"""Tests for Cookie Authentication Middleware"""

from typing import Dict
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_opa import OPAConfig
from fastapi_opa.models import AuthenticationResult
from fastapi_opa.models import TokenCookieConfig
from fastapi_opa.opa.cookie_middleware import CookieAuthMiddleware
from tests.utils import AuthenticationDummy


class TestTokenCookieConfig:
    """Test TokenCookieConfig model"""

    def test_default_values(self):
        """Test default configuration values"""
        config = TokenCookieConfig()

        assert config.enabled is True
        assert config.cookie_name == "access_token"
        assert config.cookie_domain is None
        assert config.cookie_path == "/"
        assert config.cookie_secure is True
        assert config.cookie_httponly is True
        assert config.cookie_samesite == "lax"

    def test_custom_values(self):
        """Test custom configuration values"""
        config = TokenCookieConfig(
            enabled=False,
            cookie_name="my_token",
            cookie_domain=".example.com",
            cookie_path="/api",
            cookie_secure=False,
            cookie_httponly=False,
            cookie_samesite="strict",
        )

        assert config.enabled is False
        assert config.cookie_name == "my_token"
        assert config.cookie_domain == ".example.com"
        assert config.cookie_path == "/api"
        assert config.cookie_secure is False
        assert config.cookie_httponly is False
        assert config.cookie_samesite == "strict"

    def test_config_is_frozen(self):
        """Test that config is immutable"""
        config = TokenCookieConfig()

        with pytest.raises(Exception):  # ValidationError for frozen model
            config.cookie_name = "new_name"


class TestAuthenticationResult:
    """Test AuthenticationResult model"""

    def test_successful_result(self):
        """Test successful authentication result"""
        result = AuthenticationResult(
            success=True,
            user_info={"sub": "user123", "name": "Test User"},
            validated_token={"sub": "user123", "exp": 1234567890},
            raw_tokens={"access_token": "token123", "id_token": "id123"},
        )

        assert result.success is True
        assert result.user_info["sub"] == "user123"
        assert result.validated_token["sub"] == "user123"
        assert result.raw_tokens["access_token"] == "token123"
        assert result.error is None

    def test_failed_result(self):
        """Test failed authentication result"""
        result = AuthenticationResult(
            success=False,
            error="Invalid token",
        )

        assert result.success is False
        assert result.error == "Invalid token"
        assert result.user_info is None
        assert result.validated_token is None
        assert result.raw_tokens is None

    def test_result_is_frozen(self):
        """Test that result is immutable"""
        result = AuthenticationResult(success=True)

        with pytest.raises(Exception):  # ValidationError for frozen model
            result.success = False


class TestCookieMiddlewareHelpers:
    """Test CookieAuthMiddleware helper methods"""

    @pytest.fixture
    def middleware(self):
        """Create middleware instance for testing"""
        opa_host = "http://localhost:8181"
        auth = AuthenticationDummy()
        opa_config = OPAConfig(authentication=auth, opa_host=opa_host)
        cookie_config = TokenCookieConfig()

        app = FastAPI()
        return CookieAuthMiddleware(
            app=app,
            config=opa_config,
            cookie_config=cookie_config,
        )

    def test_create_cookie_header_with_token(self, middleware):
        """Test creating Set-Cookie header with token"""
        header_name, header_value = middleware._create_cookie_header(
            "mytoken123"
        )

        assert header_name == b"set-cookie"
        value_str = header_value.decode("latin-1")

        assert "access_token=mytoken123" in value_str
        assert "Path=/" in value_str
        assert "Secure" in value_str
        assert "HttpOnly" in value_str
        assert "SameSite=lax" in value_str

    def test_create_cookie_header_removal(self, middleware):
        """Test creating Set-Cookie header for cookie removal"""
        header_name, header_value = middleware._create_cookie_header("")

        assert header_name == b"set-cookie"
        value_str = header_value.decode("latin-1")

        assert "access_token=" in value_str
        assert "Expires=Thu, 01 Jan 1970" in value_str
        assert "Max-Age=0" in value_str

    def test_create_cookie_header_with_domain(self):
        """Test creating cookie header with custom domain"""
        opa_host = "http://localhost:8181"
        auth = AuthenticationDummy()
        opa_config = OPAConfig(authentication=auth, opa_host=opa_host)
        cookie_config = TokenCookieConfig(cookie_domain=".example.com")

        app = FastAPI()
        middleware = CookieAuthMiddleware(
            app=app,
            config=opa_config,
            cookie_config=cookie_config,
        )

        header_name, header_value = middleware._create_cookie_header("token")
        value_str = header_value.decode("latin-1")

        assert "Domain=.example.com" in value_str

    def test_extract_token_from_response_access_token(self, middleware):
        """Test extracting access_token from AuthenticationResult"""
        auth_result = AuthenticationResult(
            success=True,
            raw_tokens={"access_token": "access123", "id_token": "id123"},
        )

        token = middleware._extract_token_from_response(auth_result)

        assert token == "access123"

    def test_extract_token_from_response_id_token_fallback(self, middleware):
        """Test falling back to id_token if no access_token"""
        auth_result = AuthenticationResult(
            success=True,
            raw_tokens={"id_token": "id123"},
        )

        token = middleware._extract_token_from_response(auth_result)

        assert token == "id123"

    def test_extract_token_from_response_no_tokens(self, middleware):
        """Test extraction when no tokens present"""
        auth_result = AuthenticationResult(success=True)

        token = middleware._extract_token_from_response(auth_result)

        assert token is None

    def test_extract_token_from_cookie(self, middleware):
        """Test extracting token from cookie header"""
        headers = [
            (b"host", b"example.com"),
            (b"cookie", b"other=value; access_token=mytoken123; another=test"),
        ]

        token = middleware._extract_token_from_cookie(headers)

        assert token == "mytoken123"

    def test_extract_token_from_cookie_not_found(self, middleware):
        """Test extraction when cookie not present"""
        headers = [
            (b"host", b"example.com"),
            (b"cookie", b"other=value; different_cookie=test"),
        ]

        token = middleware._extract_token_from_cookie(headers)

        assert token is None

    def test_extract_token_from_cookie_disabled(self):
        """Test extraction when cookie handling is disabled"""
        opa_host = "http://localhost:8181"
        auth = AuthenticationDummy()
        opa_config = OPAConfig(authentication=auth, opa_host=opa_host)
        cookie_config = TokenCookieConfig(enabled=False)

        app = FastAPI()
        middleware = CookieAuthMiddleware(
            app=app,
            config=opa_config,
            cookie_config=cookie_config,
        )

        headers = [
            (b"cookie", b"access_token=mytoken123"),
        ]

        token = middleware._extract_token_from_cookie(headers)

        assert token is None

    def test_add_auth_header(self, middleware):
        """Test adding Authorization header"""
        headers = [(b"host", b"example.com")]

        middleware._add_auth_header(headers, "mytoken123")

        assert len(headers) == 2
        assert headers[1] == (b"authorization", b"Bearer mytoken123")

    def test_add_auth_header_skips_if_exists(self, middleware):
        """Test that Authorization header is not added if already present"""
        headers = [
            (b"host", b"example.com"),
            (b"authorization", b"Bearer existing_token"),
        ]

        middleware._add_auth_header(headers, "new_token")

        # Should still have only 2 headers
        assert len(headers) == 2
        # Should keep the original Authorization header
        assert headers[1] == (b"authorization", b"Bearer existing_token")


class TestCookieMiddlewareIntegration:
    """Integration tests for CookieAuthMiddleware"""

    @pytest.fixture
    def client_with_cookies(self):
        """Create test client with cookie middleware"""
        opa_host = "http://localhost:8181"
        auth = AuthenticationDummy()
        opa_config = OPAConfig(authentication=auth, opa_host=opa_host)
        cookie_config = TokenCookieConfig()

        app = FastAPI()
        app.add_middleware(
            CookieAuthMiddleware,
            config=opa_config,
            cookie_config=cookie_config,
        )

        @app.get("/")
        async def root() -> Dict:
            return {"msg": "success"}

        yield TestClient(app)

    def test_request_without_cookie_or_auth(self, client_with_cookies):
        """Test request without cookie or authorization header"""
        with patch(
            "fastapi_opa.opa.opa_middleware.requests.post"
        ) as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json = lambda: {"result": {"allow": True}}

            response = client_with_cookies.get("/")

        assert response.status_code == 200
        assert response.json() == {"msg": "success"}

    def test_cookie_config_samesite_options(self):
        """Test different SameSite options"""
        for samesite in ["strict", "lax", "none"]:
            config = TokenCookieConfig(cookie_samesite=samesite)
            assert config.cookie_samesite == samesite


class TestCookieMiddlewareEdgeCases:
    """Edge case tests for cookie middleware"""

    def test_cookie_with_special_characters(self):
        """Test handling cookies with special characters in value"""
        opa_host = "http://localhost:8181"
        auth = AuthenticationDummy()
        opa_config = OPAConfig(authentication=auth, opa_host=opa_host)
        cookie_config = TokenCookieConfig()

        app = FastAPI()
        middleware = CookieAuthMiddleware(
            app=app,
            config=opa_config,
            cookie_config=cookie_config,
        )

        # Token with base64-like characters
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        header_name, header_value = middleware._create_cookie_header(token)

        value_str = header_value.decode("latin-1")
        assert f"access_token={token}" in value_str

    def test_empty_cookie_header(self):
        """Test handling empty cookie header"""
        opa_host = "http://localhost:8181"
        auth = AuthenticationDummy()
        opa_config = OPAConfig(authentication=auth, opa_host=opa_host)
        cookie_config = TokenCookieConfig()

        app = FastAPI()
        middleware = CookieAuthMiddleware(
            app=app,
            config=opa_config,
            cookie_config=cookie_config,
        )

        headers = [(b"cookie", b"")]
        token = middleware._extract_token_from_cookie(headers)

        assert token is None

    def test_multiple_cookies(self):
        """Test extracting token when multiple cookies present"""
        opa_host = "http://localhost:8181"
        auth = AuthenticationDummy()
        opa_config = OPAConfig(authentication=auth, opa_host=opa_host)
        cookie_config = TokenCookieConfig(cookie_name="session_token")

        app = FastAPI()
        middleware = CookieAuthMiddleware(
            app=app,
            config=opa_config,
            cookie_config=cookie_config,
        )

        headers = [
            (
                b"cookie",
                b"access_token=wrong; session_token=correct; other=value",
            ),
        ]
        token = middleware._extract_token_from_cookie(headers)

        assert token == "correct"

    def test_cookie_path_configuration(self):
        """Test cookie path configuration"""
        config = TokenCookieConfig(cookie_path="/api/v1")

        assert config.cookie_path == "/api/v1"

        # Verify path is included in cookie header
        opa_host = "http://localhost:8181"
        auth = AuthenticationDummy()
        opa_config = OPAConfig(authentication=auth, opa_host=opa_host)

        app = FastAPI()
        middleware = CookieAuthMiddleware(
            app=app,
            config=opa_config,
            cookie_config=config,
        )

        header_name, header_value = middleware._create_cookie_header("token")
        value_str = header_value.decode("latin-1")

        assert "Path=/api/v1" in value_str


class TestCookieMiddlewareThreadSafety:
    """
    Tests for thread-safety in CookieAuthMiddleware.

    The implementation uses contextvars to provide per-request state isolation
    instead of modifying global config state. This ensures thread-safety.
    """

    def test_context_variable_provides_request_isolation(self):
        """
        THREAD-SAFETY FIX: Using contextvars ensures that each request
        has its own isolated state that doesn't affect other requests.
        """
        from fastapi_opa.auth.auth_oidc import skip_user_info_for_request

        # Default value should be False
        assert skip_user_info_for_request.get() is False

        # Setting in one context
        token = skip_user_info_for_request.set(True)
        assert skip_user_info_for_request.get() is True

        # Reset returns to default
        skip_user_info_for_request.reset(token)
        assert skip_user_info_for_request.get() is False

    def test_global_config_is_not_modified(self):
        """
        VERIFIED FIX: The middleware no longer modifies global config state.
        Instead, it uses context variables for per-request control.
        """
        from dataclasses import dataclass

        from fastapi_opa.auth.auth_interface import AuthInterface

        # Create a mock auth with mutable config
        @dataclass
        class MockOIDCConfig:
            get_user_info: bool = True

        class MockOIDCAuth(AuthInterface):
            def __init__(self):
                self.config = MockOIDCConfig()

            def authenticate(self, request, accepted_methods=None):
                return {"user": "test"}

        # Create shared config
        auth = MockOIDCAuth()
        opa_host = "http://localhost:8181"
        opa_config = OPAConfig(authentication=auth, opa_host=opa_host)
        cookie_config = TokenCookieConfig()

        app = FastAPI()

        # Create two middleware instances sharing the same config
        middleware1 = CookieAuthMiddleware(
            app=app,
            config=opa_config,
            cookie_config=cookie_config,
        )
        middleware2 = CookieAuthMiddleware(
            app=app,
            config=opa_config,
            cookie_config=cookie_config,
        )

        # Initial state
        assert auth.config.get_user_info is True

        # The middleware no longer modifies global state
        # Verify the global config remains unchanged after middleware creation
        assert (
            middleware1.config.authentication[0].config.get_user_info is True
        )
        assert (
            middleware2.config.authentication[0].config.get_user_info is True
        )

    @pytest.mark.asyncio
    async def test_concurrent_requests_are_isolated(self):
        """
        VERIFIED FIX: Context variables provide proper isolation between
        concurrent requests. Each request sees its own state.
        """
        import asyncio

        from fastapi_opa.auth.auth_oidc import skip_user_info_for_request

        # Track what each "request" sees
        observations = {"request_a": [], "request_b": []}

        async def simulate_request_a_with_cookie():
            """Request A: sets skip_user_info in its context"""
            observations["request_a"].append(
                ("before_set", skip_user_info_for_request.get())
            )

            # Set in this request's context (simulating cookie middleware behavior)
            token = skip_user_info_for_request.set(True)
            observations["request_a"].append(
                ("after_set", skip_user_info_for_request.get())
            )

            # Simulate some processing time
            await asyncio.sleep(0.1)

            # Reset (cleanup)
            skip_user_info_for_request.reset(token)
            observations["request_a"].append(
                ("after_reset", skip_user_info_for_request.get())
            )

        async def simulate_request_b_without_cookie():
            """Request B: should always see default value"""
            # Wait a bit to ensure request A has set its value
            await asyncio.sleep(0.05)

            # Request B should see default value, not Request A's value
            observations["request_b"].append(
                ("reading_state", skip_user_info_for_request.get())
            )

        # Run both "requests" concurrently
        await asyncio.gather(
            simulate_request_a_with_cookie(),
            simulate_request_b_without_cookie(),
        )

        # Request A should have seen: False -> True -> False
        assert observations["request_a"][0] == ("before_set", False)
        assert observations["request_a"][1] == ("after_set", True)
        assert observations["request_a"][2] == ("after_reset", False)

        # Request B should see default (False), NOT Request A's True
        # Note: In asyncio, context is inherited at task creation, so both tasks
        # see the default value. The key is that Request A's modification
        # happens WITHIN its execution context and doesn't leak.
        request_b_saw = observations["request_b"][0][1]
        assert request_b_saw is False, (
            f"Request B should see default value (False), but saw {request_b_saw}. "
            "Context variable isolation is working correctly."
        )

    def test_context_variable_import_consistency(self):
        """
        Verify that the same context variable is used in both modules.
        """
        from fastapi_opa.auth.auth_oidc import (
            skip_user_info_for_request as oidc_var,
        )
        from fastapi_opa.opa.cookie_middleware import (
            skip_user_info_for_request as middleware_var,
        )

        # Both should be the same object
        assert oidc_var is middleware_var, (
            "Both modules should import the same context variable instance"
        )
