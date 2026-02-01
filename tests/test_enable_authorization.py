"""
Tests for enable_authorization configuration.

The enable_authorization parameter controls whether OPA policy checks are performed:
- enable_authorization=True (default): OPA is consulted for every request
- enable_authorization=False: OPA is bypassed, all authenticated users have access

SECURITY NOTE:
Setting enable_authorization=False disables authorization entirely.
Only authentication is performed. Use only for development/testing.
"""

import json
import logging
from unittest.mock import AsyncMock
from unittest.mock import Mock

import pytest

from fastapi_opa.opa.opa_config import OPAConfig
from fastapi_opa.opa.opa_middleware import OPAMiddleware


class TestEnableAuthorizationDefault:
    """Tests for enable_authorization default behavior."""

    def test_enable_authorization_defaults_to_true(self):
        """
        SECURE BY DEFAULT: enable_authorization defaults to True.

        This ensures OPA policy checks are performed unless explicitly disabled.
        """
        mock_auth = Mock()

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        middleware = OPAMiddleware(
            app=Mock(),
            config=config,
            # enable_authorization not specified
        )

        assert middleware.enable_authorization is True

    def test_enable_authorization_can_be_disabled(self):
        """Verify enable_authorization can be explicitly set to False."""
        mock_auth = Mock()

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        middleware = OPAMiddleware(
            app=Mock(),
            config=config,
            enable_authorization=False,
        )

        assert middleware.enable_authorization is False


class TestEnableAuthorizationWarning:
    """Tests for security warning when authorization is disabled."""

    def test_warning_logged_when_authorization_disabled(self, caplog):
        """
        A warning should be logged when enable_authorization=False.
        """
        mock_auth = Mock()

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        with caplog.at_level(logging.WARNING):
            OPAMiddleware(
                app=Mock(),
                config=config,
                enable_authorization=False,
            )

        assert any(
            "OPA authorization is disabled" in record.message
            and "enable_authorization=False" in record.message
            for record in caplog.records
        ), "Expected warning when enable_authorization=False"

    def test_no_warning_when_authorization_enabled(self, caplog):
        """No warning should be logged when enable_authorization=True (default)."""
        mock_auth = Mock()

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        with caplog.at_level(logging.WARNING):
            OPAMiddleware(
                app=Mock(),
                config=config,
                enable_authorization=True,
            )

        assert not any(
            "enable_authorization" in record.message
            for record in caplog.records
        ), "No warning should be logged when enable_authorization=True"


class TestOPAIntegrationWithEnableAuthorization:
    """Tests for OPA integration based on enable_authorization setting."""

    @pytest.mark.asyncio
    async def test_opa_called_when_authorization_enabled(self, mocker):
        """
        SECURE: With enable_authorization=True, OPA is consulted.
        """
        mock_auth = Mock()
        mock_auth.authenticate = AsyncMock(
            return_value={"sub": "user123", "roles": ["viewer"]}
        )

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        # Mock OPA response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {"allow": True}}

        mock_opa_post = mocker.patch(
            "fastapi_opa.opa.opa_middleware.requests.post",
            return_value=mock_response,
        )

        app_mock = AsyncMock()
        middleware = OPAMiddleware(
            app=app_mock,
            config=config,
            enable_authorization=True,
        )

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/resource",
            "headers": [(b"authorization", b"Bearer token")],
            "query_string": b"",
            "state": {},
        }

        await middleware(scope, AsyncMock(), AsyncMock())

        # OPA should have been called
        mock_opa_post.assert_called_once()

        # Verify request details were sent to OPA
        call_args = mock_opa_post.call_args
        opa_input = json.loads(call_args[1]["data"])
        assert opa_input["input"]["request_method"] == "GET"
        assert opa_input["input"]["request_path"] == ["api", "resource"]

    @pytest.mark.asyncio
    async def test_opa_not_called_when_authorization_disabled(self, mocker):
        """
        With enable_authorization=False, OPA is NOT consulted.
        """
        mock_auth = Mock()
        mock_auth.authenticate = AsyncMock(
            return_value={"sub": "user123", "roles": ["viewer"]}
        )

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        mock_opa_post = mocker.patch(
            "fastapi_opa.opa.opa_middleware.requests.post"
        )

        app_mock = AsyncMock()
        middleware = OPAMiddleware(
            app=app_mock,
            config=config,
            enable_authorization=False,
        )

        scope = {
            "type": "http",
            "method": "DELETE",
            "path": "/admin/users/123",
            "headers": [(b"authorization", b"Bearer token")],
            "query_string": b"",
            "state": {},
        }

        await middleware(scope, AsyncMock(), AsyncMock())

        # OPA should NOT have been called
        mock_opa_post.assert_not_called()

        # But request should have been allowed through
        app_mock.assert_called_once()


class TestAuthorizationDenial:
    """Tests for OPA denying requests."""

    @pytest.mark.asyncio
    async def test_request_denied_when_opa_returns_false(self, mocker):
        """Request should be denied when OPA returns allow=false."""
        mock_auth = Mock()
        mock_auth.authenticate = AsyncMock(
            return_value={"sub": "user123", "roles": ["viewer"]}
        )

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        # OPA denies the request
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {"allow": False}}

        mocker.patch(
            "fastapi_opa.opa.opa_middleware.requests.post",
            return_value=mock_response,
        )

        sent_messages = []

        async def capture_send(message):
            sent_messages.append(message)

        app_mock = AsyncMock()
        middleware = OPAMiddleware(
            app=app_mock,
            config=config,
            enable_authorization=True,
        )

        scope = {
            "type": "http",
            "method": "DELETE",
            "path": "/admin/users/123",
            "headers": [(b"authorization", b"Bearer token")],
            "query_string": b"",
            "state": {},
        }

        await middleware(scope, AsyncMock(), capture_send)

        # App should NOT have been called
        app_mock.assert_not_called()

        # Should have sent 401 response
        assert any(
            msg.get("status") == 401
            for msg in sent_messages
            if msg.get("type") == "http.response.start"
        )

    @pytest.mark.asyncio
    async def test_request_allowed_when_opa_returns_true(self, mocker):
        """Request should be allowed when OPA returns allow=true."""
        mock_auth = Mock()
        mock_auth.authenticate = AsyncMock(
            return_value={"sub": "admin_user", "roles": ["admin"]}
        )

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        # OPA allows the request
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {"allow": True}}

        mocker.patch(
            "fastapi_opa.opa.opa_middleware.requests.post",
            return_value=mock_response,
        )

        app_mock = AsyncMock()
        middleware = OPAMiddleware(
            app=app_mock,
            config=config,
            enable_authorization=True,
        )

        scope = {
            "type": "http",
            "method": "DELETE",
            "path": "/admin/users/123",
            "headers": [(b"authorization", b"Bearer token")],
            "query_string": b"",
            "state": {},
        }

        await middleware(scope, AsyncMock(), AsyncMock())

        # App should have been called
        app_mock.assert_called_once()


class TestCookieMiddlewareEnableAuthorization:
    """Tests for enable_authorization in CookieAuthMiddleware."""

    def test_cookie_middleware_passes_enable_authorization(self, mocker):
        """CookieAuthMiddleware should pass enable_authorization to OPAMiddleware."""
        from fastapi_opa.opa.cookie_middleware import CookieAuthMiddleware

        mock_auth = Mock()

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        middleware = CookieAuthMiddleware(
            app=Mock(),
            config=config,
            enable_authorization=False,
        )

        # The internal OPAMiddleware should have enable_authorization=False
        assert middleware.opa.enable_authorization is False

    def test_cookie_middleware_defaults_to_enabled(self, mocker):
        """CookieAuthMiddleware should default to enable_authorization=True."""
        from fastapi_opa.opa.cookie_middleware import CookieAuthMiddleware

        mock_auth = Mock()

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        middleware = CookieAuthMiddleware(
            app=Mock(),
            config=config,
            # enable_authorization not specified
        )

        # Should default to True
        assert middleware.opa.enable_authorization is True


class TestInfoLogWhenAuthorizationSkipped:
    """Tests for info logging when authorization is skipped."""

    @pytest.mark.asyncio
    async def test_info_logged_when_opa_skipped(self, mocker, caplog):
        """An info message should be logged when OPA check is skipped."""
        mock_auth = Mock()
        mock_auth.authenticate = AsyncMock(return_value={"sub": "user123"})

        config = OPAConfig(
            authentication=mock_auth,
            opa_host="http://localhost:8181",
        )

        app_mock = AsyncMock()
        middleware = OPAMiddleware(
            app=app_mock,
            config=config,
            enable_authorization=False,
        )

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/resource",
            "headers": [(b"authorization", b"Bearer token")],
            "query_string": b"",
            "state": {},
        }

        with caplog.at_level(logging.INFO):
            await middleware(scope, AsyncMock(), AsyncMock())

        assert any(
            "OPA authorization skipped" in record.message
            for record in caplog.records
        ), "Expected info log when OPA is skipped"
