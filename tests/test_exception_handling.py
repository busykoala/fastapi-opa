"""Tests for improved exception handling in OIDC authentication."""

import logging
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
import requests
from jwt.exceptions import DecodeError
from jwt.exceptions import InvalidTokenError

from fastapi_opa.auth.auth_oidc import OIDCAuthentication
from fastapi_opa.auth.auth_oidc import OIDCConfig
from fastapi_opa.auth.exceptions import OIDCException
from fastapi_opa.models import AuthenticationResult


@pytest.fixture
def oidc_config():
    """Create a basic OIDC config for testing."""
    return OIDCConfig(
        app_uri="https://example.com",
        client_id="test-client",
        client_secret="test-secret",
        well_known_endpoint="",
        authorization_endpoint="https://idp.example.com/auth",
        token_endpoint="https://idp.example.com/token",
        issuer="https://idp.example.com",
    )


@pytest.fixture
def mock_request():
    """Create a mock request with authorization code."""
    request = MagicMock()
    request.query_params.get = MagicMock(
        side_effect=lambda key: {
            "code": "auth_code_123",
            "state": "state_123",
        }.get(key)
    )
    request.headers.get = MagicMock(return_value=None)
    request.url.scheme = "https"
    request.url.netloc = "app.example.com"
    request.url.path = "/callback"
    return request


class TestNetworkExceptionHandling:
    """Tests for network error handling."""

    @pytest.mark.asyncio
    async def test_connection_error_returns_auth_result(
        self, oidc_config, mock_request
    ):
        """Test that connection errors return AuthenticationResult."""
        auth = OIDCAuthentication(oidc_config)

        # Store PKCE verifier for the state
        auth._store_pkce_verifier("state_123", "test_verifier")

        with patch.object(
            auth,
            "get_auth_token",
            side_effect=requests.ConnectionError("Network down"),
        ):
            result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "Network error" in result.error

    @pytest.mark.asyncio
    async def test_timeout_error_returns_auth_result(
        self, oidc_config, mock_request
    ):
        """Test that timeout errors return AuthenticationResult."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with patch.object(
            auth,
            "get_auth_token",
            side_effect=requests.Timeout("Request timed out"),
        ):
            result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "Network error" in result.error

    @pytest.mark.asyncio
    async def test_request_exception_returns_auth_result(
        self, oidc_config, mock_request
    ):
        """Test that generic request exceptions return AuthenticationResult."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with patch.object(
            auth,
            "get_auth_token",
            side_effect=requests.RequestException("Request failed"),
        ):
            result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "Network error" in result.error

    @pytest.mark.asyncio
    async def test_network_error_logged(
        self, oidc_config, mock_request, caplog
    ):
        """Test that network errors are logged."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with (
            caplog.at_level(logging.ERROR),
            patch.object(
                auth,
                "get_auth_token",
                side_effect=requests.ConnectionError("Connection refused"),
            ),
        ):
            await auth.authenticate(mock_request)

        assert "Network error during OIDC authentication" in caplog.text


class TestJWTExceptionHandling:
    """Tests for JWT error handling."""

    @pytest.mark.asyncio
    async def test_decode_error_returns_auth_result(
        self, oidc_config, mock_request
    ):
        """Test that JWT decode errors return AuthenticationResult."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with (
            patch.object(
                auth,
                "get_auth_token",
                return_value={"id_token": "invalid_token"},
            ),
            patch(
                "jwt.get_unverified_header",
                side_effect=DecodeError("Invalid token format"),
            ),
        ):
            result = await auth.authenticate(mock_request)

        # DecodeError is caught and wrapped in OIDCException by existing code
        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "Error getting unverified header in jwt." in result.error

    @pytest.mark.asyncio
    async def test_invalid_token_error_returns_auth_result(
        self, oidc_config, mock_request
    ):
        """Test that InvalidTokenError returns AuthenticationResult."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with (
            patch.object(
                auth,
                "get_auth_token",
                return_value={"id_token": "eyJhbGciOiJSUzI1NiJ9.e30.sig"},
            ),
            patch("jwt.get_unverified_header", return_value={"alg": "RS256"}),
            patch.object(
                auth,
                "obtain_validated_token",
                side_effect=InvalidTokenError("Token expired"),
            ),
        ):
            result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "Token validation failed" in result.error

    @pytest.mark.asyncio
    async def test_jwt_error_logged(self, oidc_config, mock_request, caplog):
        """Test that JWT errors are logged."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with (
            caplog.at_level(logging.ERROR),
            patch.object(
                auth,
                "get_auth_token",
                return_value={"id_token": "eyJhbGciOiJSUzI1NiJ9.e30.sig"},
            ),
            patch("jwt.get_unverified_header", return_value={"alg": "RS256"}),
            patch.object(
                auth,
                "obtain_validated_token",
                side_effect=InvalidTokenError("Signature verification failed"),
            ),
        ):
            await auth.authenticate(mock_request)

        assert "JWT error during OIDC authentication" in caplog.text


class TestUnexpectedExceptionHandling:
    """Tests for unexpected error handling."""

    @pytest.mark.asyncio
    async def test_unexpected_error_returns_auth_result(
        self, oidc_config, mock_request
    ):
        """Test that unexpected errors return AuthenticationResult."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with patch.object(
            auth, "get_auth_token", side_effect=RuntimeError("Something broke")
        ):
            result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "unexpected error" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unexpected_error_logged_with_traceback(
        self, oidc_config, mock_request, caplog
    ):
        """Test that unexpected errors are logged with traceback."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with (
            caplog.at_level(logging.ERROR),
            patch.object(
                auth,
                "get_auth_token",
                side_effect=RuntimeError("Unexpected failure"),
            ),
        ):
            await auth.authenticate(mock_request)

        assert "Unexpected error during OIDC authentication" in caplog.text

    @pytest.mark.asyncio
    async def test_value_error_handled(self, oidc_config, mock_request):
        """Test that ValueError is caught as unexpected error."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with patch.object(
            auth, "get_auth_token", side_effect=ValueError("Invalid value")
        ):
            result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "unexpected error" in result.error.lower()

    @pytest.mark.asyncio
    async def test_key_error_handled(self, oidc_config, mock_request):
        """Test that KeyError is caught as unexpected error."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with patch.object(
            auth, "get_auth_token", side_effect=KeyError("missing_key")
        ):
            result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "unexpected error" in result.error.lower()


class TestOIDCExceptionHandling:
    """Tests for OIDCException handling (existing behavior)."""

    @pytest.mark.asyncio
    async def test_oidc_exception_returns_auth_result(
        self, oidc_config, mock_request
    ):
        """Test that OIDCException returns AuthenticationResult with error."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with patch.object(
            auth,
            "get_auth_token",
            side_effect=OIDCException("Token exchange failed"),
        ):
            result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "Token exchange failed" in result.error

    @pytest.mark.asyncio
    async def test_missing_state_returns_oidc_exception(
        self, oidc_config, mock_request
    ):
        """Test that missing state returns error via OIDCException."""
        auth = OIDCAuthentication(oidc_config)
        # Don't store verifier for the state

        result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "Invalid or missing state" in result.error


class TestPreserveTokensOnError:
    """Tests for preserve_tokens behavior on errors."""

    @pytest.mark.asyncio
    async def test_tokens_not_preserved_on_error_by_default(
        self, oidc_config, mock_request
    ):
        """Test that tokens are not preserved on error when preserve_tokens=False."""
        auth = OIDCAuthentication(oidc_config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        with patch.object(
            auth,
            "get_auth_token",
            side_effect=requests.ConnectionError("Network down"),
        ):
            result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.raw_tokens is None

    @pytest.mark.asyncio
    async def test_tokens_preserved_on_error_when_enabled(self, mock_request):
        """Test that tokens are preserved on error when preserve_tokens=True."""
        config = OIDCConfig(
            app_uri="https://example.com",
            client_id="test-client",
            client_secret="test-secret",
            well_known_endpoint="",
            authorization_endpoint="https://idp.example.com/auth",
            token_endpoint="https://idp.example.com/token",
            issuer="https://idp.example.com",
            preserve_tokens=True,
        )
        auth = OIDCAuthentication(config)
        auth._store_pkce_verifier("state_123", "test_verifier")

        # Return partial token then fail
        auth_token = {"id_token": "partial_token"}
        with (
            patch.object(auth, "get_auth_token", return_value=auth_token),
            patch("jwt.get_unverified_header", return_value={"alg": "RS256"}),
            patch.object(
                auth,
                "obtain_validated_token",
                side_effect=InvalidTokenError("Invalid"),
            ),
        ):
            result = await auth.authenticate(mock_request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.raw_tokens == auth_token
