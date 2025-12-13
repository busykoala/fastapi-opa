"""Tests for PKCE (Proof Key for Code Exchange) implementation"""

from unittest.mock import Mock
from unittest.mock import patch

import pytest
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from fastapi_opa.auth.auth_oidc import OIDCAuthentication
from fastapi_opa.auth.auth_oidc import OIDCConfig
from fastapi_opa.auth.exceptions import OIDCException
from tests.utils import mock_response
from tests.utils import oidc_well_known_response


class TestOIDCConfigPKCE:
    """Test PKCE configuration in OIDCConfig"""

    def test_pkce_parameters_generated_on_init(self):
        """Verify that code_verifier and code_challenge are generated"""
        with patch("fastapi_opa.auth.auth_oidc.requests.get") as mock_get:
            mock_get.return_value = oidc_well_known_response()
            config = OIDCConfig(
                well_known_endpoint="http://example.com/.well-known",
                app_uri="http://app.example.com",
                client_id="test-client",
                client_secret="test-secret",
            )

        # Verify code_verifier is generated (128 chars by default)
        assert hasattr(config, "code_verifier")
        assert len(config.code_verifier) > 0

        # Verify code_challenge is generated
        assert hasattr(config, "code_challenge")
        assert len(config.code_challenge) > 0

        # Verify code_challenge is S256 hash of code_verifier
        expected_challenge = create_s256_code_challenge(config.code_verifier)
        assert config.code_challenge == expected_challenge

    def test_default_pkce_method_is_s256(self):
        """Verify default code_challenge_method is S256"""
        with patch("fastapi_opa.auth.auth_oidc.requests.get") as mock_get:
            mock_get.return_value = oidc_well_known_response()
            config = OIDCConfig(
                well_known_endpoint="http://example.com/.well-known",
                app_uri="http://app.example.com",
                client_id="test-client",
                client_secret="test-secret",
            )

        assert config.code_challenge_method == "S256"

    def test_confidential_client_requires_secret(self):
        """Verify confidential client (default) requires client_secret"""
        with pytest.raises(OIDCException) as exc_info:
            OIDCConfig(
                well_known_endpoint="http://example.com/.well-known",
                app_uri="http://app.example.com",
                client_id="test-client",
                # No client_secret provided
            )

        assert "client_secret is required" in str(exc_info.value)

    def test_public_client_does_not_require_secret(self):
        """Verify public client does not require client_secret"""
        with patch("fastapi_opa.auth.auth_oidc.requests.get") as mock_get:
            mock_get.return_value = oidc_well_known_response()
            config = OIDCConfig(
                well_known_endpoint="http://example.com/.well-known",
                app_uri="http://app.example.com",
                client_id="test-client",
                is_public_client=True,
                # No client_secret needed
            )

        assert config.is_public_client is True
        assert config.client_secret is None


class TestPKCETokenRequest:
    """Test PKCE in token requests"""

    def test_public_client_token_request(self, mocker):
        """Test token request for public client includes client_id in body"""
        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )
        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="public-client",
            is_public_client=True,
        )
        oidc = OIDCAuthentication(config)

        mock_post = mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(200, {"access_token": "token123"}),
        )
        oidc.get_auth_token("auth_code", "http://callback")

        call_kwargs = mock_post.call_args[1]
        data = call_kwargs["data"]

        # Public client should have client_id in body
        assert data["client_id"] == "public-client"
        # Should have code_verifier for PKCE
        assert "code_verifier" in data
        assert data["code_verifier"] == config.code_verifier
        # Should NOT have Authorization header
        assert "Authorization" not in call_kwargs.get("headers", {})

    def test_confidential_client_with_auth_header(self, mocker):
        """Test confidential client uses Authorization header by default"""
        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )
        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="confidential-client",
            client_secret="super-secret",
            use_auth_header=True,  # Default
        )
        oidc = OIDCAuthentication(config)

        mock_post = mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(200, {"access_token": "token123"}),
        )
        oidc.get_auth_token("auth_code", "http://callback")

        call_kwargs = mock_post.call_args[1]
        data = call_kwargs["data"]
        headers = call_kwargs["headers"]

        # Should have Authorization header
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")
        # client_id should NOT be in body when using auth header
        assert "client_id" not in data
        # Should have code_verifier for PKCE
        assert "code_verifier" in data

    def test_confidential_client_with_body_credentials(self, mocker):
        """Test confidential client can send credentials in body"""
        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )
        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="confidential-client",
            client_secret="super-secret",
            use_auth_header=False,  # Send in body instead
        )
        oidc = OIDCAuthentication(config)

        mock_post = mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(200, {"access_token": "token123"}),
        )
        oidc.get_auth_token("auth_code", "http://callback")

        call_kwargs = mock_post.call_args[1]
        data = call_kwargs["data"]

        # client_id and client_secret should be in body
        assert data["client_id"] == "confidential-client"
        assert data["client_secret"] == "super-secret"
        # Should have code_verifier for PKCE
        assert "code_verifier" in data
        # Should NOT have Authorization header
        assert "Authorization" not in call_kwargs.get("headers", {})


class TestPKCEAuthorizationRedirect:
    """Test PKCE parameters in authorization redirect"""

    def test_redirect_uri_contains_pkce_params(self, mocker):
        """Verify redirect URI contains code_challenge and method"""
        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )
        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
        )
        oidc = OIDCAuthentication(config)

        redirect_uri = oidc.get_auth_redirect_uri("http://callback/path")

        assert f"code_challenge={config.code_challenge}" in redirect_uri
        assert "code_challenge_method=S256" in redirect_uri

    def test_code_verifier_matches_code_challenge(self, mocker):
        """Verify code_verifier can be validated against code_challenge"""
        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )
        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
        )

        # This is what the authorization server would do to verify
        computed_challenge = create_s256_code_challenge(config.code_verifier)
        assert computed_challenge == config.code_challenge


class TestPreserveTokensOption:
    """Test preserve_tokens configuration option"""

    @pytest.mark.asyncio
    async def test_preserve_tokens_true_includes_raw_tokens(self, mocker):
        """When preserve_tokens=True, raw_tokens should be in result"""
        import datetime

        import jwt

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )
        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
            preserve_tokens=True,
        )
        oidc = OIDCAuthentication(config)

        # Create a valid JWT token
        iat = datetime.datetime.now().timestamp()
        token_payload = {
            "sub": "user123",
            "aud": "test-client",
            "iat": int(iat),
            "exp": int(iat + 3600),
        }
        id_token = jwt.encode(token_payload, "test-secret", algorithm="HS256")

        mock_token_response = {
            "access_token": "access123",
            "id_token": id_token,
        }
        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(200, mock_token_response),
        )

        # Mock request with code
        request = Mock()
        request.headers = {}
        request.query_params = {"code": "auth_code"}
        request.url = Mock(
            scheme="http", netloc="app.example.com", path="/callback"
        )

        result = await oidc.authenticate(request)

        assert result.success is True
        assert result.raw_tokens is not None
        assert result.raw_tokens["access_token"] == "access123"
        assert result.raw_tokens["id_token"] == id_token

    @pytest.mark.asyncio
    async def test_preserve_tokens_false_excludes_raw_tokens(self, mocker):
        """When preserve_tokens=False, raw_tokens should be None"""
        import datetime

        import jwt

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )
        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
            preserve_tokens=False,
        )
        oidc = OIDCAuthentication(config)

        # Create a valid JWT token
        iat = datetime.datetime.now().timestamp()
        token_payload = {
            "sub": "user123",
            "aud": "test-client",
            "iat": int(iat),
            "exp": int(iat + 3600),
        }
        id_token = jwt.encode(token_payload, "test-secret", algorithm="HS256")

        mock_token_response = {
            "access_token": "access123",
            "id_token": id_token,
        }
        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(200, mock_token_response),
        )

        # Mock request with code
        request = Mock()
        request.headers = {}
        request.query_params = {"code": "auth_code"}
        request.url = Mock(
            scheme="http", netloc="app.example.com", path="/callback"
        )

        result = await oidc.authenticate(request)

        assert result.success is True
        assert result.raw_tokens is None


class TestOIDCConfigEndpoints:
    """Test OIDC endpoint configuration options"""

    def test_config_with_explicit_endpoints(self):
        """Test configuration with explicit endpoints instead of well-known"""
        config = OIDCConfig(
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
            issuer="http://idp.example.com",
            authorization_endpoint="http://idp.example.com/authorize",
            token_endpoint="http://idp.example.com/token",
            jwks_uri="http://idp.example.com/jwks",
        )
        oidc = OIDCAuthentication(config)

        assert oidc.issuer == "http://idp.example.com"
        assert oidc.authorization_endpoint == "http://idp.example.com/authorize"
        assert oidc.token_endpoint == "http://idp.example.com/token"
        assert oidc.jwks_uri == "http://idp.example.com/jwks"

    def test_config_requires_endpoints(self):
        """Test that configuration fails without endpoints"""
        config = OIDCConfig(
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
            # No well_known_endpoint or explicit endpoints
        )

        with pytest.raises(OIDCException) as exc_info:
            OIDCAuthentication(config)

        assert "Endpoints not provided" in str(exc_info.value)

    def test_get_user_info_requires_userinfo_endpoint(self):
        """Test that get_user_info=True requires userinfo_endpoint"""
        config = OIDCConfig(
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
            issuer="http://idp.example.com",
            authorization_endpoint="http://idp.example.com/authorize",
            token_endpoint="http://idp.example.com/token",
            get_user_info=True,
            # No userinfo_endpoint
        )

        with pytest.raises(OIDCException) as exc_info:
            OIDCAuthentication(config)

        assert "Userinfo endpoint not provided" in str(exc_info.value)
