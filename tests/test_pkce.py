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

    def test_pkce_pair_generated_per_request(self, mocker):
        """Verify that code_verifier and code_challenge are generated per-request"""
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

        # Generate PKCE pair
        code_verifier, code_challenge = oidc._generate_pkce_pair()

        # Verify code_verifier is generated (128 chars by default)
        assert len(code_verifier) > 0

        # Verify code_challenge is generated
        assert len(code_challenge) > 0

        # Verify code_challenge is S256 hash of code_verifier
        expected_challenge = create_s256_code_challenge(code_verifier)
        assert code_challenge == expected_challenge

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

        # Generate a code_verifier for this test
        test_code_verifier = "test_verifier_12345"

        mock_post = mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(200, {"access_token": "token123"}),
        )
        oidc.get_auth_token("auth_code", "http://callback", test_code_verifier)

        call_kwargs = mock_post.call_args[1]
        data = call_kwargs["data"]

        # Public client should have client_id in body
        assert data["client_id"] == "public-client"
        # Should have code_verifier for PKCE
        assert "code_verifier" in data
        assert data["code_verifier"] == test_code_verifier
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

        # Generate a code_verifier for this test
        test_code_verifier = "test_verifier_12345"

        mock_post = mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(200, {"access_token": "token123"}),
        )
        oidc.get_auth_token("auth_code", "http://callback", test_code_verifier)

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
        assert data["code_verifier"] == test_code_verifier

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

        # Generate a code_verifier for this test
        test_code_verifier = "test_verifier_12345"

        mock_post = mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(200, {"access_token": "token123"}),
        )
        oidc.get_auth_token("auth_code", "http://callback", test_code_verifier)

        call_kwargs = mock_post.call_args[1]
        data = call_kwargs["data"]

        # client_id and client_secret should be in body
        assert data["client_id"] == "confidential-client"
        assert data["client_secret"] == "super-secret"
        # Should have code_verifier for PKCE
        assert "code_verifier" in data
        assert data["code_verifier"] == test_code_verifier
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

        # Generate PKCE pair and pass code_challenge explicitly
        code_verifier, code_challenge = oidc._generate_pkce_pair()
        redirect_uri = oidc.get_auth_redirect_uri(
            "http://callback/path",
            code_challenge=code_challenge,
            state="test_state",
        )

        assert f"code_challenge={code_challenge}" in redirect_uri
        assert "code_challenge_method=S256" in redirect_uri
        assert "state=test_state" in redirect_uri

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
        oidc = OIDCAuthentication(config)

        # Generate PKCE pair
        code_verifier, code_challenge = oidc._generate_pkce_pair()

        # This is what the authorization server would do to verify
        computed_challenge = create_s256_code_challenge(code_verifier)
        assert computed_challenge == code_challenge


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

        # Pre-populate PKCE store (simulating a previous redirect)
        test_state = "test_state_123"
        test_code_verifier = "test_code_verifier_xyz"
        oidc._store_pkce_verifier(test_state, test_code_verifier)

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

        # Mock request with code and state (callback from IdP)
        request = Mock()
        request.headers = {}
        request.query_params = {"code": "auth_code", "state": test_state}
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

        # Pre-populate PKCE store (simulating a previous redirect)
        test_state = "test_state_456"
        test_code_verifier = "test_code_verifier_abc"
        oidc._store_pkce_verifier(test_state, test_code_verifier)

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

        # Mock request with code and state (callback from IdP)
        request = Mock()
        request.headers = {}
        request.query_params = {"code": "auth_code", "state": test_state}
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


class TestPKCESecurityRequirements:
    """
    Tests for PKCE security requirements.

    According to RFC 7636, a fresh code_verifier MUST be generated for each
    authorization request to prevent authorization code injection attacks.
    """

    @pytest.mark.asyncio
    async def test_multiple_auth_redirects_use_different_code_challenges(
        self, mocker
    ):
        """
        SECURITY: Each authorization redirect MUST use a unique code_challenge.

        Per RFC 7636 Section 4.1: The client creates a code verifier for each
        OAuth 2.0 authorization request.
        """
        from urllib.parse import parse_qs
        from urllib.parse import urlparse

        from starlette.responses import RedirectResponse

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

        # Simulate two different users/sessions requesting authentication
        request1 = Mock()
        request1.headers = {}
        request1.query_params = {}  # No code = redirect to IdP
        request1.url = Mock(
            scheme="http", netloc="app.example.com", path="/callback"
        )

        request2 = Mock()
        request2.headers = {}
        request2.query_params = {}  # No code = redirect to IdP
        request2.url = Mock(
            scheme="http", netloc="app.example.com", path="/callback"
        )

        # Get two redirect responses
        response1 = await oidc.authenticate(request1)
        response2 = await oidc.authenticate(request2)

        assert isinstance(response1, RedirectResponse)
        assert isinstance(response2, RedirectResponse)

        # Extract code_challenge from both redirects
        parsed1 = urlparse(response1.headers["location"])
        parsed2 = urlparse(response2.headers["location"])
        params1 = parse_qs(parsed1.query)
        params2 = parse_qs(parsed2.query)

        code_challenge1 = params1["code_challenge"][0]
        code_challenge2 = params2["code_challenge"][0]

        # SECURITY REQUIREMENT: code_challenges MUST be different
        assert code_challenge1 != code_challenge2, (
            "SECURITY VIOLATION: Same code_challenge used for multiple auth requests! "
            "Each authorization request MUST have a unique code_verifier/code_challenge pair."
        )

    @pytest.mark.asyncio
    async def test_code_verifier_in_token_request_matches_redirect(
        self, mocker
    ):
        """
        Verify that code_verifier sent in token request matches the
        code_challenge sent in the authorization redirect.
        """
        import datetime
        from urllib.parse import parse_qs
        from urllib.parse import urlparse

        import jwt
        from starlette.responses import RedirectResponse

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

        # Step 1: Get redirect to capture code_challenge
        request_initial = Mock()
        request_initial.headers = {}
        request_initial.query_params = {}
        request_initial.url = Mock(
            scheme="http", netloc="app.example.com", path="/callback"
        )

        redirect_response = await oidc.authenticate(request_initial)
        assert isinstance(redirect_response, RedirectResponse)

        parsed = urlparse(redirect_response.headers["location"])
        params = parse_qs(parsed.query)
        code_challenge_from_redirect = params["code_challenge"][0]
        state_from_redirect = params["state"][0]

        # Step 2: Simulate callback with code and state - capture code_verifier
        iat = datetime.datetime.now().timestamp()
        token_payload = {
            "sub": "user123",
            "aud": "test-client",
            "iat": int(iat),
            "exp": int(iat + 3600),
        }
        id_token = jwt.encode(token_payload, "test-secret", algorithm="HS256")

        mock_post = mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(
                200, {"access_token": "token", "id_token": id_token}
            ),
        )

        request_callback = Mock()
        request_callback.headers = {}
        request_callback.query_params = {
            "code": "auth_code_from_idp",
            "state": state_from_redirect,
        }
        request_callback.url = Mock(
            scheme="http", netloc="app.example.com", path="/callback"
        )

        await oidc.authenticate(request_callback)

        # Extract code_verifier from token request
        call_kwargs = mock_post.call_args[1]
        code_verifier_from_token_request = call_kwargs["data"]["code_verifier"]

        # Verify: code_verifier should produce the same code_challenge
        computed_challenge = create_s256_code_challenge(
            code_verifier_from_token_request
        )
        assert computed_challenge == code_challenge_from_redirect, (
            "code_verifier in token request does not match code_challenge from redirect"
        )

    def test_code_verifier_has_sufficient_entropy(self, mocker):
        """
        RFC 7636 Section 4.1: code_verifier should have at least 256 bits of entropy.
        A 128-character token provides sufficient entropy.
        """
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

        # Generate a code_verifier using the OIDC instance
        code_verifier, _ = oidc._generate_pkce_pair()

        # RFC 7636: code_verifier must be between 43-128 characters
        assert len(code_verifier) >= 43, (
            "code_verifier too short (min 43 chars)"
        )
        assert len(code_verifier) <= 128, (
            "code_verifier too long (max 128 chars)"
        )

    def test_multiple_pkce_generations_have_different_verifiers(self, mocker):
        """
        Each call to _generate_pkce_pair should produce different code_verifiers.
        """
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

        # Generate multiple PKCE pairs
        verifier1, challenge1 = oidc._generate_pkce_pair()
        verifier2, challenge2 = oidc._generate_pkce_pair()

        # Different calls should produce different verifiers
        assert verifier1 != verifier2, (
            "Multiple PKCE generations should produce unique code_verifiers"
        )
        assert challenge1 != challenge2, (
            "Multiple PKCE generations should produce unique code_challenges"
        )
