"""
Security tests for preserve_tokens configuration.

These tests demonstrate the security implications of preserve_tokens=True (current default).

SECURITY ISSUE:
When preserve_tokens=True, raw tokens (access_token, id_token) are included in
AuthenticationResult and can be:
1. Exposed to client-side JavaScript if cookie httponly=False
2. Leaked over HTTP if cookie secure=False
3. Stolen via XSS attacks if tokens are accessible to JavaScript
4. Inadvertently logged or exposed in error messages

RECOMMENDATION:
- Default should be preserve_tokens=False (secure by default)
- Users who need tokens should explicitly opt-in with preserve_tokens=True
- When preserve_tokens=True, warn if cookie security flags are relaxed
"""

import datetime
from unittest.mock import Mock

import jwt
import pytest

from fastapi_opa.auth.auth_oidc import OIDCAuthentication
from fastapi_opa.auth.auth_oidc import OIDCConfig
from fastapi_opa.models import TokenCookieConfig
from tests.utils import mock_response
from tests.utils import oidc_well_known_response


class TestPreserveTokensDefaultBehavior:
    """Tests demonstrating the current default behavior and its security implications."""

    def test_preserve_tokens_default_is_false(self):
        """
        SECURE BY DEFAULT: preserve_tokens defaults to False.

        This ensures tokens are not exposed unless explicitly requested,
        following the principle of least privilege.
        """
        # Check the default value in the dataclass field
        from dataclasses import fields

        preserve_tokens_field = next(
            f for f in fields(OIDCConfig) if f.name == "preserve_tokens"
        )

        # SECURE: The default is False (secure by default)
        assert preserve_tokens_field.default is False, (
            "preserve_tokens should default to False for security. "
            "Tokens should only be preserved when explicitly requested."
        )

    def test_preserve_tokens_default_value_in_valid_config(self, mocker):
        """Verify preserve_tokens defaults to False in a valid configuration."""
        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )

        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
            # Note: preserve_tokens not specified, should default to False
        )

        # SECURE: Default does not expose tokens
        assert config.preserve_tokens is False


class TestTokenExposureWithPreserveTokensTrue:
    """Tests demonstrating how tokens are exposed when preserve_tokens=True."""

    @pytest.mark.asyncio
    async def test_raw_tokens_exposed_in_auth_result(self, mocker):
        """
        SECURITY ISSUE: With preserve_tokens=True, raw tokens are in AuthenticationResult.

        These tokens can then be:
        - Stored in cookies (potentially accessible to JavaScript)
        - Logged accidentally
        - Exposed in error responses
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
            preserve_tokens=True,  # Explicitly set, but this is the default
        )
        oidc = OIDCAuthentication(config)

        # Pre-populate PKCE store
        test_state = "test_state_123"
        oidc._store_pkce_verifier(test_state, "test_verifier")

        # Create a valid JWT token with sensitive claims
        iat = datetime.datetime.now().timestamp()
        token_payload = {
            "sub": "user123",
            "aud": "test-client",
            "iat": int(iat),
            "exp": int(iat + 3600),
            "email": "user@example.com",  # PII
            "name": "John Doe",  # PII
            "roles": ["admin"],  # Sensitive permission info
        }
        id_token = jwt.encode(token_payload, "test-secret", algorithm="HS256")
        access_token = "sensitive_access_token_xyz123"

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(
                200,
                {
                    "access_token": access_token,
                    "id_token": id_token,
                },
            ),
        )

        request = Mock()
        request.headers = {}
        request.query_params = {"code": "auth_code", "state": test_state}
        request.url = Mock(
            scheme="http", netloc="app.example.com", path="/callback"
        )

        result = await oidc.authenticate(request)

        # SECURITY ISSUE: Raw tokens are exposed in the result
        assert result.success is True
        assert result.raw_tokens is not None
        assert result.raw_tokens["access_token"] == access_token
        assert result.raw_tokens["id_token"] == id_token

        # These tokens contain sensitive information that could be stolen
        decoded = jwt.decode(
            result.raw_tokens["id_token"],
            "test-secret",
            algorithms=["HS256"],
            audience="test-client",
        )
        assert decoded["email"] == "user@example.com"
        assert decoded["roles"] == ["admin"]

    @pytest.mark.asyncio
    async def test_tokens_not_exposed_with_preserve_tokens_false(self, mocker):
        """
        SECURE: With preserve_tokens=False, raw tokens are NOT in AuthenticationResult.

        This is the secure behavior that should be the default.
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
            preserve_tokens=False,  # Secure setting
        )
        oidc = OIDCAuthentication(config)

        # Pre-populate PKCE store
        test_state = "test_state_456"
        oidc._store_pkce_verifier(test_state, "test_verifier")

        iat = datetime.datetime.now().timestamp()
        token_payload = {
            "sub": "user123",
            "aud": "test-client",
            "iat": int(iat),
            "exp": int(iat + 3600),
        }
        id_token = jwt.encode(token_payload, "test-secret", algorithm="HS256")

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(
                200,
                {
                    "access_token": "secret_token",
                    "id_token": id_token,
                },
            ),
        )

        request = Mock()
        request.headers = {}
        request.query_params = {"code": "auth_code", "state": test_state}
        request.url = Mock(
            scheme="http", netloc="app.example.com", path="/callback"
        )

        result = await oidc.authenticate(request)

        # SECURE: No raw tokens exposed
        assert result.success is True
        assert result.raw_tokens is None


class TestCookieSecurityWithPreserveTokens:
    """Tests demonstrating cookie security issues with preserve_tokens=True."""

    def test_insecure_cookie_config_allows_js_access(self):
        """
        SECURITY ISSUE: Cookies without HttpOnly can be accessed by JavaScript.

        If preserve_tokens=True and httponly=False, tokens can be stolen via XSS.
        """
        # Insecure configuration - tokens accessible to JavaScript
        insecure_config = TokenCookieConfig(
            enabled=True,
            cookie_name="access_token",
            cookie_secure=False,  # INSECURE: allows HTTP
            cookie_httponly=False,  # INSECURE: allows JavaScript access
            cookie_samesite="lax",
        )

        # With this config + preserve_tokens=True, an XSS attack could:
        # 1. Execute: document.cookie to read the access_token
        # 2. Send it to attacker's server
        # 3. Attacker impersonates the user

        assert insecure_config.cookie_httponly is False
        assert insecure_config.cookie_secure is False

    def test_secure_cookie_config_protects_tokens(self):
        """
        SECURE: Proper cookie flags protect tokens from JavaScript access.

        Even with preserve_tokens=True, proper cookie flags provide some protection.
        """
        secure_config = TokenCookieConfig(
            enabled=True,
            cookie_name="access_token",
            cookie_secure=True,  # HTTPS only
            cookie_httponly=True,  # No JavaScript access
            cookie_samesite="strict",  # No cross-site requests
        )

        assert secure_config.cookie_httponly is True
        assert secure_config.cookie_secure is True
        assert secure_config.cookie_samesite == "strict"

    def test_default_cookie_config_is_reasonably_secure(self):
        """Verify default TokenCookieConfig has secure defaults."""
        default_config = TokenCookieConfig()

        # These defaults are good
        assert default_config.cookie_secure is True
        assert default_config.cookie_httponly is True
        assert default_config.cookie_samesite == "lax"


class TestTokenLeakageScenarios:
    """Tests demonstrating various token leakage scenarios."""

    @pytest.mark.asyncio
    async def test_tokens_in_auth_result_could_be_logged(self, mocker):
        """
        SECURITY ISSUE: AuthenticationResult with tokens could be accidentally logged.

        Common mistake: logging auth results for debugging exposes tokens in logs.
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
            preserve_tokens=True,
        )
        oidc = OIDCAuthentication(config)

        test_state = "test_state_789"
        oidc._store_pkce_verifier(test_state, "test_verifier")

        iat = datetime.datetime.now().timestamp()
        id_token = jwt.encode(
            {
                "sub": "user123",
                "aud": "test-client",
                "iat": int(iat),
                "exp": int(iat + 3600),
            },
            "test-secret",
            algorithm="HS256",
        )

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(
                200,
                {
                    "access_token": "super_secret_token_do_not_log",
                    "id_token": id_token,
                },
            ),
        )

        request = Mock()
        request.headers = {}
        request.query_params = {"code": "auth_code", "state": test_state}
        request.url = Mock(
            scheme="http", netloc="app.example.com", path="/callback"
        )

        result = await oidc.authenticate(request)

        # Simulating what happens when someone logs the auth result
        # This is a common debugging mistake
        result_str = str(result.model_dump())

        # SECURITY ISSUE: Sensitive token is in the string representation
        assert "super_secret_token_do_not_log" in result_str

    @pytest.mark.asyncio
    async def test_tokens_not_leaked_when_preserve_false(self, mocker):
        """
        SECURE: With preserve_tokens=False, logging auth result is safe.
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
            preserve_tokens=False,
        )
        oidc = OIDCAuthentication(config)

        test_state = "test_state_abc"
        oidc._store_pkce_verifier(test_state, "test_verifier")

        iat = datetime.datetime.now().timestamp()
        id_token = jwt.encode(
            {
                "sub": "user123",
                "aud": "test-client",
                "iat": int(iat),
                "exp": int(iat + 3600),
            },
            "test-secret",
            algorithm="HS256",
        )

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(
                200,
                {
                    "access_token": "super_secret_token_do_not_log",
                    "id_token": id_token,
                },
            ),
        )

        request = Mock()
        request.headers = {}
        request.query_params = {"code": "auth_code", "state": test_state}
        request.url = Mock(
            scheme="http", netloc="app.example.com", path="/callback"
        )

        result = await oidc.authenticate(request)

        # SECURE: Token is NOT in the result
        result_str = str(result.model_dump())
        assert "super_secret_token_do_not_log" not in result_str


class TestSecureByDefaultPrinciple:
    """
    Tests advocating for secure-by-default behavior.

    The principle of "secure by default" means:
    - Default configurations should be the most secure option
    - Users must explicitly opt-in to less secure behaviors
    - Security should not require special knowledge to achieve
    """

    def test_preserve_tokens_defaults_to_false(self, mocker):
        """
        IMPLEMENTED: preserve_tokens now defaults to False.

        Rationale:
        1. Most apps don't need raw tokens after auth
        2. Exposing tokens increases attack surface
        3. Users who need tokens can explicitly enable
        4. Follows principle of least privilege
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

        # SECURE: Default is now False
        assert config.preserve_tokens is False

    def test_explicit_preserve_tokens_true_works(self, mocker):
        """
        Users who need tokens should explicitly set preserve_tokens=True.

        This is the secure pattern: opt-in to sensitive features.
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
            preserve_tokens=True,  # Explicit opt-in
        )

        assert config.preserve_tokens is True

    def test_preserve_tokens_true_logs_security_warning(self, mocker, caplog):
        """
        When preserve_tokens=True, a security warning should be logged.

        This ensures users are aware of the security implications.
        """
        import logging

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )

        with caplog.at_level(logging.WARNING):
            OIDCConfig(
                well_known_endpoint="http://example.com/.well-known",
                app_uri="http://app.example.com",
                client_id="test-client",
                client_secret="test-secret",
                preserve_tokens=True,
            )

        # Verify warning was logged
        assert any(
            "SECURITY WARNING" in record.message
            and "preserve_tokens=True" in record.message
            for record in caplog.records
        ), "Expected security warning to be logged when preserve_tokens=True"

    def test_preserve_tokens_false_no_warning(self, mocker, caplog):
        """
        When preserve_tokens=False (default), no security warning should be logged.
        """
        import logging

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )

        with caplog.at_level(logging.WARNING):
            OIDCConfig(
                well_known_endpoint="http://example.com/.well-known",
                app_uri="http://app.example.com",
                client_id="test-client",
                client_secret="test-secret",
                preserve_tokens=False,
            )

        # Verify no warning was logged about preserve_tokens
        assert not any(
            "preserve_tokens" in record.message for record in caplog.records
        ), "No warning should be logged when preserve_tokens=False"


class TestAccessTokenViaBearer:
    """Tests for access token authentication via Bearer header."""

    @pytest.mark.asyncio
    async def test_bearer_auth_with_preserve_tokens_true_exposes_token(
        self, mocker
    ):
        """
        SECURITY ISSUE: Bearer token is exposed in raw_tokens when preserve_tokens=True.
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
            preserve_tokens=True,
            get_user_info=True,
        )
        oidc = OIDCAuthentication(config)

        # Mock userinfo endpoint
        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=mock_response(
                200,
                {
                    "sub": "user123",
                    "email": "user@example.com",
                },
            ),
        )

        request = Mock()
        request.headers = {"Authorization": "Bearer secret_bearer_token_xyz"}
        request.query_params = {}
        request.url = Mock(
            scheme="http", netloc="app.example.com", path="/api/resource"
        )

        result = await oidc.authenticate(request, ["access_token"])

        # SECURITY ISSUE: The bearer token is exposed
        assert result.success is True
        assert result.raw_tokens is not None
        assert result.raw_tokens["access_token"] == "secret_bearer_token_xyz"

    @pytest.mark.asyncio
    async def test_bearer_auth_with_preserve_tokens_false_hides_token(
        self, mocker
    ):
        """
        SECURE: Bearer token is NOT exposed when preserve_tokens=False.
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
            preserve_tokens=False,
            get_user_info=True,
        )
        oidc = OIDCAuthentication(config)

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=mock_response(
                200,
                {
                    "sub": "user123",
                    "email": "user@example.com",
                },
            ),
        )

        request = Mock()
        request.headers = {"Authorization": "Bearer secret_bearer_token_xyz"}
        request.query_params = {}
        request.url = Mock(
            scheme="http", netloc="app.example.com", path="/api/resource"
        )

        result = await oidc.authenticate(request, ["access_token"])

        # SECURE: Token is not exposed
        assert result.success is True
        assert result.raw_tokens is None
