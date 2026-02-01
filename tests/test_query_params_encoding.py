"""Tests for safe query parameter encoding to prevent injection attacks."""

from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest

from fastapi_opa.auth.auth_oidc import OIDCAuthentication
from fastapi_opa.auth.auth_oidc import OIDCConfig


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


class TestQueryParamsEncoding:
    """Tests for safe URL encoding of query parameters."""

    def test_get_auth_redirect_uri_encodes_redirect_uri(self, oidc_config):
        """Test that redirect_uri with special chars is properly encoded."""
        auth = OIDCAuthentication(oidc_config)

        # Callback URI with special characters
        callback_uri = "https://app.example.com/callback?foo=bar&baz=qux"
        redirect_url = auth.get_auth_redirect_uri(
            callback_uri,
            code_challenge="test_challenge",
            state="test_state",
        )

        # Parse the redirect URL
        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # The redirect_uri should be properly encoded (not contain raw & or =)
        assert "redirect_uri" in params
        # The value should be the full original URL when decoded
        assert params["redirect_uri"][0] == callback_uri

    def test_get_auth_redirect_uri_encodes_ampersand_in_value(
        self, oidc_config
    ):
        """Test that & in parameter values doesn't create extra params."""
        auth = OIDCAuthentication(oidc_config)

        # Malicious callback with injection attempt
        malicious_callback = (
            "https://app.example.com/callback?inject=value&admin=true"
        )
        redirect_url = auth.get_auth_redirect_uri(
            malicious_callback,
            code_challenge="test_challenge",
            state="test_state",
        )

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # Should NOT have 'admin' as a separate parameter
        assert "admin" not in params
        # Should NOT have 'inject' as a separate parameter
        assert "inject" not in params
        # redirect_uri should contain the full malicious string (encoded)
        assert params["redirect_uri"][0] == malicious_callback

    def test_get_auth_redirect_uri_encodes_equals_in_value(self, oidc_config):
        """Test that = in parameter values is properly encoded."""
        auth = OIDCAuthentication(oidc_config)

        # Callback with = in query param
        callback_uri = "https://app.example.com/callback?encoded=a%3Db"
        redirect_url = auth.get_auth_redirect_uri(
            callback_uri,
            code_challenge="test_challenge",
            state="test_state",
        )

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # The redirect_uri should preserve the original value
        assert params["redirect_uri"][0] == callback_uri

    def test_get_auth_redirect_uri_encodes_space(self, oidc_config):
        """Test that spaces are properly encoded."""
        auth = OIDCAuthentication(oidc_config)

        # scope with spaces should be encoded
        redirect_url = auth.get_auth_redirect_uri(
            "https://app.example.com/callback",
            code_challenge="test_challenge",
            state="test_state",
        )

        parsed = urlparse(redirect_url)
        # Query should not contain literal spaces
        assert " " not in parsed.query
        # But when decoded, scope should have spaces
        params = parse_qs(parsed.query)
        assert " " in params["scope"][0]  # "openid email profile"

    def test_get_auth_redirect_uri_preserves_all_params(self, oidc_config):
        """Test that all required OIDC params are present."""
        auth = OIDCAuthentication(oidc_config)

        redirect_url = auth.get_auth_redirect_uri(
            "https://app.example.com/callback",
            code_challenge="my_code_challenge",
            state="my_state",
        )

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        assert params["response_type"][0] == "code"
        assert params["client_id"][0] == "test-client"
        assert params["code_challenge"][0] == "my_code_challenge"
        assert params["code_challenge_method"][0] == "S256"
        assert params["state"][0] == "my_state"

    def test_get_auth_redirect_uri_no_state_when_none(self, oidc_config):
        """Test that state is not included when None."""
        auth = OIDCAuthentication(oidc_config)

        redirect_url = auth.get_auth_redirect_uri(
            "https://app.example.com/callback",
            code_challenge="test_challenge",
            state=None,
        )

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        assert "state" not in params

    def test_encoding_special_unicode_characters(self, oidc_config):
        """Test encoding of unicode characters in callback URI."""
        auth = OIDCAuthentication(oidc_config)

        # Callback with unicode
        callback_uri = "https://app.example.com/callback?name=João"
        redirect_url = auth.get_auth_redirect_uri(
            callback_uri,
            code_challenge="test_challenge",
            state="test_state",
        )

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # The decoded redirect_uri should match original
        assert params["redirect_uri"][0] == callback_uri


class TestExistingQueryParamsPreservation:
    """Tests for preserving existing query params during redirect."""

    def test_existing_params_with_special_chars_are_encoded(self, oidc_config):
        """Test that existing query params with special chars are encoded."""
        from urllib.parse import urlencode

        # Simulate malicious query param value
        params = {"return_url": "https://evil.com?steal=token&admin=true"}
        query_string = urlencode(params)

        # The & in the value should be encoded as %26
        assert "%26" in query_string
        # Should not have 'admin' or 'steal' as separate params
        assert query_string.count("=") == 1  # Only return_url=...

    def test_empty_query_params_handled(self, oidc_config):
        """Test that empty query params don't cause issues."""
        from urllib.parse import urlencode

        existing_params = {}
        query_string = urlencode(existing_params) if existing_params else ""

        assert query_string == ""

    def test_multiple_params_preserved(self, oidc_config):
        """Test that multiple query params are all preserved."""
        from urllib.parse import urlencode

        existing_params = {
            "param1": "value1",
            "param2": "value2",
            "param3": "value3",
        }
        query_string = urlencode(existing_params)
        decoded = parse_qs(query_string)

        assert decoded["param1"][0] == "value1"
        assert decoded["param2"][0] == "value2"
        assert decoded["param3"][0] == "value3"


class TestInjectionPrevention:
    """Tests specifically for injection attack prevention."""

    def test_prevent_parameter_injection_via_ampersand(self, oidc_config):
        """Test that & in values cannot inject new parameters."""
        auth = OIDCAuthentication(oidc_config)

        # Attempt to inject 'admin=true' via malicious callback
        injection_attempt = (
            "https://app.example.com/callback&admin=true&role=superuser"
        )

        redirect_url = auth.get_auth_redirect_uri(
            injection_attempt,
            code_challenge="test",
            state="test",
        )

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # These should NOT be separate parameters
        assert "admin" not in params
        assert "role" not in params

        # The whole injection attempt should be in redirect_uri
        assert injection_attempt in params["redirect_uri"][0]

    def test_prevent_parameter_override_via_injection(self, oidc_config):
        """Test that injected params cannot override OIDC params."""
        auth = OIDCAuthentication(oidc_config)

        # Attempt to override client_id via malicious callback
        injection_attempt = (
            "https://app.example.com/callback&client_id=evil_client"
        )

        redirect_url = auth.get_auth_redirect_uri(
            injection_attempt,
            code_challenge="test",
            state="test",
        )

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # client_id should still be the original, not overridden
        assert params["client_id"][0] == "test-client"
        assert len(params["client_id"]) == 1

    def test_prevent_response_type_override(self, oidc_config):
        """Test that response_type cannot be overridden via injection."""
        auth = OIDCAuthentication(oidc_config)

        # Attempt to change response_type to token (implicit flow)
        injection_attempt = (
            "https://app.example.com/callback&response_type=token"
        )

        redirect_url = auth.get_auth_redirect_uri(
            injection_attempt,
            code_challenge="test",
            state="test",
        )

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # response_type should still be 'code', not 'token'
        assert params["response_type"][0] == "code"
        assert len(params["response_type"]) == 1

    def test_encoded_injection_attempt(self, oidc_config):
        """Test that pre-encoded injection attempts are handled."""
        auth = OIDCAuthentication(oidc_config)

        # Attempt injection with already-encoded characters
        injection_attempt = "https://app.example.com/callback%26admin%3Dtrue"

        redirect_url = auth.get_auth_redirect_uri(
            injection_attempt,
            code_challenge="test",
            state="test",
        )

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # admin should not be a separate param
        assert "admin" not in params
        # The encoded string should be preserved in redirect_uri
        assert "callback%26admin%3Dtrue" in params["redirect_uri"][0]
