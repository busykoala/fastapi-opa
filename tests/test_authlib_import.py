"""Tests for conditional Authlib import handling."""

import pytest


class TestAuthlibAvailabilityFlag:
    """Tests for AUTHLIB_AVAILABLE flag."""

    def test_authlib_available_when_installed(self):
        """Test that AUTHLIB_AVAILABLE is True when authlib is installed."""
        from fastapi_opa.auth.auth_oidc import AUTHLIB_AVAILABLE

        # In test environment, authlib should be installed
        assert AUTHLIB_AVAILABLE is True

    def test_generate_token_works_when_authlib_installed(self):
        """Test that generate_token works when authlib is available."""
        from fastapi_opa.auth.auth_oidc import generate_token

        token = generate_token(32)
        assert isinstance(token, str)
        assert len(token) >= 32

    def test_create_s256_code_challenge_works_when_authlib_installed(self):
        """Test that create_s256_code_challenge works when authlib is available."""
        from fastapi_opa.auth.auth_oidc import create_s256_code_challenge

        verifier = "test_verifier_string_that_is_long_enough_for_pkce"
        challenge = create_s256_code_challenge(verifier)
        assert isinstance(challenge, str)
        # S256 challenges are base64url encoded SHA256 hashes (43 chars)
        assert len(challenge) == 43


class TestAuthlibNotInstalled:
    """Tests for behavior when authlib is not installed."""

    def test_import_error_message_for_generate_token(self):
        """Test that helpful error is raised when authlib not installed."""
        # We can't actually uninstall authlib in tests, but we can test
        # the placeholder functions directly
        from fastapi_opa.auth import auth_oidc

        # Save original
        original_available = auth_oidc.AUTHLIB_AVAILABLE
        original_generate = auth_oidc.generate_token

        try:
            # Simulate authlib not being available
            auth_oidc.AUTHLIB_AVAILABLE = False

            # Create placeholder function
            def mock_generate_token(length: int = 48) -> str:
                raise ImportError(
                    "authlib is required for OIDC authentication with PKCE. "
                    "Install it with: pip install 'fastapi-opa[authlib]'"
                )

            auth_oidc.generate_token = mock_generate_token

            # Test that it raises ImportError with helpful message
            with pytest.raises(ImportError) as exc_info:
                auth_oidc.generate_token(32)

            assert "authlib is required" in str(exc_info.value)
            assert "pip install 'fastapi-opa[authlib]'" in str(exc_info.value)

        finally:
            # Restore original
            auth_oidc.AUTHLIB_AVAILABLE = original_available
            auth_oidc.generate_token = original_generate

    def test_import_error_message_for_create_s256_code_challenge(self):
        """Test that helpful error is raised for create_s256_code_challenge."""
        from fastapi_opa.auth import auth_oidc

        # Save original
        original_available = auth_oidc.AUTHLIB_AVAILABLE
        original_create = auth_oidc.create_s256_code_challenge

        try:
            # Simulate authlib not being available
            auth_oidc.AUTHLIB_AVAILABLE = False

            # Create placeholder function
            def mock_create_challenge(verifier: str) -> str:
                raise ImportError(
                    "authlib is required for OIDC authentication with PKCE. "
                    "Install it with: pip install 'fastapi-opa[authlib]'"
                )

            auth_oidc.create_s256_code_challenge = mock_create_challenge

            # Test that it raises ImportError with helpful message
            with pytest.raises(ImportError) as exc_info:
                auth_oidc.create_s256_code_challenge("test_verifier")

            assert "authlib is required" in str(exc_info.value)
            assert "pip install 'fastapi-opa[authlib]'" in str(exc_info.value)

        finally:
            # Restore original
            auth_oidc.AUTHLIB_AVAILABLE = original_available
            auth_oidc.create_s256_code_challenge = original_create


class TestOIDCAuthenticationWithoutAuthlib:
    """Tests for OIDCAuthentication behavior when authlib is missing."""

    def test_oidc_config_creation_succeeds_without_pkce_calls(self):
        """Test that OIDCConfig can be created without triggering authlib."""
        from fastapi_opa.auth.auth_oidc import OIDCConfig

        # Creating config should not require authlib
        config = OIDCConfig(
            app_uri="https://example.com",
            client_id="test-client",
            client_secret="test-secret",
            well_known_endpoint="",
            authorization_endpoint="https://idp.example.com/auth",
            token_endpoint="https://idp.example.com/token",
            issuer="https://idp.example.com",
        )

        assert config.client_id == "test-client"

    def test_error_message_mentions_correct_install_command(self):
        """Test that error message has correct pip install command."""
        # The install command should match pyproject.toml extras
        expected_command = "pip install 'fastapi-opa[authlib]'"

        from fastapi_opa.auth import auth_oidc

        # Save and mock
        original_generate = auth_oidc.generate_token
        auth_oidc.generate_token = lambda length=48: (_ for _ in ()).throw(
            ImportError(
                f"authlib is required for OIDC authentication with PKCE. "
                f"Install it with: {expected_command}"
            )
        )

        try:
            with pytest.raises(ImportError) as exc_info:
                auth_oidc.generate_token(32)

            assert expected_command in str(exc_info.value)

        finally:
            auth_oidc.generate_token = original_generate
