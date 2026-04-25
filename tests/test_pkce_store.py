"""Tests for PKCE Store abstraction and InMemoryPKCEStore implementation."""

import datetime
import threading
import time
from unittest.mock import Mock

import jwt
import pytest

from fastapi_opa.auth.pkce_store import DEFAULT_MAX_ENTRIES
from fastapi_opa.auth.pkce_store import DEFAULT_TTL_SECONDS
from fastapi_opa.auth.pkce_store import InMemoryPKCEStore
from fastapi_opa.auth.pkce_store import PKCEStoreProtocol
from fastapi_opa.models import AuthenticationResult
from tests.utils import mock_response


class TestPKCEStoreProtocol:
    """Test PKCEStoreProtocol compliance."""

    def test_inmemory_store_implements_protocol(self):
        """Verify InMemoryPKCEStore implements PKCEStoreProtocol."""
        store = InMemoryPKCEStore()
        assert isinstance(store, PKCEStoreProtocol)

    def test_custom_store_implements_protocol(self):
        """Verify custom store with correct methods implements Protocol."""

        class CustomStore:
            def __init__(self):
                self._data = {}

            def store(self, state: str, code_verifier: str) -> None:
                self._data[state] = code_verifier

            def retrieve(self, state: str) -> str | None:
                return self._data.pop(state, None)

        custom = CustomStore()
        assert isinstance(custom, PKCEStoreProtocol)

    def test_incomplete_store_does_not_implement_protocol(self):
        """Verify incomplete store does not implement Protocol."""

        class IncompleteStore:
            def store(self, state: str, code_verifier: str) -> None:
                pass

            # Missing retrieve method

        incomplete = IncompleteStore()
        assert not isinstance(incomplete, PKCEStoreProtocol)


class TestInMemoryPKCEStoreBasicOperations:
    """Test basic store/retrieve operations."""

    def test_store_and_retrieve(self):
        """Test basic store and retrieve."""
        store = InMemoryPKCEStore()
        store.store("state1", "verifier1")

        result = store.retrieve("state1")

        assert result == "verifier1"

    def test_retrieve_removes_entry(self):
        """Verify retrieve removes the entry (one-time use)."""
        store = InMemoryPKCEStore()
        store.store("state1", "verifier1")

        # First retrieve should succeed
        result1 = store.retrieve("state1")
        assert result1 == "verifier1"

        # Second retrieve should return None
        result2 = store.retrieve("state1")
        assert result2 is None

    def test_retrieve_nonexistent_returns_none(self):
        """Verify retrieve returns None for nonexistent state."""
        store = InMemoryPKCEStore()

        result = store.retrieve("nonexistent")

        assert result is None

    def test_multiple_entries(self):
        """Test storing and retrieving multiple entries."""
        store = InMemoryPKCEStore()
        store.store("state1", "verifier1")
        store.store("state2", "verifier2")
        store.store("state3", "verifier3")

        assert store.retrieve("state2") == "verifier2"
        assert store.retrieve("state1") == "verifier1"
        assert store.retrieve("state3") == "verifier3"

    def test_overwrite_existing_entry(self):
        """Test that storing with same state overwrites."""
        store = InMemoryPKCEStore()
        store.store("state1", "verifier1")
        store.store("state1", "verifier2")

        result = store.retrieve("state1")

        assert result == "verifier2"

    def test_size_property(self):
        """Test size property returns correct count."""
        store = InMemoryPKCEStore()
        assert store.size == 0

        store.store("state1", "verifier1")
        assert store.size == 1

        store.store("state2", "verifier2")
        assert store.size == 2

        store.retrieve("state1")
        assert store.size == 1


class TestInMemoryPKCEStoreTTL:
    """Test TTL (time-to-live) functionality."""

    def test_default_ttl(self):
        """Verify default TTL is 600 seconds (10 minutes)."""
        store = InMemoryPKCEStore()
        assert store._ttl_seconds == DEFAULT_TTL_SECONDS
        assert store._ttl_seconds == 600

    def test_custom_ttl(self):
        """Test custom TTL configuration."""
        store = InMemoryPKCEStore(ttl_seconds=300)
        assert store._ttl_seconds == 300

    def test_expired_entry_returns_none(self):
        """Test that expired entries return None."""
        store = InMemoryPKCEStore(ttl_seconds=1)
        store.store("state1", "verifier1")

        # Wait for expiration
        time.sleep(1.1)

        result = store.retrieve("state1")
        assert result is None

    def test_non_expired_entry_returns_value(self):
        """Test that non-expired entries return value."""
        store = InMemoryPKCEStore(ttl_seconds=10)
        store.store("state1", "verifier1")

        result = store.retrieve("state1")
        assert result == "verifier1"

    def test_cleanup_expired_removes_old_entries(self):
        """Test cleanup_expired removes expired entries."""
        store = InMemoryPKCEStore(ttl_seconds=1)
        store.store("state1", "verifier1")
        store.store("state2", "verifier2")

        assert store.size == 2

        # Wait for expiration
        time.sleep(1.1)

        removed = store.cleanup_expired()

        assert removed == 2
        assert store.size == 0

    def test_cleanup_expired_keeps_valid_entries(self):
        """Test cleanup_expired keeps non-expired entries."""
        store = InMemoryPKCEStore(ttl_seconds=10)
        store.store("state1", "verifier1")

        removed = store.cleanup_expired()

        assert removed == 0
        assert store.size == 1


class TestInMemoryPKCEStoreMaxEntries:
    """Test max entries limit functionality."""

    def test_default_max_entries(self):
        """Verify default max entries is 10000."""
        store = InMemoryPKCEStore()
        assert store._max_entries == DEFAULT_MAX_ENTRIES
        assert store._max_entries == 10000

    def test_custom_max_entries(self):
        """Test custom max entries configuration."""
        store = InMemoryPKCEStore(max_entries=100)
        assert store._max_entries == 100

    def test_removes_oldest_when_at_capacity(self):
        """Test that oldest entry is removed when at capacity."""
        store = InMemoryPKCEStore(max_entries=3, ttl_seconds=3600)

        store.store("state1", "verifier1")
        time.sleep(0.01)  # Ensure different timestamps
        store.store("state2", "verifier2")
        time.sleep(0.01)
        store.store("state3", "verifier3")

        assert store.size == 3

        # Adding fourth should remove oldest (state1)
        time.sleep(0.01)
        store.store("state4", "verifier4")

        assert store.size == 3
        assert store.retrieve("state1") is None  # Should be removed
        assert store.retrieve("state2") == "verifier2"

    def test_cleanup_before_removing_oldest(self):
        """Test that expired entries are cleaned before removing oldest."""
        store = InMemoryPKCEStore(max_entries=3, ttl_seconds=1)

        store.store("state1", "verifier1")
        time.sleep(1.1)  # Let state1 expire
        store.store("state2", "verifier2")
        store.store("state3", "verifier3")

        # At capacity, but state1 is expired
        # Adding state4 should cleanup state1 first
        store.store("state4", "verifier4")

        assert store.size == 3
        # state2, state3, state4 should be present
        assert store.retrieve("state2") == "verifier2"


class TestInMemoryPKCEStoreThreadSafety:
    """Test thread-safety of the store."""

    def test_concurrent_store_operations(self):
        """Test concurrent store operations are thread-safe."""
        store = InMemoryPKCEStore()
        errors = []
        num_threads = 10
        ops_per_thread = 100

        def store_entries(thread_id):
            try:
                for i in range(ops_per_thread):
                    store.store(
                        f"state_{thread_id}_{i}", f"verifier_{thread_id}_{i}"
                    )
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=store_entries, args=(i,))
            for i in range(num_threads)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert store.size == num_threads * ops_per_thread

    def test_concurrent_retrieve_operations(self):
        """Test concurrent retrieve operations are thread-safe."""
        store = InMemoryPKCEStore()
        num_entries = 1000

        # Pre-populate store
        for i in range(num_entries):
            store.store(f"state_{i}", f"verifier_{i}")

        results = []
        errors = []
        lock = threading.Lock()

        def retrieve_entries(start, end):
            try:
                for i in range(start, end):
                    result = store.retrieve(f"state_{i}")
                    with lock:
                        if result is not None:
                            results.append(result)
            except Exception as e:
                errors.append(e)

        num_threads = 10
        chunk_size = num_entries // num_threads
        threads = [
            threading.Thread(
                target=retrieve_entries,
                args=(i * chunk_size, (i + 1) * chunk_size),
            )
            for i in range(num_threads)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # Each entry should be retrieved exactly once
        assert len(results) == num_entries

    def test_concurrent_store_and_retrieve(self):
        """Test concurrent store and retrieve operations."""
        store = InMemoryPKCEStore()
        errors = []
        stored_states = []
        retrieved_values = []
        lock = threading.Lock()

        def store_entries():
            try:
                for i in range(100):
                    state = f"state_{i}"
                    store.store(state, f"verifier_{i}")
                    with lock:
                        stored_states.append(state)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        def retrieve_entries():
            try:
                for i in range(100):
                    state = f"state_{i}"
                    result = store.retrieve(state)
                    if result:
                        with lock:
                            retrieved_values.append(result)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        store_thread = threading.Thread(target=store_entries)
        retrieve_thread = threading.Thread(target=retrieve_entries)

        store_thread.start()
        retrieve_thread.start()

        store_thread.join()
        retrieve_thread.join()

        assert len(errors) == 0


class TestInMemoryPKCEStoreWithOIDCConfig:
    """Test integration with OIDCConfig."""

    def test_oidc_config_with_default_store(self, mocker):
        """Test OIDCConfig uses default InMemoryPKCEStore when not specified."""
        from fastapi_opa.auth.auth_oidc import OIDCAuthentication
        from fastapi_opa.auth.auth_oidc import OIDCConfig
        from tests.utils import oidc_well_known_response

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

        assert isinstance(oidc._pkce_store, InMemoryPKCEStore)

    def test_oidc_config_with_custom_store(self, mocker):
        """Test OIDCConfig accepts custom PKCE store."""
        from fastapi_opa.auth.auth_oidc import OIDCAuthentication
        from fastapi_opa.auth.auth_oidc import OIDCConfig
        from tests.utils import oidc_well_known_response

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )

        custom_store = InMemoryPKCEStore(ttl_seconds=300, max_entries=500)

        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
            pkce_store=custom_store,
        )
        oidc = OIDCAuthentication(config)

        assert oidc._pkce_store is custom_store
        assert oidc._pkce_store._ttl_seconds == 300
        assert oidc._pkce_store._max_entries == 500

    def test_oidc_authentication_uses_store_methods(self, mocker):
        """Test OIDCAuthentication uses store.store() and store.retrieve()."""
        from fastapi_opa.auth.auth_oidc import OIDCAuthentication
        from fastapi_opa.auth.auth_oidc import OIDCConfig
        from tests.utils import oidc_well_known_response

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

        # Test store method
        oidc._store_pkce_verifier("test_state", "test_verifier")
        assert isinstance(oidc._pkce_store, InMemoryPKCEStore)
        assert oidc._pkce_store.size == 1

        # Test retrieve method
        result = oidc._retrieve_pkce_verifier("test_state")
        assert result == "test_verifier"
        assert oidc._pkce_store.size == 0


class TestCustomPKCEStoreImplementation:
    """Test custom PKCE store implementations."""

    def test_mock_redis_store(self, mocker):
        """Test a mock Redis-like store implementation."""
        from fastapi_opa.auth.auth_oidc import OIDCAuthentication
        from fastapi_opa.auth.auth_oidc import OIDCConfig
        from tests.utils import oidc_well_known_response

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )

        class MockRedisPKCEStore:
            """Mock Redis PKCE store for testing."""

            def __init__(self):
                self._data = {}

            def store(self, state: str, code_verifier: str) -> None:
                self._data[f"pkce:{state}"] = code_verifier

            def retrieve(self, state: str) -> str | None:
                key = f"pkce:{state}"
                return self._data.pop(key, None)

        redis_store = MockRedisPKCEStore()

        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
            pkce_store=redis_store,
        )
        oidc = OIDCAuthentication(config)

        # Verify custom store is used
        assert oidc._pkce_store is redis_store

        # Test operations through OIDC
        oidc._store_pkce_verifier("state1", "verifier1")
        assert "pkce:state1" in redis_store._data

        result = oidc._retrieve_pkce_verifier("state1")
        assert result == "verifier1"
        assert "pkce:state1" not in redis_store._data

    @pytest.mark.asyncio
    async def test_legacy_custom_store_preserves_nonce_and_callback_uri(
        self, mocker
    ):
        from fastapi_opa.auth.auth_oidc import OIDCAuthentication
        from fastapi_opa.auth.auth_oidc import OIDCConfig
        from tests.utils import oidc_well_known_response

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )

        class MockRedisPKCEStore:
            def __init__(self):
                self._data = {}

            def store(self, state: str, code_verifier: str) -> None:
                self._data[f"pkce:{state}"] = code_verifier

            def retrieve(self, state: str) -> str | None:
                return self._data.pop(f"pkce:{state}", None)

        redis_store = MockRedisPKCEStore()
        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
            pkce_store=redis_store,
        )
        oidc = OIDCAuthentication(config)

        redirect_uri = oidc.get_auth_redirect_uri(
            "http://app.example.com/callback"
        )
        state = redirect_uri.split("state=")[1].split("&", 1)[0]
        nonce = redirect_uri.split("nonce=")[1].split("&", 1)[0]

        iat = int(datetime.datetime.now().timestamp())
        id_token = jwt.encode(
            {
                "sub": "user123",
                "aud": "test-client",
                "iss": "http://keycloak.busykoala.ch/auth/realms/example-realm",
                "nonce": nonce,
                "iat": iat,
                "exp": iat + 3600,
            },
            "test-secret",
            algorithm="HS256",
        )

        post_mock = mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(
                200,
                {"access_token": "access123", "id_token": id_token},
            ),
        )

        request = Mock()
        request.headers = {}
        request.query_params = {"code": "auth_code", "state": state}
        request.url = Mock(
            scheme="http",
            netloc="other-worker.example.com",
            path="/callback",
        )

        result = await oidc.authenticate(request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is True
        assert (
            post_mock.call_args.kwargs["data"]["redirect_uri"]
            == "http://app.example.com/callback"
        )

    @pytest.mark.asyncio
    async def test_legacy_custom_store_still_enforces_nonce_validation(
        self, mocker
    ):
        from fastapi_opa.auth.auth_oidc import OIDCAuthentication
        from fastapi_opa.auth.auth_oidc import OIDCConfig
        from tests.utils import oidc_well_known_response

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.get",
            return_value=oidc_well_known_response(),
        )

        class MockRedisPKCEStore:
            def __init__(self):
                self._data = {}

            def store(self, state: str, code_verifier: str) -> None:
                self._data[f"pkce:{state}"] = code_verifier

            def retrieve(self, state: str) -> str | None:
                return self._data.pop(f"pkce:{state}", None)

        config = OIDCConfig(
            well_known_endpoint="http://example.com/.well-known",
            app_uri="http://app.example.com",
            client_id="test-client",
            client_secret="test-secret",
            pkce_store=MockRedisPKCEStore(),
        )
        oidc = OIDCAuthentication(config)

        redirect_uri = oidc.get_auth_redirect_uri(
            "http://app.example.com/callback"
        )
        state = redirect_uri.split("state=")[1].split("&", 1)[0]

        iat = int(datetime.datetime.now().timestamp())
        wrong_nonce_token = jwt.encode(
            {
                "sub": "user123",
                "aud": "test-client",
                "iss": "http://keycloak.busykoala.ch/auth/realms/example-realm",
                "nonce": "wrong-nonce",
                "iat": iat,
                "exp": iat + 3600,
            },
            "test-secret",
            algorithm="HS256",
        )

        mocker.patch(
            "fastapi_opa.auth.auth_oidc.requests.post",
            return_value=mock_response(
                200,
                {"access_token": "access123", "id_token": wrong_nonce_token},
            ),
        )

        request = Mock()
        request.headers = {}
        request.query_params = {"code": "auth_code", "state": state}
        request.url = Mock(
            scheme="http",
            netloc="other-worker.example.com",
            path="/callback",
        )

        result = await oidc.authenticate(request)

        assert isinstance(result, AuthenticationResult)
        assert result.success is False
        assert result.error is not None
        assert "nonce mismatch" in result.error
