"""PKCE Store abstraction for secure PKCE request storage."""

import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Dict
from typing import Optional
from typing import Protocol
from typing import Tuple
from typing import runtime_checkable

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_TTL_SECONDS = 600  # 10 minutes
DEFAULT_MAX_ENTRIES = 10000


@dataclass(frozen=True)
class PKCERequestData:
    """Stored PKCE request state for the authorization code flow."""

    code_verifier: str
    callback_uri: str
    nonce: Optional[str] = None


@runtime_checkable
class PKCEStoreProtocol(Protocol):
    """Protocol for PKCE code_verifier storage.

    Implementations must provide thread-safe storage for PKCE code_verifiers
    mapped by state parameter. The retrieve operation MUST remove the entry
    to prevent replay attacks.

    Example custom implementation (Redis):

        class RedisPKCEStore:
            def __init__(self, redis_client, ttl: int = 600):
                self.redis = redis_client
                self.ttl = ttl

            def store(self, state: str, code_verifier: str) -> None:
                self.redis.setex(f"pkce:{state}", self.ttl, code_verifier)

            def retrieve(self, state: str) -> Optional[str]:
                key = f"pkce:{state}"
                pipe = self.redis.pipeline()
                pipe.get(key)
                pipe.delete(key)
                value, _ = pipe.execute()
                return value.decode() if value else None
    """

    def store(self, state: str, code_verifier: str) -> None:
        """Store code_verifier for the given state.

        Args:
            state: Unique state parameter for this auth request
            code_verifier: The PKCE code_verifier to store
        """
        ...

    def retrieve(self, state: str) -> Optional[str]:
        """Retrieve and remove code_verifier for the given state.

        This operation MUST be atomic (retrieve + delete) to prevent
        replay attacks. Returns None if state not found or expired.

        Args:
            state: The state parameter from the callback

        Returns:
            The code_verifier if found, None otherwise
        """
        ...


class InMemoryPKCEStore:
    """Thread-safe in-memory PKCE store with TTL and size limits.

    This is the default implementation suitable for single-process deployments.
    For multi-process or distributed deployments, use a custom implementation
    with external storage (Redis, database, etc.).

    Args:
        ttl_seconds: Time-to-live for entries in seconds (default: 600)
        max_entries: Maximum number of entries before cleanup (default: 10000)
    """

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        # state -> (verifier, timestamp)
        self._store: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries

    def store(self, state: str, code_verifier: str) -> None:
        """Store code_verifier with timestamp for TTL tracking."""
        with self._lock:
            # Cleanup if at capacity
            if len(self._store) >= self._max_entries:
                self._cleanup_expired_unsafe()
                # If still at capacity after cleanup, remove oldest
                if len(self._store) >= self._max_entries:
                    self._remove_oldest_unsafe()

            self._store[state] = (code_verifier, time.time())

    def store_request_data(
        self,
        state: str,
        code_verifier: str,
        callback_uri: str,
        nonce: Optional[str] = None,
    ) -> None:
        """Store full PKCE request data.

        This extends the legacy verifier-only contract without breaking
        custom stores that still implement only store/retrieve.
        """
        self.store(
            state,
            self._serialize_request_data(code_verifier, callback_uri, nonce),
        )

    def retrieve(self, state: str) -> Optional[str]:
        """Retrieve and remove code_verifier, checking TTL."""
        with self._lock:
            entry = self._store.pop(state, None)
            if entry is None:
                return None

            code_verifier, timestamp = entry
            # Check if expired
            if time.time() - timestamp > self._ttl_seconds:
                logger.warning(
                    f"PKCE entry expired for state (TTL: {self._ttl_seconds}s)"
                )
                return None

            return code_verifier

    def retrieve_request_data(self, state: str) -> Optional[PKCERequestData]:
        """Retrieve full PKCE request data when available."""
        entry = self.retrieve(state)
        if entry is None:
            return None
        return self._deserialize_request_data(entry)

    def cleanup_expired(self) -> int:
        """Remove all expired entries. Returns count of removed entries."""
        with self._lock:
            return self._cleanup_expired_unsafe()

    def _cleanup_expired_unsafe(self) -> int:
        """Internal cleanup without lock (caller must hold lock)."""
        now = time.time()
        expired = [
            state
            for state, (_, ts) in self._store.items()
            if now - ts > self._ttl_seconds
        ]
        for state in expired:
            del self._store[state]
        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired PKCE entries")
        return len(expired)

    def _remove_oldest_unsafe(self) -> None:
        """Remove oldest entry (caller must hold lock)."""
        if not self._store:
            return
        oldest_state = min(self._store.keys(), key=lambda s: self._store[s][1])
        del self._store[oldest_state]
        logger.warning("PKCE store at capacity, removed oldest entry")

    @property
    def size(self) -> int:
        """Current number of entries in the store."""
        with self._lock:
            return len(self._store)

    @staticmethod
    def _serialize_request_data(
        code_verifier: str, callback_uri: str, nonce: Optional[str] = None
    ) -> str:
        return json.dumps(
            {
                "code_verifier": code_verifier,
                "callback_uri": callback_uri,
                "nonce": nonce,
            }
        )

    @staticmethod
    def _deserialize_request_data(entry: str) -> PKCERequestData:
        try:
            parsed = json.loads(entry)
            if isinstance(parsed, dict) and "code_verifier" in parsed:
                return PKCERequestData(
                    code_verifier=parsed.get("code_verifier", ""),
                    callback_uri=parsed.get("callback_uri", ""),
                    nonce=parsed.get("nonce"),
                )
        except json.JSONDecodeError:
            pass

        code_verifier, separator, callback_uri = entry.partition("\n")
        if not separator:
            return PKCERequestData(
                code_verifier=entry,
                callback_uri="",
                nonce=None,
            )
        return PKCERequestData(
            code_verifier=code_verifier,
            callback_uri=callback_uri,
            nonce=None,
        )
