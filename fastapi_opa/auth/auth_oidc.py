import hashlib
import logging
import secrets
import threading
from base64 import b64encode
from base64 import urlsafe_b64encode
from collections.abc import Mapping
from collections.abc import Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from dataclasses import field
from json.decoder import JSONDecodeError
from typing import Protocol
from typing import cast
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.parse import urlunparse

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import PyJWK
from jwt.exceptions import DecodeError
from jwt.exceptions import InvalidTokenError
from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.auth.exceptions import OIDCException
from fastapi_opa.auth.pkce_store import ExtendedPKCEStoreProtocol
from fastapi_opa.auth.pkce_store import InMemoryPKCEStore
from fastapi_opa.auth.pkce_store import PKCERequestData
from fastapi_opa.auth.pkce_store import PKCEStoreProtocol
from fastapi_opa.auth.pkce_store import deserialize_request_data
from fastapi_opa.auth.pkce_store import serialize_request_data
from fastapi_opa.models import AuthenticationResult

logger = logging.getLogger(__name__)

# Authlib is an optional dependency for OIDC/PKCE support
try:
    from authlib.common.security import generate_token
    from authlib.oauth2.rfc7636 import create_s256_code_challenge

    AUTHLIB_AVAILABLE = True
except ImportError:
    AUTHLIB_AVAILABLE = False

    def generate_token(length: int = 48) -> str:
        """Generate a URL-safe token without requiring Authlib."""
        token = ""  # nosec B105
        while len(token) < length:
            token += secrets.token_urlsafe(length)
        return token[:length]

    def create_s256_code_challenge(verifier: str) -> str:
        """Create an RFC 7636 S256 code challenge without requiring Authlib."""
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class ResponseLike(Protocol):
    status_code: int
    url: str

    def json(self) -> object: ...


# Context variable for per-request override of get_user_info setting
# This allows thread-safe, request-scoped control without modifying global config
skip_user_info_for_request: ContextVar[bool] = ContextVar(
    "skip_user_info_for_request",
    default=False,
)

# RFC 7636 Section 4.1: code_verifier length must be 43-128 characters
PKCE_CODE_VERIFIER_MIN_LENGTH = 43
PKCE_CODE_VERIFIER_MAX_LENGTH = 128
PKCE_CODE_VERIFIER_DEFAULT_LENGTH = 128


def _combine_uri_paths(base_path: str, request_path: str) -> str:
    normalized_request_path = (
        request_path if request_path.startswith("/") else f"/{request_path}"
    )
    normalized_base_path = base_path.rstrip("/")

    if not normalized_base_path:
        return normalized_request_path
    if normalized_request_path == normalized_base_path:
        return normalized_request_path
    if normalized_request_path.startswith(f"{normalized_base_path}/"):
        return normalized_request_path
    if normalized_request_path == "/":
        return f"{normalized_base_path}/"
    return f"{normalized_base_path}{normalized_request_path}"


@dataclass
class OIDCConfig:
    """
    Configuration for the OIDC flow with PKCE support.

    PARAMETERS
    ----------
    app_uri: str
        Unused
    client_id: str
        The OIDC client id of the service, to be passed with the
        redirect to the OIDC provider
    client_secret: str, default=None
        The OIDC client secret, must be passed with the access_token
        request from the middleware to the OIDC provider for confidential
        clients. It is optional for public clients.
    scope: str, default="openid email profile"
        Space separated list of scopes to request from the OIDC provider
    trust_x_headers: bool, default=False
        Whether to trust incoming `x-forwarded-` headers when constructing
        the redirect to pass to the OIDC provider.
        The constructed redirect may have to match with a matcher regex
        configured with the OIDC provider for the client-id.
        However with a wildcard client-id this may open pathways for
        malicious injection of headers as part of a cross-site attack,
        and so defaults to false.
    is_public_client: bool, default=False
        Boolean configuration for public clients, default is false for
        confidential clients.
    use_auth_header: bool, default=True
        Token request configuration for sending client_id and secret
        in body if False and not public.
    preserve_tokens: bool, default=False
        Boolean configuration to preserve the tokens id_token and
        access_token in the request for downstream inspection.
        WARNING: Setting this to True exposes raw tokens which could be
        leaked via logs, error messages, or stolen via XSS if cookie
        security flags are misconfigured. Only enable if you explicitly
        need access to raw tokens downstream.
    code_challenge_method: str, default="S256"
        Hashing method for the transformation
    response_type: str, default="code"
        Authorization code response type
    grant_type: str, default="authorization_code"
        Grant type for the OIDC flow
    code_verifier_length: int, default=128
        Length of the PKCE code_verifier in characters.
        Per RFC 7636, must be between 43 and 128 characters.
        Default is 128 for maximum entropy.
    """

    app_uri: str
    client_id: str
    client_secret: str | None = None
    scope: str = field(default="openid email profile")
    trust_x_headers: bool = field(default=False)

    # Client authentication options for the token request
    is_public_client: bool = field(default=False)
    use_auth_header: bool = field(default=True)
    preserve_tokens: bool = field(default=False)

    # PKCE specific fields - note: code_verifier/code_challenge are now
    # generated per-request in OIDCAuthentication for security
    code_challenge_method: str = field(default="S256")
    response_type: str = field(default="code")
    grant_type: str = field(default="authorization_code")
    code_verifier_length: int = field(
        default=PKCE_CODE_VERIFIER_DEFAULT_LENGTH,
    )

    # OIDC endpoints configuration
    well_known_endpoint: str = field(default="")
    authorization_endpoint: str = field(default="")
    issuer: str = field(default="")
    token_endpoint: str = field(default="")
    jwks_uri: str = field(default="")
    userinfo_endpoint: str = field(default="")
    get_user_info: bool = field(default=False)

    # PKCE store configuration
    # If None, uses InMemoryPKCEStore with default settings
    # For multi-process deployments, provide a custom store (e.g., Redis)
    pkce_store: PKCEStoreProtocol | None = field(default=None)

    def __post_init__(self) -> None:
        """Validate configuration."""
        parsed_app_uri = urlparse(self.app_uri)
        if (
            parsed_app_uri.scheme not in {"http", "https"}
            or not parsed_app_uri.netloc
            or parsed_app_uri.params
            or parsed_app_uri.query
            or parsed_app_uri.fragment
        ):
            raise OIDCException(
                "app_uri must be an absolute http(s) URL without params, "
                "query, or fragment",
            )
        if not self.is_public_client and not self.client_secret:
            raise OIDCException(
                "client_secret is required for confidential clients",
            )
        if not (
            PKCE_CODE_VERIFIER_MIN_LENGTH
            <= self.code_verifier_length
            <= PKCE_CODE_VERIFIER_MAX_LENGTH
        ):
            raise OIDCException(
                f"code_verifier_length must be between "
                f"{PKCE_CODE_VERIFIER_MIN_LENGTH} and "
                f"{PKCE_CODE_VERIFIER_MAX_LENGTH} per RFC 7636",
            )
        if self.preserve_tokens:
            logger.warning(
                "SECURITY WARNING: preserve_tokens=True exposes raw tokens "
                "(access_token, id_token) in AuthenticationResult. These tokens "
                "could be leaked via logs, error messages, or stolen via XSS "
                "attacks if cookie security flags are misconfigured. Only enable "
                "this option if you explicitly need access to raw tokens downstream.",
            )


class OIDCAuthentication(AuthInterface):
    def __init__(self, config: OIDCConfig) -> None:
        self.config = config
        self.issuer: str = ""
        self.authorization_endpoint: str = ""
        self.token_endpoint: str = ""
        self.jwks_uri: str = ""
        self.userinfo_endpoint: str = ""

        self._pkce_store: PKCEStoreProtocol = (
            config.pkce_store
            if config.pkce_store is not None
            else InMemoryPKCEStore()
        )
        self._fallback_callback_uris: dict[str, str] = {}
        self._fallback_callback_uris_lock = threading.Lock()
        self._nonce_by_state: dict[str, str] = {}
        self._nonce_by_state_lock = threading.Lock()

        if self.config.well_known_endpoint:
            self.set_from_well_known()
        elif (
            self.config.issuer
            and self.config.authorization_endpoint
            and self.config.token_endpoint
        ):
            self.issuer = self.config.issuer
            self.authorization_endpoint = self.config.authorization_endpoint
            self.token_endpoint = self.config.token_endpoint
            self.jwks_uri = self.config.jwks_uri
            self.userinfo_endpoint = self.config.userinfo_endpoint
            if self.config.get_user_info and not self.userinfo_endpoint:
                raise OIDCException("Userinfo endpoint not provided")
        else:
            raise OIDCException("Endpoints not provided")

    def _generate_pkce_pair(self) -> tuple[str, str]:
        """Generate a new PKCE code_verifier and code_challenge pair.

        Per RFC 7636, the code_verifier is a high-entropy cryptographic
        random string with 43-128 characters. The length is configurable
        via OIDCConfig.code_verifier_length.
        """
        code_verifier = generate_token(self.config.code_verifier_length)
        code_challenge = create_s256_code_challenge(code_verifier)
        return code_verifier, code_challenge

    def _store_pkce_verifier(self, state: str, code_verifier: str) -> None:
        """Store code_verifier for later retrieval during token exchange."""
        self._pkce_store.store(state, code_verifier)

    def _retrieve_pkce_verifier(self, state: str) -> str | None:
        """Retrieve and remove code_verifier for the given state."""
        return self._pkce_store.retrieve(state)

    def _store_pkce_request_data(
        self,
        state: str,
        code_verifier: str,
        callback_uri: str,
        nonce: str | None = None,
    ) -> None:
        """Store the verifier together with the exact redirect URI."""
        if isinstance(self._pkce_store, ExtendedPKCEStoreProtocol):
            self._pkce_store.store_request_data(
                state,
                code_verifier,
                callback_uri,
                nonce,
            )
            return

        self._pkce_store.store(
            state,
            serialize_request_data(code_verifier, callback_uri, nonce),
        )

    def _store_nonce(self, state: str, nonce: str) -> None:
        with self._nonce_by_state_lock:
            self._nonce_by_state[state] = nonce

    def _retrieve_nonce(self, state: str) -> str | None:
        with self._nonce_by_state_lock:
            return self._nonce_by_state.pop(state, None)

    def _retrieve_pkce_request_data(
        self,
        state: str,
    ) -> PKCERequestData | None:
        """Retrieve the verifier and original callback URI for a state."""
        if isinstance(self._pkce_store, ExtendedPKCEStoreProtocol):
            return self._pkce_store.retrieve_request_data(state)

        entry = self._pkce_store.retrieve(state)
        if entry is None:
            return None

        request_data = deserialize_request_data(entry)
        with self._fallback_callback_uris_lock:
            callback_uri = self._fallback_callback_uris.pop(state, "")
        nonce = self._retrieve_nonce(state)
        if request_data.callback_uri or request_data.nonce is not None:
            return request_data

        return PKCERequestData(
            code_verifier=request_data.code_verifier,
            callback_uri=callback_uri,
            nonce=nonce,
        )

    def _build_callback_uri(
        self,
        request: Request,
        query_params: dict[str, str] | None = None,
    ) -> str:
        """Build a callback URI pinned to the configured application origin."""
        parsed_app_uri = urlparse(self.config.app_uri)
        uri_parts = [
            parsed_app_uri.scheme,
            parsed_app_uri.netloc,
            _combine_uri_paths(parsed_app_uri.path, request.url.path),
            "",
            urlencode(query_params) if query_params else "",
            "",
        ]
        return urlunparse(uri_parts)

    def set_from_well_known(self) -> None:
        endpoints = self.to_dict_or_raise(
            requests.get(self.config.well_known_endpoint, timeout=5),
        )

        issuer = endpoints.get("issuer")
        authorization_endpoint = endpoints.get("authorization_endpoint")
        token_endpoint = endpoints.get("token_endpoint")
        jwks_uri = endpoints.get("jwks_uri")
        userinfo_endpoint = endpoints.get("userinfo_endpoint")

        if not isinstance(issuer, str):
            raise OIDCException("OIDC discovery response missing issuer")
        if not isinstance(authorization_endpoint, str):
            raise OIDCException(
                "OIDC discovery response missing authorization_endpoint",
            )
        if not isinstance(token_endpoint, str):
            raise OIDCException(
                "OIDC discovery response missing token_endpoint",
            )

        self.issuer = issuer
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.jwks_uri = jwks_uri if isinstance(jwks_uri, str) else ""
        self.userinfo_endpoint = (
            userinfo_endpoint if isinstance(userinfo_endpoint, str) else ""
        )

        if self.config.get_user_info and not self.userinfo_endpoint:
            raise OIDCException("Userinfo endpoint not provided")

    def get_auth_token(
        self,
        code: str,
        callback_uri: str,
        code_verifier: str,
    ) -> dict[str, object]:
        """
        Handle client authentication for public/confidential clients
        to get the token.

        Args:
            code: The authorization code from the IdP callback
            callback_uri: The redirect URI used in the authorization request
            code_verifier: The PKCE code_verifier for this specific auth flow
        """
        data = {
            "grant_type": self.config.grant_type,
            "code": code,
            "redirect_uri": callback_uri,
            "code_verifier": code_verifier,
            "client_id": self.config.client_id,
        }

        headers = {}
        if not self.config.is_public_client:
            if self.config.use_auth_header:
                authentication_string = "Basic " + b64encode(
                    f"{self.config.client_id}:{self.config.client_secret}".encode(),
                ).decode("utf-8")
                headers["Authorization"] = authentication_string
                data.pop("client_id")
            else:
                data["client_secret"] = self.config.client_secret or ""

        response = requests.post(
            self.token_endpoint,
            data=data,
            headers=headers,
            timeout=5,
        )
        return self.to_dict_or_raise(response)

    @staticmethod
    def extract_raw_tokens(
        auth_token: Mapping[str, object] | None,
    ) -> dict[str, str] | None:
        if auth_token is None:
            return None

        raw_tokens = {
            key: value
            for key, value in auth_token.items()
            if isinstance(value, str)
        }
        return raw_tokens or None

    async def authenticate(
        self,
        request: Request,
        accepted_methods: list[str] | None = None,
    ) -> RedirectResponse | AuthenticationResult:
        if accepted_methods is None:
            accepted_methods = ["id_token", "access_token"]

        code = request.query_params.get("code")
        state = request.query_params.get("state")
        bearer = request.headers.get("Authorization")
        auth_token: dict[str, object] | None = None

        # Redirect to identity provider if no authorization code or bearer
        # token is present.
        if not code and not bearer:
            redirect_callback = self._build_callback_uri(
                request,
                dict(request.query_params.items()),
            )
            return RedirectResponse(
                url=self.get_auth_redirect_uri(redirect_callback),
                status_code=303,
            )

        try:
            if not bearer:
                if "id_token" not in accepted_methods:
                    raise OIDCException("Using id token is not accepted")

                request_data = (
                    self._retrieve_pkce_request_data(state) if state else None
                )
                if not request_data or not request_data.code_verifier:
                    raise OIDCException(
                        "Invalid or missing state parameter for PKCE",
                    )

                expected_nonce = (
                    request_data.nonce
                    if request_data and request_data.nonce is not None
                    else self._retrieve_nonce(state)
                    if state
                    else None
                )

                token_callback_uri = (
                    request_data.callback_uri
                    or self._build_callback_uri(
                        request,
                        {
                            key: value
                            for key, value in request.query_params.items()
                            if key not in {"code", "state"}
                        },
                    )
                )

                if code is None:
                    raise OIDCException("Missing authorization code")

                auth_token = self.get_auth_token(
                    code,
                    token_callback_uri,
                    request_data.code_verifier,
                )

                id_token = auth_token.get("id_token")
                if not isinstance(id_token, str):
                    raise OIDCException("Missing id_token in auth response")

                try:
                    alg = jwt.get_unverified_header(id_token).get("alg")
                except DecodeError as e:
                    raise OIDCException(
                        "Error getting unverified header in jwt.",
                    ) from e

                if not isinstance(alg, str):
                    raise OIDCException("Missing alg in token header")

                validated_token = self.obtain_validated_token(alg, id_token)

                if expected_nonce is not None:
                    token_nonce = validated_token.get("nonce")
                    if token_nonce != expected_nonce:
                        raise OIDCException("OIDC nonce mismatch")

                should_skip_user_info = (
                    not self.config.get_user_info
                    or skip_user_info_for_request.get(False)
                )
                if should_skip_user_info:
                    return AuthenticationResult(
                        success=True,
                        validated_token=validated_token,
                        raw_tokens=self.extract_raw_tokens(auth_token)
                        if self.config.preserve_tokens
                        else None,
                    )

                access_token = auth_token.get("access_token")
                if not isinstance(access_token, str):
                    raise OIDCException(
                        "Missing access_token in auth response",
                    )

                user_info = self.get_user_info(access_token)
                self.validate_sub_matching(validated_token, user_info)

                return AuthenticationResult(
                    success=True,
                    user_info=user_info,
                    validated_token=validated_token,
                    raw_tokens=self.extract_raw_tokens(auth_token)
                    if self.config.preserve_tokens
                    else None,
                )

            if "access_token" not in accepted_methods:
                raise OIDCException("Using access token is not accepted")

            access_token = bearer.replace("Bearer ", "")
            user_info = self.get_user_info(access_token)

            return AuthenticationResult(
                success=True,
                user_info=user_info,
                raw_tokens={"access_token": access_token}
                if self.config.preserve_tokens
                else None,
            )

        except OIDCException as e:
            return AuthenticationResult(
                success=False,
                error=str(e),
                raw_tokens=self.extract_raw_tokens(auth_token)
                if self.config.preserve_tokens
                else None,
            )
        except requests.RequestException:
            logger.exception("Network error during OIDC authentication")
            return AuthenticationResult(
                success=False,
                error="Network error during authentication",
                raw_tokens=self.extract_raw_tokens(auth_token)
                if self.config.preserve_tokens
                else None,
            )
        except (DecodeError, InvalidTokenError):
            logger.exception("JWT error during OIDC authentication")
            return AuthenticationResult(
                success=False,
                error="Token validation failed",
                raw_tokens=self.extract_raw_tokens(auth_token)
                if self.config.preserve_tokens
                else None,
            )
        except Exception:
            logger.exception("Unexpected error during OIDC authentication")
            return AuthenticationResult(
                success=False,
                error="Authentication failed due to unexpected error",
                raw_tokens=self.extract_raw_tokens(auth_token)
                if self.config.preserve_tokens
                else None,
            )

    def get_auth_redirect_uri(
        self,
        callback_uri: str,
        code_challenge: str | None = None,
        state: str | None = None,
        code_verifier: str | None = None,
    ) -> str:
        """
        Build the authorization redirect URI with PKCE parameters.

        Args:
            callback_uri: The callback URI after authentication
            code_challenge: The PKCE code_challenge generated per request
            state: The state parameter to correlate request/response
            code_verifier: The PKCE code_verifier for explicit PKCE flows
        """
        nonce = generate_token(32)

        should_store_request_data = True
        if code_verifier is None:
            if code_challenge is None:
                code_verifier, code_challenge = self._generate_pkce_pair()
            else:
                should_store_request_data = False
        elif code_challenge is None:
            code_challenge = create_s256_code_challenge(code_verifier)

        if state is None:
            state = generate_token(32)

        if should_store_request_data and code_verifier is not None:
            self._store_pkce_request_data(
                state,
                code_verifier,
                callback_uri,
                nonce,
            )
        else:
            self._store_nonce(state, nonce)

        params = {
            "response_type": self.config.response_type,
            "scope": self.config.scope,
            "client_id": self.config.client_id,
            "redirect_uri": callback_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": self.config.code_challenge_method,
            "nonce": nonce,
        }
        if state:
            params["state"] = state

        query = urlencode(params)
        return f"{self.authorization_endpoint}?{query}"

    def obtain_validated_token(
        self,
        alg: str,
        id_token: str,
    ) -> dict[str, object]:
        if alg == "HS256":
            if self.config.client_secret is None:
                raise OIDCException(
                    "client_secret is required for HS256 tokens",
                )
            try:
                return jwt.decode(
                    id_token,
                    self.config.client_secret,
                    algorithms=["HS256"],
                    audience=self.config.client_id,
                    issuer=self.issuer,
                )
            except InvalidTokenError as e:
                raise OIDCException(
                    "An error occurred while decoding the id_token",
                ) from e

        if alg == "RS256":
            if not self.jwks_uri:
                logger.error("JWKS endpoint not provided but RS256 used.")
                raise OIDCException(
                    "JWKS endpoint not provided but RS256 used.",
                )

            response = requests.get(self.jwks_uri, timeout=5)
            web_key_sets = self.to_dict_or_raise(response)
            keys = web_key_sets.get("keys")
            if not isinstance(keys, list):
                raise OIDCException("JWKS response missing 'keys' field")
            if not all(isinstance(key, dict) for key in keys):
                raise OIDCException("JWKS response contains invalid keys")

            jwks = cast(Sequence[Mapping[str, object]], keys)
            public_key = self.extract_token_key(jwks, id_token)

            try:
                return jwt.decode(
                    id_token,
                    key=public_key,
                    algorithms=["RS256"],
                    audience=self.config.client_id,
                    issuer=self.issuer,
                )
            except InvalidTokenError as e:
                raise OIDCException(
                    "An error occurred while decoding the id_token",
                ) from e

        raise OIDCException("Unsupported jwt algorithm found.")

    @staticmethod
    def extract_token_key(
        jwks: Sequence[Mapping[str, object]],
        id_token: str,
    ) -> RSAPublicKey:
        public_keys: dict[str, RSAPublicKey] = {}

        for jwk in jwks:
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not kid:
                continue

            raw_key = PyJWK.from_dict(dict(jwk)).key
            if not isinstance(raw_key, RSAPublicKey):
                raise OIDCException(
                    f"JWKS entry for kid '{kid}' is not an RSA public key",
                )

            public_keys[kid] = raw_key

        try:
            kid = jwt.get_unverified_header(id_token).get("kid")
        except DecodeError as e:
            raise OIDCException("kid could not be extracted.") from e

        if not isinstance(kid, str):
            raise OIDCException("kid not found in token header")

        key = public_keys.get(kid)
        if key is None:
            raise OIDCException(f"Public key not found for kid: {kid}")

        return key

    def get_user_info(self, access_token: str) -> dict[str, object]:
        bearer = f"Bearer {access_token}"
        headers = {"Authorization": bearer}
        response = requests.get(
            self.userinfo_endpoint,
            headers=headers,
            timeout=5,
        )
        return self.to_dict_or_raise(response)

    @staticmethod
    def validate_sub_matching(
        token: Mapping[str, object],
        user_info: Mapping[str, object],
    ) -> None:
        token_sub = token.get("sub") if token else None
        if token_sub != user_info.get("sub") or not token_sub:
            logger.warning("Subject mismatch error.")
            raise OIDCException("Subject mismatch error.")

    @staticmethod
    def to_dict_or_raise(response: ResponseLike) -> dict[str, object]:
        if response.status_code != 200:
            logger.error("Returned with status %s.", response.status_code)
            raise OIDCException(
                f"Status code {response.status_code} for {response.url}.",
            )
        try:
            data = response.json()
        except JSONDecodeError as e:
            raise OIDCException(
                "Was not able to retrieve data from the response.",
            ) from e

        if not isinstance(data, dict):
            raise OIDCException(
                "Was not able to retrieve a JSON object from the response.",
            )

        return cast(dict[str, object], data)
