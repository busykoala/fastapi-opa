import json
import logging
from base64 import b64encode
from contextvars import ContextVar
from dataclasses import dataclass
from dataclasses import field
from json.decoder import JSONDecodeError
from typing import Dict
from typing import List
from typing import Optional
from typing import Union
from urllib.parse import quote
from urllib.parse import urlunparse

import jwt
import requests
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from jwt.exceptions import DecodeError
from jwt.exceptions import InvalidTokenError
from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.auth.exceptions import OIDCException
from fastapi_opa.models import AuthenticationResult

logger = logging.getLogger(__name__)

# Context variable for per-request override of get_user_info setting
# This allows thread-safe, request-scoped control without modifying global config
skip_user_info_for_request: ContextVar[bool] = ContextVar(
    "skip_user_info_for_request", default=False
)


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
            Space seperated list of scopes to request from the OIDC provider
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
        preserve_tokens: bool, default=True
            Boolean configuration to preserve the tokens id_token and
            access_token in the request for downstream inspection.
        code_challenge_method: str, default="S256"
            Hashing method for the trasformation
        response_type: str, default="code"
            Authorization code response type
        grant_type: str, default="authorization_code"
            Grant type for the OIDC flow
    """

    app_uri: str
    client_id: str
    client_secret: Optional[str] = None
    scope: str = field(default="openid email profile")
    trust_x_headers: bool = field(default=False)

    # Client authentication options for the token request
    is_public_client: bool = field(default=False)
    use_auth_header: bool = field(default=True)
    preserve_tokens: bool = field(default=True)

    # PKCE specific fields - note: code_verifier/code_challenge are now
    # generated per-request in OIDCAuthentication for security
    code_challenge_method: str = field(default="S256")
    response_type: str = field(default="code")
    grant_type: str = field(default="authorization_code")

    # OIDC endpoints configuration
    well_known_endpoint: str = field(default="")
    authorization_endpoint: str = field(default="")
    issuer: str = field(default="")
    token_endpoint: str = field(default="")
    jwks_uri: str = field(default="")
    userinfo_endpoint: str = field(default="")
    get_user_info: bool = field(default=False)

    def __post_init__(self):
        """Validate configuration."""
        if not self.is_public_client and not self.client_secret:
            raise OIDCException(
                "client_secret is required for confidential clients"
            )


class OIDCAuthentication(AuthInterface):
    def __init__(self, config: OIDCConfig) -> None:
        self.config = config
        # PKCE store: maps state -> code_verifier for secure per-request PKCE
        self._pkce_store: Dict[str, str] = {}
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

    def _generate_pkce_pair(self) -> tuple:
        """Generate a new PKCE code_verifier and code_challenge pair."""
        code_verifier = generate_token(128)
        code_challenge = create_s256_code_challenge(code_verifier)
        return code_verifier, code_challenge

    def _store_pkce_verifier(self, state: str, code_verifier: str) -> None:
        """Store code_verifier for later retrieval during token exchange."""
        self._pkce_store[state] = code_verifier

    def _retrieve_pkce_verifier(self, state: str) -> Optional[str]:
        """Retrieve and remove code_verifier for the given state."""
        return self._pkce_store.pop(state, None)

    def set_from_well_known(self):
        endpoints = self.to_dict_or_raise(
            requests.get(self.config.well_known_endpoint, timeout=5),
        )
        self.issuer = endpoints.get("issuer")
        self.authorization_endpoint = endpoints.get("authorization_endpoint")
        self.token_endpoint = endpoints.get("token_endpoint")
        self.jwks_uri = endpoints.get("jwks_uri")
        self.userinfo_endpoint = endpoints.get("userinfo_endpoint")
        if self.config.get_user_info and not self.userinfo_endpoint:
            raise OIDCException("Userinfo endpoint not provided")

    def get_auth_token(
        self, code: str, callback_uri: str, code_verifier: str
    ) -> Dict:
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
                    f"{self.config.client_id}:{self.config.client_secret}".encode(
                        "utf-8"
                    )
                ).decode("utf-8")
                headers["Authorization"] = authentication_string
                data.pop("client_id")
            else:
                data["client_secret"] = self.config.client_secret

        response = requests.post(
            self.token_endpoint, data=data, headers=headers, timeout=5
        )
        return self.to_dict_or_raise(response)

    async def authenticate(
        self,
        request: Request,
        accepted_methods: Optional[List[str]] = None,
    ) -> Union[RedirectResponse, AuthenticationResult]:
        if accepted_methods is None:
            accepted_methods = ["id_token", "access_token"]

        callback_uri = urlunparse(
            [
                (
                    request.headers.get("x-forwarded-proto", request.url.scheme)
                    if self.config.trust_x_headers
                    else request.url.scheme
                ),
                (
                    request.headers.get("x-forwarded-host", request.url.netloc)
                    if self.config.trust_x_headers
                    else request.url.netloc
                ),
                request.url.path,
                "",
                "",
                "",
            ]
        )
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        bearer = request.headers.get("Authorization")

        # redirect to id provider if code query-value is not present
        if not code and not bearer:
            # Generate fresh PKCE pair for this authorization request
            code_verifier, code_challenge = self._generate_pkce_pair()

            # Generate unique state for this request
            pkce_state = generate_token(32)

            # Store code_verifier for later retrieval
            self._store_pkce_verifier(pkce_state, code_verifier)

            # Build query params, preserving existing ones
            query_params = "&".join(
                f"{k}={v}" for k, v in request.query_params.items()
            )
            return RedirectResponse(
                url=self.get_auth_redirect_uri(
                    f"{callback_uri}?{query_params}",
                    code_challenge=code_challenge,
                    state=pkce_state,
                ),
                status_code=303,
            )

        try:
            auth_token = None
            if not bearer:
                if "id_token" not in accepted_methods:
                    raise OIDCException("Using id token is not accepted")

                # Retrieve code_verifier for this state
                code_verifier = (
                    self._retrieve_pkce_verifier(state) if state else None
                )
                if not code_verifier:
                    raise OIDCException(
                        "Invalid or missing state parameter for PKCE"
                    )

                auth_token = self.get_auth_token(
                    code, callback_uri, code_verifier
                )
                id_token = auth_token.get("id_token")

                try:
                    alg = jwt.get_unverified_header(id_token).get("alg")
                except DecodeError:
                    logging.warning("Error getting unverified header in jwt.")
                    raise OIDCException

                validated_token = self.obtain_validated_token(alg, id_token)

                # Check both global config and per-request context variable
                # The context variable allows thread-safe per-request override
                should_skip_user_info = (
                    not self.config.get_user_info
                    or skip_user_info_for_request.get(False)
                )
                if should_skip_user_info:
                    return AuthenticationResult(
                        success=True,
                        validated_token=validated_token,
                        raw_tokens=auth_token
                        if self.config.preserve_tokens
                        else None,
                    )

                user_info = self.get_user_info(auth_token.get("access_token"))
                self.validate_sub_matching(validated_token, user_info)

                return AuthenticationResult(
                    success=True,
                    user_info=user_info,
                    validated_token=validated_token,
                    raw_tokens=auth_token
                    if self.config.preserve_tokens
                    else None,
                )

            else:
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
                raw_tokens=auth_token if self.config.preserve_tokens else None,
            )

    def get_auth_redirect_uri(
        self,
        callback_uri: str,
        code_challenge: Optional[str] = None,
        state: Optional[str] = None,
    ) -> str:
        """
        Build the authorization redirect URI with PKCE parameters.

        Args:
            callback_uri: The callback URI after authentication
            code_challenge: The PKCE code_challenge (generated per-request)
            state: The state parameter to correlate request/response
        """
        if code_challenge is None:
            # Fallback: generate new PKCE pair (for backwards compatibility)
            _, code_challenge = self._generate_pkce_pair()

        params = {
            "response_type": self.config.response_type,
            "scope": self.config.scope,
            "client_id": self.config.client_id,
            "redirect_uri": quote(callback_uri),
            "code_challenge": code_challenge,
            "code_challenge_method": self.config.code_challenge_method,
        }
        if state:
            params["state"] = state
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self.authorization_endpoint}?{query}"

    def obtain_validated_token(self, alg: str, id_token: str) -> Dict:
        if alg == "HS256":
            try:
                return jwt.decode(
                    id_token,
                    self.config.client_secret,
                    algorithms=["HS256"],
                    audience=self.config.client_id,
                )
            except InvalidTokenError:
                logger.error("An error occurred while decoding the id_token")
                raise OIDCException(
                    "An error occurred while decoding the id_token"
                )
        elif alg == "RS256":
            if not self.jwks_uri:
                logger.error("JWKS endpoint not provided but RS256 used.")
                raise OIDCException(
                    "JWKS endpoint not provided but RS256 used."
                )
            response = requests.get(self.jwks_uri, timeout=5)
            web_key_sets = self.to_dict_or_raise(response)
            keys = web_key_sets.get("keys")
            public_key = self.extract_token_key(keys, id_token)
            try:
                return jwt.decode(
                    id_token,
                    key=public_key,
                    algorithms=["RS256"],
                    audience=self.config.client_id,
                )
            except InvalidTokenError:
                logger.error("An error occurred while decoding the id_token")
                raise OIDCException(
                    "An error occurred while decoding the id_token"
                )
        else:
            raise OIDCException("Unsupported jwt algorithm found.")

    @staticmethod
    def extract_token_key(jwks: List[Dict], id_token: str) -> str:
        public_keys = {}
        for jwk in jwks:
            kid = jwk.get("kid")
            if not kid:
                continue
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        try:
            kid = jwt.get_unverified_header(id_token).get("kid")
        except DecodeError:
            logger.warning("kid could not be extracted.")
            raise OIDCException("kid could not be extracted.")
        return public_keys.get(kid)

    def get_user_info(self, access_token: str) -> Dict:
        bearer = "Bearer {}".format(access_token)
        headers = {"Authorization": bearer}
        response = requests.get(
            self.userinfo_endpoint, headers=headers, timeout=5
        )
        return self.to_dict_or_raise(response)

    @staticmethod
    def validate_sub_matching(token: Dict, user_info: Dict) -> None:
        token_sub = ""  # nosec
        if token:
            token_sub = token.get("sub")
        if token_sub != user_info.get("sub") or not token_sub:
            logger.warning("Subject mismatch error.")
            raise OIDCException("Subject mismatch error.")

    @staticmethod
    def to_dict_or_raise(response: requests.Response) -> Dict:
        if response.status_code != 200:
            logger.error(f"Returned with status {response.status_code}.")
            raise OIDCException(
                f"Status code {response.status_code} for {response.url}."
            )
        try:
            return response.json()
        except JSONDecodeError:
            logger.error("Unable to decode json.")
            raise OIDCException(
                "Was not able to retrieve data from the response."
            )
