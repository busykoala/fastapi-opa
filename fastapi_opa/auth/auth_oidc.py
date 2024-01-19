import json
import logging
from base64 import b64encode
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
from jwt.exceptions import DecodeError
from jwt.exceptions import InvalidTokenError
from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.auth.exceptions import OIDCException

logger = logging.getLogger(__name__)


@dataclass
class OIDCConfig:
    """
    Configuration for the OIDC flow.

        PARAMETERS
        ----------
        app_uri: str
            Unused
        client_id: str
            The OIDC client id of the service, to be passed with the
            redirect to the OIDC provider
        client_secret: str
            The OIDC client secret, to be passed with the access_token
            request from the middleware to the OIDC provider
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
    """

    app_uri: str
    client_id: str
    client_secret: str
    scope: str = field(default="openid email profile")
    trust_x_headers: bool = field(default=False)

    # provide either well_known or all the other values
    well_known_endpoint: str = field(default="")
    authorization_endpoint: str = field(default="")
    issuer: str = field(default="")
    token_endpoint: str = field(default="")
    jwks_uri: str = field(default="")

    userinfo_endpoint: str = field(default="")
    get_user_info: bool = field(default=False)


class OIDCAuthentication(AuthInterface):
    def __init__(self, config: OIDCConfig) -> None:
        self.config = config
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

    async def authenticate(
        self,
        request: Request,
        accepted_methods: Optional[List[str]] = ["id_token", "access_token"],
    ) -> Union[RedirectResponse, Dict]:
        callback_uri = urlunparse(
            [
                request.headers.get("x-forwarded-proto", request.url.scheme)
                if self.config.trust_x_headers
                else request.url.scheme,
                request.headers.get("x-forwarded-host", request.url.netloc)
                if self.config.trust_x_headers
                else request.url.netloc,
                request.url.path,
                "",
                "",
                "",
            ]
        )
        code = request.query_params.get("code")
        bearer = request.headers.get("Authorization")

        # redirect to id provider if code query-value is not present
        if not code and not bearer:
            return RedirectResponse(
                url=self.get_auth_redirect_uri(callback_uri), status_code=303
            )

        if not bearer:
            if "id_token" not in accepted_methods:
                raise OIDCException("Using id token is not accepted")
            auth_token = self.get_auth_token(code, callback_uri)
            id_token = auth_token.get("id_token")
            try:
                alg = jwt.get_unverified_header(id_token).get("alg")
            except DecodeError:
                logging.warning("Error getting unverified header in jwt.")
                raise OIDCException
            validated_token = self.obtain_validated_token(alg, id_token)
            if not self.config.get_user_info:
                return validated_token
            user_info = self.get_user_info(auth_token.get("access_token"))
            self.validate_sub_matching(validated_token, user_info)
        else:
            if "access_token" not in accepted_methods:
                raise OIDCException("Using access token is not accepted")
            access_token = bearer.replace("Bearer ", "")
            user_info = self.get_user_info(access_token)
        return user_info

    def get_auth_redirect_uri(self, callback_uri):
        return "{}?response_type=code&scope={}&client_id={}&redirect_uri={}".format(  # noqa
            self.authorization_endpoint,
            self.config.scope,
            self.config.client_id,
            quote(callback_uri),
        )

    def get_auth_token(self, code: str, callback_uri: str) -> Dict:
        authentication_string = "Basic " + b64encode(
            f"{self.config.client_id}:{self.config.client_secret}".encode(
                "utf-8"
            )
        ).decode("utf-8")
        headers = {"Authorization": authentication_string}
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_uri,
        }
        response = requests.post(
            self.token_endpoint, data=data, headers=headers, timeout=5
        )
        return self.to_dict_or_raise(response)

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
