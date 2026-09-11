from json import JSONDecodeError
from unittest.mock import Mock

from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_opa.auth import OIDCConfig
from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.auth.exceptions import AuthenticationException
from fastapi_opa.models import AuthenticationResult
from fastapi_opa.opa.opa_config import Injectable


def mock_response(status_code, json_data=None, **kwargs):
    json_ = Mock()
    json_.return_value = json_data
    return Mock(status_code=status_code, json=json_, **kwargs)


# ***************************
# OPA Utils
# ***************************
class AuthenticationDummy(AuthInterface):
    def __init__(self, accept_all=True):
        self.accept_all = accept_all

    async def authenticate(
        self, request: Request, accepted_methods=None
    ) -> RedirectResponse | AuthenticationResult:
        if not self.accept_all and "Authorization" not in request.headers:
            raise AuthenticationException("Unauthorized")
        return AuthenticationResult(
            success=True,
            user_info={
                "stuff": "some info",
                "username": "John Doe",
                "role": "Administrator",
            },
        )


class OPAInjectableExample(Injectable):
    async def extract(self, request: Request) -> list:
        return [await self.get_payload(request)]

    @staticmethod
    async def get_payload(request):
        try:
            return await request.json()
        except JSONDecodeError:
            return None


# ***************************
# OIDC Utils
# ***************************
def oidc_well_known_response():
    return mock_response(
        200,
        json_data={
            "issuer": "http://keycloak.busykoala.ch/auth/realms/example-realm",
            "authorization_endpoint": "http://keycloak.busykoala.ch/auth/realms/example-realm/protocol/openid-connect/auth",
            "token_endpoint": "http://keycloak.busykoala.ch/auth/realms/example-realm/protocol/openid-connect/token",
            "userinfo_endpoint": "http://keycloak.busykoala.ch/auth/realms/example-realm/protocol/openid-connect/userinfo",
            "jwks_uri": "http://keycloak.busykoala.ch/auth/realms/example-realm/protocol/openid-connect/certs",
        },
    )


def oidc_config():
    return OIDCConfig(
        well_known_endpoint="http://keycloak.busykoala.ch/auth/realms/example-realm/.well-known/openid-configuration",
        app_uri="http://fastapi-app.busykoala.ch",
        client_id="example-client",
        client_secret="secret",
    )  # nosec


# ***************************
# OPA client
# ***************************
class FakeOPAClient:
    """An in-memory ``OPAClient``: records every decision request, answers as told.

    Injected through ``OPAConfig(opa_client=...)`` so the tests never patch
    the middleware's transport.
    """

    def __init__(
        self,
        status_code: int = 200,
        payload: object | None = None,
        error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self.payload: object = (
            {"result": {"allow": True}} if payload is None else payload
        )
        self.error = error
        self.calls: list[tuple[str, object]] = []

    async def post(self, url: str, *, json: object) -> Mock:
        self.calls.append((url, json))
        if self.error is not None:
            raise self.error
        return mock_response(self.status_code, json_data=self.payload)
