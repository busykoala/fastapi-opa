from json import JSONDecodeError
from typing import Dict
from typing import List
from typing import Union

from mock import Mock
from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_opa.auth import OIDCConfig
from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.opa.opa_config import Injectable


def mock_response(status_code, json_data=None, **kwargs):
    json_ = Mock()
    json_.return_value = json_data
    return Mock(status_code=status_code, json=json_, **kwargs)


# ***************************
# OPA Utils
# ***************************
class AuthenticationDummy(AuthInterface):
    def authenticate(
        self, *args: object, **kwargs: object
    ) -> Union[RedirectResponse, Dict]:
        return {
            "stuff": "some info",
            "username": "John Doe",
            "role": "Administrator",
        }


class OPAInjectableExample(Injectable):
    async def extract(self, request: Request) -> List:
        return [await self.get_payload(request)]

    @staticmethod
    async def get_payload(request):
        try:
            return await request.json()
        except JSONDecodeError:
            return


# ***************************
# OIDC Utils
# ***************************
def oidc_well_known_response():
    return mock_response(
        200,
        json_data={
            "issuer": "http://keycloak.busykoala.ch/auth/realms/example-realm",
            "authorization_endpoint": "http://keycloak.busykoala.ch/auth/realms/example-realm/protocol/openid-connect/auth",  # noqa
            "token_endpoint": "http://keycloak.busykoala.ch/auth/realms/example-realm/protocol/openid-connect/token",  # noqa
            "userinfo_endpoint": "http://keycloak.busykoala.ch/auth/realms/example-realm/protocol/openid-connect/userinfo",  # noqa
            "jwks_uri": "http://keycloak.busykoala.ch/auth/realms/example-realm/protocol/openid-connect/certs",  # noqa
        },
    )


def oidc_config():
    return OIDCConfig(
        well_known_endpoint="http://keycloak.busykoala.ch/auth/realms/example-realm/.well-known/openid-configuration",  # noqa
        app_uri="http://fastapi-app.busykoala.ch",
        client_id="example-client",
        client_secret="secret",
    )  # nosec
