from typing import Dict
from typing import Union

from mock import Mock
from starlette.responses import RedirectResponse

from fastapi_opa.auth import OIDCConfig
from fastapi_opa.auth.auth_interface import AuthInterface


def mock_response(status_code, json_data=None):
    json_ = Mock()
    json_.return_value = json_data
    return Mock(status_code=status_code, json=json_)


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
        host="http://keycloak.busykoala.ch",
        realm="example-realm",
        app_uri="http://fastapi-app.busykoala.ch",
        client_id="example-client",
        client_secret="secret",
    )  # nosec
