from mock import Mock

from fastapi_opa.auth import OIDCConfig


def mock_response(status_code, json_data=None):
    mock_resp = Mock()
    mock_resp.status_code = status_code
    if json_data:
        def _json():
            return json_data

        mock_resp.json = _json
    return mock_resp


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
        }
    )


def oidc_config():
    return OIDCConfig(
        host="http://keycloak.busykoala.ch",
        realm="example-realm",
        app_uri="http://fastapi-app.busykoala.ch",
        client_id="example-client",
        client_secret="secret",
    )  # nosec


# def oidc_http_connection():
#     mock_resp = Mock()
#     mock_resp.url.scheme = "http"
#     mock_resp.url.netloc = "fastapi-app.busykoala.ch"
#     mock_resp.url.path = "/"
#
#     def _get(*args, **kwargs):
#         return "oidc-user-code"
#
#     mock_resp.query_params.get = _get
#     return mock_resp
