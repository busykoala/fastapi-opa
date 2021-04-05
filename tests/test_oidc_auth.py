from fastapi_opa.auth.auth_oidc import OIDCAuthentication
from tests.utils import oidc_config
from tests.utils import mock_response
from tests.utils import oidc_well_known_response


def test_auth_redirect_uri(mocker):
    callback_uri = "http://fastapi-app.busykoala.ch/test/path"
    with mocker.patch('fastapi_opa.auth.auth_oidc.requests.get', return_value=oidc_well_known_response()):
        config = oidc_config()
        oidc = OIDCAuthentication(config)
    response = oidc.get_auth_redirect_uri(callback_uri=callback_uri)
    expected_url = 'http://keycloak.busykoala.ch/auth/realms/example-realm/protocol/openid-connect/auth?response_type=code&scope=openid email profile&client_id=example-client&redirect_uri=http%3A//fastapi-app.busykoala.ch/test/path'

    assert expected_url == response


def test_get_auth_token(mocker):
    with mocker.patch('fastapi_opa.auth.auth_oidc.requests.get', return_value=oidc_well_known_response()):
        config = oidc_config()
        oidc = OIDCAuthentication(config)

    mock = mocker.patch('fastapi_opa.auth.auth_oidc.requests.post', return_value=mock_response(200, {}))
    oidc.get_auth_token("example_code", "callback_uri")
    kwargs = mock.call_args_list.pop().kwargs

    expected = {
        'data': {
            'grant_type': 'authorization_code',
            'code': 'example_code',
            'redirect_uri': 'callback_uri'
        },
        'headers': {
            'Authorization': 'Basic ZXhhbXBsZS1jbGllbnQ6c2VjcmV0'
        }
    }
    assert expected == kwargs


def test_get_validated_token_using_hs256(mocker):
    hs265_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhdWQiOiJleGFtcGxlLWNsaWVudCIsImp0aSI6IjY4ZjdjZjU3LTExMGQtNGNiZi05ZjI5LTBmNWFkNGM5MDMyOCIsImlhdCI6MTYxNzY2MDk2NCwiZXhwIjoxNjE3NjY0NTY0fQ.7KOnNJ0SjDFVeJQVqDz_Nzb_aWdKKZpdDwGwwS4fpYs"

    with mocker.patch('fastapi_opa.auth.auth_oidc.requests.get', return_value=oidc_well_known_response()):
        config = oidc_config()
        oidc = OIDCAuthentication(config)
    response = oidc.obtain_validated_token("HS256", hs265_token)

    expected = {
        'name': 'John Doe',
        'aud': 'example-client',
        'jti': '68f7cf57-110d-4cbf-9f29-0f5ad4c90328',
        'iat': 1617660964,
        'exp': 1617664564
    }
    assert expected == response


def test_get_validated_token_using_rs256():
    # TODO: implement
    assert True


def test_extract_token_keys():
    # TODO: implement
    assert True


def test_get_user_info():
    # TODO: implement
    assert True


def test_validate_sub_matching():
    # TODO: implement
    assert True


def test_to_dict_or_raise():
    # TODO: implement
    assert True
