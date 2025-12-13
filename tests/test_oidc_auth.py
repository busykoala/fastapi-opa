import datetime
from typing import Any
from typing import Dict
from typing import Optional
from urllib.parse import parse_qs
from urllib.parse import urlparse

import jwt
import pytest
from authlib.jose import JsonWebKey
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives._serialization import PublicFormat
from freezegun import freeze_time
from mock import Mock
from starlette.datastructures import URL
from starlette.datastructures import Headers
from starlette.requests import Request

from fastapi_opa.auth.auth_oidc import OIDCAuthentication
from fastapi_opa.auth.exceptions import OIDCException
from tests.utils import mock_response
from tests.utils import oidc_config
from tests.utils import oidc_well_known_response


def test_auth_redirect_uri(mocker):
    callback_uri = "http://fastapi-app.busykoala.ch/test/path"
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    oidc = OIDCAuthentication(config)
    response = oidc.get_auth_redirect_uri(callback_uri=callback_uri)

    # Parse the URL and verify parameters
    parsed = urlparse(response)
    params = parse_qs(parsed.query)

    assert parsed.scheme == "http"
    assert parsed.netloc == "keycloak.busykoala.ch"
    assert (
        parsed.path == "/auth/realms/example-realm/protocol/openid-connect/auth"
    )
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid email profile"]
    assert params["client_id"] == ["example-client"]
    assert "redirect_uri" in params
    # PKCE parameters
    assert "code_challenge" in params
    assert params["code_challenge_method"] == ["S256"]


@pytest.mark.asyncio
async def test_auth_redirect_uri_from_headers(mocker):
    call_uri = "http://fastapi-app.busykoala.ch/test/path"
    headers = {"x-forwarded-proto": "https", "x-forwarded-host": "foo.bar.ch"}
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    config.trust_x_headers = True
    oidc = OIDCAuthentication(config)
    request: Request = Request({"type": "http", "query_string": ""})
    request._headers = Headers(headers)
    request._url = URL(call_uri)
    response = await oidc.authenticate(request)

    # Parse the redirect URL and verify parameters
    parsed = urlparse(response.headers["location"])
    params = parse_qs(parsed.query)

    assert parsed.scheme == "http"
    assert parsed.netloc == "keycloak.busykoala.ch"
    assert (
        parsed.path == "/auth/realms/example-realm/protocol/openid-connect/auth"
    )
    assert params["response_type"] == ["code"]
    assert params["client_id"] == ["example-client"]
    # Verify redirect_uri uses forwarded headers (parse_qs decodes the URL)
    assert "https://foo.bar.ch" in params["redirect_uri"][0]
    # PKCE parameters
    assert "code_challenge" in params
    assert params["code_challenge_method"] == ["S256"]


def test_get_auth_token(mocker):
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    oidc = OIDCAuthentication(config)

    mock = mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.post",
        return_value=mock_response(200, {}),
    )

    # Generate a code_verifier for this test
    test_code_verifier = "test_code_verifier_12345"
    oidc.get_auth_token("example_code", "callback_uri", test_code_verifier)

    for call in mock.call_args_list:
        args, kwargs = call
        data = kwargs.get("data")
        # Verify required fields
        assert data["grant_type"] == "authorization_code"
        assert data["code"] == "example_code"
        assert data["redirect_uri"] == "callback_uri"
        # PKCE: code_verifier must be present
        assert "code_verifier" in data
        assert data["code_verifier"] == test_code_verifier
        # For confidential clients with auth header, client_id should not be in data
        assert kwargs["timeout"] == 5
        assert "Authorization" in kwargs["headers"]
        assert kwargs["headers"]["Authorization"].startswith("Basic ")


@freeze_time("2021-04-04 12:12:12")
def test_get_validated_token_using_hs256(mocker):
    hs265_token, expected = construct_jwt("HS256")

    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    oidc = OIDCAuthentication(config)
    response = oidc.obtain_validated_token("HS256", hs265_token)

    assert expected == response


def test_get_validated_token_using_rs256(mocker):
    priv_key, pub_key = get_key_pair()
    rs265_token, expected = construct_jwt("RS256", private_key=priv_key)

    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    oidc = OIDCAuthentication(config)
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.OIDCAuthentication.extract_token_key",
        return_value=pub_key,
    )
    response = oidc.obtain_validated_token("RS256", rs265_token)

    assert expected == response


def test_extract_token_keys(mocker):
    jwks = get_jwks()
    id_token_payload = {"kid": "happy-kid", "alg": "RS256"}
    priv_key, _ = get_key_pair()
    id_token = construct_jwt(
        "RS256",
        private_key=priv_key,
        msg=id_token_payload,
        headers={"kid": "happy-kid"},
    )[0]
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    oidc = OIDCAuthentication(config)
    key = oidc.extract_token_key(jwks, id_token)

    actual = key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    expected = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQCuPmDRtWxsHB8cRrG8+toZ+/+NRzDbdjwNy+CQTSKeRRdrnT0mXJVMIxOMq//Hs8zFy4MBpceL5o9QHEiCDsDP"  # noqa
    assert expected == actual


def test_validate_sub_matching(mocker):
    sub_1 = {"sub": "subject1"}
    sub_2 = {"sub": "subject2"}
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    oidc = OIDCAuthentication(config)

    # expected to not raise (matching sub)
    oidc.validate_sub_matching(sub_1, sub_1)
    # expected to raise (non matching sub)
    with pytest.raises(OIDCException):
        assert not oidc.validate_sub_matching(sub_1, sub_2)


def construct_jwt(
    algorithm: str,
    private_key: str = "",
    msg: Dict[str, Any] = None,
    headers: Optional[Dict] = None,
):
    iat_timestamp = datetime.datetime.now().timestamp()
    delta_days = 1000000
    # This or patch jwt.decode
    if not msg:
        msg = {
            "name": "John Doe",
            "aud": "example-client",
            "jti": "68f7cf57-110d-4cbf-9f29-0f5ad4c90328",
            "sub": "test-sub",
            "iat": int(iat_timestamp),
            "exp": int(iat_timestamp + 3600 * 24 * delta_days),
        }
    if algorithm == "HS256":
        return jwt.encode(msg, "secret", algorithm=algorithm), msg
    elif algorithm == "RS256" and private_key:
        return (
            jwt.encode(msg, private_key, algorithm=algorithm, headers=headers),
            msg,
        )
    else:
        raise Exception("Arguments not matching with the algorithm")


def get_key_pair():
    private_key = """-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEArj5g0bVsbBwfHEax
vPraGfv/jUcw23Y8DcvgkE0inkUXa509JlyVTCMTjKv/x7PMxcuDAaXHi+aPUBxI
gg7AzwIDAQABAkEApkc2w8k7H2wysBwyj2Jf8f4OYHb4g+Yv5waRVYOWrqsy1ths
vw+0//Ae+YeKKUn3LZNNYfOIC1/dC+sw185faQIhAN3vvBaPJiuMjeKORTO8IVLd
HC4VuUaAV+ZDtReuZScFAiEAyPy2HpDXbGG/RFT+V0zr4nMxSEjTeTX/RAWxc98I
aMMCIQDPUTb+S9J4M+AGlqgGX+MxKOM+GYTtWs7BhtYPvRU4kQIgG2uGuSLPkQTA
4GSsEmL3J3zJs2/kEfxQ6AnSzNkXv5sCIG8BsNrNIoghblYHvaDam6h4oLN2SypZ
2O6b+Pe3za2l
-----END PRIVATE KEY-----"""
    public_key = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK4+YNG1bGwcHxxGsbz62hn7/41HMNt2
PA3L4JBNIp5FF2udPSZclUwjE4yr/8ezzMXLgwGlx4vmj1AcSIIOwM8CAwEAAQ==
-----END PUBLIC KEY-----"""
    return private_key, public_key


def get_jwks():
    _, pub_key = get_key_pair()
    jwk_ = JsonWebKey.import_key(pub_key, {"kty": "RSA"})
    jwk_dict = jwk_.as_dict()
    jwk_dict["kid"] = "happy-kid"
    jwk_dict["use"] = "sig"
    return [jwk_dict]


@pytest.mark.asyncio
async def test_token_type_not_accepted(mocker):
    from fastapi_opa.models import AuthenticationResult

    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    oidc = OIDCAuthentication(config)

    url = Mock(scheme="http", netloc="www.test.com", path="test")

    # Ensure that we do not accept id tokens
    request = mock_response(
        200, url=url, query_params={"code": "abc"}, headers={}
    )

    result = await oidc.authenticate(request, accepted_methods=["access_token"])
    assert isinstance(result, AuthenticationResult)
    assert result.success is False
    assert "id token is not accepted" in result.error

    # Ensure that we do not accept access tokens
    request = mock_response(
        200, url=url, query_params={}, headers={"Authorization": "abc"}
    )
    result = await oidc.authenticate(request, accepted_methods=["id_token"])
    assert isinstance(result, AuthenticationResult)
    assert result.success is False
    assert "access token is not accepted" in result.error
