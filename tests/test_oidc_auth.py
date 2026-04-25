import datetime
from typing import Any
from typing import cast
from unittest.mock import Mock
from urllib.parse import parse_qs
from urllib.parse import urlparse

import jwt
import pytest
from authlib.jose import JsonWebKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from freezegun import freeze_time
from starlette.datastructures import URL
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_opa.auth.auth_oidc import OIDCAuthentication
from fastapi_opa.auth.exceptions import OIDCException
from fastapi_opa.models import AuthenticationResult
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
        parsed.path
        == "/auth/realms/example-realm/protocol/openid-connect/auth"
    )
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid email profile"]
    assert params["client_id"] == ["example-client"]
    assert "redirect_uri" in params
    # PKCE parameters
    assert "code_challenge" in params
    assert params["code_challenge_method"] == ["S256"]
    assert "nonce" in params


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
    assert isinstance(response, RedirectResponse)
    parsed = urlparse(response.headers["location"])
    params = parse_qs(parsed.query)

    assert parsed.scheme == "http"
    assert parsed.netloc == "keycloak.busykoala.ch"
    assert (
        parsed.path
        == "/auth/realms/example-realm/protocol/openid-connect/auth"
    )
    assert params["response_type"] == ["code"]
    assert params["client_id"] == ["example-client"]
    # Verify redirect_uri is pinned to the configured app URI origin
    redirect_uri = params["redirect_uri"][0]
    parsed_redirect = urlparse(redirect_uri)
    assert parsed_redirect.scheme == "http"
    assert parsed_redirect.netloc == "fastapi-app.busykoala.ch"
    assert parsed_redirect.path == "/test/path"
    # PKCE parameters
    assert "code_challenge" in params
    assert params["code_challenge_method"] == ["S256"]
    assert "nonce" in params


@pytest.mark.asyncio
async def test_app_uri_with_base_path_is_applied_to_redirect_callback(
    mocker,
):
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    config.app_uri = "https://public.example.com/prefix"
    oidc = OIDCAuthentication(config)

    request: Request = Request({"type": "http", "query_string": ""})
    request._headers = Headers({})
    request._url = URL("http://internal.example.com/callback")

    response = await oidc.authenticate(request)

    assert isinstance(response, RedirectResponse)
    parsed = urlparse(response.headers["location"])
    redirect_uri = parse_qs(parsed.query)["redirect_uri"][0]
    parsed_redirect = urlparse(redirect_uri)

    assert parsed_redirect.scheme == "https"
    assert parsed_redirect.netloc == "public.example.com"
    assert parsed_redirect.path == "/prefix/callback"


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
        _args, kwargs = call
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
        side_effect=[
            oidc_well_known_response(),
            mock_response(200, json_data={"keys": []}),
        ],
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
    expected = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQCuPmDRtWxsHB8cRrG8+toZ+/+NRzDbdjwNy+CQTSKeRRdrnT0mXJVMIxOMq//Hs8zFy4MBpceL5o9QHEiCDsDP"
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


def test_get_validated_token_rejects_wrong_issuer(mocker):
    wrong_issuer_payload = {
        "name": "John Doe",
        "aud": "example-client",
        "iss": "http://evil-issuer.example",
        "sub": "test-sub",
        "iat": int(datetime.datetime.now().timestamp()),
        "exp": int(datetime.datetime.now().timestamp() + 3600),
    }
    hs265_token = jwt.encode(wrong_issuer_payload, "secret", algorithm="HS256")

    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    oidc = OIDCAuthentication(config)

    with pytest.raises(OIDCException):
        oidc.obtain_validated_token("HS256", hs265_token)


@pytest.mark.asyncio
async def test_authenticate_rejects_nonce_mismatch(mocker):
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    config = oidc_config()
    oidc = OIDCAuthentication(config)

    request_initial = Mock()
    request_initial.headers = {}
    request_initial.query_params = {}
    request_initial.url = Mock(
        scheme="http", netloc="app.example.com", path="/callback"
    )

    redirect_response = await oidc.authenticate(cast(Request, request_initial))
    assert isinstance(redirect_response, RedirectResponse)
    parsed = urlparse(redirect_response.headers["location"])
    params = parse_qs(parsed.query)
    state_from_redirect = params["state"][0]

    iat = int(datetime.datetime.now().timestamp())
    id_token = jwt.encode(
        {
            "sub": "user123",
            "aud": "example-client",
            "iss": "http://keycloak.busykoala.ch/auth/realms/example-realm",
            "nonce": "wrong-nonce",
            "iat": iat,
            "exp": iat + 3600,
        },
        "secret",
        algorithm="HS256",
    )

    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.post",
        return_value=mock_response(
            200, {"access_token": "token", "id_token": id_token}
        ),
    )

    request_callback = Mock()
    request_callback.headers = {}
    request_callback.query_params = {
        "code": "auth_code_from_idp",
        "state": state_from_redirect,
    }
    request_callback.url = Mock(
        scheme="http", netloc="app.example.com", path="/callback"
    )

    result = await oidc.authenticate(cast(Request, request_callback))
    assert isinstance(result, AuthenticationResult)
    assert result.success is False
    assert result.error is not None
    assert "nonce mismatch" in result.error


def test_hs256_decode_includes_issuer_argument(mocker):
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    )
    decode_mock = mocker.patch(
        "fastapi_opa.auth.auth_oidc.jwt.decode",
        return_value={"sub": "test-sub"},
    )

    config = oidc_config()
    oidc = OIDCAuthentication(config)
    oidc.obtain_validated_token("HS256", "dummy-token")

    assert decode_mock.call_args.kwargs["issuer"] == oidc.issuer


def test_rs256_decode_includes_issuer_argument(mocker):
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        side_effect=[
            oidc_well_known_response(),
            mock_response(200, {"keys": []}),
        ],
    )
    mocker.patch(
        "fastapi_opa.auth.auth_oidc.OIDCAuthentication.extract_token_key",
        return_value="public-key",
    )
    decode_mock = mocker.patch(
        "fastapi_opa.auth.auth_oidc.jwt.decode",
        return_value={"sub": "test-sub"},
    )

    config = oidc_config()
    oidc = OIDCAuthentication(config)
    oidc.obtain_validated_token("RS256", "dummy-token")

    assert decode_mock.call_args.kwargs["issuer"] == oidc.issuer


def construct_jwt(
    algorithm: str,
    private_key: str = "",
    msg: dict[str, Any] | None = None,
    headers: dict | None = None,
):
    iat_timestamp = datetime.datetime.now().timestamp()
    delta_days = 1000000
    # This or patch jwt.decode
    if not msg:
        msg = {
            "name": "John Doe",
            "aud": "example-client",
            "iss": "http://keycloak.busykoala.ch/auth/realms/example-realm",
            "jti": "68f7cf57-110d-4cbf-9f29-0f5ad4c90328",
            "sub": "test-sub",
            "iat": int(iat_timestamp),
            "exp": int(iat_timestamp + 3600 * 24 * delta_days),
        }
    if algorithm == "HS256":
        return jwt.encode(msg, "secret", algorithm=algorithm), msg
    if algorithm == "RS256" and private_key:
        return (
            jwt.encode(msg, private_key, algorithm=algorithm, headers=headers),
            msg,
        )
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

    result = await oidc.authenticate(
        request, accepted_methods=["access_token"]
    )
    assert isinstance(result, AuthenticationResult)
    assert result.success is False
    assert result.error is not None
    assert "id token is not accepted" in result.error

    # Ensure that we do not accept access tokens
    request = mock_response(
        200, url=url, query_params={}, headers={"Authorization": "abc"}
    )
    result = await oidc.authenticate(request, accepted_methods=["id_token"])
    assert isinstance(result, AuthenticationResult)
    assert result.success is False
    assert result.error is not None
    assert "access token is not accepted" in result.error
