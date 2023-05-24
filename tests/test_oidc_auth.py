import datetime
from typing import Any
from typing import Dict
from typing import Optional

import jwt
import pytest
from authlib.jose import jwk
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives._serialization import PublicFormat
from freezegun import freeze_time
from mock import Mock

from fastapi_opa.auth.auth_oidc import OIDCAuthentication
from fastapi_opa.auth.exceptions import OIDCException
from tests.utils import mock_response
from tests.utils import oidc_config
from tests.utils import oidc_well_known_response


def test_auth_redirect_uri(mocker):
    callback_uri = "http://fastapi-app.busykoala.ch/test/path"
    with mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    ):
        config = oidc_config()
        oidc = OIDCAuthentication(config)
    response = oidc.get_auth_redirect_uri(callback_uri=callback_uri)
    expected_url = "http://keycloak.busykoala.ch/auth/realms/example-realm/protocol/openid-connect/auth?response_type=code&scope=openid email profile&client_id=example-client&redirect_uri=http%3A//fastapi-app.busykoala.ch/test/path"  # noqa

    assert expected_url == response


def test_get_auth_token(mocker):
    with mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    ):
        config = oidc_config()
        oidc = OIDCAuthentication(config)

    mock = mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.post",
        return_value=mock_response(200, {}),
    )
    oidc.get_auth_token("example_code", "callback_uri")

    expected = {
        "data": {
            "grant_type": "authorization_code",
            "code": "example_code",
            "redirect_uri": "callback_uri",
        },
        "timeout": 5,
        "headers": {"Authorization": "Basic ZXhhbXBsZS1jbGllbnQ6c2VjcmV0"},
    }

    for call in mock.call_args_list:
        args, kwargs = call
        for _ in args:
            assert expected == kwargs


@freeze_time("2021-04-04 12:12:12")
def test_get_validated_token_using_hs256(mocker):
    hs265_token, expected = construct_jwt("HS256")

    with mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    ):
        config = oidc_config()
        oidc = OIDCAuthentication(config)
    response = oidc.obtain_validated_token("HS256", hs265_token)

    assert expected == response


def test_get_validated_token_using_rs256(mocker):
    priv_key, pub_key = get_key_pair()
    rs265_token, expected = construct_jwt("RS256", private_key=priv_key)

    with mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    ):
        config = oidc_config()
        oidc = OIDCAuthentication(config)
    with mocker.patch(
        "fastapi_opa.auth.auth_oidc.OIDCAuthentication.extract_token_key",
        return_value=pub_key,
    ):
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
    with mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    ):
        config = oidc_config()
        oidc = OIDCAuthentication(config)
    key = oidc.extract_token_key(jwks, id_token)

    actual = key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    expected = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQCuPmDRtWxsHB8cRrG8+toZ+/+NRzDbdjwNy+CQTSKeRRdrnT0mXJVMIxOMq//Hs8zFy4MBpceL5o9QHEiCDsDP"  # noqa
    assert expected == actual


def test_validate_sub_matching(mocker):
    sub_1 = {"sub": "subject1"}
    sub_2 = {"sub": "subject2"}
    with mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    ):
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
    iat_timestamp = datetime.datetime.utcnow().timestamp()
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
    jwk_ = jwk.dumps(pub_key, kty="RSA")
    jwk_["kid"] = "happy-kid"
    jwk_["use"] = "sig"
    return [jwk_]


@pytest.mark.asyncio
async def test_token_type_not_accepted(mocker):
    with mocker.patch(
        "fastapi_opa.auth.auth_oidc.requests.get",
        return_value=oidc_well_known_response(),
    ):
        config = oidc_config()
        oidc = OIDCAuthentication(config)

    url = Mock(scheme="http", netloc="www.test.com", path="test")

    # Ensure that we do not accept id tokens
    request = mock_response(
        200, url=url, query_params={"code": "abc"}, headers={}
    )

    with pytest.raises(OIDCException):
        await oidc.authenticate(request, accepted_methods=["access_token"])

    # Ensure that we do not accept access tokens
    request = mock_response(
        200, url=url, query_params={}, headers={"Authorization": "abc"}
    )
    with pytest.raises(OIDCException):
        await oidc.authenticate(request, accepted_methods=["id_token"])
