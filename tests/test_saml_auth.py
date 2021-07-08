from unittest.mock import Mock

import pytest
from mock import patch
from starlette.responses import RedirectResponse

from fastapi_opa.auth.auth_saml import SAMLAuthentication
from fastapi_opa.auth.auth_saml import SAMLConfig


@pytest.mark.asyncio
async def test_single_sign_on():
    saml_conf = SAMLConfig(settings_directory="./tests/test_data/saml")
    saml_auth = SAMLAuthentication(saml_conf)

    saml_auth_mock = Mock()
    saml_auth_mock.login.return_value = "http://idp.com/cryptic-stuff"
    url = "http://idp.com/cryptic-stuff/attrs"
    response = await saml_auth.single_sign_on(saml_auth_mock, url)

    assert isinstance(response, RedirectResponse)
    assert response.headers.get("location") == "http://idp.com/cryptic-stuff"


@pytest.mark.asyncio
async def test_single_sign_on_with_parameter():
    saml_conf = SAMLConfig(settings_directory="./tests/test_data/saml")
    saml_auth = SAMLAuthentication(saml_conf)

    def side_effect(url):
        return url

    saml_auth_mock = Mock()
    saml_auth_mock.login = Mock(side_effect=side_effect)
    attr_url = "http://idp.com/cryptic-stuff/attrs"
    response = await saml_auth.single_sign_on(saml_auth_mock, attr_url)

    assert isinstance(response, RedirectResponse)
    assert response.headers.get("location") == attr_url


@pytest.mark.asyncio
@patch("fastapi_opa.auth.auth_saml.OneLogin_Saml2_Utils")
async def test_assertion_consumer_service(saml_util_mock):
    saml_util_mock.get_self_url.return_value = "http://sp.com"
    saml_conf = SAMLConfig(settings_directory="./tests/test_data/saml")
    saml_auth = SAMLAuthentication(saml_conf)

    request_mock = Mock()
    request_mock.session.__setitem__ = Mock()

    saml_auth_mock = Mock()
    saml_auth_mock.get_errors.return_value = []
    saml_auth_mock.get_attributes.return_value = {
        "Role": [
            "default-roles-example-realm",
            "uma_authorization",
            "view-profile",
            "manage-account",
            "manage-account-links",
            "offline_access",
        ]
    }
    saml_auth_mock.get_nameid.return_value = "alice"
    saml_auth_mock.get_nameid_format.return_value = (
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    )
    saml_auth_mock.get_nameid_nq.return_value = None
    saml_auth_mock.get_nameid_spnq.return_value = None
    saml_auth_mock.get_session_index.return_value = "8167416b-6a10-4a4c-889c-7574074e3fc5::f1eaf88b-2bb9-4d2e-8d3d-39587ba1ef37"  # noqa

    response = await saml_auth.assertion_consumer_service(
        saml_auth_mock, {"post_data": []}, request_mock
    )
    expected = {
        "samlUserdata": {
            "Role": [
                "default-roles-example-realm",
                "uma_authorization",
                "view-profile",
                "manage-account",
                "manage-account-links",
                "offline_access",
            ]
        },
        "samlNameId": "alice",
        "samlNameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",  # noqa
        "samlNameIdNameQualifier": None,
        "samlNameIdSPNameQualifier": None,
        "samlSessionIndex": "8167416b-6a10-4a4c-889c-7574074e3fc5::f1eaf88b-2bb9-4d2e-8d3d-39587ba1ef37",  # noqa
    }

    request_mock.session.__setitem__.assert_called()
    assert expected == response


@pytest.mark.asyncio
async def test_single_log_out():
    saml_conf = SAMLConfig(settings_directory="./tests/test_data/saml")
    saml_auth = SAMLAuthentication(saml_conf)

    saml_auth_mock = Mock()
    saml_auth_mock.get_slo_url.return_value = "http://idp.com"
    saml_auth_mock.get_self_url_no_query.return_value = "http://idp.com"
    saml_auth_mock.get_nameid.return_value = "alice"
    saml_auth_mock.get_nameid_format.return_value = (
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    )
    saml_auth_mock.get_nameid_nq.return_value = None
    saml_auth_mock.get_nameid_spnq.return_value = None
    saml_auth_mock.get_session_index.return_value = "8167416b-6a10-4a4c-889c-7574074e3fc5::f1eaf88b-2bb9-4d2e-8d3d-39587ba1ef37"  # noqa

    response = await saml_auth.single_log_out(saml_auth_mock)
    assert isinstance(response, RedirectResponse)
    assert response.status_code == 307


# @pytest.mark.asyncio
# async def test_single_log_out_from_IdP_has_error():
#     saml_conf = SAMLConfig(settings_directory="./tests/test_data/saml")
#     saml_auth = SAMLAuthentication(saml_conf)
#
#     request_mock = Mock()
#     request_mock.query_params.return_value = {'post_data': {}}
#     request_mock.session.__setitem__ = Mock()
#
#     saml_auth_mock = Mock()
#     saml_auth_mock.process_slo.return_value = None
#
#     response = await saml_auth.single_log_out_from_IdP(request_mock)
#     request_mock.session.__setitem__.assert_called()
#     assert list(response.keys()) == ['error']


# @pytest.mark.asyncio
# async def test_single_log_out_from_IdP_without_url():
#     saml_conf = SAMLConfig(settings_directory="./tests/test_data/saml")
#     saml_auth = SAMLAuthentication(saml_conf)
#
#     request_mock = Mock()
#     request_mock.query_params.return_value = {'post_data': {}}
#     request_mock.session.__setitem__ = Mock()
#
#     saml_auth_mock = Mock()
#     saml_auth_mock.process_slo.return_value = None
#     saml_auth_mock.get_errors.return_value = []
#
#     response = await saml_auth.single_log_out_from_IdP(saml_auth_mock, request_mock)
#     request_mock.session.__setitem__.assert_called()
#     assert isinstance(response, RedirectResponse)
#     assert response.status_code == 307
#     assert b'mock.login()' in response.headers.raw[0][1]
#
#
# @pytest.mark.asyncio
# async def test_single_log_out_from_IdP_with_url():
#     saml_conf = SAMLConfig(settings_directory="./tests/test_data/saml")
#     saml_auth = SAMLAuthentication(saml_conf)
#
#     request_mock = Mock()
#     request_mock.query_params.return_value = {'post_data': {}}
#     request_mock.session.__setitem__ = Mock()
#
#     saml_auth_mock = Mock()
#     saml_auth_mock.process_slo.return_value = 'http://sp.com'
#     saml_auth_mock.get_errors.return_value = []
#
#     response = await saml_auth.single_log_out_from_IdP(saml_auth_mock, request_mock)
#     request_mock.session.__setitem__.assert_called()
#
#     assert isinstance(response, RedirectResponse)
#     assert response.status_code == 307
#     assert response.headers.raw[0] == (b'location', b'http://sp.com')
