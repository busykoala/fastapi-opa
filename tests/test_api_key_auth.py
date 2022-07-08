from collections import namedtuple

import pytest

from fastapi_opa.auth.exceptions import AuthenticationException

FakeClient = namedtuple("FakeClient", "host")
FakeRequest = namedtuple("FakeRequest", "headers client")


@pytest.mark.asyncio
async def test_key_api_auth(api_key_auth):
    header_key = api_key_auth["header_key"]
    api_key = api_key_auth["api_key"]
    auth = api_key_auth["auth"]

    host = "1.2.3.4"
    fake_client = FakeClient(host)
    fake_request = FakeRequest({header_key: api_key}, fake_client)

    # Do a successful test
    answer = await auth.authenticate(fake_request)
    assert answer["user"] == "APIKey"
    assert answer["client"] == host

    # Do a failure due to wrong key
    with pytest.raises(AuthenticationException):
        fake_request = FakeRequest({header_key: "098125u"}, fake_client)
        answer = await auth.authenticate(fake_request)

    # Do a failure due to missing key
    with pytest.raises(AuthenticationException):
        fake_request = FakeRequest({}, fake_client)
        answer = await auth.authenticate(fake_request)
