import json

import pytest
from mock import patch

from fastapi_opa import OPAConfig
from tests.utils import AuthenticationDummy


def test_opa_config():
    authentication = AuthenticationDummy()
    opa_conf = OPAConfig(authentication, "localhost")

    assert "localhost/v1/data/httpapi/authz" == opa_conf.opa_url


def test_successful_opa_flow(client):
    with patch("fastapi_opa.opa.opa_middleware.requests.post") as req:
        req.return_value.status_code = 200
        req.return_value.json = lambda: {"result": {"allow": True}}
        response = client.get("/")

    url = req.call_args_list[0][0][0]
    payload = json.loads(req.call_args_list[0][1].get("data")).get("input")

    expected_url = "http://localhost:8181/v1/data/httpapi/authz"
    expected_payload = {
        "stuff": "some info",
        "username": "John Doe",
        "role": "Administrator",
        "request_method": "GET",
        "request_path": [""],
    }

    assert expected_url == url
    assert expected_payload == payload
    assert {"msg": "success"} == response.json()


@pytest.mark.asyncio
async def test_not_allowing_opa_flow(client):
    with patch("fastapi_opa.opa.opa_middleware.requests.post") as req:
        req.return_value.status_code = 200
        req.return_value.json = lambda: {"result": {"allow": False}}
        response = client.get("/")

    url = req.call_args_list[0][0][0]
    payload = json.loads(req.call_args_list[0][1].get("data")).get("input")

    expected_url = "http://localhost:8181/v1/data/httpapi/authz"
    expected_payload = {
        "stuff": "some info",
        "username": "John Doe",
        "role": "Administrator",
        "request_method": "GET",
        "request_path": [""],
    }

    assert expected_url == url
    assert expected_payload == payload
    assert {"message": "Unauthorized"} == response.json()


@pytest.mark.asyncio
async def test_function_injection(injected_client):
    with patch("fastapi_opa.opa.opa_middleware.requests.post") as req:
        payload = {"some": "data"}
        injected_client.get("/", json=payload)

    expected_payload = {
        "stuff": "some info",
        "username": "John Doe",
        "role": "Administrator",
        "example_injectable": [{"some": "data"}],
        "request_method": "GET",
        "request_path": [""],
    }

    payload = json.loads(req.call_args_list[0][1].get("data")).get("input")
    assert expected_payload == payload
