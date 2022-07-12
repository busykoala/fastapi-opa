import json
import re

import pytest
from lxml import html
from mock import patch

from fastapi_opa import OPAConfig
from fastapi_opa.opa.opa_middleware import should_skip_endpoint
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


def test_openapi_docs_endpoint_accessable(client):
    response = client.get("/docs")
    doc = html.fromstring(response.content)
    title = doc.xpath(".//title")[0].text
    assert "FastAPI - Swagger UI" == title


def test_openapi_redoc_endpoint_accessable(client):
    response = client.get("/redoc")
    doc = html.fromstring(response.content)
    title = doc.xpath(".//title")[0].text
    assert "FastAPI - ReDoc" == title


def test_openapi_json_endpoint_accessable(client):
    response = client.get("/openapi.json")
    title = response.json()["info"]["title"]
    assert "FastAPI" == title


def test_skip_endpoints():
    skip_endpoints = ["/api", "/test1/[^/]*/test"]
    skip_endpoints = [re.compile(skip) for skip in skip_endpoints]

    # Test an exact match
    assert should_skip_endpoint("/api", skip_endpoints)

    # Test a regex match
    assert should_skip_endpoint("/test1/abcdef.23$/test", skip_endpoints)

    # Test a  non match
    assert not should_skip_endpoint("/test1", skip_endpoints)


def test_multiple_authentication(
    api_key_auth, client_multiple_authentications
):
    client = client_multiple_authentications

    header_key = api_key_auth["header_key"]
    api_key = api_key_auth["api_key"]

    with patch("fastapi_opa.opa.opa_middleware.requests.post") as req:
        req.return_value.status_code = 200
        req.return_value.json = lambda: {"result": {"allow": True}}
        response = client.get("/")
        assert response.status_code == 401

        response = client.get("/", headers={"Authorization": "1234"})
        assert response.status_code == 200

        response = client.get("/", headers={header_key: api_key})
        assert response.status_code == 200
