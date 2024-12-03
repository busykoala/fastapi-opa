import threading
import time
from typing import Dict
from fastapi import FastAPI, Request
import httpx
import json

import pytest
from mock import patch
import uvicorn

from fastapi_opa.opa.opa_config import OPAConfig
from fastapi_opa.opa.opa_middleware import OPAMiddleware
from tests.utils import AuthenticationDummy


@pytest.fixture
def asgi_server():
    opa_host = "http://localhost:8181"
    oidc_auth = AuthenticationDummy()
    opa_config = OPAConfig(authentication=oidc_auth, opa_host=opa_host)

    # Add the mock before creating the FastAPI app
    with patch("fastapi_opa.opa.opa_middleware.requests.post") as req:
        req.return_value.status_code = 200
        req.return_value.json = lambda: {"result": {"allow": True}}

        app = FastAPI()
        app.add_middleware(OPAMiddleware, config=opa_config)

        @app.post("/items")
        async def process_request_body(request: Request) -> Dict:
            data = await request.json()
            return {"msg": f"Received {len(json.dumps(data))} bytes"}

        # Start uvicorn server in a separate thread
        config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="error")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run)
        thread.daemon = True
        thread.start()

        # Give the server a moment to start
        time.sleep(1)

        try:
            yield "http://127.0.0.1:8000"
        finally:
            # Signal shutdown and short grace period
            server.should_exit = True
            time.sleep(1)

            # Force shutdown even if requests are hanging
            server.force_exit = True
            thread.join(timeout=2)  # Wait max 2 second for thread to finish
            if thread.is_alive():
                # If thread is still alive, we don't wait for it
                # This is expected when requests are hanging
                pass


def test_access_small_request_body_in_endpoint(asgi_server):
    with open("tests/test_data/small_request_body.json", "r") as f:
        json_data = json.load(f)
    try:
        response = httpx.post(f"{asgi_server}/items", json=json_data, timeout=5)
        assert {
            "msg": f"Received {len(json.dumps(json_data))} bytes"
        } == response.json()
    except httpx.TimeoutException:
        pytest.fail("Request timed out after 5 seconds")


def test_access_large_request_body_in_endpoint(asgi_server):
    with open("tests/test_data/large_request_body.json", "r") as f:
        json_data = json.load(f)
    try:
        response = httpx.post(f"{asgi_server}/items", json=json_data, timeout=5)
        assert {
            "msg": f"Received {len(json.dumps(json_data))} bytes"
        } == response.json()
    except httpx.TimeoutException:
        pytest.fail("Request timed out after 5 seconds")
