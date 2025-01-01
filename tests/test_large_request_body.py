import asyncio
from typing import Any
from typing import AsyncGenerator
from typing import Callable
from typing import Dict
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


async def simulate_request(client: TestClient, large_body):
    """
    Simulate a request to the FastAPI app with a chunked body.

    This function mimics the ASGI protocol behavior for handling large HTTP
    request bodies. The body is split into chunks, and each chunk is yielded
    through the `mock_receive` function. The ASGI app processes these chunks
    until the entire body is consumed.
    """

    async def mock_receive():
        """
        Mimic the ASGI `receive` function to send chunks of the request body.
        """
        async for chunk in large_body():
            # Yield control to the event loop to allow timeout enforcement
            await asyncio.sleep(0)
            yield chunk

    async def mock_send(message):
        """
        Mimic the ASGI `send` function to capture the app's response.
        """
        nonlocal response_body
        if message["type"] == "http.response.body":
            response_body += message.get("body", b"")

    # Define the ASGI scope for the request
    scope = {
        "type": "http",  # HTTP request
        "method": "POST",  # HTTP method
        "path": "/items",  # Target endpoint
        "headers": [(b"content-type", b"application/json")],  # Request headers
        "query_string": b"",  # No query parameters
    }

    response_body = b""  # Buffer to store the response body

    # Pass the ASGI scope, mock_receive, and mock_send to the ASGI app
    await client.app(scope, mock_receive().__anext__, mock_send)
    return response_body.decode("utf-8")


@pytest.mark.asyncio
@pytest.mark.timeout(2)  # Enforce a 2-second timeout on the test
async def test_large_request_body(
    client: TestClient,
    large_body: Callable[[], AsyncGenerator[Dict[str, Any], None]],
) -> None:
    """
    Test that the FastAPI app handles a large request body correctly.

    This test verifies that the app can process a request with a large JSON
    payload, delivered in chunks, and return the expected response. It also
    mocks the OPA middleware to ensure the app processes the request as if it
    were allowed by OPA.
    """
    with patch("fastapi_opa.opa.opa_middleware.requests.post") as req:
        # Mock the OPA middleware to allow the request
        req.return_value.status_code = 200
        req.return_value.json = lambda: {"result": {"allow": True}}

        # Simulate the ASGI request and capture the response
        response = await simulate_request(client, large_body)

        # Verify that the app processes the large body correctly
        assert response == '{"msg":"Received 5242917 bytes"}'
