from typing import Protocol

import httpx

DEFAULT_TIMEOUT_SECONDS = 5.0


class OPAResponse(Protocol):
    """What the middleware reads from the OPA decision response."""

    status_code: int

    def json(self) -> object: ...


class OPAClient(Protocol):
    """An asynchronous HTTP client able to post the OPA input document.

    ``httpx.AsyncClient`` satisfies it as is. A custom client only has to
    accept the ``json`` keyword and return an object exposing
    ``status_code`` and ``json()``; the middleware never blocks the event
    loop waiting for it, so the client must not either.
    """

    async def post(self, url: str, *, json: object) -> OPAResponse: ...


def default_opa_client() -> httpx.AsyncClient:
    """The client used when none is configured: httpx, five-second timeout."""
    return httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS)
