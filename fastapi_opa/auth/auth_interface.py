from abc import ABC
from abc import abstractmethod
from typing import List
from typing import Optional
from typing import Union

from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_opa.models import AuthenticationResult


class AuthInterface(ABC):
    """The interface provides necessary methods for the OPAMiddleware
    authentication flow. This allows to easily integrate various auth methods.
    """

    @abstractmethod
    async def authenticate(
        self,
        request: Request,
        accepted_methods: Optional[List[str]] = None,
    ) -> Union[RedirectResponse, AuthenticationResult]:
        """Return an authentication result or a redirect to an identity provider."""
        pass
