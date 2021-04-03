from abc import ABC
from abc import abstractmethod
from typing import Dict
from typing import Union

from starlette.requests import HTTPConnection
from starlette.responses import RedirectResponse


class AuthInterface(ABC):
    """The interface provides necessary methods for the OPAMiddleware
    authentication flow. This allows to easily integrate various auth methods.
    """

    @abstractmethod
    def authenticate(
        self, *args: object, **kwargs: object
    ) -> Union[RedirectResponse, Dict]:
        """The method returns a dictionary containing the valid and authorized
        users information or a redirect since some flows require calling a
        identity broker beforehand.
        """
        pass


class OIDCAuthenticationInterface(AuthInterface):
    """The interface provides the necessary interface for the oidc
    authentication flow.
    """

    @abstractmethod
    def authenticate(
        self, connection: HTTPConnection
    ) -> Union[RedirectResponse, Dict]:
        """The method returns a dictionary containing the valid and authorized
        users information or a redirect since OIDC requires to call the id
        broker beforehand.
        """
        pass
