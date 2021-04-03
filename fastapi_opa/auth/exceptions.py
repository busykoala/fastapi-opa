class AuthenticationException(Exception):
    """This is being raised for exceptions within the auth flow."""

    pass


class OIDCException(AuthenticationException):
    """OIDC authentication flow exception."""

    pass
