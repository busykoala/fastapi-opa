class AuthenticationException(Exception):
    """This is being raised for exceptions within the auth flow."""

    pass


class OIDCException(AuthenticationException):
    """OIDC authentication flow exception."""

    pass


class SAMLException(AuthenticationException):
    """SAML authentication flow exception."""

    pass
