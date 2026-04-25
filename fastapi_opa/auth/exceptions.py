class AuthenticationException(Exception):
    """This is being raised for exceptions within the auth flow."""


class OIDCException(AuthenticationException):
    """OIDC authentication flow exception."""


class SAMLException(AuthenticationException):
    """SAML authentication flow exception."""
