from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

# Valid values for SameSite cookie attribute
SameSitePolicy = Literal["strict", "lax", "none"]


class TokenCookieConfig(BaseModel):
    """Configuration handler for cookies"""

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    cookie_name: str = "access_token"
    cookie_domain: str | None = None
    cookie_path: str = "/"
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: SameSitePolicy = "lax"


class AuthenticationResult(BaseModel):
    """Authentication result with optional tokens"""

    model_config = ConfigDict(frozen=True)

    success: bool
    user_info: dict[str, object] | None = Field(default=None)
    validated_token: dict[str, object] | None = Field(default=None)
    raw_tokens: dict[str, str] | None = Field(default=None)
    error: str | None = Field(default=None)
