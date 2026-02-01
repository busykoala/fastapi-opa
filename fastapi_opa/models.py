from typing import Dict
from typing import Literal
from typing import Optional

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
    cookie_domain: Optional[str] = None
    cookie_path: str = "/"
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: SameSitePolicy = "lax"


class AuthenticationResult(BaseModel):
    """Authentication result with optional tokens"""

    model_config = ConfigDict(frozen=True)

    success: bool
    user_info: Optional[Dict] = Field(default=None)
    validated_token: Optional[Dict] = Field(default=None)
    raw_tokens: Optional[Dict] = Field(default=None)
    error: Optional[str] = Field(default=None)
