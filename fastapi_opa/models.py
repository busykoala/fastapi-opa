from typing import Optional, Dict
from pydantic import BaseModel, Field


class TokenCookieConfig(BaseModel):
    """Configuration handler for cookies"""
    enabled: bool = True
    cookie_name: str = "access_token"
    cookie_domain: Optional[str] = None
    cookie_path: str = "/"
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: str = "lax"

    class Config:
        frozen = True


class AuthenticationResult(BaseModel):
    """Authentication result with optional tokens"""
    success: bool
    user_info: Optional[Dict] = Field(default=None)
    validated_token: Optional[Dict] = Field(default=None)
    raw_tokens: Optional[Dict] = Field(default=None)
    error: Optional[str] = Field(default=None)

    class Config:
        frozen = True
