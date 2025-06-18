from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class OK(BaseModel):
    ok: bool

class AuthRequest(BaseModel):
    type: str = "user" # user or apikey
    username: Optional[str] = None
    password: Optional[str] = None
    key: Optional[str] = None

class AuthUser(BaseModel):
    id: str
    username: str
    roles: list[str]
    last_login: Optional[datetime]

class AuthAPIKey(BaseModel):
    id: str
    roles: list[str]
    created_at: datetime
    expiration: Optional[datetime]

class AuthUserResponse(BaseModel):
    token: str
    session_type: str
    creation_date: datetime
    expiration_date: datetime
    user: AuthUser

class AuthAPIKeyResponse(BaseModel):
    token: str
    session_type: str
    creation_date: datetime
    expiration_date: datetime
    api_key: AuthAPIKey

class AuthWebRTCResponse(BaseModel):
    token: str
    session_type: str
    creation_date: datetime
    expiration_date: datetime