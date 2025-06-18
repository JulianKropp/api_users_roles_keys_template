from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class OK(BaseModel):
    ok: bool

class APIKeyResponse(BaseModel):
    id: str
    roles: List[str]
    created_at: datetime
    expiration: Optional[datetime]

class APIKeyCreateResponse(BaseModel):
    id: str
    key: str
    roles: List[str]
    created_at: datetime
    expiration: Optional[datetime]

class APIKeyCreateRequest(BaseModel):
    roles: List[str] = []
    expiration: Optional[datetime] = None

class APIKeyPutRequest(BaseModel):
    roles: Optional[List[str]] = None
    expiration: Optional[datetime] = None

class WebRTCSession(BaseModel):
    id: str
    expiration_date: datetime
    creation_date: datetime
    user_id: str
    parent_session_id: str