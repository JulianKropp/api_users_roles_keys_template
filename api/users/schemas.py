from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

class OK(BaseModel):
    ok: bool

class UserResponse(BaseModel):
    id: str
    username: str
    roles: List[str]
    last_login: Optional[datetime]

class UserCreate(BaseModel):
    username: str
    password: str 
    roles: Optional[List[str]] = []

class UserUpdatePassword(BaseModel):
    current_password: str
    new_password: str

class UserResetPassword(BaseModel):
    new_password: str

class UserSetRole(BaseModel):
    roles: List[str]