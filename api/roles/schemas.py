from typing import List, Optional
from pydantic import BaseModel
from enum import Enum

class OK(BaseModel):
    ok: bool

class MethodResponse(str, Enum):  # Inherit from str and Enum for JSON serialization
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    ANY = "ANY"

class EndpointResponse(BaseModel):
    method: MethodResponse
    path_filter: str

class RoleResponse(BaseModel):
    id: str
    rolename: str
    endpoints: List[EndpointResponse]

class RoleCreateRequest(BaseModel):
    rolename: str
    endpoints: Optional[List[EndpointResponse]] = None

class RolePutRequest(BaseModel):
    rolename: Optional[str] = None
    endpoints: Optional[List[EndpointResponse]] = None