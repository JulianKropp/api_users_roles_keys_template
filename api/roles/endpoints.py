import logging
import re
from fastapi import APIRouter, Depends, HTTPException
from typing import Union, List
from config import Config
from ..api_auth import SM, auth, BOSS_ROLE, get_user_roles_by_session, compare_roles
from .schemas import RoleResponse, RoleCreateRequest, RolePutRequest, OK, EndpointResponse, MethodResponse
from session import SessionUser, SessionAPIKey
from models.role import Endpoint, Role, Method

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CONFIG = Config()

router = APIRouter(tags=["Roles"])

@router.get(
    "/api/v1/roles",
    response_model=List[RoleResponse],
    tags=["Roles"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="List all roles in the system."
)
async def api_roles(session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))) -> List[RoleResponse]:
    """List all roles in the system."""
    roles = Role.objects() # type: ignore[attr-defined]
    return [
        RoleResponse(
            id=str(r.id),
            rolename=r.rolename,
            endpoints=[
                EndpointResponse(
                    method=MethodResponse(e.method.value), 
                    path_filter=e.path_filter
                ) for e in r.api_endpoints
            ]
        ) for r in roles
    ]

@router.get(
    "/api/v1/role/{role_id}",
    response_model=RoleResponse,
    tags=["Roles"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Get a specific role by its ID."
)
async def api_role(role_id: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE]))) -> RoleResponse:
    """Get a specific role by its ID."""
    role = Role.objects(id=role_id).first() # type: ignore[attr-defined]
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    
    return RoleResponse(
        id=role.id,
        rolename=role.rolename,
        endpoints=[EndpointResponse(method=MethodResponse(e.method.value), path_filter=e.path_filter) for e in role.api_endpoints]
    )

@router.post(
    "/api/v1/role",
    response_model=RoleResponse,
    status_code=201,
    tags=["Roles"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Create a new role with specified endpoints."
)
async def api_create_role(role: RoleCreateRequest, session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))) -> RoleResponse:
    """Create a new role with specified endpoints."""
    user_roles = get_user_roles_by_session(session)

    if role.endpoints is not None:
        for e in role.endpoints:
            if not re.fullmatch(r"[\w\-*/]+", e.path_filter):
                raise HTTPException(status_code=400, detail="Invalid path filter. Only alphanumeric characters, '-', '*', and '/' are allowed.")

    endpoints = [Endpoint(method=Method(e.method), path_filter=e.path_filter) for e in role.endpoints] if role.endpoints else []

    if Role.objects(rolename=role.rolename).first(): # type: ignore[attr-defined]
        raise HTTPException(status_code=400, detail="Role already exists")

    new_role = Role(rolename=role.rolename, api_endpoints=endpoints)

    if not compare_roles(user_roles, new_role):
        raise HTTPException(status_code=403, detail="You do not have permission to create this role. The new role has more permissions than your current roles.")

    new_role.save()

    return RoleResponse(
        id=str(new_role.id),
        rolename=new_role.rolename,
        endpoints=[EndpointResponse(method=MethodResponse(e.method.value), path_filter=e.path_filter) for e in new_role.api_endpoints]
    )

@router.delete(
    "/api/v1/role/{role_id}",
    response_model=OK,
    tags=["Roles"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Delete a specific role by its ID."
)
async def api_delete_role(role_id: str, session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))) -> OK:
    """Delete a specific role by its ID."""
    role = Role.objects(id=role_id).first() # type: ignore[attr-defined]
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")

    # Delete the role
    role.delete()

    return OK(ok=True)

@router.put(
    "/api/v1/role/{role_id}",
    response_model=RoleResponse,
    tags=["Roles"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Update a specific role by its ID."
)
async def api_update_role(role_id: str, role: RolePutRequest, session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))) -> RoleResponse:
    """Update a specific role by its ID."""
    existing_role = Role.objects(id=role_id).first() # type: ignore[attr-defined]
    if existing_role is None:
        raise HTTPException(status_code=404, detail="Role not found")

    if role.rolename is not None:
        existing_role.rolename = role.rolename
    if role.endpoints is not None:
        endpoints = [Endpoint(method=Method(e.method), path_filter=e.path_filter) for e in role.endpoints]
        existing_role.api_endpoints = endpoints

    existing_role.save()

    return RoleResponse(
        id=str(existing_role.id),
        rolename=existing_role.rolename,
        endpoints=[EndpointResponse(method=MethodResponse(e.method.value), path_filter=e.path_filter) for e in existing_role.api_endpoints]
    )