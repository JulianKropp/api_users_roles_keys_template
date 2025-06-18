import logging
from typing import List, Union

from fastapi import APIRouter, Depends, HTTPException

from config import Config
from ..api_auth import SM, auth, BOSS_ROLE, get_user_roles_by_session, compare_roles
from .schemas import OK, UserCreate, UserResponse, UserUpdatePassword, UserResetPassword, UserSetRole
from session import SessionUser, SessionAPIKey
from models.user import User
from models.role import Role


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CONFIG = Config()

router = APIRouter(tags=["Users"])

@router.get(
    "/api/v1/users",
    response_model=List[UserResponse],
    tags=["Users"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="List all users in the system."
)
async def api_users(session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))) -> List[UserResponse]:
    """List all users in the system."""
    users = User.objects() # type: ignore[attr-defined]
    return [
        UserResponse(
            id=str(u.id),
            username=u.username,
            roles=[str(role.id) for role in u.roles],
            last_login=u.last_login,
        )
        for u in users
    ]

@router.post(
    "/api/v1/user",
    response_model=UserResponse,
    status_code=201,
    tags=["Users"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Create a new user in the system."
)
async def api_create_user(
    user: UserCreate,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> UserResponse:
    """Create a new user in the system."""
    if User.objects(username=user.username).first(): # type: ignore[attr-defined]
        raise HTTPException(status_code=400, detail="User already exists")

    # Validate roles
    roles = []
    if user.roles:
        roles = Role.objects(id__in=user.roles) # type: ignore[attr-defined]
        if len(roles) != len(user.roles):
            raise HTTPException(status_code=400, detail="One or more roles do not exist")

    # Check if the new roles are broader than the user's roles
    req_user_roles = get_user_roles_by_session(session)
    for r in roles:
        if not compare_roles(req_user_roles, r):
            raise HTTPException(status_code=403, detail="You do not have permission to create this user. The new user has more permissions than your current roles.")

    new_user = User(username=user.username, roles=roles)
    new_user.set_password(user.password)
    new_user.save()

    return UserResponse(
        id=str(new_user.id),
        username=new_user.username,
        roles=[str(role.id) for role in new_user.roles],
        last_login=new_user.last_login,
    )


@router.put(
    "/api/v1/user/password",
    response_model=OK,
    tags=["Users"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Change own password"
)
async def api_change_user_password(
    password_update: UserUpdatePassword,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> OK:
    """Update password for the current user."""
    if isinstance(session, SessionAPIKey):
        raise HTTPException(
            status_code=403,
            detail="You cannot change the password using an API key session. Please use a user session.",
        )

    user = User.objects(id=session.user_id).first() # type: ignore[attr-defined]
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.verify_password(password_update.current_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    user.set_password(password_update.new_password)
    user.save()

    return OK(ok=True)

@router.put(
    "/api/v1/user/{user_id}/password",
    response_model=OK,
    tags=["Users"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Reset a user's password (admin only)"
)
async def api_reset_user_password(
    user_id: str,
    pw: UserResetPassword,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> OK:
    """Reset the user password."""
    user = User.objects(id=user_id).first() # type: ignore[attr-defined]
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user.set_password(pw.new_password)
    user.save()

    return OK(ok=True)

@router.put(
    "/api/v1/user/{user_id}/roles",
    response_model=UserResponse,
    tags=["Users"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Update a user's roles (admin only)"
)
async def api_set_user_roles(
    user_id: str,
    user_roles: UserSetRole,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> UserResponse:
    """Set roles for a user. Only accessible by admin."""
    user = User.objects(id=user_id).first() # type: ignore[attr-defined]
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify all roles exist
    roles = Role.objects(id__in=user_roles.roles) # type: ignore[attr-defined]
    if len(roles) != len(user_roles.roles):
        raise HTTPException(status_code=400, detail="One or more roles do not exist")

    # Update user's roles
    user.roles = roles
    user.save()

    return UserResponse(
        id=str(user.id),
        username=user.username,
        roles=[str(role.id) for role in user.roles],
        last_login=user.last_login
    )

@router.delete(
    "/api/v1/user/{user_id}",
    response_model=OK,
    tags=["Users"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Delete a user (admin only)"
)
async def api_delete_user(
    user_id: str,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> OK:
    """Delete a user. Only accessible by admin."""
    user = User.objects(id=user_id).first() # type: ignore[attr-defined]
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Logout and delete all sessions for the user's API keys
    if user.api_keys:
        for api_key in user.api_keys:
            api_key_sessions = await SM.get_sessions_by_apikey(str(api_key.id))
            for ak_session in api_key_sessions:
                await ak_session.logout()

    # Logout all sessions for the user
    user_sessions = await SM.get_sessions_by_user(user_id)
    for us in user_sessions:
        await us.logout()

    # Deleting the user will also delete all associated API keys
    # due to the reverse_delete_rule=CASCADE on the ApiKey.user field.
    user.delete()

    return OK(ok=True)