import logging
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi_limiter.depends import RateLimiter
from pydantic import BaseModel
from typing import Union, List
from datetime import datetime, timezone
from models.user import User
from models.api_key import ApiKey
from session import SessionManager
from config import Config
from ..api_auth import SM, auth, no_auth, BOSS_ROLE, get_user_or_apikey_from_session
from .schemas import AuthUserResponse, AuthAPIKeyResponse, AuthWebRTCResponse, AuthUser, AuthAPIKey, AuthRequest, OK
from session import SessionUser, SessionAPIKey, SessionWebRTC

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CONFIG = Config()

router = APIRouter(tags=["Authentication"])

@router.post(
    "/api/v1/auth/token",
    response_model=Union[AuthUserResponse, AuthAPIKeyResponse],
    tags=["Authentication"],
    dependencies=[Depends(CONFIG.API_LVL3_RATE_LIMITER)],
    description="Authenticate a user with a username and password. Creates a new session token and returns detailed session information."
)
async def api_auth_login(auth: AuthRequest) -> Union[AuthUserResponse, AuthAPIKeyResponse]:
    """Authenticate a user or API key and create a new session token."""
    if auth.type == "user" and auth.username and auth.password:
        session, user = await SM.login(auth.username, auth.password)

        user.last_login = datetime.now(timezone.utc)
        user.save()

        return AuthUserResponse(
            token=session.id,
            session_type="user",
            creation_date=session.creation_date,
            expiration_date=session.expiration_date,
            user=AuthUser(
                id=str(user.id),
                username=user.username,
                last_login=user.last_login,
                roles=[str(role.id) for role in user.roles],
            ),
        )

    elif auth.type == "apikey" and auth.key:
        session_apikey, apikey = await SM.login_apikey(auth.key)

        return AuthAPIKeyResponse(
            token=session_apikey.id,
            session_type="apikey",
            creation_date=session_apikey.creation_date,
            expiration_date=session_apikey.expiration_date,
            api_key=AuthAPIKey(
                id=str(apikey.id),
                roles=[str(role.id) for role in apikey.roles],
                created_at=apikey.created_at,
                expiration=apikey.expiration,
            ),
        )

    else:
        raise HTTPException(status_code=400, detail="Invalid authentication type or missing credentials.")


@router.get(
    "/api/v1/auth/status",
    response_model=Union[AuthUserResponse, AuthAPIKeyResponse, AuthWebRTCResponse],
    tags=["Authentication"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Return the current authentication sessions details, including token and user information."
)
async def api_auth_status(session: Union[SessionUser, SessionAPIKey] = Depends(no_auth())) -> Union[AuthUserResponse, AuthAPIKeyResponse]:
    """Check the current authentication session status."""
    user_or_apikey = get_user_or_apikey_from_session(session)

    if isinstance(user_or_apikey, User):
        return AuthUserResponse(
            token=session.id,
            session_type="user",
            creation_date=session.creation_date,
            expiration_date=session.expiration_date,
            user=AuthUser(
                id=str(user_or_apikey.id),
                username=user_or_apikey.username,
                roles=[str(role.id) for role in user_or_apikey.roles],
                last_login=user_or_apikey.last_login,
            ),
        )
    elif isinstance(user_or_apikey, ApiKey):
        return AuthAPIKeyResponse(
            token=session.id,
            session_type="apikey",
            creation_date=session.creation_date,
            expiration_date=session.expiration_date,
            api_key=AuthAPIKey(
                id=str(user_or_apikey.id),
                roles=[str(role.id) for role in user_or_apikey.roles],
                created_at=user_or_apikey.created_at,
                expiration=user_or_apikey.expiration,
            ),
        )

@router.delete(
    "/api/v1/auth/logout",
    response_model=OK,
    tags=["Authentication"],
    dependencies=[Depends(CONFIG.API_LVL3_RATE_LIMITER)],
    description="Logout the current user session, invalidating the session token."
)
async def api_auth_logout(session: Union[SessionUser, SessionAPIKey]= Depends(no_auth())) -> OK:
    await session.logout()
    return OK(ok=True)


class AuthSessionResponse(BaseModel):
    sessions: List[Union[AuthUserResponse, AuthAPIKeyResponse, AuthWebRTCResponse]]

@router.get(
    "/api/v1/auth/sessions",
    response_model=AuthSessionResponse,
    tags=["Authentication"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="For administrative users: Retrieve a list of all active sessions with detailed session information."
)
async def api_auth_sessions(session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))) -> AuthSessionResponse:
    """For administrative users: Retrieve a list of all active sessions with detailed session information."""
    sessions = await SM.get_sessions()
    return_sessions: List[Union[AuthUserResponse, AuthAPIKeyResponse, AuthWebRTCResponse]] = []
    for s in sessions.values():
        if isinstance(s, (SessionUser, SessionAPIKey)):
            try:
                user_or_apikey = get_user_or_apikey_from_session(s)
            except HTTPException:
                continue  # Skip sessions with missing users/apikeys

            if isinstance(user_or_apikey, User):
                return_sessions.append(
                    AuthUserResponse(
                        token=s.id,
                        session_type="user",
                        creation_date=s.creation_date,
                        expiration_date=s.expiration_date,
                        user=AuthUser(
                            id=str(user_or_apikey.id),
                            username=user_or_apikey.username,
                            roles=[str(role.id) for role in user_or_apikey.roles],
                            last_login=user_or_apikey.last_login,
                        ),
                    )
                )
            elif isinstance(user_or_apikey, ApiKey):
                return_sessions.append(
                    AuthAPIKeyResponse(
                        token=s.id,
                        session_type="apikey",
                        creation_date=s.creation_date,
                        expiration_date=s.expiration_date,
                        api_key=AuthAPIKey(
                            id=str(user_or_apikey.id),
                            roles=[str(role.id) for role in user_or_apikey.roles],
                            created_at=user_or_apikey.created_at,
                            expiration=user_or_apikey.expiration,
                        ),
                    )
                )
        elif isinstance(s, SessionWebRTC):
            return_sessions.append(
                AuthWebRTCResponse(
                    token=s.id,
                    session_type="webrtc",
                    creation_date=s.creation_date,
                    expiration_date=s.expiration_date,
                )
            )

    return AuthSessionResponse(sessions=return_sessions)


@router.delete(
    "/api/v1/auth/session/{token}",
    response_model=OK,
    tags=["Authentication"],
    dependencies=[Depends(CONFIG.API_LVL3_RATE_LIMITER)],
    description="For administrators only: Logout a specific session identified by its token."
)
async def api_auth_session_logout(token: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE]))) -> OK:
   
    s = await SM.get_session(token)
    if s is None:
        raise HTTPException(status_code=404, detail="Session not found")
    
    await s.logout()
    return OK(ok=True)