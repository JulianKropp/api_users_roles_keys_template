import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from enum import Enum
import fnmatch
from math import ceil
import os
import re
from typing import AsyncIterator, Awaitable, Callable, Dict, List, Optional, Tuple, Union, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.routing import APIRoute
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi_limiter import FastAPILimiter
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from pydantic import BaseModel
import redis.asyncio as redis
from starlette.datastructures import Headers
import uvicorn
from aiortc import RTCPeerConnection, RTCSessionDescription, MediaStreamTrack

from config import Config
from mongoengine import Document, connect
from mongoengine import disconnect # type: ignore
from user import User
from role import Endpoint, Role, Method
from api_key import ApiKey
from session import Session, SessionWebRTC, SessionAPIKey, SessionUser, SessionManager
from webrtc import AudioPeerManager, AudioPeer, ErrorResponse, OfferRequest, OfferResponse, OggOpusRecorder, PeerIDRequest, StatusResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STATUS: Literal["starting", "running", "stopping", "stopped"] = "starting"

# ---------------------------
# Configuration
# ---------------------------
# Load environment variables from .env file
CONFIG = Config()

# connect to db
connect(
    db=CONFIG.MONGO_DB_NAME,
    host=CONFIG.MONGO_HOST,
    port=CONFIG.MONGO_PORT,
    username=CONFIG.MONGO_USER,
    password=CONFIG.MONGO_PASSWORD,
    authentication_source=CONFIG.MONGO_AUTH_SOURCE
)

# API Rate Limiters
LVL0_RATE_LIMITER = RateLimiter(times=6000, minutes=1)
LVL1_RATE_LIMITER = RateLimiter(times=600, minutes=1)
LVL2_RATE_LIMITER = RateLimiter(times=60, minutes=1)
LVL3_RATE_LIMITER = RateLimiter(times=6, minutes=1)

APM = AudioPeerManager(CONFIG.WEBRTC_TIMEOUT)

# ---------------------------
# Setup db
# ---------------------------
# Create default boss role if it doesn't exist
if not Role.objects(rolename="boss").first(): # type: ignore[attr-defined]
    boss_role = Role(
        rolename="boss",
        api_endpoints=[
            Endpoint(
                method=Method.ANY,
                path_filter="/*"
            )
        ]
    )
    print(boss_role.to_mongo())
    boss_role.save()

BOSS_ROLE = Role.objects(rolename="boss").first() # type: ignore[attr-defined]
if BOSS_ROLE is None:
    raise Exception("Boss role not found. Please reinitialize the database.")

# create a boss user if it doesn't exist
if not User.objects(username="boss").first(): # type: ignore[attr-defined]
    boss_user = User(
        username="boss",
        roles=[BOSS_ROLE]
    )
    boss_user.set_password("boss")
    boss_user.save()

# check if the boss user has the boss role, and add it if not
BOSS_USER = User.objects(username="boss").first() # type: ignore[attr-defined]
if not BOSS_ROLE in BOSS_USER.roles: # type: ignore[attr-defined]
    BOSS_USER.roles.append(BOSS_ROLE) # type: ignore[attr-defined]
    BOSS_USER.save()

# ---------------------------
# FastAPI App Initialization
# ---------------------------
# Identify the service by the Service-Name header or the IP address
async def service_name_identifier(request: Request) -> Union[str, Headers]:
    if request.client is None:
        return "unknown"
    return request.headers.get("Service-Name") or request.client.host  # Identify by IP if no header

async def rate_limit_exceeded_callback(request: Request, response: Response, pexpire: int) -> None:
    """
    default callback when too many requests
    :param request:
    :param pexpire: The remaining milliseconds
    :param response:
    :return:
    """
    expire = ceil(pexpire / 1000)

    raise HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        f"Too Many Requests. Retry after {expire} seconds.",
        headers={"Retry-After": str(expire)},
    )

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Connect to Redis
    redis_connection = redis.from_url(CONFIG.REDIS_URL, encoding="utf8", decode_responses=True)
    await FastAPILimiter.init(
        redis_connection,
        identifier=service_name_identifier,
        http_callback=rate_limit_exceeded_callback,
    )

    # Check for timeouts for WebRTC connections
    asyncio.create_task(APM.check_timeouts())

    try:
        yield
    finally:
        # Disconnect from MongoDB
        disconnect()
        # Close Redis connection
        await FastAPILimiter.close()

app = FastAPI(
    lifespan=lifespan,
    title="User Management API",
    description="An API for managing users, roles, authentication sessions, and API keys.",
    version="1.0",
    openapi_tags=[
        {
            "name": "Webpage",
            "description": "Webpage endpoints"
        },
        {
            "name": "System",
            "description": "System information endpoints"
        },
        {
            "name": "Authentication",
            "description": "User and API key authentication endpoints"
        },
        {
            "name": "Roles",
            "description": "Role management endpoints"
        },
        {
            "name": "Users",
            "description": "User management endpoints"
        },
        {
            "name": "API Keys",
            "description": "API key management endpoints"
        },
        {
            "name": "WebRTC",
            "description": "WebRTC communication endpoints"
        }
    ]
)

# ---------------------------
# CORS Middleware
# ---------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[CONFIG.EXTERNAL_URL],  # Allowed Origins from the frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Authentication Dependencies
# ---------------------------
security = HTTPBearer()

# Session Manager for getting the user session
SM = SessionManager(session_duration=CONFIG.SESSION_DURATION_SECONDS)

def check_role(role: Role, request: Endpoint) -> bool:
    """
    Check if the given role grants access to the specified endpoint.
    It converts the role's endpoint patterns into regexes; any '*' is replaced with '.*'.
    """
    for endpoint in role.api_endpoints:
        # check if the request method is the same
        if endpoint.method != Method.ANY and endpoint.method != request.method:
            continue

        # Escape special regex characters, then replace the escaped wildcard with regex equivalent.
        regex_pattern = '^' + re.escape(endpoint.path_filter).replace(r'\*', '.*') + '$'
        if re.match(regex_pattern, request.path_filter):
            return True
    return False

def compare_roles(
    request_role: Union[List[Role], Role],
    new_role: Role
) -> bool:
    """
    Validate that **`new_role` never grants *more* than any of the
    `request_role`s passed in.

    Parameters
    ----------
    request_role : Role | List[Role]
        A single role or a list of roles that represent the *maximum* authority
        allowed.  `new_role` must stay within the intersection of all these
        roles permissions.
    new_role : Role
        The role we want to verify.

    Returns
    -------
    bool
        • **True**  - `new_role` is a subset (or equal) of *every* role in
          `request_role`.  
        • **False** - `new_role` has at least one permission that **any** of
          the `request_role`s does **not** grant.

    Notes
    -----
    We rely on the existing `check_role` helper so wildcard/method/path
    semantics stay identical across the code-base.
    """
    # Normalise to a list so the same logic works for single & multiple roles
    roles_to_check: List[Role] = (
        request_role if isinstance(request_role, list) else [request_role]
    )

    # For every permission in new_role, confirm that *all* request roles cover it
    for new_endpoint in new_role.api_endpoints:
        for req_role in roles_to_check:
            if not check_role(req_role, new_endpoint):
                # Found a permission that req_role lacks -> new_role is broader
                return False

    # new_role never exceeded any request_role’s permissions
    return True


def get_user_roles_by_session(session: Union[SessionUser, SessionAPIKey]) -> List[Role]:
    if isinstance(session, SessionUser):
        user = User.objects(id=session.user_id).first() # type: ignore[attr-defined]
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return user.roles
    elif isinstance(session, SessionAPIKey):
        api_key = ApiKey.objects(id=session.apikey_id).first() # type: ignore[attr-defined]
        if api_key is None:
            raise HTTPException(status_code=404, detail="ApiKey not found")
        return api_key.roles

def get_user_or_apikey_from_session(session: Session) -> Union[User, ApiKey]:
    """Retrieves a User or ApiKey object from a session."""
    logger.debug(f"Session of type {session.__class__.__name__} for token: {session.id}")

    if isinstance(session, SessionUser):
        user = User.objects(id=session.user_id).first() # type: ignore[attr-defined]
        if not user:
            logger.error(f"User {session.user_id} not found for token: {session.id}")
            raise HTTPException(status_code=403, detail="Invalid authentication token")
        return user
    elif isinstance(session, SessionAPIKey):
        api_key = ApiKey.objects(id=session.apikey_id).first() # type: ignore[attr-defined]
        if not api_key:
            logger.error(f"ApiKey {session.apikey_id} not found for token: {session.id}")
            raise HTTPException(status_code=403, detail="Invalid authentication token")
        return api_key
    else:
        logger.error(f"Unsupported session type: {session.__class__.__name__}")
        raise HTTPException(status_code=403, detail="Invalid authentication token")

# get session from token
def auth(required_roles: Optional[List[Optional[Role]]] = None) -> Callable[[Request, HTTPAuthorizationCredentials], Awaitable[Union[SessionUser, SessionAPIKey]]]:
    """
    Authentication dependency that returns a session if access is granted.
    It first checks if the user has one of the required roles directly.
    If not, it checks the request path against the API endpoint patterns defined in each role.
    
    The API endpoint is printed/formatted (e.g., GET-/endpoint) as indicated in the docstring.
    """
    async def new_auth(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)) -> Union[SessionUser, SessionAPIKey]:
        token = credentials.credentials
        session = await SM.get_session(token)
        if session is None:
            logger.info(f"Session not found for token: {token}")
            raise HTTPException(status_code=403, detail="Invalid authentication token")

        # check if the session is of a supported type
        if not isinstance(session, (SessionUser, SessionAPIKey)):
            logger.error(f"Session type {session.__class__.__name__} not supported for token: {session.id}")
            raise HTTPException(status_code=403, detail="Invalid authentication token")

        # get user
        user_or_apikey = get_user_or_apikey_from_session(session)
        
        # check if apikey is expired
        if isinstance(user_or_apikey, ApiKey):
            if user_or_apikey.is_expired():
                logger.error(f"ApiKey {user_or_apikey.id} is expired for token: {session.id}")
                raise HTTPException(status_code=403, detail="Invalid authentication token")

        roles = user_or_apikey.roles

        roles_names = [role.rolename for role in roles]
        
        # If specific required roles are provided, check if the user has at least one of them.
        if required_roles is not None:
            if any(role.rolename in roles_names for role in required_roles if role is not None):
                return session

        # current request method and path
        new_request = Endpoint(
            method=Method(request.method),
            path_filter=request.url.path
        )


        # Build a list of Role objects corresponding to the user's roles.
        roles_list = [role for role in roles if role.rolename in roles_names]

        # Check if any of the user's roles permit access to the requested endpoint.
        for role_obj in roles_list:
            if check_role(role_obj, new_request):
                return session

        # If no matching role endpoint pattern is found, deny access.
        raise HTTPException(status_code=403, detail="Access forbidden")

    return new_auth


def no_auth() -> Callable[[Request, HTTPAuthorizationCredentials], Awaitable[Union[SessionUser, SessionAPIKey]]]:
    """
    Authentication dependency that returns a session if access is granted.
    It first checks if the user has one of the required roles directly.
    If not, it checks the request path against the API endpoint patterns defined in each role.
    
    The API endpoint is printed/formatted (e.g., GET-/endpoint) as indicated in the docstring.
    """
    async def new_auth(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)) -> Union[SessionUser, SessionAPIKey]:
        token = credentials.credentials
        session = await SM.get_session(token)
        if session is None:
            logger.info(f"Session not found for token: {token}")
            raise HTTPException(status_code=403, detail="Invalid authentication token")

        # check if the session is of a supported type
        if not isinstance(session, (SessionUser, SessionAPIKey)):
            logger.error(f"Session type {session.__class__.__name__} not supported for token: {session.id}")
            raise HTTPException(status_code=403, detail="Invalid authentication token. Only User and ApiKey sessions are supported.")

        # get user
        user_or_apikey = get_user_or_apikey_from_session(session)

        # check if apikey is expired
        if isinstance(user_or_apikey, ApiKey):
            if user_or_apikey.is_expired():
                logger.error(f"ApiKey {user_or_apikey.id} is expired for token: {session.id}")
                raise HTTPException(status_code=403, detail="Invalid authentication token")

        return session

    return new_auth

# ---------------------------
# Auth Endpoints
# ---------------------------
# Auth models
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

@app.post(
    "/api/v1/auth/token",
    response_model=Union[AuthUserResponse, AuthAPIKeyResponse, AuthWebRTCResponse],
    tags=["Authentication"],
    dependencies=[Depends(LVL3_RATE_LIMITER)],
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


@app.get(
    "/api/v1/auth/status",
    response_model=Union[AuthUserResponse, AuthAPIKeyResponse, AuthWebRTCResponse],
    tags=["Authentication"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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

# Logout model
class OK(BaseModel):
    ok: bool

@app.delete(
    "/api/v1/auth/logout",
    response_model=OK,
    tags=["Authentication"],
    dependencies=[Depends(LVL3_RATE_LIMITER)],
    description="Logout the current user session, invalidating the session token."
)
async def api_auth_logout(session: Union[SessionUser, SessionAPIKey]= Depends(no_auth())) -> OK:
    await session.logout()
    return OK(ok=True)


class AuthSessionResponse(BaseModel):
    sessions: List[Union[AuthUserResponse, AuthAPIKeyResponse, AuthWebRTCResponse]]

@app.get(
    "/api/v1/auth/sessions",
    response_model=AuthSessionResponse,
    tags=["Authentication"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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


@app.delete(
    "/api/v1/auth/session/{token}",
    response_model=OK,
    tags=["Authentication"],
    dependencies=[Depends(LVL3_RATE_LIMITER)],
    description="For administrators only: Logout a specific session identified by its token."
)
async def api_auth_session_logout(token: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE]))) -> OK:
   
    s = await SM.get_session(token)
    if s is None:
        raise HTTPException(status_code=404, detail="Session not found")
    
    await s.logout()
    return OK(ok=True)


# ---------------------------
# Role Endpoints
# ---------------------------
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

@app.get(
    "/api/v1/roles",
    response_model=List[RoleResponse],
    tags=["Roles"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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

@app.get(
    "/api/v1/role/{role_id}",
    response_model=RoleResponse,
    tags=["Roles"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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

@app.post(
    "/api/v1/role",
    response_model=RoleResponse,
    status_code=201,
    tags=["Roles"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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

@app.delete(
    "/api/v1/role/{role_id}",
    response_model=OK,
    tags=["Roles"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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

@app.put(
    "/api/v1/role/{role_id}",
    response_model=RoleResponse,
    tags=["Roles"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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



# ---------------------------
# User Endpoints
# ---------------------------
class UserResponse(BaseModel):
    id: str
    username: str
    roles: List[str]
    last_login: Optional[datetime]

@app.get(
    "/api/v1/users",
    response_model=List[UserResponse],
    tags=["Users"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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

# create a user
class UserCreate(BaseModel):
    username: str
    password: str 
    roles: Optional[List[str]] = []

@app.post(
    "/api/v1/user",
    response_model=UserResponse,
    status_code=201,
    tags=["Users"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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

# update user password
class UserUpdatePassword(BaseModel):
    current_password: str
    new_password: str

@app.put(
    "/api/v1/user/password",
    response_model=OK,
    tags=["Users"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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

class UserResetPassword(BaseModel):
    new_password: str

@app.put(
    "/api/v1/user/{user_id}/password",
    response_model=OK,
    tags=["Users"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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

class UserSetRole(BaseModel):
    roles: List[str]

@app.put(
    "/api/v1/user/{user_id}/roles",
    response_model=UserResponse,
    tags=["Users"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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

@app.delete(
    "/api/v1/user/{user_id}",
    response_model=OK,
    tags=["Users"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
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




# ---------------------------
# API Key Endpoints
# ---------------------------
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

def _list_apikeys(user_id: str) -> List[APIKeyResponse]:
    user = User.objects(id=user_id).first() # type: ignore[attr-defined]
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return [
        APIKeyResponse(
            id=str(api_key.id),
            roles=[str(role.id) for role in api_key.roles],
            created_at=api_key.created_at,
            expiration=api_key.expiration,
        )
        for api_key in user.api_keys
    ]


def _get_apikey(user_id: str, apikey_id: str) -> APIKeyResponse:
    user = User.objects(id=user_id).first() # type: ignore[attr-defined]
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    api_key = ApiKey.objects(id=apikey_id).first() # type: ignore[attr-defined]
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    if api_key.user != user:
        raise HTTPException(status_code=403, detail="API key does not belong to the user")

    return APIKeyResponse(
        id=str(api_key.id),
        roles=[str(role.id) for role in api_key.roles],
        created_at=api_key.created_at,
        expiration=api_key.expiration,
    )


def _create_apikey(session: Union[SessionUser, SessionAPIKey], user_id: str, req: APIKeyCreateRequest) -> APIKeyCreateResponse:
    """Helper function to create a new API key for a user.
    
    Args:
        session: The current user session
        user_id: The ID of the user to create the API key for
        req: The API key creation request
        
    Returns:
        APIKeyCreateResponse with the new API key details
        
    Raises:
        HTTPException: If validation fails or an error occurs
    """
    try:
        # Check if expiration date is in the past
        now = datetime.now(timezone.utc)
        if req.expiration is not None and req.expiration < now:
            raise HTTPException(
                status_code=400, 
                detail="Expiration date cannot be in the past"
            )

        # Get the user
        user_obj = User.objects(id=user_id).first()  # type: ignore[attr-defined]
        if user_obj is None:
            raise HTTPException(status_code=404, detail="User not found")

        # Validate roles
        roles = []
        if req.roles:
            roles = list(Role.objects(id__in=req.roles))  # type: ignore[attr-defined]
            if len(roles) != len(req.roles):
                raise HTTPException(
                    status_code=400, 
                    detail="One or more roles do not exist"
                )

        # Check if the new roles are broader than the user's roles
        req_user_roles = get_user_roles_by_session(session)
        for r in roles:
            if not compare_roles(req_user_roles, r):
                raise HTTPException(
                    status_code=403, 
                    detail=(
                        "You do not have permission to create an API key with these roles. "
                        "The roles you assigned are broader than your current roles."
                    )
                )

        # Create the new API key
        api_key, raw_key = ApiKey.create_key(
            user=user_obj, 
            roles=roles, 
            expiration=req.expiration
        )

        # Add the new key to the user's list of keys and save
        user_obj.api_keys.append(api_key)
        user_obj.save()

        # Log the creation (without exposing the raw key)
        logger.info(f"Created API key {api_key.id} for user {user_id}")

        return APIKeyCreateResponse(
            id=str(api_key.id),
            key=raw_key,  # This is the only time the raw key is exposed
            roles=[str(role.id) for role in api_key.roles],
            created_at=api_key.created_at,
            expiration=api_key.expiration,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating API key for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while creating the API key"
        )


def _delete_apikey(user_id: str, apikey_id: str) -> OK:
    """Helper function to delete an API key.
    
    Args:
        user_id: The ID of the user who owns the API key
        apikey_id: The ID of the API key to delete
        
    Returns:
        OK response if successful
        
    Raises:
        HTTPException: If the user or API key is not found, or if an error occurs
    """
    try:
        # Get the user
        user = User.objects(id=user_id).first()  # type: ignore[attr-defined]
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Find the API key to get its details for logging
        api_key = ApiKey.objects(id=apikey_id).first()  # type: ignore[attr-defined]
        if not api_key:
            # The API key doesn't exist at all
            raise HTTPException(status_code=404, detail="API key not found")

        # Check if the API key belongs to the user
        if str(api_key.user.id) != user_id:  # type: ignore[attr-defined]
            raise HTTPException(
                status_code=403, 
                detail="API key does not belong to the specified user"
            )

        # Delete the API key document from the database
        ApiKey.objects(id=apikey_id).delete()  # type: ignore[attr-defined]
        
        logger.info(f"Deleted API key {apikey_id} for user {user_id}")
        return OK(ok=True)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting API key {apikey_id} for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while deleting the API key"
        )


def _update_apikey(user_id: str, apikey_id: str, req: APIKeyPutRequest) -> APIKeyResponse:
    """Helper function to update an existing API key.
    
    Args:
        user_id: The ID of the user who owns the API key
        apikey_id: The ID of the API key to update
        req: The update request containing new values
        
    Returns:
        APIKeyResponse with the updated API key details
        
    Raises:
        HTTPException: If validation fails or an error occurs
    """
    try:
        # Get the user
        user = User.objects(id=user_id).first()  # type: ignore[attr-defined]
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Find the API key document (not just the reference in user.api_keys)
        api_key = ApiKey.objects(id=apikey_id).first()  # type: ignore[attr-defined]
        if not api_key:
            raise HTTPException(status_code=404, detail="API key not found")
            
        # Verify the API key belongs to the user
        if str(api_key.user.id) != user_id:  # type: ignore[attr-defined]
            raise HTTPException(
                status_code=403, 
                detail="API key does not belong to the specified user"
            )

        # Check if the API key is in the user's list (should be, but verify)
        user_api_key = next((key for key in user.api_keys if str(key.id) == apikey_id), None)
        if not user_api_key:
            # This should not happen if the API key exists and belongs to the user
            raise HTTPException(
                status_code=404, 
                detail="API key not associated with this user"
            )

        # Update roles if provided
        if req.roles is not None:
            roles = list(Role.objects(id__in=req.roles))  # type: ignore[attr-defined]
            if len(roles) != len(req.roles):
                raise HTTPException(
                    status_code=400, 
                    detail="One or more roles do not exist"
                )
            api_key.roles = roles

        # Update expiration if provided
        if req.expiration is not None:
            # Check if the new expiration is in the past
            if req.expiration < datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=400, 
                    detail="Expiration date cannot be in the past"
                )
            api_key.expiration = req.expiration

        # Save the updated API key
        api_key.updated_at = datetime.now(timezone.utc)
        api_key.save()
        
        # Also update the reference in the user's api_keys list
        for key in user.api_keys:
            if str(key.id) == apikey_id:
                key.roles = api_key.roles
                key.expiration = api_key.expiration
                key.updated_at = api_key.updated_at
                break
        user.save()
        
        logger.info(f"Updated API key {apikey_id} for user {user_id}")

        return APIKeyResponse(
            id=str(api_key.id),
            roles=[str(role.id) for role in api_key.roles],
            created_at=api_key.created_at,
            expiration=api_key.expiration,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating API key {apikey_id} for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while updating the API key"
        )


@app.get(
    "/api/v1/user/{user_id}/apikeys",
    response_model=List[APIKeyResponse],
    tags=["API Keys"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="List all API keys for a specific user (admin only)"
)
async def api_list_apikeys(
    user_id: str, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> List[APIKeyResponse]:
    """List all API keys for a specific user."""
    return _list_apikeys(user_id)


@app.get(
    "/api/v1/user/me/apikeys",
    response_model=List[APIKeyResponse],
    tags=["API Keys"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="List current user's API keys"
)
async def api_list_own_apikeys(
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> List[APIKeyResponse]:
    """List all API keys for the currently authenticated user."""
    if isinstance(session, SessionAPIKey):
        logger.warning(f"Attempt to list API keys using API key session: {session.id}")
        raise HTTPException(
            status_code=403,
            detail="You cannot list the API keys using an API key session. Please use a user session."
        )

    return _list_apikeys(session.user_id)


@app.get(
    "/api/v1/user/{user_id}/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    tags=["API Keys"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Get a specific API key for a user (admin only)"
)
async def api_get_apikey(
    user_id: str, 
    apikey_id: str, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> APIKeyResponse:
    """Get a specific API key for a user."""
    return _get_apikey(user_id, apikey_id)


@app.get(
    "/api/v1/user/me/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    tags=["API Keys"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Get a specific API key for the current user"
)
async def api_get_own_apikey(
    apikey_id: str, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> APIKeyResponse:
    """Get a specific API key for the currently authenticated user."""
    if isinstance(session, SessionAPIKey):
        logger.warning(f"Attempt to get API key using API key session: {session.id}")
        raise HTTPException(
            status_code=403,
            detail="You cannot get an API key using an API key session. Please use a user session."
        )
    return _get_apikey(session.user_id, apikey_id)


@app.post(
    "/api/v1/user/{user_id}/apikey",
    response_model=APIKeyCreateResponse,
    status_code=201,
    tags=["API Keys"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Create a new API key for a user (admin only)"
)
async def api_create_apikey(
    user_id: str,
    apikey: APIKeyCreateRequest,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE])),
) -> APIKeyCreateResponse:
    """Create a new API key for a user."""
    return _create_apikey(session, user_id, apikey)


@app.post(
    "/api/v1/user/me/apikey",
    response_model=APIKeyCreateResponse,
    status_code=201,
    tags=["API Keys"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Create a new API key for the current user"
)
async def api_create_own_apikey(
    apikey: APIKeyCreateRequest, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> APIKeyCreateResponse:
    """Create a new API key for the currently authenticated user."""
    if isinstance(session, SessionAPIKey):
        logger.warning(f"Attempt to create API key using API key session: {session.id}")
        raise HTTPException(
            status_code=403,
            detail="You cannot create an API key using an API key session. Please use a user session."
        )
    
    return _create_apikey(session, session.user_id, apikey)


@app.delete(
    "/api/v1/user/{user_id}/apikey/{apikey_id}",
    response_model=OK,
    tags=["API Keys"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Delete a specific API key for a user (admin only)"
)
async def api_delete_apikey(
    user_id: str, 
    apikey_id: str, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> OK:
    """Delete a specific API key for a user."""
    return _delete_apikey(user_id, apikey_id)


@app.delete(
    "/api/v1/user/me/apikey/{apikey_id}",
    response_model=OK,
    tags=["API Keys"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Delete a specific API key for the current user"
)
async def api_delete_own_apikey(
    apikey_id: str, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> OK:
    """Delete a specific API key for the currently authenticated user."""
    if isinstance(session, SessionAPIKey):
        logger.warning(f"Attempt to delete API key using API key session: {session.id}")
        raise HTTPException(
            status_code=403,
            detail="You cannot delete an API key using an API key session. Please use a user session."
        )

    return _delete_apikey(session.user_id, apikey_id)


@app.put(
    "/api/v1/user/{user_id}/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    tags=["API Keys"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Update a specific API key for a user (admin only)"
)
async def api_update_apikey(
    user_id: str,
    apikey_id: str,
    apikey: APIKeyPutRequest,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE])),
) -> APIKeyResponse:
    """Update a specific API key for a user."""
    return _update_apikey(user_id, apikey_id, apikey)


@app.put(
    "/api/v1/user/me/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    tags=["API Keys"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Update a specific API key for the current user"
)
async def api_update_own_apikey(
    apikey_id: str,
    apikey: APIKeyPutRequest,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE])),
) -> APIKeyResponse:
    """Update a specific API key for the currently authenticated user."""
    if isinstance(session, SessionAPIKey):
        logger.warning(f"Attempt to update API key using API key session: {session.id}")
        raise HTTPException(
            status_code=403,
            detail="You cannot update an API key using an API key session. Please use a user session."
        )

    return _update_apikey(session.user_id, apikey_id, apikey)



# ---------------------------
# API info
# ---------------------------
class APIendpointResponse(BaseModel):
    method: str
    path: str

@app.get(
    "/api/v1/endpoints",
    response_model=List[APIendpointResponse],
    tags=["System"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="List all available API endpoints"
)
def list_endpoints() -> List[APIendpointResponse]:
    endpoints: List[APIendpointResponse] = []
    for route in app.routes:
        # only include standard HTTP routes (skip websockets, static, etc.)
        if isinstance(route, APIRoute):
            for method in sorted(route.methods):
                # you can also filter by prefix if you only want /api/v1/…
                # if not route.path.startswith("/api/v1"):
                #     continue
                endpoints.append(
                    APIendpointResponse(
                        method=method,
                        path=route.path
                    )
                )
    return endpoints

class APIHealthResponse(BaseModel):
    status: Literal["starting", "running", "stopping", "stopped"]
    version: str

@app.get(
    "/api/v1/health",
    response_model=APIHealthResponse,
    tags=["System"],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Check if the API is running"
)
def health() -> APIHealthResponse:
    return APIHealthResponse(
        status=STATUS,
        version="1.0.0"
    )

# ---------------------------
# WebRTC
# ---------------------------
@app.post(
        "/api/v1/webrtc/offer",
        response_model=OfferResponse,
        tags=["WebRTC"],
        responses={400: {"model": ErrorResponse}},
        dependencies=[Depends(LVL2_RATE_LIMITER)],
        description="Handle WebRTC offer and return an answer."
        )
async def offer(
    request_data: OfferRequest,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE])),
    ) -> OfferResponse:
    offer = RTCSessionDescription(
        sdp=request_data.sdp,
        type=request_data.type
    )

    webrtc_peer = await SM.login_webrtc(session)
    peer_id = webrtc_peer.id

    pc = RTCPeerConnection()

    @pc.on("connectionstatechange")
    async def on_connectionstatechange() -> None:
        logger.info(f"Connection state for peer {peer_id} is {pc.connectionState}")
        if pc.connectionState in ["failed", "closed"]:
            try:
                await APM.remove_peer(peer_id)
                try:
                    await SM.logout(peer_id)
                except Exception as e:
                    logger.error(f"Error logging out peer {peer_id}: {e}")
            except Exception as e:
                logger.error(f"Error cleaning up peer {peer_id}: {e}")

    async def on_close(webrtc_peer_id: str) -> None:
        logger.info(f"Peer {webrtc_peer_id} connection closed")
        try:
            await SM.logout(webrtc_peer_id)
        except Exception as e:
            logger.error(f"Error logging out peer {webrtc_peer_id}: {e}")

    # Call on_close after 5 seconds if the connection isnt astablished
    async def close_after_timeout() -> None:
        await asyncio.sleep(CONFIG.WEBRTC_TIMEOUT)
        await on_close(peer_id)
    init_time_out = asyncio.create_task(close_after_timeout())

    @pc.on("track")
    def on_track(track: MediaStreamTrack) -> None:
        logger.info(f"Received {track.kind} track for peer {peer_id}")
        if track.kind == "audio":
            # cancel the close_after_timeout task if we received a track
            init_time_out.cancel()
            # Create an AudioPeer object to handle the audio track
            peer_obj = AudioPeer(pc=pc, track=track, user_id=session.id, session_id=session.id, peer_id=peer_id, converter=OggOpusRecorder(file_name=peer_id), on_close=on_close)
            APM.add_peer(peer_obj)

    await pc.setRemoteDescription(offer)
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)

    return OfferResponse(
        sdp=pc.localDescription.sdp,
        type=pc.localDescription.type,
        peer_id=peer_id
    )

@app.post(
    "/api/v1/webrtc/recording/{peer_id}/start",
    response_model=StatusResponse,
    tags=["WebRTC"],
    responses={400: {"model": ErrorResponse}},
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Start recording for a specific peer."
)
async def start_recording(
    peer_id: str,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE])),
    ) -> StatusResponse:

    # get the webrtc sessions of this user
    webrtc_sessions = await SM.get_webrtc_sessions_from_session(session)

    if peer_id not in [ws.id for ws in webrtc_sessions]:
        raise HTTPException(status_code=403, detail="The peer does not belong to your WebRTC sessions.")

    ap = await APM.get_peer(peer_id)
    if not peer_id or ap is None:
        raise HTTPException(status_code=400, detail="Invalid peer ID")

    try:
        await ap.start_recording()
        return StatusResponse(status="Recording started")
    except Exception as e:
        logger.error(f"Error starting recording: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete(
    "/api/v1/webrtc/{peer_id}/stop_recording",
    tags=["WebRTC"],
    response_model=StatusResponse,
    responses={400: {"model": ErrorResponse}},
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Stop recording for a specific peer."
)
async def stop_recording(
    peer_id: str,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE])),
    ) -> StatusResponse:
    ap = await APM.get_peer(peer_id)
    if not peer_id or ap is None:
        raise HTTPException(status_code=400, detail="Invalid peer ID")

    try:
        await ap.stop_recording()
        return StatusResponse(status="Recording stopped")
    except Exception as e:
        logger.error(f"Error stopping recording: {e}")
        raise HTTPException(status_code=500, detail=str(e))

class WebRTCSession(BaseModel):
    id: str
    expiration_date: datetime
    creation_date: datetime
    user_id: str
    parent_session_id: str

@app.get(
    "/api/v1/webrtc/sessions",
    tags=["WebRTC"],
    response_model=List[WebRTCSession],
    dependencies=[Depends(LVL2_RATE_LIMITER)]
)
async def get_webrtc_sessions(
    user_id: str = "*",
    user_or_api_session_type: Literal["user", "api_key", "*"] = "*",
    session_id: str = "*",
    node_id: str = "*",
    webrtc_id: str = "*",
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE])),
) -> List[WebRTCSession]:
    """
    Retrieve a list of all WebRTC sessions according to the filters provided.
    """
    webrtc_sessions = await SM.get_webrtc_sessions(
        user_id=user_id,
        user_or_api_session_type=user_or_api_session_type,
        session_id=session_id,
        node_id=node_id,
        webrtc_id=webrtc_id
    )
    return_list = []
    for s in webrtc_sessions:
        return_list.append(WebRTCSession(
            id=s.id,
            expiration_date=s.expiration_date,
            creation_date=s.creation_date,
            user_id=s.user_id,
            parent_session_id=s.parent_session_id
        ))
    return return_list



















# ---------------------------
# Webpage
# ---------------------------
app.mount("/assets", StaticFiles(directory="frontend/dist/assets"), name="assets")

# Catch-all route: For any path, serve the index.html so React can handle routing.
@app.get(
    "/{full_path:path}",
    tags=["Webpage"],
    response_class=HTMLResponse,
    description="Catch-all route that serves the React application's index.html for any unspecified path."
)
async def serve_react_app(full_path: str) -> FileResponse:
    index_path = os.path.join("static-webrtc", "index.html")
    return FileResponse(index_path)


# ---------------------------
# Main
# ---------------------------
async def main() -> None:
    # Configure the server (this does not call asyncio.run() internally)
    config = uvicorn.Config(app, host=CONFIG.HOST, port=CONFIG.PORT, log_level="info")
    server = uvicorn.Server(config)
    # Run the server asynchronously
    await asyncio.gather(
        server.serve()
    )

if __name__ == "__main__":
    STATUS = "running"
    asyncio.run(main())
    STATUS = "stopped"