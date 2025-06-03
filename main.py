import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from enum import Enum
import fnmatch
from math import ceil
import os
import re
from typing import AsyncIterator, Awaitable, Callable, Dict, List, Optional, Tuple, Union

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

from api_key import APIKey
from db_connection import MongoDBConnection
from role import Endpoint, Role, Method
from user import User
from session import Session, SessionWebRTC, SessionAPIKey, SessionUser, SessionManager
from webrtc import AudioPeerManager, AudioPeer, ErrorResponse, OfferRequest, OfferResponse, OggOpusRecorder, PeerIDRequest, StatusResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------
# Configuration
# ---------------------------
# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

PORT=int(os.getenv("PORT", 8000))
EXTERNAL_URL: str = os.getenv("EXTERNAL_URL", "http://localhost:8000")
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

System: MongoDBConnection = MongoDBConnection(
                mongo_uri=os.getenv("MONGO_URI", "localhost:27017"),
                user=os.getenv("MONGO_USER", "admin"),
                password=os.getenv("MONGO_PASSWORD", "admin"),
                db_name="transcription_service",
                admin=True
            )

WEBRTC_TIMEOUT: int = int(os.getenv("WEBRTC_TIMEOUT", 5))  # Timeout for WebRTC connections in seconds

# API Rate Limiters
LVL0_RATE_LIMITER = RateLimiter(times=6000, minutes=1)
LVL1_RATE_LIMITER = RateLimiter(times=600, minutes=1)
LVL2_RATE_LIMITER = RateLimiter(times=60, minutes=1)
LVL3_RATE_LIMITER = RateLimiter(times=6, minutes=1)

APM = AudioPeerManager(WEBRTC_TIMEOUT)

# ---------------------------
# Setup db
# ---------------------------
# This will create the database and the collections if they do not exist
Role.db_create_collection(System)
User.db_create_collection(System)
APIKey.db_create_collection(System)

# Create default roles
if not Role.db_find_by_rolename(System, "boss"):
    boss_role = Role.new(
        db_connection=System,
        rolename="boss",
        api_endpoints=[
            Endpoint(
                method=Method.ANY,
                path_filter="/*"
            )
        ]
    )
    # user_role = Role.new(
    #     db_connection=System,
    #     rolename="user",
    #     api_endpoints=[
    #         Endpoint(
    #             method=Method.GET,
    #             path_filter="/api/v1/auth/*"
    #         ),
    #         Endpoint(
    #             method=Method.POST,
    #             path_filter="/api/v1/auth/*"
    #         ),
    #         Endpoint(
    #             method=Method.PUT,
    #             path_filter="/api/v1/auth/*"
    #         ),
    #         Endpoint(
    #             method=Method.DELETE,
    #             path_filter="/api/v1/auth/*"
    #         )
    #     ]
    # )

# USER_ROLE = Role.db_find_by_rolename(System, "user")
# if USER_ROLE is None:
#     raise Exception("User role not found. Pls reinitialize the database.")

BOSE_ROLE = Role.db_find_by_rolename(System, "boss")
if BOSE_ROLE is None:
    raise Exception("Boss role not found. Pls reinitialize the database.")

# create a boss user
if not User.db_find_by_username(System, "boss"):
    User.new(
        db_connection=System,
        username="boss",
        password="boss",
        roles_id=[BOSE_ROLE._id]
    )



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
    redis_connection = redis.from_url(REDIS_URL, encoding="utf8", decode_responses=True)
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
        System.close()
        await FastAPILimiter.close()

app = FastAPI(
    lifespan=lifespan,
    title="Transcription Service",
    description="A service for transcribing live audio streams.",
    version="1.0",
)

# ---------------------------
# CORS Middleware
# ---------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[EXTERNAL_URL],  # Allowed Origins from the frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Authentication Dependencies
# ---------------------------
security = HTTPBearer()

# Session Manager for getting the user session
SM = SessionManager()

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
        # get the current users roles
        user = User.db_find_by_id(System, session.user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        roles: List[Role] = []
        for role_id in user.roles:
            role_obj = Role.db_find_by_id(System, role_id)
            if role_obj is None:
                raise HTTPException(status_code=404, detail="Role not found")
            roles.append(role_obj)
        
        return roles
    elif isinstance(session, SessionAPIKey):
        # get the current apikey roles
        api_key = APIKey.db_find_by_id(System, session.apikey_id)
        if api_key is None:
            raise HTTPException(status_code=404, detail="APIKey not found")
        roles_api: List[Role] = []
        for role_id in api_key.roles:
            role_obj = Role.db_find_by_id(System, role_id)
            if role_obj is None:
                raise HTTPException(status_code=404, detail="Role not found")
            roles_api.append(role_obj)
        
        return roles_api

def get_user_or_apikey_from_session(session: Session) -> Union[User, APIKey]:
    
    logger.debug(f"Session of type {session.__class__.__name__} for token: {session._id}")

    if isinstance(session, SessionUser):
        # get user
        user_id = session.user_id
        user = User.db_find_by_id(System, user_id)
        if user is None:
            logger.error(f"User {user_id} not found for token: {session._id}")
            raise HTTPException(status_code=403, detail="Invalid authentication token")
        return user
    elif isinstance(session, SessionAPIKey):
        # get api key
        api_key_id = session.apikey_id
        api_key = APIKey.db_find_by_id(System, api_key_id)
        if api_key is None:
            logger.error(f"APIKey {api_key_id} not found for token: {session._id}")
            raise HTTPException(status_code=403, detail="Invalid authentication token")
        return api_key
    else:
        logger.error(f"Session type {session.__class__.__name__} not supported for token: {session._id}")
        raise HTTPException(status_code=403, detail="Invalid authentication token. Only User and APIKey sessions are supported.")

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
            logger.error(f"Session type {session.__class__.__name__} not supported for token: {session._id}")
            raise HTTPException(status_code=403, detail="Invalid authentication token. Only User and APIKey sessions are supported.")

        # get user
        user_or_apikey = get_user_or_apikey_from_session(session)
        
        role_ids = user_or_apikey.roles

        # Fetch all roles from the database.
        roles_db = Role.db_find_all(System)
        roles = [user_role for user_role in roles_db.values() if user_role._id in role_ids]

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
        roles_list = [role_obj for role_id, role_obj in roles_db.items() if role_id in role_ids]

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
            logger.error(f"Session type {session.__class__.__name__} not supported for token: {session._id}")
            raise HTTPException(status_code=403, detail="Invalid authentication token. Only User and APIKey sessions are supported.")

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
    response_model=Union[AuthUserResponse, AuthAPIKeyResponse],
    dependencies=[Depends(LVL3_RATE_LIMITER)],
    description="Authenticate a user with a username and password. Creates a new session token and returns detailed session information."
)
async def api_auth_login(auth: AuthRequest) -> Union[AuthUserResponse, AuthAPIKeyResponse]:
    """Authenticate a user and create a new session token."""
    if auth.type == "user" and auth.username is not None and auth.password is not None:
        try:
            session, user = await SM.login(System, auth.username, auth.password)
        except Exception as e:
            if str(e) == "User not found":
                raise HTTPException(status_code=404, detail="Username or password are wrong")
            elif str(e) == "Incorrect password":
                raise HTTPException(status_code=403, detail="Username or password are wrong")
            else:
                raise e
        
        return AuthUserResponse(
            token=session._id,
            session_type="user",
            creation_date=session.creation_date,
            expiration_date=session.expiration_date,
            user=AuthUser(
                id=user._id,
                username=user.username,
                last_login=user.last_login,
                roles=user.roles
            )
        )
    elif auth.type == "apikey" and auth.key is not None:
        try:
            session_api, apikey = await SM.login_apikey(System, auth.key)
        except Exception as e:
            if str(e) == "APIKey not found":
                raise HTTPException(status_code=404, detail="APIKey not found")
            elif str(e) == "APIKey expired":
                raise HTTPException(status_code=403, detail="APIKey expired")
            else:
                raise e

        return AuthAPIKeyResponse(
            token=session_api._id,
            session_type="apikey",
            creation_date=session_api.creation_date,
            expiration_date=session_api.expiration_date,
            api_key=AuthAPIKey(
                id=apikey._id,
                roles=apikey.roles,
                created_at=apikey.created_at,
                expiration=apikey.expiration
            )
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid authentication type. Must be 'user' or 'apikey'.")


@app.get(
    "/api/v1/auth/status",
    response_model=Union[AuthUserResponse, AuthAPIKeyResponse],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Return the current authentication sessions details, including token and user information."
)
async def api_auth_status(session: Union[SessionUser, SessionAPIKey]= Depends(no_auth())) -> Union[AuthUserResponse, AuthAPIKeyResponse]:
    """Check the current authentication session status."""

    # get user
    user_or_apikey = get_user_or_apikey_from_session(session)
    if isinstance(user_or_apikey, User):
        return AuthUserResponse(
            token=session._id,
            session_type="user",
            creation_date=session.creation_date,
            expiration_date=session.expiration_date,
            user=AuthUser(
                id=user_or_apikey._id,
                username=user_or_apikey.username,
                roles=user_or_apikey.roles,
                last_login=user_or_apikey.last_login
            )
        )
    elif isinstance(user_or_apikey, APIKey):
        return AuthAPIKeyResponse(
            token=session._id,
            session_type="apikey",
            creation_date=session.creation_date,
            expiration_date=session.expiration_date,
            api_key=AuthAPIKey(
                id=user_or_apikey._id,
                roles=user_or_apikey.roles,
                created_at=user_or_apikey.created_at,
                expiration=user_or_apikey.expiration
            )
        )

# Logout model
class OK(BaseModel):
    ok: bool

@app.get(
    "/api/v1/auth/logout",
    response_model=OK,
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
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="For administrative users: Retrieve a list of all active sessions with detailed session information."
)
async def api_auth_sessions(session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))) -> AuthSessionResponse:
    sessions = await SM.get_sessions()
    return_sessions: List[Union[AuthUserResponse, AuthAPIKeyResponse, AuthWebRTCResponse]] = []
    for s in sessions.values():
        # get user or apikey
        if isinstance(s, (SessionUser, SessionAPIKey)):
            try:
                user_or_apikey = get_user_or_apikey_from_session(s)
            except HTTPException as e:
                continue

            if isinstance(user_or_apikey, User):
                return_sessions.append(AuthUserResponse(
                    token=s._id,
                    session_type="user",
                    creation_date=s.creation_date,
                    expiration_date=s.expiration_date,
                    user=AuthUser(
                        id=user_or_apikey._id,
                        username=user_or_apikey.username,
                        roles=user_or_apikey.roles,
                        last_login=user_or_apikey.last_login
                    )
                ))
            elif isinstance(user_or_apikey, APIKey):
                return_sessions.append(AuthAPIKeyResponse(
                    token=s._id,
                    session_type="apikey",
                    creation_date=s.creation_date,
                    expiration_date=s.expiration_date,
                    api_key=AuthAPIKey(
                        id=user_or_apikey._id,
                        roles=user_or_apikey.roles,
                        created_at=user_or_apikey.created_at,
                        expiration=user_or_apikey.expiration
                    )
                ))
        elif isinstance(s, SessionWebRTC):
            return_sessions.append(AuthWebRTCResponse(
                token=s.id,
                session_type="webrtc",
                creation_date=s.creation_date,
                expiration_date=s.expiration_date
            ))

    return AuthSessionResponse(sessions=return_sessions)


@app.get(
    "/api/v1/auth/session/logout/{token}",
    response_model=OK,
    dependencies=[Depends(LVL3_RATE_LIMITER)],
    description="For administrators only: Logout a specific session identified by its token."
)
async def api_auth_session_logout(token: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))) -> OK:
   
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
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="List all roles in the system."
)
async def api_roles(session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))) -> List[RoleResponse]:
    """List all roles in the system."""
    roles = Role.db_find_all(System)
    return_roles: List[RoleResponse] = []
    for r in roles.values():
        return_roles.append(RoleResponse(
            id=r._id,
            rolename=r.rolename,
            endpoints=[EndpointResponse(method=MethodResponse(e.method.value), path_filter=e.path_filter) for e in r.api_endpoints]
        ))
    return return_roles

@app.get(
    "/api/v1/role/{role_id}",
    response_model=RoleResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Get a specific role by its ID."
)
async def api_role(role_id: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))) -> RoleResponse:
    """Get a specific role by its ID."""
    role = Role.db_find_by_id(System, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    
    return RoleResponse(
        id=role._id,
        rolename=role.rolename,
        endpoints=[EndpointResponse(method=MethodResponse(e.method.value), path_filter=e.path_filter) for e in role.api_endpoints]
    )

@app.post(
    "/api/v1/role",
    response_model=RoleResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Create a new role with specified endpoints."
)
async def api_create_role(role: RoleCreateRequest, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))) -> RoleResponse:
    """Create a new role with specified endpoints."""
    roles = get_user_roles_by_session(session)

    # check if path_filter is valid. It should not contain any regex special characters
    if role.endpoints is not None:
        for e in role.endpoints:
            if not re.fullmatch(r"[\w\-*/]+", e.path_filter):
                raise HTTPException(status_code=400, detail="Invalid path filter. Only alphanumeric characters, '-', '*', and '/' are allowed.")

    # Convert the incoming endpoints to Endpoint objects
    endpoints = [Endpoint(method=Method(e.method), path_filter=e.path_filter) for e in role.endpoints] if role.endpoints else []

    # Check if the role already exists
    existing_role = Role.db_find_by_rolename(System, role.rolename)
    if existing_role is not None:
        raise HTTPException(status_code=400, detail="Role already exists")

    # Create the new role
    new_role = Role(
        rolename=role.rolename,
        api_endpoints=endpoints
    )

    # Check if the new role is broader than the user's roles
    if not compare_roles(roles, new_role):
        raise HTTPException(status_code=403, detail="You do not have permission to create this role. The new role has more permissions than your current roles.")
    
    # Save the new role to the database
    new_role.db_save(System)

    return RoleResponse(
        id=new_role._id,
        rolename=new_role.rolename,
        endpoints=[EndpointResponse(method=MethodResponse(e.method.value), path_filter=e.path_filter) for e in new_role.api_endpoints]
    )

@app.delete(
    "/api/v1/role/{role_id}",
    response_model=OK,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Delete a specific role by its ID."
)
async def api_delete_role(role_id: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))) -> OK:
    """Delete a specific role by its ID."""
    role = Role.db_find_by_id(System, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    
    # Check if the role is in use by any user
    # Remove the role from all users
    users = User.db_find_all(System)
    for user in users.values():
        if role._id in user.roles:
            user.roles.remove(role._id)
            user.db_save(System)
    
    # Check if the role is in use by any API key
    # Remove the role from all API keys
    apikeys = APIKey.db_find_all(System)
    for apikey in apikeys:
        if role._id in apikey.roles:
            apikey.roles.remove(role._id)
            apikey.db_save(System)

    # Delete the role
    Role.db_delete_by_id(System, role_id)

    return OK(ok=True)

@app.put(
    "/api/v1/role/{role_id}",
    response_model=RoleResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Update a specific role by its ID."
)
async def api_update_role(role_id: str, role: RolePutRequest, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))) -> RoleResponse:
    """Update a specific role by its ID."""
    # Convert the incoming endpoints to Endpoint objects
    endpoints = [Endpoint(method=Method(e.method), path_filter=e.path_filter) for e in role.endpoints] if role.endpoints else []

    # Find role by ID
    existing_role = Role.db_find_by_id(System, role_id)
    if existing_role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    
    # Update the role
    if role.rolename is not None:
        existing_role.rolename = role.rolename
    if role.endpoints is not None:
        existing_role.api_endpoints = endpoints
    existing_role.db_update(System)
    return RoleResponse(
        id=existing_role._id,
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
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="List all users in the system."
)
async def api_users(session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))) -> List[UserResponse]:
    """List all users in the system."""
    users = User.db_find_all(System)
    return_users: List[UserResponse] = []
    for u in users.values():
        return_users.append(UserResponse(
            id=u._id,
            username=u.username,
            roles=u.roles,
            last_login=u.last_login
        ))
    return return_users

# create a user
class UserCreate(BaseModel):
    username: str
    password: str 
    roles: Optional[List[str]] = []

@app.post(
    "/api/v1/user",
    response_model=UserResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Create a new user in the system."
)
async def api_create_user(
    user: UserCreate,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> UserResponse:
    """Create a new user in the system."""
    # check if the user already exists
    existing_user = User.db_find_by_username(System, user.username)
    if existing_user is not None:
        raise HTTPException(status_code=400, detail="User already exists")

    user_roles = user.roles if user.roles else []

    # get the roles obj
    roles: List[Role] = []
    for role_id in user_roles:
        role_obj = Role.db_find_by_id(System, role_id)
        if role_obj is None:
            raise HTTPException(status_code=404, detail=f"Role {role_id} not found")
        roles.append(role_obj)
    
    # Check if the new role is broader than the user's roles
    req_user_roles = get_user_roles_by_session(session)
    for r in roles:
        if not compare_roles(req_user_roles, r):
            raise HTTPException(status_code=403, detail="You do not have permission to create this user. The new user has more permissions than your current roles.")

    try:
        new_user = User.new(
            db_connection=System,
            username=user.username,
            password=user.password,
            roles_id=user.roles
        )
        return UserResponse(
            id=new_user._id,
            username=new_user.username,
            roles=new_user.roles,
            last_login=new_user.last_login
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# update user password
class UserUpdatePassword(BaseModel):
    current_password: str
    new_password: str

@app.put(
    "/api/v1/user/password/change",
    response_model=UserResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Change the user password."
)
async def api_change_user_password(
    password_update: UserUpdatePassword,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> UserResponse:
    """Update password for the current user."""
    # check if the session is called by an apikey
    if isinstance(session, SessionAPIKey):
        raise HTTPException(status_code=403, detail="You cannot change the password using an API key session. Please use a user session.")

    # Get the current user
    user = User.db_find_by_id(System, session.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify current password
    if not user.verify_password(password_update.current_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    try:
        # Generate new password hash and salt
        password_hash, password_salt = User.hash_password(password_update.new_password)
        
        # Update user's password in database
        user.password_hash = password_hash
        user.password_salt = password_salt
        user.db_update(System)

        return UserResponse(
            id=user._id,
            username=user.username,
            roles=user.roles,
            last_login=user.last_login
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

class UserResetPassword(BaseModel):
    new_password: str

@app.put(
    "/api/v1/user/{user_id}/password/reset",
    response_model=UserResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Reset the user password."
)
async def api_reset_user_password(
    user_id: str,
    pw: UserResetPassword,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> UserResponse:
    """Reset the user password."""
    user = User.db_find_by_id(System, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        # Generate new password hash and salt
        password_hash, password_salt = User.hash_password(pw.new_password)

        # Update user's password in database
        user.password_hash = password_hash
        user.password_salt = password_salt
        user.db_update(System)

        return UserResponse(
            id=user._id,
            username=user.username,
            roles=user.roles,
            last_login=user.last_login
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

class UserSetRole(BaseModel):
    roles: List[str]

@app.put(
    "/api/v1/user/{user_id}/roles",
    response_model=UserResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Set roles for a user. Requires admin privileges."
)
async def api_set_user_roles(
    user_id: str,
    user_roles: UserSetRole,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> UserResponse:
    """Set roles for a user. Only accessible by admin."""
    user = User.db_find_by_id(System, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        # Verify all roles exist
        db_roles = Role.db_find_all(System)
        for role_id in user_roles.roles:
            if role_id not in [r for r in db_roles]:
                raise HTTPException(status_code=400, detail=f"Role '{role_id}' does not exist")

        # Update user's roles
        user.roles = user_roles.roles
        user.db_update(System)

        return UserResponse(
            id=user._id,
            username=user.username,
            roles=user.roles,
            last_login=user.last_login
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete(
    "/api/v1/user/{user_id}",
    response_model=OK,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Delete a user. Requires admin privileges."
)
async def api_delete_user(
    user_id: str,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> OK:
    """Delete a user. Only accessible by admin."""
    user = User.db_find_by_id(System, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # get all API keys for the user, logout and delete them
    user_api_keys = user.api_keys_ids
    for ak in user_api_keys:
        # logout all sessions for the API key
        user_api_key_session = await SM.get_sessions_by_apikey(ak)
        for ak_session in user_api_key_session:
            # delete the session
            await ak_session.logout()

        # delete the API key
        ak_obj = APIKey.db_find_by_id(System, ak)
        if ak_obj is not None:
            ak_obj.db_delete(System)

    # get all sessions for the user and logout
    user_sessions = await SM.get_sessions_by_user(user_id)
    for us in user_sessions:
        # delete the session
        await us.logout()

    try:
        user.db_delete(System)
        return OK(ok=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




# ---------------------------
# API Key Endpoints
# ---------------------------
class APIKeyResponse(BaseModel):
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
    user_obj = User.db_find_by_id(System, user_id)
    if user_obj is None:
        raise HTTPException(status_code=404, detail="User not found")

    return [
        APIKeyResponse(
            id=apikey._id,
            key=apikey.key,
            roles=apikey.roles,
            created_at=apikey.created_at,
            expiration=apikey.expiration,
        )
        for apikey_id in user_obj.api_keys_ids
        if (apikey := APIKey.db_find_by_id(System, apikey_id)) is not None
    ]


def _get_apikey(user_id: str, apikey_id: str) -> APIKeyResponse:
    user_obj = User.db_find_by_id(System, user_id)
    if user_obj is None:
        raise HTTPException(status_code=404, detail="User not found")

    if apikey_id not in user_obj.api_keys_ids:
        raise HTTPException(
            status_code=403, detail="API key does not belong to the user"
        )

    apikey = APIKey.db_find_by_id(System, apikey_id)
    if apikey is None:
        raise HTTPException(status_code=404, detail="API key not found")

    return APIKeyResponse(
        id=apikey._id,
        key=apikey.key,
        roles=apikey.roles,
        created_at=apikey.created_at,
        expiration=apikey.expiration,
    )


def _create_apikey(session: Union[SessionUser, SessionAPIKey], user_id: str, req: APIKeyCreateRequest) -> APIKeyResponse:
    user_obj = User.db_find_by_id(System, user_id)
    if user_obj is None:
        raise HTTPException(status_code=404, detail="User not found")

    # get the roles obj
    roles: List[Role] = []
    for role_id in req.roles:
        role_obj = Role.db_find_by_id(System, role_id)
        if role_obj is None:
            raise HTTPException(status_code=404, detail=f"Role {role_id} not found")
        roles.append(role_obj)

    # Check if the new role is broader than the user's roles
    req_user_roles = get_user_roles_by_session(session)
    for r in roles:
        if not compare_roles(req_user_roles, r):
            raise HTTPException(status_code=403, detail="You do not have permission to create this api key with this roles. The roles you assigned are broader than your current roles.")

    new_key = APIKey.new(
        user_id=user_id,
        db_connection=System,
        expiration=req.expiration,
        roles=req.roles,
    )

    try:
        user_obj.api_keys_ids.append(new_key._id)
        user_obj.db_update(System)
        new_key.db_save(System)
    except Exception:
        # roll back user change if the key save fails
        if new_key._id in user_obj.api_keys_ids:
            user_obj.api_keys_ids.remove(new_key._id)
            user_obj.db_update(System)
        raise HTTPException(status_code=500, detail="Failed to create API key")

    return APIKeyResponse(
        id=new_key._id,
        key=new_key.key,
        roles=new_key.roles,
        created_at=new_key.created_at,
        expiration=new_key.expiration,
    )


def _delete_apikey(user_id: str, apikey_id: str) -> OK:
    user_obj = User.db_find_by_id(System, user_id)
    if user_obj is None:
        raise HTTPException(status_code=404, detail="User not found")

    if apikey_id not in user_obj.api_keys_ids:
        raise HTTPException(
            status_code=403, detail="API key does not belong to the user"
        )

    apikey = APIKey.db_find_by_id(System, apikey_id)
    if apikey is None:
        raise HTTPException(status_code=404, detail="API key not found")

    try:
        user_obj.api_keys_ids.remove(apikey._id)
        user_obj.db_update(System)
        apikey.db_delete(System)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to delete API key")

    return OK(ok=True)


def _update_apikey(
    user_id: str, apikey_id: str, req: APIKeyPutRequest
) -> APIKeyResponse:
    user_obj = User.db_find_by_id(System, user_id)
    if user_obj is None:
        raise HTTPException(status_code=404, detail="User not found")

    if apikey_id not in user_obj.api_keys_ids:
        raise HTTPException(
            status_code=403, detail="API key does not belong to the user"
        )

    apikey_obj = APIKey.db_find_by_id(System, apikey_id)
    if apikey_obj is None:
        raise HTTPException(status_code=404, detail="API key not found")

    if req.roles is not None:
        db_roles = Role.db_find_all(System)
        for role_id in req.roles:
            if role_id not in [r for r in db_roles]:
                raise HTTPException(status_code=400, detail=f"Role '{role_id}' does not exist")

        apikey_obj.roles = req.roles
    
    if req.expiration is not None:
        apikey_obj.expiration = req.expiration

    try:
        apikey_obj.db_update(System)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to update API key")

    return APIKeyResponse(
        id=apikey_obj._id,
        key=apikey_obj.key,
        roles=apikey_obj.roles,
        created_at=apikey_obj.created_at,
        expiration=apikey_obj.expiration,
    )


@app.get(
    "/api/v1/user/{user_id}/apikeys",
    response_model=List[APIKeyResponse],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="List all API keys for a specific user.",
)
async def api_list_apikeys(
    user_id: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> List[APIKeyResponse]:
    return _list_apikeys(user_id)


@app.get(
    "/api/v1/user/apikeys",
    response_model=List[APIKeyResponse],
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="List all API keys for the authenticated user.",
)
async def api_list_own_apikeys(
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> List[APIKeyResponse]:
    # check if the session is called by an apikey
    if isinstance(session, SessionAPIKey):
        raise HTTPException(status_code=403, detail="You cannot list the API keys using an API key session. Please use a user session.")

    return _list_apikeys(session.user_id)


@app.get(
    "/api/v1/user/{user_id}/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Get a specific API key for a user.",
)
async def api_get_apikey(
    user_id: str, apikey_id: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> APIKeyResponse:
    return _get_apikey(user_id, apikey_id)


@app.get(
    "/api/v1/user/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Get one of *your* API keys (user_id from session).",
)
async def api_get_own_apikey(
    apikey_id: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> APIKeyResponse:
    # check if the session is called by an apikey
    if isinstance(session, SessionAPIKey):
        raise HTTPException(status_code=403, detail="You cannot get the API key using an API key session. Please use a user session.")

    return _get_apikey(session.user_id, apikey_id)


@app.post(
    "/api/v1/user/{user_id}/apikey",
    response_model=APIKeyResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Create a new API key for a specific user.",
)
async def api_create_apikey(
    user_id: str,
    apikey: APIKeyCreateRequest,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE])),
) -> APIKeyResponse:
    return _create_apikey(session, user_id, apikey)


@app.post(
    "/api/v1/user/apikey",
    response_model=APIKeyResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Create a new API key for the authenticated user.",
)
async def api_create_own_apikey(
    apikey: APIKeyCreateRequest, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> APIKeyResponse:
    # check if the session is called by an apikey
    if isinstance(session, SessionAPIKey):
        raise HTTPException(status_code=403, detail="You cannot create the API key using an API key session. Please use a user session.")
    
    return _create_apikey(session, session.user_id, apikey)


@app.delete(
    "/api/v1/user/{user_id}/apikey/{apikey_id}",
    response_model=OK,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Delete a specific API key for a user.",
)
async def api_delete_apikey(
    user_id: str, apikey_id: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> OK:
    return _delete_apikey(user_id, apikey_id)


@app.delete(
    "/api/v1/user/apikey/{apikey_id}",
    response_model=OK,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Delete one of *your* API keys.",
)
async def api_delete_own_apikey(
    apikey_id: str, session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE]))
) -> OK:
    # check if the session is called by an apikey
    if isinstance(session, SessionAPIKey):
        raise HTTPException(status_code=403, detail="You cannot delete the API key using an API key session. Please use a user session.")

    return _delete_apikey(session.user_id, apikey_id)


@app.put(
    "/api/v1/user/{user_id}/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Update a specific API key.",
)
async def api_update_apikey(
    user_id: str,
    apikey_id: str,
    apikey: APIKeyPutRequest,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE])),
) -> APIKeyResponse:
    return _update_apikey(user_id, apikey_id, apikey)


@app.put(
    "/api/v1/user/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Update one of *your* API keys.",
)
async def api_update_own_apikey(
    apikey_id: str,
    apikey: APIKeyPutRequest,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE])),
) -> APIKeyResponse:
    # check if the session is called by an apikey
    if isinstance(session, SessionAPIKey):
        raise HTTPException(status_code=403, detail="You cannot update the API key using an API key session. Please use a user session.")

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
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="List all available API endpoints."
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


# ---------------------------
# WebRTC
# ---------------------------
@app.post(
        "/api/v1/webrtc/offer",
        response_model=OfferResponse,
        responses={400: {"model": ErrorResponse}},
        dependencies=[Depends(LVL2_RATE_LIMITER)],
        description="Handle WebRTC offer and return an answer."
        )
async def offer(
    request_data: OfferRequest,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE])),
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
        await asyncio.sleep(5)
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
    "/api/v1/webrtc/{peer_id}/start_recording",
    response_model=StatusResponse,
    responses={400: {"model": ErrorResponse}},
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Start recording for a specific peer."
)
async def start_recording(
    peer_id: str,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE])),
    ) -> StatusResponse:
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
    response_model=StatusResponse,
    responses={400: {"model": ErrorResponse}},
    dependencies=[Depends(LVL2_RATE_LIMITER)],
    description="Stop recording for a specific peer."
)
async def stop_recording(
    peer_id: str,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSE_ROLE])),
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



















# ---------------------------
# Webpage
# ---------------------------
app.mount("/assets", StaticFiles(directory="frontend/dist/assets"), name="assets")

# Catch-all route: For any path, serve the index.html so React can handle routing.
@app.get(
    "/{full_path:path}",
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
    config = uvicorn.Config(app, host="0.0.0.0", port=PORT, log_level="info")
    server = uvicorn.Server(config)
    # Run the server asynchronously
    await asyncio.gather(
        server.serve()
    )

if __name__ == "__main__":
    asyncio.run(main())