import asyncio
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

from db_connection import MongoDBConnection
from role import Endpoint, Role, Method
from user import User
from session import Session, SessionManager

URL: str = "http://localhost:8000"
REDIS_URL: str = "redis://localhost:6379"

System: MongoDBConnection = MongoDBConnection(
                mongo_uri="localhost:27017",
                user="admin", # type: ignore
                password="admin", # type: ignore
                db_name="transcription_service",
                admin=True
            )

# ---------------------------
# Setup db
# ---------------------------
# This will create the database and the collections if they do not exist
Role.db_create_collection(System)
User.db_create_collection(System)

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
    allow_origins=[URL],  # Allowed Origins from the frontend
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

def get_user_from_session(session: Session) -> User:
    # get user
    user_id = session.user_id
    user = User.db_find_by_id(System, user_id)
    if user is None:
        raise HTTPException(status_code=403, detail="Invalid authentication token")
    return user

# get session from token
def auth(required_roles: Optional[List[Optional[Role]]] = None) -> Callable[[Request, HTTPAuthorizationCredentials], Awaitable[object]]:
    """
    Authentication dependency that returns a session if access is granted.
    It first checks if the user has one of the required roles directly.
    If not, it checks the request path against the API endpoint patterns defined in each role.
    
    The API endpoint is printed/formatted (e.g., GET-/endpoint) as indicated in the docstring.
    """
    async def new_auth(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)) -> object:
        token = credentials.credentials
        session = await SM.get_session(token)
        if session is None:
            raise HTTPException(status_code=403, detail="Invalid authentication token")

        # get user
        user = get_user_from_session(session)
        
        user_role_ids = user.roles

        # Fetch all roles from the database.
        roles_db = Role.db_find_all(System)
        user_roles = [user_role for user_role in roles_db.values() if user_role._id in user_role_ids]

        user_roles_names = [role.rolename for role in user_roles]
        
        # If specific required roles are provided, check if the user has at least one of them.
        if required_roles is not None:
            if any(role.rolename in user_roles_names for role in required_roles if role is not None):
                return session

        # current request method and path
        new_request = Endpoint(
            method=Method(request.method),
            path_filter=request.url.path
        )


        # Build a list of Role objects corresponding to the user's roles.
        roles_list = [role_obj for role_id, role_obj in roles_db.items() if role_id in user_role_ids]

        # Check if any of the user's roles permit access to the requested endpoint.
        for role_obj in roles_list:
            if check_role(role_obj, new_request):
                return session

        # If no matching role endpoint pattern is found, deny access.
        raise HTTPException(status_code=403, detail="Access forbidden")

    return new_auth


# ---------------------------
# Auth Endpoints
# ---------------------------
# Auth models
class AuthRequest(BaseModel):
    username: str
    password: str

class AuthUser(BaseModel):
    id: str
    username: str
    roles: list[str]
    last_login: Optional[datetime]

class AuthResponse(BaseModel):
    token: str
    creation_date: datetime
    expiration_date: datetime
    user: AuthUser

@app.post(
    "/api/v1/auth/token",
    response_model=AuthResponse,
    dependencies=[Depends(RateLimiter(times=5, minutes=1))],
    description="Authenticate a user with a username and password. Creates a new session token and returns detailed session information."
)
async def api_auth_login(auth: AuthRequest) -> AuthResponse:
    """Authenticate a user and create a new session token."""
    try:
        session, user = await SM.login(System, auth.username, auth.password)
    except Exception as e:
        if str(e) == "User not found":
            raise HTTPException(status_code=404, detail="Username or password are wrong")
        elif str(e) == "Incorrect password":
            raise HTTPException(status_code=403, detail="Username or password are wrong")
        else:
            raise e
    
    return AuthResponse(
        token=session._id,
        creation_date=session.creation_date,
        expiration_date=session.expiration_date,
        user=AuthUser(
            id=user._id,
            username=user.username,
            last_login=user.last_login,
            roles=user.roles
        )
    )


@app.get(
    "/api/v1/auth/status",
    response_model=AuthResponse,
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="Return the current authentication sessions details, including token and user information."
)
async def api_auth_status(session: Session = Depends(auth())) -> AuthResponse:
    """Check the current authentication session status."""

    # get user
    user = get_user_from_session(session)

    return AuthResponse(
        token=session._id,
        creation_date=session.creation_date,
        expiration_date=session.expiration_date,
        user=AuthUser(
            id=user._id,
            username=user.username,
            roles=user.roles,
            last_login=user.last_login
        )
    )

# Logout model
class OK(BaseModel):
    ok: bool

@app.get(
    "/api/v1/auth/logout",
    response_model=OK,
    dependencies=[Depends(RateLimiter(times=5, minutes=1))],
    description="Logout the current user session, invalidating the session token."
)
async def api_auth_logout(session: Session = Depends(auth())) -> OK:
    await session.logout()
    return OK(ok=True)


class AuthSessionResponse(BaseModel):
    sessions: List[AuthResponse]

@app.get(
    "/api/v1/auth/sessions",
    response_model=AuthSessionResponse,
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="For administrative users: Retrieve a list of all active sessions with detailed session information."
)
async def api_auth_sessions(session: Session = Depends(auth([BOSE_ROLE]))) -> AuthSessionResponse:
    sessions = await SM.get_sessions()
    return_sessions: List[AuthResponse] = []
    for s in sessions.values():

        # get user
        user = get_user_from_session(s)

        return_sessions.append(AuthResponse(
            token=s._id,
            creation_date=s.creation_date,
            expiration_date=s.expiration_date,
            user=AuthUser(
                id=user._id,
                username=user.username,
                roles=user.roles,
                last_login=user.last_login
            )
        ))

    return AuthSessionResponse(sessions=return_sessions)


@app.get(
    "/api/v1/auth/session/logout/{token}",
    response_model=OK,
    dependencies=[Depends(RateLimiter(times=5, minutes=1))],
    description="For administrators only: Logout a specific session identified by its token."
)
async def api_auth_session_logout(token: str, session: Session = Depends(auth([BOSE_ROLE]))) -> OK:
   
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
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="List all roles in the system."
)
async def api_roles(session: Session = Depends(auth([BOSE_ROLE]))) -> List[RoleResponse]:
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
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="Get a specific role by its ID."
)
async def api_role(role_id: str, session: Session = Depends(auth([BOSE_ROLE]))) -> RoleResponse:
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
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="Create a new role with specified endpoints."
)
async def api_create_role(role: RoleCreateRequest, session: Session = Depends(auth([BOSE_ROLE]))) -> RoleResponse:
    """Create a new role with specified endpoints."""
    # check if path_filter is valid. It should not contain any regex special characters
    if role.endpoints is not None:
        for e in role.endpoints:
            if re.search(r"[*\\]", e.path_filter):
                raise HTTPException(status_code=400, detail="Invalid path filter. Only '*' is allowed.")

    # Convert the incoming endpoints to Endpoint objects
    endpoints = [Endpoint(method=Method(e.method), path_filter=e.path_filter) for e in role.endpoints] if role.endpoints else []

    # Check if the role already exists
    existing_role = Role.db_find_by_rolename(System, role.rolename)
    if existing_role is not None:
        raise HTTPException(status_code=400, detail="Role already exists")

    # Create the new role
    new_role = Role.new(
        db_connection=System,
        rolename=role.rolename,
        api_endpoints=endpoints
    )

    return RoleResponse(
        id=new_role._id,
        rolename=new_role.rolename,
        endpoints=[EndpointResponse(method=MethodResponse(e.method.value), path_filter=e.path_filter) for e in new_role.api_endpoints]
    )

@app.delete(
    "/api/v1/role/{role_id}",
    response_model=OK,
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="Delete a specific role by its ID."
)
async def api_delete_role(role_id: str, session: Session = Depends(auth([BOSE_ROLE]))) -> OK:
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

    # Delete the role
    Role.db_delete_by_id(System, role_id)

    return OK(ok=True)

@app.put(
    "/api/v1/role/{role_id}",
    response_model=RoleResponse,
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="Update a specific role by its ID."
)
async def api_update_role(role_id: str, role: RolePutRequest, session: Session = Depends(auth([BOSE_ROLE]))) -> RoleResponse:
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
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="List all users in the system."
)
async def api_users(session: Session = Depends(auth([BOSE_ROLE]))) -> List[UserResponse]:
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
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="Create a new user in the system."
)
async def api_create_user(
    user: UserCreate,
    session: Session = Depends(auth([BOSE_ROLE]))
) -> UserResponse:
    """Create a new user in the system."""
    # check if the user already exists
    existing_user = User.db_find_by_username(System, user.username)
    if existing_user is not None:
        raise HTTPException(status_code=400, detail="User already exists")

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
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="Change the user password."
)
async def api_change_user_password(
    password_update: UserUpdatePassword,
    session: Session = Depends(auth([BOSE_ROLE]))
) -> UserResponse:
    """Update password for the current user."""
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
    username: str
    new_password: str

@app.put(
    "/api/v1/user/password/reset",
    response_model=UserResponse,
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="Reset the user password."
)
async def api_reset_user_password(
    user_and_pw: UserResetPassword,
    session: Session = Depends(auth([BOSE_ROLE]))
) -> UserResponse:
    """Reset the user password."""
    user = User.db_find_by_username(System, user_and_pw.username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        # Generate new password hash and salt
        password_hash, password_salt = User.hash_password(user_and_pw.new_password)

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
    username: str
    roles: List[str]

@app.put(
    "/api/v1/user/roles",
    response_model=UserResponse,
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="Set roles for a user. Requires admin privileges."
)
async def api_set_user_roles(
    user_roles: UserSetRole,
    session: Session = Depends(auth([BOSE_ROLE]))
) -> UserResponse:
    """Set roles for a user. Only accessible by admin."""
    user = User.db_find_by_username(System, user_roles.username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        # Verify all roles exist
        db_roles = Role.db_find_all(System)
        for role_id in user_roles.roles:
            if role_id not in [r for r in db_roles]:
                raise ValueError(f"Role '{role_id}' does not exist")

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
    "/api/v1/user/{username}",
    response_model=dict,
    dependencies=[Depends(RateLimiter(times=1, seconds=1))],
    description="Delete a user. Requires admin privileges."
)
async def api_delete_user(
    username: str,
    session: Session = Depends(auth([BOSE_ROLE]))
) -> dict:
    """Delete a user. Only accessible by admin."""
    user = User.db_find_by_username(System, username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        user.db_delete(System)
        return {"message": f"User '{username}' deleted successfully"}
    except Exception as e:
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
    index_path = os.path.join("frontend/dist", "index.html")
    return FileResponse(index_path)


# ---------------------------
# Main
# ---------------------------
async def main() -> None:
    # Configure the server (this does not call asyncio.run() internally)
    config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(config)
    # Run the server asynchronously
    await asyncio.gather(
        server.serve()
    )

if __name__ == "__main__":
    asyncio.run(main())