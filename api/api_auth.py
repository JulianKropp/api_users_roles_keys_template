import logging

import re
from typing import List, Union, Optional, Callable, Awaitable
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from enum import Enum

from models.user import User
from models.api_key import ApiKey
from models.role import Endpoint, Role, Method
from session import SessionManager, Session, SessionUser, SessionAPIKey

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------
# Authentication Dependencies
# ---------------------------
security = HTTPBearer()

# Session Manager (singleton) for getting the user session
SM = SessionManager()
BOSS_ROLE = Role.objects(rolename="boss").first()

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