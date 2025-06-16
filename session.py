from abc import ABC, abstractmethod
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid
import json

# Async Redis client  (pip install redis)
import redis.asyncio as redis

from api_key import ApiKey
from config import Config
from user import User
from role import Role

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Constants & helpers
# --------------------------------------------------------------------------- #
# New Redis key format
SESSION_KEY = "session:{user_id}:{user_or_api_session}:{session_id}:data"
LOGOUT_SESSION_KEY = "session:{user_id}:{user_or_api_session}:{session_id}:*"
USER_SESSION_KEY = "session:{user_id}:sessions:{session_id}:data"
APIKEY_SESSION_KEY = "session:{user_id}:api_keys:{apikey_id}:sessions:{session_id}:data"
WEBRTC_SESSION_KEY = "session:{user_id}:{user_or_api_session}:{session_id}:node:{node_id}:webrtc:{webrtc_id}:data"

CONFIG = Config()

def build_user_session_key(user_id: str, session_id: str) -> str:
    return USER_SESSION_KEY.format(user_id=user_id, session_id=session_id)

def build_apikey_session_key(user_id: str, apikey_id: str, session_id: str) -> str:
    return APIKEY_SESSION_KEY.format(
        user_id=user_id, apikey_id=apikey_id, session_id=session_id
    )

def build_session_key(user_id: str = "*", user_or_api_session: str = "*", session_id: str = "*") -> str:
    if user_or_api_session == "user":
        user_or_api_session = "sessions"
    elif user_or_api_session == "api_key":
        user_or_api_session = "api_keys"
    elif user_or_api_session != "*":
        raise ValueError("user_or_api_session must be 'user', 'api_key', or '*'")

    return SESSION_KEY.format(
        user_id=user_id,
        user_or_api_session=user_or_api_session,
        session_id=session_id
    )

def build_webrtc_session_key(user_id: str, user_or_api_session: str, session_id: str, webrtc_id: str, node_id: str = CONFIG.NODE_ID) -> str:
    if user_or_api_session == "user":
        user_or_api_session = "sessions"
    elif user_or_api_session == "api_key":
        user_or_api_session = "api_keys"
    elif user_or_api_session == "*":
        user_or_api_session = "*"
    else:
        raise ValueError("user_or_api_session must be 'user' or 'api_key'")
    
    return WEBRTC_SESSION_KEY.format(
        user_id=user_id,
        user_or_api_session=user_or_api_session,
        session_id=session_id,
        node_id=node_id,
        webrtc_id=webrtc_id
    )

def build_logout_session_key(user_id: str = "*", user_or_api_session: str = "*", session_id: str = "*") -> str:
    if user_or_api_session == "user":
        user_or_api_session = "sessions"
    elif user_or_api_session == "api_key":
        user_or_api_session = "api_keys"
    elif user_or_api_session == "*":
        user_or_api_session = "*"
    else:
        raise ValueError("user_or_api_session must be 'user' or 'api_key'")
    
    return LOGOUT_SESSION_KEY.format(
        user_id=user_id,
        user_or_api_session=user_or_api_session,
        session_id=session_id
    )

# Helper converters
def datetime_to_str(dt: datetime) -> str:
    return dt.isoformat()

def str_to_datetime(dt_str: str) -> datetime:
    return datetime.fromisoformat(dt_str)

# --------------------------------------------------------------------------- #
#  Session dataclasses
# --------------------------------------------------------------------------- #
class Status(Enum):
    ACTIVE   = "active"
    INACTIVE = "inactive"


@dataclass
class Session(ABC):
    expiration_date: datetime
    creation_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: str = ""
    _id: str = field(default_factory=lambda: f"SESSION-{uuid.uuid4()}")

    @property
    def id(self) -> str:
        return self._id

    def to_json(self) -> str:
        """Serialize the Session object to a JSON string."""
        return json.dumps(self.to_dict(), indent=4)

    @abstractmethod
    def to_dict(self) -> dict:
        """Convert the Session object into a dictionary for JSON serialization."""
        raise NotImplementedError("Subclasses must implement this method.")
    
    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict) -> "Session":
        """
        Create a Session object from a dictionary.
        This method converts ISO-formatted datetime strings back to datetime objects 
        and rebuilds the nested User object.
        """
        raise NotImplementedError("Subclasses must implement this method.")
    
    @classmethod
    @abstractmethod
    def from_json(cls, json_str: str) -> "Session":
        """Deserialize the JSON string and return a Session object."""
        raise NotImplementedError("Subclasses must implement this method.")

    async def logout(self) -> None:
        """Log out the session by removing it from the session manager."""
        await SessionManager().logout(self._id)


@dataclass
class SessionUser(Session):
    _id: str = field(default_factory=lambda: f"SESSION-USER-{uuid.uuid4()}")

    def to_dict(self) -> dict:
        """Convert the Session object into a dictionary for JSON serialization."""
        return {
            "_id": self._id,
            "creation_date": datetime_to_str(self.creation_date),
            "expiration_date": datetime_to_str(self.expiration_date),
            "user_id": self.user_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SessionUser":
        """
        Create a Session object from a dictionary.
        This method converts ISO-formatted datetime strings back to datetime objects 
        and rebuilds the nested User object.
        """        
        # Convert string dates back to datetime objects.
        creation_date = str_to_datetime(data["creation_date"])
        expiration_date = str_to_datetime(data["expiration_date"])

        if creation_date is None:
            raise ValueError("creation_date is required")
        if expiration_date is None:
            raise ValueError("expiration_date is required")
        
        return cls(
            user_id=data["user_id"],
            creation_date=creation_date,
            expiration_date=expiration_date,
            _id=data["_id"]
        )

    @classmethod
    def from_json(cls, json_str: str) -> "SessionUser":
        return cls.from_dict(json.loads(json_str))


@dataclass
class SessionAPIKey(Session):
    _id: str = field(default_factory=lambda: f"SESSION-API-{uuid.uuid4()}")
    apikey_id: str = ""

    def to_dict(self) -> dict:
        return {
            "_id": self._id,
            "creation_date": datetime_to_str(self.creation_date),
            "expiration_date": datetime_to_str(self.expiration_date),
            "apikey_id": self.apikey_id,
            "user_id": self.user_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SessionAPIKey":
        """
        Create a Session object from a dictionary.
        This method converts ISO-formatted datetime strings back to datetime objects 
        and rebuilds the nested User object.
        """        
        # Convert string dates back to datetime objects.
        creation_date = str_to_datetime(data["creation_date"])
        expiration_date = str_to_datetime(data["expiration_date"])

        if creation_date is None:
            raise ValueError("creation_date is required")
        if expiration_date is None:
            raise ValueError("expiration_date is required")
        
        return cls(
            apikey_id=data["apikey_id"],
            creation_date=creation_date,
            expiration_date=expiration_date,
            _id=data["_id"]
        )

    @classmethod
    def from_json(cls, json_str: str) -> "SessionAPIKey":
        return cls.from_dict(json.loads(json_str))

@dataclass
class SessionWebRTC(Session):
    _id: str = field(default_factory=lambda: f"SESSION-WEBRTC-{uuid.uuid4()}")
    parent_session_id: str = ""

    def to_dict(self) -> dict:
        """Convert the Session object into a dictionary for JSON serialization."""
        return {
            "_id": self._id,
            "creation_date": datetime_to_str(self.creation_date),
            "expiration_date": datetime_to_str(self.expiration_date),
            "user_id": self.user_id,
            "parent_session_id": self.parent_session_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "SessionWebRTC":
        """
        Create a Session object from a dictionary.
        This method converts ISO-formatted datetime strings back to datetime objects 
        and rebuilds the nested User object.
        """        
        # Convert string dates back to datetime objects.
        creation_date = str_to_datetime(data["creation_date"])
        expiration_date = str_to_datetime(data["expiration_date"])

        if creation_date is None:
            raise ValueError("creation_date is required")
        if expiration_date is None:
            raise ValueError("expiration_date is required")
        
        return cls(
            user_id=data["user_id"],
            parent_session_id=data["parent_session_id"],
            creation_date=creation_date,
            expiration_date=expiration_date,
            _id=data["_id"]
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> "SessionWebRTC":
        return cls.from_dict(json.loads(json_str))
    
# --------------------------------------------------------------------------- #
#  SessionManager
# --------------------------------------------------------------------------- #
class SessionManager:
    """Singleton responsible for (de)serialising sessions into Redis."""
    _instance = None

    def __new__(cls, *args: Any, **kwargs: Any) -> "SessionManager":
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, redis_url: str = "redis://localhost:6379", session_duration: int = 86400) -> None:
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.session_duration = session_duration
        self.lock  = asyncio.Lock()

    # -- Login helpers ------------------------------------------------------ #
    async def login(self, username: str, password: str) -> Tuple[SessionUser, User]:
        user = User.objects(username=username).first() # type: ignore[attr-defined]
        if user is None:
            raise ValueError("User not found")

        if not user.verify_password(password):
            raise ValueError("Incorrect password")

        now = datetime.now(timezone.utc)
        user.last_login = now
        user.save()

        session = SessionUser(
            user_id=str(user.id),
            expiration_date=now + timedelta(seconds=self.session_duration),
        )

        key = build_user_session_key(str(user.id), session.id)
        async with self.lock:
            await self.redis.set(key, session.to_json(), ex=self.session_duration)
        return session, user

    async def login_apikey(self, apikey: str) -> Tuple[SessionAPIKey, ApiKey]:
        key_hash = ApiKey.hash_key(apikey)

        apikey_obj = ApiKey.objects(key_hash=key_hash).first() # type: ignore[attr-defined]
        if apikey_obj is None:
            raise ValueError("API key not found")

        if apikey_obj.expiration and apikey_obj.expiration < datetime.now(timezone.utc):
            raise ValueError("API key expired")

        user = apikey_obj.user
        if user is None:
            raise ValueError("Owner of API key not found")

        session = SessionAPIKey(
            apikey_id=str(apikey_obj.id),
            user_id=str(user.id),
            expiration_date=datetime.now(timezone.utc) + timedelta(seconds=self.session_duration),
        )

        key = build_apikey_session_key(str(user.id), str(apikey_obj.id), session.id)
        async with self.lock:
            await self.redis.set(key, session.to_json(), ex=self.session_duration)
        return session, apikey_obj

    async def login_webrtc(self, session: Union[SessionUser, SessionAPIKey]) -> SessionWebRTC:
        """
        Create a WebRTC session for the given user or API key session.
        This is a placeholder implementation, as WebRTC sessions would typically
        involve more complex signaling and state management.
        """
        if not isinstance(session, (SessionUser, SessionAPIKey)):
            raise TypeError(
                "login_webrtc expects a SessionUser or SessionAPIKey, "
                f"got {type(session).__name__}"
            )

        webrtc_session = SessionWebRTC(
            user_id=session.user_id,
            parent_session_id=session.id,
            expiration_date=session.expiration_date,
        )

        key = build_webrtc_session_key(
            user_id=session.user_id,
            user_or_api_session="user" if isinstance(session, SessionUser) else "api_key",
            session_id=session.id,
            webrtc_id=webrtc_session.id
        )

        async with self.lock:
            await self.redis.set(key, webrtc_session.to_json(), ex=CONFIG.WEBRTC_TIMEOUT*2)
        return webrtc_session

    async def _get_keys(self, key_pattern: str, first_only: bool = False) -> List[str]:
        keys: List[str] = []
        async for k in self.redis.scan_iter(match=key_pattern):
            keys.append(k)
            if first_only:
                break
        return keys
    
    async def _get_value(self, key: str) -> Union[bytes, None]:
        data: Union[bytes, None]
        async for k in self.redis.scan_iter(match=key):
            # we expect at most one real key; take the first and break
            data = await self.redis.get(k)
            break
        
        return data

    # -- Public API --------------------------------------------------------- #
    async def logout(self, session_id: str) -> None:
        pattern_key = build_logout_session_key(session_id=session_id)
        keys = await self._get_keys(pattern_key)
        if len(keys) == 0:
            return
        async with self.lock:
            await self.redis.delete(keys[0])

    async def logout_user(self, user_id: str) -> None:
        """
        This will logout all sessions of a user
        """
        pattern_key = build_logout_session_key(user_id=user_id, user_or_api_session="user")
        keys = await self._get_keys(pattern_key)
        if len(keys) == 0:
            return
        async with self.lock:
            await self.redis.delete(*keys)

    async def logout_apikey(self, user_id: str) -> None:
        """
        This will logout all sessions of an API key of an user
        """
        pattern_key = build_logout_session_key(user_id=user_id, user_or_api_session="api_key")
        keys = await self._get_keys(pattern_key)
        if len(keys) == 0:
            return
        async with self.lock:
            await self.redis.delete(*keys)

    async def logout_all(self) -> None:
        pattern_key = build_logout_session_key()
        keys = await self._get_keys(pattern_key)
        if len(keys) == 0:
            return
        async with self.lock:
            await self.redis.delete(*keys)

    async def set_ttl(self, session_id: str, new_ttl: int) -> None:
        pattern_key: str = build_session_key(session_id=session_id)
        keys = await self._get_keys(pattern_key, first_only=True)
        if len(keys) == 0:
            logger.error(f"Unable to set ttl for redis key with pattern: {pattern_key}")
            return None
        async with self.lock:
            await self.redis.expire(keys[0], new_ttl)
            logger.debug(f"Set ttl of redis key {keys[0]} to {new_ttl}")
        

    async def exists(self, session_id: str) -> bool:
        pattern_key: str = build_session_key(session_id=session_id)
        keys = await self._get_keys(pattern_key)
        # `exists` with multiple keys returns count of existing ones
        return len(keys) > 0

    async def get_session(self, session_id: str) -> Optional[Session]:
        pattern_key: str = build_session_key(session_id=session_id)
        keys = await self._get_keys(pattern_key)
        if len(keys) == 0:
            return None
        value = await self._get_value(keys[0])

        if value is None:
            return None

        encoded_data = value.decode() if isinstance(value, (bytes, bytearray)) else value

        # The key string determines which Session subclass to return.
        if ":webrtc:" in keys[0]:
            return SessionWebRTC.from_json(encoded_data)
        if ":api_keys:" in keys[0]:
            return SessionAPIKey.from_json(encoded_data)
        return SessionUser.from_json(encoded_data)

    async def get_sessions(self) -> Dict[str, Session]:
        """
        Return **all** sessions in Redis, indexed by their session_id.
        """
        sessions: Dict[str, Session] = {}

        # user-sessions
        async for key in self.redis.scan_iter(match=build_user_session_key(user_id="*", session_id="*")[:-5] + "*"):
            raw = await self.redis.get(key)
            if raw:
                s = SessionUser.from_json(raw)
                sessions[s.id] = s

        # API-key-sessions
        async for key in self.redis.scan_iter(match=build_apikey_session_key(user_id="*", apikey_id="*", session_id="*")[:-5] + "*"):
            raw = await self.redis.get(key)
            if raw:
                sa = SessionAPIKey.from_json(raw)
                sessions[sa.id] = sa

        # webrtc-sessions
        async for key in self.redis.scan_iter(match=build_webrtc_session_key(user_id="*", user_or_api_session="user", session_id="*", webrtc_id="*")[:-5] + "*"):
            raw = await self.redis.get(key)
            if raw:
                sw = SessionWebRTC.from_json(raw)
                sessions[sw.id] = sw

        return sessions

    async def get_sessions_by_user(self, user_id: str) -> List[SessionUser]:
        pattern = build_user_session_key(user_id=user_id, session_id="*")[:-5] + "*"
        sessions: List[SessionUser] = []
        async for key in self.redis.scan_iter(match=pattern):
            raw = await self.redis.get(key)
            if raw:
                s = SessionUser.from_json(raw)
                sessions.append(s)
        return sessions

    async def get_sessions_by_apikey(self, apikey_id: str) -> List[SessionAPIKey]:
        pattern = build_apikey_session_key(user_id="*", apikey_id=apikey_id, session_id="*")[:-5] + "*"
        sessions: List[SessionAPIKey] = []
        async for key in self.redis.scan_iter(match=pattern):
            raw = await self.redis.get(key)
            if raw:
                sa = SessionAPIKey.from_json(raw)
                sessions.append(sa)
        return sessions

    async def get_webrtc_sessions(self, user_id: str = "*", user_or_api_session_type: str = "*", session_id: str = "*", webrtc_id: str = "*", node_id: str = "*") -> List[SessionWebRTC]:
        sessions: List[SessionWebRTC] = []
        pattern = build_webrtc_session_key(
            user_id=user_id,
            user_or_api_session=user_or_api_session_type,
            session_id=session_id,
            node_id=node_id,
            webrtc_id=webrtc_id
        )

        async for key in self.redis.scan_iter(match=pattern):
            raw = await self.redis.get(key)
            if raw:
                # all data should be webrtc keys
                # "session:*:{user_or_api_session}:*:node:{node_id}:webrtc:*:data"
                sw = SessionWebRTC.from_json(raw)
                sessions.append(sw)
        return sessions

    async def get_webrtc_sessions_from_session(self, session: Union[SessionUser, SessionAPIKey]) -> List[SessionWebRTC]:
        """
        Get all WebRTC sessions associated with a user or API key session.
        """
        if not isinstance(session, (SessionUser, SessionAPIKey)):
            raise TypeError(
                "get_webrtc_sessions_from_session expects a SessionUser or SessionAPIKey, "
                f"got {type(session).__name__}"
            )

        pattern = build_webrtc_session_key(
            user_id=session.user_id,
            user_or_api_session="user" if isinstance(session, SessionUser) else "api_key",
            session_id=session.id,
            node_id="*",
            webrtc_id="*"
        )
        webrtc_sessions: List[SessionWebRTC] = []
        async for key in self.redis.scan_iter(match=pattern):
            raw = await self.redis.get(key)
            if raw:
                webrtc_sessions.append(SessionWebRTC.from_json(raw))
        return webrtc_sessions



# --- Test the Simplified Session Manager ---
async def test_session_manager() -> None:
    from mongoengine import connect
    from mongoengine.connection import disconnect as mongo_disconnect
    from role import Role
    from user import User

    # Disconnect any existing connections to start fresh
    mongo_disconnect()
    MONGODB_URI = "mongodb://localhost:27017/photo_booth_test"
    MONGODB_ADMIN_USER = "admin"
    MONGODB_ADMIN_PASSWORD = "admin"

    # Connect to the test database
    connect(host=MONGODB_URI)

    session_manager = SessionManager(redis_url="redis://localhost:6379")

    # Create a test role if it doesn't exist
    admin_role = Role.objects(rolename="admin").first() # type: ignore[attr-defined]
    if not admin_role:
        admin_role = Role(rolename="admin").save()

    # Create a test user if it doesn't exist
    if not User.objects(username=MONGODB_ADMIN_USER).first(): # type: ignore[attr-defined]
        admin_user = User(username=MONGODB_ADMIN_USER, roles=[admin_role])
        admin_user.set_password(MONGODB_ADMIN_PASSWORD)
        admin_user.save()

    # Log in to create a session.
    session_user = await session_manager.login(MONGODB_ADMIN_USER, MONGODB_ADMIN_PASSWORD)
    session, user = session_user
    print(f"Created session: {session._id}, user_id: {session.user_id}, roles: {[str(r.id) for r in user.roles]}")

    sessions = await session_manager.get_sessions()
    print("Active sessions:", list(sessions.keys()))

    # Log out of the session.
    await session.logout()
    print(f"Session {session._id} logged out")

    # Check that the session is removed from Redis.
    sessions = await session_manager.get_sessions()
    print("Active sessions after logout:", list(sessions.keys()))

    # Clean up the test database
    User.objects().delete() # type: ignore[attr-defined]
    Role.objects().delete() # type: ignore[attr-defined]
    mongo_disconnect()


if __name__ == "__main__":
    asyncio.run(test_session_manager())