from abc import ABC, abstractmethod
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid
import json

# Async Redis client  (pip install redis)
import redis.asyncio as redis

from api_key import APIKey
from db_connection import MongoDBConnection
from user import User, datetime_from_str, datetime_to_str


# --------------------------------------------------------------------------- #
#  Constants & helpers
# --------------------------------------------------------------------------- #
SESSION_DURATION_SECONDS = 60 * 60 * 24  # 24 h

# New Redis key format
USER_SESSION_KEY     = "session:{user_id}:sessions:{session_id}:data"
APIKEY_SESSION_KEY   = "session:{user_id}:api_keys:{apikey_id}:sessions:{session_id}:data"
WEBRTC_SESSION_KEY = "session:{user_id}:{user_or_api_session}:{session_id}:webrtc:{webrtc_id}:data"

def build_user_session_key(user_id: str, session_id: str) -> str:
    return USER_SESSION_KEY.format(user_id=user_id, session_id=session_id)

def build_apikey_session_key(user_id: str, apikey_id: str, session_id: str) -> str:
    return APIKEY_SESSION_KEY.format(
        user_id=user_id, apikey_id=apikey_id, session_id=session_id
    )

def build_webrtc_session_key(user_id: str, user_or_api_session: str, session_id: str, webrtc_id: str) -> str:
    if user_or_api_session == "user":
        user_or_api_session = "sessions"
    elif user_or_api_session == "api_key":
        user_or_api_session = "api_keys"
    else:
        raise ValueError("user_or_api_session must be 'user' or 'api_key'")
    
    return WEBRTC_SESSION_KEY.format(
        user_id=user_id,
        user_or_api_session=user_or_api_session,
        session_id=session_id,
        webrtc_id=webrtc_id
    )

# --------------------------------------------------------------------------- #
#  Session dataclasses
# --------------------------------------------------------------------------- #
class Status(Enum):
    ACTIVE   = "active"
    INACTIVE = "inactive"


@dataclass
class Session(ABC):
    expiration_date: datetime
    creation_date: datetime = field(default_factory=datetime.now)
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
        creation_date = datetime_from_str(data.get("creation_date"))
        expiration_date = datetime_from_str(data.get("expiration_date"))

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
        creation_date = datetime_from_str(data.get("creation_date"))
        expiration_date = datetime_from_str(data.get("expiration_date"))

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
        creation_date = datetime_from_str(data.get("creation_date"))
        expiration_date = datetime_from_str(data.get("expiration_date"))

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

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.lock  = asyncio.Lock()

    # -- Login helpers ------------------------------------------------------ #
    async def login(
        self, db: MongoDBConnection, username: str, password: str
    ) -> Tuple[SessionUser, User]:
        user = User.db_find_by_username(db, username)
        if user is None:
            raise ValueError("User not found")

        hashed, _ = User.hash_password(password, user.password_salt)
        if hashed != user.password_hash:
            raise ValueError("Incorrect password")

        user.last_login = datetime.now()
        user.db_update(db)

        session = SessionUser(
            user_id=user.id,
            expiration_date=datetime.now() + timedelta(seconds=SESSION_DURATION_SECONDS),
        )

        key = build_user_session_key(user.id, session.id)
        async with self.lock:
            await self.redis.set(key, session.to_json(), ex=SESSION_DURATION_SECONDS)
        return session, user

    async def login_apikey(
        self, db: MongoDBConnection, apikey: str
    ) -> Tuple[SessionAPIKey, APIKey]:
        apikey_obj = APIKey.db_find_by_key(db, apikey)
        if apikey_obj is None:
            raise ValueError("API key not found")

        user = User.db_find_by_id(db, apikey_obj.user_id)
        if user is None:
            raise ValueError("Owner of API key not found")

        session = SessionAPIKey(
            apikey_id=apikey_obj.id,
            user_id=user.id,
            expiration_date=datetime.now() + timedelta(seconds=SESSION_DURATION_SECONDS),
        )

        key = build_apikey_session_key(user.id, apikey_obj.id, session.id)
        async with self.lock:
            await self.redis.set(key, session.to_json(), ex=SESSION_DURATION_SECONDS)
        return session, apikey_obj

    async def login_webrtc(self, session: Union[SessionUser, SessionAPIKey]) -> SessionWebRTC:
        """
        Create a WebRTC session for the given user or API key session.
        This is a placeholder implementation, as WebRTC sessions would typically
        involve more complex signaling and state management.
        """
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

        calculate_expiration = (
            session.expiration_date - datetime.now()
        ).total_seconds()

        async with self.lock:
            await self.redis.set(key, webrtc_session.to_json(), ex=calculate_expiration)
        return webrtc_session

    # -- Private utilities -------------------------------------------------- #
    async def _keys_for_session_id(self, session_id: str) -> List[str]:
        """
        Resolve the *full* Redis key(s) that contain a given session_id.
        """
        patterns = [
            f"session:*:sessions:{session_id}:*",
            f"session:*:api_keys:*:sessions:{session_id}:*",
            f"session:*:*:*:webrtc:{session_id}:*"
        ]
        keys: List[str] = []
        for patt in patterns:
            async for k in self.redis.scan_iter(match=patt):
                keys.append(k)
        return keys

    # -- Public API --------------------------------------------------------- #
    async def logout(self, session_id: str) -> None:
        keys = await self._keys_for_session_id(session_id)
        if not keys:
            return
        async with self.lock:
            await self.redis.delete(*keys)

    async def exists(self, session_id: str) -> bool:
        keys = await self._keys_for_session_id(session_id)
        if not keys:
            return False
        # `exists` with multiple keys returns count of existing ones
        return await self.redis.exists(*keys) > 0

    async def get_session(
        self, session_id: str
    ) -> Optional[Union[SessionUser, SessionAPIKey]]:
        keys = await self._keys_for_session_id(session_id)
        if not keys:
            return None

        data = await self.redis.get(keys[0])
        if data is None:
            return None

        # Decide type from key shape
        if ":api_keys:" in keys[0]:
            return SessionAPIKey.from_json(data)
        return SessionUser.from_json(data)

    async def get_sessions(self) -> Dict[str, Union[SessionUser, SessionAPIKey]]:
        """
        Return **all** sessions in Redis, indexed by their session_id.
        """
        sessions: Dict[str, Union[SessionUser, SessionAPIKey]] = {}

        # user-sessions
        async for key in self.redis.scan_iter(match="session:*:sessions:*"):
            raw = await self.redis.get(key)
            if raw:
                s = SessionUser.from_json(raw)
                sessions[s.id] = s

        # API-key-sessions
        async for key in self.redis.scan_iter(match="session:*:api_keys:*:sessions:*"):
            raw = await self.redis.get(key)
            if raw:
                sa = SessionAPIKey.from_json(raw)
                sessions[s.id] = sa

        return sessions

    async def get_sessions_by_user(self, user_id: str) -> List[SessionUser]:
        pattern = f"session:{user_id}:sessions:*"
        sessions: List[SessionUser] = []
        async for key in self.redis.scan_iter(match=pattern):
            raw = await self.redis.get(key)
            if raw:
                sessions.append(SessionUser.from_json(raw))
        return sessions

    async def get_sessions_by_apikey(self, apikey_id: str) -> List[SessionAPIKey]:
        pattern = f"session:*:api_keys:{apikey_id}:sessions:*"
        sessions: List[SessionAPIKey] = []
        async for key in self.redis.scan_iter(match=pattern):
            raw = await self.redis.get(key)
            if raw:
                sessions.append(SessionAPIKey.from_json(raw))
        return sessions



# --- Test the Simplified Session Manager ---
async def test_session_manager() -> None:
    MONGODB_URI = "localhost:27017"
    MONGODB_DB_NAME = "photo_booth"
    MONGODB_ADMIN_USER = "admin"
    MONGODB_ADMIN_PASSWORD = "admin"

    db_connection = MongoDBConnection(
        mongo_uri=MONGODB_URI,
        user=MONGODB_ADMIN_USER,
        password=MONGODB_ADMIN_PASSWORD,
        db_name=MONGODB_DB_NAME,
        admin=True
    )
    session_manager = SessionManager(redis_url="redis://localhost:6379")

    # create user admin if not exists
    User.db_create_collection(db_connection)
    if not User.db_find_by_username(db_connection, MONGODB_ADMIN_USER):
        User.new(
            db_connection=db_connection,
            username=MONGODB_ADMIN_USER,
            password=MONGODB_ADMIN_PASSWORD,
            roles_id=["admin"]
        )

    # Log in to create a session.
    session_user = await session_manager.login(db_connection, MONGODB_ADMIN_USER, MONGODB_ADMIN_PASSWORD)
    session, user = session_user
    print(f"Created session: {session._id}, user_id: {session.user_id}, roles: {user.roles}")

    sessions = await session_manager.get_sessions()
    print("Active sessions:", list(sessions.keys()))

    # Log out of the session.
    await session.logout()
    print(f"Session {session._id}")

    # Check that the session is removed from Redis.
    sessions = await session_manager.get_sessions()
    print("Active sessions after logout:", list(sessions.keys()))


if __name__ == "__main__":
    asyncio.run(test_session_manager())