

# Helper functions to convert datetime objects to/from strings.
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import List, Optional, Tuple
import uuid

import bcrypt

from db_connection import MongoDBConnection


def datetime_to_str(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None

def datetime_from_str(dt_str: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(dt_str) if dt_str else None

# Define a module-level constant for the collection name.
APIKEY_COLLECTION = "api_keys"

@dataclass
class APIKey:
    """
    Represents an API key with its associated metadata.
    """
    created_at: datetime
    user_id: str
    key_hash: str
    expiration: Optional[datetime] = None
    roles: List[str] = field(default_factory=list)
    _id: str = field(default_factory=lambda: f"API-{uuid.uuid4()}")

    # Collection name for MongoDB.
    COLLECTION_NAME: str = APIKEY_COLLECTION

    @property
    def id(self) -> str:
        return self._id

    def to_dict(self) -> dict:
        """
        Converts the APIKey instance to a dictionary.
        """
        return{
                "key_hash": self.key_hash,
                "user_id": self.user_id,
                "created_at": datetime_to_str(self.created_at),
                "expiration": datetime_to_str(self.expiration),
                "roles": self.roles,
                "_id": self._id,
            }

    @classmethod
    def from_dict(cls, data: dict) -> "APIKey":
        """
        Creates an APIKey instance from a dictionary.
        """
        create_date = datetime_from_str(data["created_at"])
        return cls(
            key_hash=data["key_hash"],
            user_id=data["user_id"],
            created_at=create_date if create_date is not None else datetime.now(timezone.utc),
            expiration=datetime_from_str(data["expiration"]),
            roles=data.get("roles", []),
            _id=data["_id"],
        )
    
    def __str__(self) -> str:
        """
        Returns a string representation of the APIKey instance.
        """
        return json.dumps({
            "key_hash": self.key_hash,
            "user_id": self.user_id,
            "created_at": datetime_to_str(self.created_at),
            "expiration": datetime_to_str(self.expiration),
            "roles": self.roles,
            "_id": self._id,
        }, indent=4)
    
    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, APIKey):
            return self.id == other.id
        return False

    def __hash__(self) -> int:
        return hash(self.id)
    
    @classmethod
    def db_create_collection(cls, db_connection: MongoDBConnection) -> None:
        """
        Creates the collection in the database if it doesn't exist.
        """
        schema = {
            "validator": {
                "$jsonSchema": {
                    "bsonType": "object",
                    "required": ["_id", "key_hash", "user_id", "created_at", "roles", "expiration"],
                    "properties": {
                        "_id": {
                            "bsonType": "string",
                            "description": "must be a string and is required"
                        },
                        "user_id": {
                            "bsonType": "string",
                            "description": "must be a string and is required"
                        },
                        "key_hash": {
                            "bsonType": "string",
                            "description": "must be a string and is required"
                        },
                        "created_at": {
                            "bsonType": "string",
                            "description": "must be a string as ISO date"
                        },
                        "expiration": {
                            "bsonType": ["string", "null"],
                            "description": "must be a string as ISO date or null"
                        },
                        "roles": {
                            "bsonType": "array",
                            "description": "must be an array and is required",
                            "items": {
                                "bsonType": "string"
                            }
                        }
                    }
                }
            },
            "validationLevel": "strict",
            "validationAction": "error"
        }
        if cls.COLLECTION_NAME not in db_connection.db.list_collection_names():
            print(f"Creating collection {cls.COLLECTION_NAME} with schema: {schema}")
            db_connection.db.create_collection(
                name=cls.COLLECTION_NAME,
                validator=schema["validator"],
                validationLevel=schema["validationLevel"],
                validationAction=schema["validationAction"]
            )

            db_connection.db[cls.COLLECTION_NAME].create_index([("key_hash", 1)], unique=True)
    
    @classmethod
    def db_drop_collection(cls, db_connection: MongoDBConnection) -> None:
        """
        Drop the MongoDB collection for users.
        """
        db_connection.db.drop_collection(cls.COLLECTION_NAME)

    @classmethod
    def new(cls, db_connection: MongoDBConnection, user_id: str, expiration: Optional[datetime] = None, roles: Optional[List[str]] = None) -> Tuple["APIKey", str]:
        """
        Creates a new APIKey instance and saves it to the database.
        """
        key = f"key-{uuid.uuid4()}"
        key_hash = cls.hash_key(key)

        api_key = cls(
            user_id=user_id,
            key_hash=key_hash,
            created_at=datetime.now(timezone.utc),
            expiration=expiration,
            roles=roles if roles else [],
        )
        return api_key, key

    @staticmethod
    def hash_key(key: str) -> str:
        """
        Deterministically hash the key using PBKDF2 with a salt derived from the key.
        """
        salt = ("key_salt" + key[::-1] + "key_salt").encode()  # not nice but I need to search the hash in the db, so the salt has to be generated out of the key
        dk = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100_000)
        return base64.b64encode(dk).decode()

    def verify_key(self, key: str) -> bool:
        """
        Verify the key against the stored hash.
        """
        return self.hash_key(key) == self.key_hash

    def db_save(self, db_connection: MongoDBConnection) -> None:
        """
        Save the user object to MongoDB.
        """
        collection = db_connection.db[self.COLLECTION_NAME]
        data = self.to_dict()
        collection.insert_one(data)

    @classmethod
    def db_find_by_id(cls, db_connection: MongoDBConnection, _id: str) -> Optional["APIKey"]:
        """
        Find an APIKey by its ID.
        """
        collection = db_connection.db[cls.COLLECTION_NAME]
        data = collection.find_one({"_id": _id})
        if data:
            return cls.from_dict(data)
        return None
    
    @classmethod
    def db_find_by_key(cls, db_connection: MongoDBConnection, key: str) -> Optional["APIKey"]:
        """
        Find an APIKey by its key.
        """
        collection = db_connection.db[cls.COLLECTION_NAME]
        data = collection.find_one({"key": key})
        if data:
            return cls.from_dict(data)
        return None
    
    @classmethod
    def db_find_by_key_hash(cls, db_connection: MongoDBConnection, key_hash: str) -> Optional["APIKey"]:
        """
        Find an APIKey by its key hash.
        """
        collection = db_connection.db[cls.COLLECTION_NAME]
        data = collection.find_one({"key_hash": key_hash})
        if data:
            return cls.from_dict(data)
        return None

    def db_refresh(self, db_connection: MongoDBConnection) -> None:
        """
        Refresh the APIKey instance from the database.
        """
        collection = db_connection.db[self.COLLECTION_NAME]
        data = collection.find_one({"_id": self._id})
        if data:
            create_date = datetime_from_str(data["created_at"])
            self.key_hash = data["key_hash"]
            self.user_id = data["user_id"]
            self.created_at = create_date if create_date is not None else datetime.now(timezone.utc)
            self.expiration = datetime_from_str(data["expiration"])
            self.roles = data.get("roles", [])
        else:
            raise ValueError(f"APIKey with id {self._id} not found in the database.")
    
    def db_update(self, db_connection: MongoDBConnection) -> None:
        """
        Update the APIKey instance in the database.
        """
        collection = db_connection.db[self.COLLECTION_NAME]
        data = self.to_dict()
        collection.update_one({"_id": self._id}, {"$set": data})
    
    def db_delete(self, db_connection: MongoDBConnection) -> None:
        """
        Delete the APIKey instance from the database.
        """
        collection = db_connection.db[self.COLLECTION_NAME]
        collection.delete_one({"_id": self._id})
    
    @classmethod
    def db_find_all(cls, db_connection: MongoDBConnection) -> list["APIKey"]:
        """
        Find all APIKeys in the database.
        """
        collection = db_connection.db[cls.COLLECTION_NAME]
        data = collection.find()
        return [cls.from_dict(item) for item in data]
    
    def is_expired(self) -> bool:
        """
        Check if the API key is expired.
        """
        now = datetime.now(timezone.utc)
        if self.expiration is None:
            return False
        return now > self.expiration