

import base64
from datetime import datetime, timezone
import hashlib
import uuid
from typing import Tuple, Optional, List

import mongoengine
from mongoengine import Document, signals
CASCADE = 2
from mongoengine.fields import (
    DateTimeField,
    StringField,
    ListField,
    ReferenceField,
)

class ApiKey(Document):
    id = StringField(primary_key=True, required=True, default=lambda: f"APIKEY-{uuid.uuid4()}")
    user = ReferenceField('User', required=True, reverse_delete_rule=CASCADE) # type: ignore
    key_hash = StringField(required=True, unique=True)
    created_at = DateTimeField(required=True, default=datetime.utcnow)
    expiration = DateTimeField()
    roles = ListField(ReferenceField('Role'))

    meta = {
        'collection': 'api_keys',
        'indexes': [
            'key_hash',
        ]
    }

    @staticmethod
    def hash_key(key: str) -> str:
        """
        Deterministically hash the key using PBKDF2 with a salt derived from the key.
        """
        salt = ("key_salt" + key[::-1] + "key_salt").encode()
        dk = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100_000)
        return base64.b64encode(dk).decode()

    def verify_key(self, key: str) -> bool:
        """
        Verify the key against the stored hash.
        """
        return self.hash_key(key) == self.key_hash

    @classmethod
    def create_key(cls, user: 'User', roles: Optional[List['Role']] = None, expiration: Optional[datetime] = None) -> Tuple['ApiKey', str]:
        """
        Creates a new APIKey instance and saves it to the database.
        Returns the instance and the raw (unhashed) key.
        The caller is responsible for adding this key to the user's api_keys list and saving the user.
        """
        raw_key = f"key-{uuid.uuid4()}"
        key_hash = cls.hash_key(raw_key)

        api_key = cls(
            user=user,
            key_hash=key_hash,
            expiration=expiration,
            roles=roles if roles else [],
        )
        api_key.save()
        return api_key, raw_key

    def is_expired(self) -> bool:
        """
        Check if the API key is expired.
        """
        if self.expiration is None:
            return False
        return datetime.now(timezone.utc) > self.expiration

    @classmethod
    def pre_delete(cls, sender, document, **kwargs):
        """
        Signal handler to remove this API key from the user's api_keys list before deletion.
        This ensures referential integrity when an API key is deleted.
        """
        if document.user and document in document.user.api_keys:
            # Use atomic operation to remove the reference
            from user import User
            User.objects(id=document.user.id).update_one(pull__api_keys=document)

# Connect the signal handler
signals.pre_delete.connect(ApiKey.pre_delete, sender=ApiKey)