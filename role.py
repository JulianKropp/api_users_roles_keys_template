import uuid
from enum import Enum
from mongoengine import Document, EmbeddedDocument
from mongoengine.fields import (
    EmbeddedDocumentField,
    StringField,
    BooleanField,
    DateTimeField,
    ListField,
    ReferenceField,
    EnumField,
)


class Method(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    ANY = "ANY"


class Endpoint(EmbeddedDocument):
    method = EnumField(Method, required=True)
    path_filter = StringField(required=True)


class Role(Document):
    id = StringField(primary_key=True, required=True, default=lambda: f"ROLE-{uuid.uuid4()}")
    rolename = StringField(required=True, unique=True)
    api_endpoints = ListField(EmbeddedDocumentField(Endpoint))

    meta = {
        'collection': 'roles',
        'indexes': [
            'rolename',
        ]
    }
