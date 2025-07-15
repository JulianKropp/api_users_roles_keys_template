from pydantic import BaseModel
from datetime import datetime

class WSSession(BaseModel):
    """Pydantic model for WebSocket session data"""
    id: str
    expiration_date: datetime
    creation_date: datetime
    user_id: str
    parent_session_id: str
