from pydantic import BaseModel
from datetime import datetime

class WebRTCSession(BaseModel):
    id: str
    expiration_date: datetime
    creation_date: datetime
    user_id: str
    parent_session_id: str