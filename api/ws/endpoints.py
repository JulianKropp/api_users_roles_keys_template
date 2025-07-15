import logging
import asyncio
import uuid
import sys
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from typing import Union, List, Literal, Optional, Any, Dict, cast
from pydantic import BaseModel

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config import Config
from api.api_auth import SM, auth, BOSS_ROLE

# Import session module
from session import SessionUser, SessionAPIKey

# Define SessionWS class if not available from session module
class SessionWS:
    """WebSocket session class"""
    def __init__(self, id: str, expiration_date: datetime, creation_date: datetime, user_id: str, parent_session_id: str = ""):
        self.id = id
        self.expiration_date = expiration_date
        self.creation_date = creation_date
        self.user_id = user_id
        self.parent_session_id = parent_session_id
    
    @classmethod
    def from_json(cls, json_str):
        """Create a SessionWS object from JSON string"""
        import json
        data = json.loads(json_str)
        return cls(
            id=data.get('id', ''),
            expiration_date=datetime.fromisoformat(data.get('expiration_date')),
            creation_date=datetime.fromisoformat(data.get('creation_date')),
            user_id=data.get('user_id', ''),
            parent_session_id=data.get('parent_session_id', '')
        )

# Define WSConnection class for WebSocket connection handling
class WSConnection:
    """WebSocket connection class"""
    def __init__(self, client_id: str):
        self.client_id = client_id
        
    async def send_message(self, data: Dict[str, Any]) -> None:
        """Send a message to the WebSocket client"""
        pass

# Define WSManager class for WebSocket connection management
class WSManager:
    """WebSocket connection manager"""
    def __init__(self):
        self.connections = {}
        
    async def add_connection(self, connection):
        """Add a WebSocket connection to the manager"""
        self.connections[connection.client_id] = connection
        
    async def remove_connection(self, client_id: str, reason: str = ""):
        """Remove a WebSocket connection from the manager"""
        if client_id in self.connections:
            del self.connections[client_id]

# Define the WSSession model directly here to avoid import issues
class WSSession(BaseModel):
    """Pydantic model for WebSocket session data"""
    id: str
    expiration_date: datetime
    creation_date: datetime
    user_id: str
    parent_session_id: str

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CONFIG = Config()

router = APIRouter(tags=["WebSocket"])

@router.websocket("/api/v1/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time communication.
    """
    client_id = str(uuid.uuid4())
    logger.info(f"New WebSocket connection: {client_id}")
    
    try:
        # Accept the connection
        await websocket.accept()
        
        # Send welcome message
        await websocket.send_json({"type": "welcome", "message": f"Connected with ID: {client_id}"})
        logger.info(f"WebSocket connection established: {client_id}")
        
        # Create a session for this WebSocket connection
        # This would typically involve storing the session in Redis
        # For now, we'll just log it
        logger.info(f"Created WebSocket session for {client_id}")
        
        # Handle messages
        while True:
            data = await websocket.receive_json()
            logger.info(f"Message from {client_id}: {data}")
            # Echo the message back
            await websocket.send_json({"type": "echo", "data": data})
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {client_id}")
    except Exception as e:
        logger.error(f"Error in WebSocket connection: {e}")
        try:
            await websocket.close()
        except:
            pass

@router.get(
    "/api/v1/ws/sessions",
    tags=["WebSocket"],
    response_model=List[WSSession],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)]
)
async def get_ws_sessions(
    user_id: str = "*",
    user_or_api_session_type: Literal["user", "api_key", "*"] = "*",
    session_id: str = "*",
    node_id: str = "*",
    ws_id: str = "*",
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE])),
) -> List[WSSession]:
    """
    Retrieve a list of all WebSocket sessions according to the filters provided.
    """
    # Use Redis pattern matching to find WebSocket sessions
    try:
        # Try to use the get_ws_sessions method if available
        if hasattr(SM, 'get_ws_sessions'):
            ws_sessions = await SM.get_ws_sessions(
                user_id=user_id,
                user_or_api_session_type=user_or_api_session_type,
                session_id=session_id,
                node_id=node_id,
                ws_id=ws_id
            )
        else:
            # Fallback: Use the get_sessions method and filter for WebSocket sessions
            logger.warning("get_ws_sessions method not available, using fallback")
            # For now, return an empty list as we don't have a proper fallback
            ws_sessions = []
    except Exception as e:
        logger.error(f"Error retrieving WebSocket sessions: {e}")
        ws_sessions = []
    return_list = []
    for s in ws_sessions:
        # Handle the case where parent_session_id might not be available
        parent_session_id = getattr(s, 'parent_session_id', '')
        
        return_list.append(WSSession(
            id=s.id,
            expiration_date=s.expiration_date,
            creation_date=s.creation_date,
            user_id=s.user_id,
            parent_session_id=parent_session_id
        ))
    return return_list

@router.get(
    "/api/v1/ws/sessions/{id}",
    tags=["WebSocket"],
    response_model=WSSession,
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)]
)
async def get_ws_session(
    id: str,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE])),
) -> WSSession:
    """
    Retrieve a specific WebSocket session by ID.
    """
    try:
        # Check if the session exists
        exists = await SM.exists(id)
        if not exists:
            raise HTTPException(status_code=404, detail="WebSocket session not found")
        
        # Try to get the session data
        session_data = await SM.get_session(id)
        if not session_data:
            raise HTTPException(status_code=404, detail="WebSocket session not found")
        
        # Convert to WSSession model
        # Handle the case where parent_session_id might not be available
        parent_session_id = getattr(session_data, 'parent_session_id', '')
        
        return WSSession(
            id=session_data.id,
            expiration_date=session_data.expiration_date,
            creation_date=session_data.creation_date,
            user_id=session_data.user_id,
            parent_session_id=parent_session_id
        )
    except Exception as e:
        logger.error(f"Error retrieving WebSocket session {id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving WebSocket session: {str(e)}")

@router.delete(
    "/api/v1/ws/sessions/{id}",
    tags=["WebSocket"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)]
)
async def delete_ws_session(
    id: str,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE])),
):
    """
    Delete a specific WebSocket session by ID.
    """
    try:
        # Check if the session exists
        exists = await SM.exists(id)
        if not exists:
            raise HTTPException(status_code=404, detail="WebSocket session not found")
        
        # Delete the session
        success = await SM.logout(id)
        if not success:
            raise HTTPException(status_code=404, detail="WebSocket session not found")
        
        return {"status": "success", "message": f"WebSocket session {id} deleted"}
    except Exception as e:
        logger.error(f"Error deleting WebSocket session {id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting WebSocket session: {str(e)}")
