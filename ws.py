import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Set, Any, Callable, Awaitable, List

from fastapi import WebSocket, WebSocketDisconnect

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WSConnection:
    def __init__(self, websocket: WebSocket, client_id: Optional[str] = None, 
                 on_start_callback: Optional[Callable[["WSConnection"], Awaitable[None]]] = None,
                 on_close_callback: Optional[Callable[["WSConnection"], Awaitable[None]]] = None,
                 on_msg_callback: Optional[Callable[["WSConnection", Any], Awaitable[None]]] = None):
        self.websocket = websocket
        self.client_id = client_id or f"WS-{uuid.uuid4()}"
        self.connection_id = str(uuid.uuid4())  # Unique ID for this connection
        self.connected_at = datetime.now(timezone.utc)
        self.last_activity = self.connected_at
        self.custom_data: Dict[str, Any] = {}
        
        # Custom callbacks
        self._on_start_callback = on_start_callback
        self._on_close_callback = on_close_callback
        self._on_msg_callback = on_msg_callback
    
    async def on_start(self) -> None:
        """Called when a client connection is established"""
        await self.websocket.accept()
        self.last_activity = datetime.now(timezone.utc)
        logger.info(f"Client {self.client_id} connected")
        
        # Call custom callback if provided
        if self._on_start_callback:
            await self._on_start_callback(self)
    
    async def on_close(self) -> None:
        """Called when a client connection is closed"""
        logger.info(f"Client {self.client_id} disconnected")
        
        # Call custom callback if provided
        if self._on_close_callback:
            await self._on_close_callback(self)
    
    async def on_msg(self, data: Any) -> None:
        """Called when a message is received from the client"""
        self.last_activity = datetime.now(timezone.utc)
        logger.info(f"Received message from {self.client_id}: {data}")
        
        # Call custom callback if provided
        if self._on_msg_callback:
            await self._on_msg_callback(self, data)
    
    async def send_message(self, message: Any) -> None:
        """Send a message to the client"""
        if isinstance(message, dict) or isinstance(message, list):
            await self.websocket.send_json(message)
        elif isinstance(message, str):
            await self.websocket.send_text(message)
        elif isinstance(message, bytes):
            await self.websocket.send_bytes(message)
        else:
            await self.websocket.send_text(str(message))
        self.last_activity = datetime.now(timezone.utc)

class WSManager:
    def __init__(self, inactive_timeout: int = 5,
                 on_new_client_callback: Optional[Callable[[WSConnection], Awaitable[None]]] = None,
                 on_client_removed_callback: Optional[Callable[[str, Optional[str]], Awaitable[None]]] = None,
                 add_connection_callback: Optional[Callable[[WSConnection], Awaitable[None]]] = None):
        self.connections: Dict[str, WSConnection] = {}  # connection_id -> connection
        self.client_connections: Dict[str, Set[str]] = {}  # client_id -> set of connection_ids
        self.inactive_timeout = inactive_timeout  # seconds
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Custom callbacks
        self._on_new_client_callback = on_new_client_callback
        self._on_client_removed_callback = on_client_removed_callback
        self._add_connection_callback = add_connection_callback
    
    def start_cleanup_task(self) -> None:
        """Start the background task to clean up inactive connections"""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_inactive_connections())
    
    async def _cleanup_inactive_connections(self) -> None:
        """Periodically check and remove inactive connections"""
        async def timeout() -> None:
                """Remove connections that have been inactive for too long"""
                now = datetime.now(timezone.utc)
                timeout_ids = []
                
                for connection_id, connection in list(self.connections.items()):
                    if (now - connection.last_activity).total_seconds() > self.inactive_timeout:
                        timeout_ids.append(connection_id)
                
                for connection_id in timeout_ids:
                    await self.remove_connection(connection_id, reason="timeout")

        while True:
            await asyncio.sleep(self.inactive_timeout)  # Check every minute
            await timeout()
    
    async def on_new_client(self, connection: WSConnection) -> None:
        """Called when a new client is added"""
        logger.info(f"New client added: {connection.client_id}")
        
        # Call custom callback if provided
        if self._on_new_client_callback:
            await self._on_new_client_callback(connection)
    
    async def on_client_removed(self, client_id: str, reason: Optional[str] = None) -> None:
        """Called when a client is removed"""
        logger.info(f"Client removed: {client_id}, reason: {reason or 'unknown'}")
        
        # Call custom callback if provided
        if self._on_client_removed_callback:
            await self._on_client_removed_callback(client_id, reason)
    
    async def add_connection(self, connection: WSConnection) -> None:
        """Add a new WebSocket connection"""
        await connection.on_start()
        
        # Store the connection by its unique connection_id
        self.connections[connection.connection_id] = connection
        
        # Track this connection under the client_id
        if connection.client_id not in self.client_connections:
            self.client_connections[connection.client_id] = set()
        self.client_connections[connection.client_id].add(connection.connection_id)
        
        # Call custom callback if provided
        if self._add_connection_callback:
            await self._add_connection_callback(connection)
        
        await self.on_new_client(connection)
    
    async def remove_connection(self, connection_id: str, reason: Optional[str] = None) -> None:
        """Remove a WebSocket connection by its connection_id"""
        connection = self.connections.pop(connection_id, None)
        if connection:
            # Remove from client_connections mapping
            client_id = connection.client_id
            if client_id in self.client_connections:
                self.client_connections[client_id].discard(connection_id)
                if not self.client_connections[client_id]:  # If no more connections for this client
                    del self.client_connections[client_id]
            
            try:
                await connection.on_close()
            except Exception as e:
                logger.error(f"Error during connection close: {e}")
            await self.on_client_removed(client_id, reason)
    
    def get_connection(self, connection_id: str) -> Optional[WSConnection]:
        """Get a specific connection by connection ID"""
        return self.connections.get(connection_id)
        
    def get_client_connections(self, client_id: str) -> List[WSConnection]:
        """Get all connections for a specific client ID"""
        if client_id not in self.client_connections:
            return []
        return [self.connections[conn_id] for conn_id in self.client_connections[client_id] 
                if conn_id in self.connections]
    
    def get_connections(self) -> List[WSConnection]:
        """Get all active connections"""
        return list(self.connections.values())

# FastAPI integration
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse
import uvicorn
import os

async def main():
    # Create FastAPI app
    app = FastAPI(title="WebSocket Demo")
    
    # Example custom callback functions
    async def custom_on_new_client(connection: WSConnection) -> None:
        print(f"Custom handler: New client connected: {connection.client_id}")
        # You could perform additional actions here like database updates
    
    async def custom_on_client_removed(client_id: str, reason: Optional[str]) -> None:
        print(f"Custom handler: Client {client_id} removed. Reason: {reason}")
        # You could perform cleanup actions here
    
    async def custom_add_connection(connection: WSConnection) -> None:
        print(f"Custom handler: Connection {connection.connection_id} added for client {connection.client_id}")
        # You could initialize client-specific resources here
    
    async def custom_on_start(connection: WSConnection) -> None:
        print(f"Custom handler: Connection started for {connection.client_id}")
        # Send a welcome message
        await connection.send_message({"type": "system", "message": "Welcome to the WebSocket server!"})
    
    async def custom_on_close(connection: WSConnection) -> None:
        print(f"Custom handler: Connection closed for {connection.client_id}")
        # Perform any cleanup specific to this connection
    
    async def custom_on_msg(connection: WSConnection, data: Any) -> None:
        print(f"Custom handler: Message from {connection.client_id}: {data}")
        # You could implement custom message handling logic here
        if isinstance(data, dict) and data.get("type") == "echo":
            await connection.send_message({"type": "echo_response", "original": data})
    
    # Create WebSocket manager with custom callbacks
    manager = WSManager(
        inactive_timeout=5,  # 5 seconds timeout for demo
        on_new_client_callback=custom_on_new_client,
        on_client_removed_callback=custom_on_client_removed,
        add_connection_callback=custom_add_connection
    )
    manager.start_cleanup_task()
    
    # Mount static files
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static-ws")
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    # Serve index.html
    @app.get("/")
    async def get_index():
        return FileResponse(os.path.join(static_dir, "index.html"))
    
    # Helper function to broadcast messages to all clients
    async def broadcast_message(sender_id: str, message_data: dict):
        # Create a message with sender information and timestamp
        broadcast_msg = {
            "type": "broadcast",
            "sender_id": sender_id,
            "data": message_data,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Send to all connected clients
        for client in manager.get_connections():
            try:
                await client.send_message(broadcast_msg)
            except Exception as e:
                logger.error(f"Error broadcasting to {client.client_id}: {e}")
    
    # WebSocket endpoint
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        # Create connection with custom callbacks
        connection = WSConnection(
            websocket, 
            on_start_callback=custom_on_start,
            on_close_callback=custom_on_close,
            on_msg_callback=custom_on_msg
        )
        await manager.add_connection(connection)
        
        # Notify all clients about the new connection
        await broadcast_message("system", {
            "type": "notification",
            "text": f"Client {connection.client_id} has joined"
        })
        
        try:
            while True:
                # Receive message from client
                data = await websocket.receive_json()
                await connection.on_msg(data)
                
                # Broadcast the message to all clients
                await broadcast_message(connection.client_id, data)
        except WebSocketDisconnect:
            await manager.remove_connection(connection.connection_id, reason="disconnected")
            # Notify remaining clients about the disconnection
            await broadcast_message("system", {
                "type": "notification",
                "text": f"Client {connection.client_id} has left"
            })
        except Exception as e:
            logger.error(f"Error in WebSocket connection: {e}")
            await manager.remove_connection(connection.connection_id, reason=f"error: {str(e)}")

    return app

if __name__ == "__main__":
    # Run the FastAPI application
    app = asyncio.run(main())
    
    # Start the server
    uvicorn.run(app, host="0.0.0.0", port=8000)
