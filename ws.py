import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

app = FastAPI()


class ConnectionManager:
    """Keeps track of active WebSocket connections and
    provides convenience helpers for sending / broadcasting."""
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active:
            self.active.remove(websocket)

    async def send_personal(self, msg: str, websocket: WebSocket):
        await websocket.send_text(msg)

    async def broadcast(self, msg: str):
        """Send the same message to all connected clients."""
        for ws in self.active:
            await ws.send_text(msg)


manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Handles a single WebSocket connection life-cycle."""
    await manager.connect(websocket)
    try:
        # Inform the client it is connected
        await manager.send_personal("👋 Connected to FastAPI WebSocket server", websocket)

        # Loop forever waiting for incoming messages
        while True:
            data = await websocket.receive_text()  # ← message from browser
            # Echo the message back (custom-process here if you like)
            await manager.send_personal(f"Server received: {data}", websocket)

            # Example: broadcast the same payload to everyone else
            await manager.broadcast(f"(broadcast) {data}")

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        # Inform the rest of the clients that someone left
        await manager.broadcast("❌ A client disconnected")


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    with open("static-ws/index.html") as f:
        return f.read()

# Optional helper so you can run the app directly with `python server.py`
# ---------------------------
# Main
# ---------------------------
async def main() -> None:
    # Configure the server (this does not call asyncio.run() internally)
    config = uvicorn.Config(app, host="0.0.0.0", port=8001, log_level="info")
    server = uvicorn.Server(config)
    # Run the server asynchronously
    await asyncio.gather(
        server.serve()
    )

if __name__ == "__main__":
    asyncio.run(main())