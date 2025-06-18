import asyncio
import logging
from contextlib import asynccontextmanager
from math import ceil
import os
from typing import AsyncIterator, Union

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi_limiter import FastAPILimiter
from fastapi_limiter import FastAPILimiter
import redis.asyncio as redis
from starlette.datastructures import Headers
import uvicorn

from config import Config
from mongoengine import connect
from mongoengine import disconnect # type: ignore
from models.user import User
from models.role import Endpoint, Role, Method
from webrtc import APM

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------
# Configuration
# ---------------------------
# Load environment variables from .env file
CONFIG = Config()

# connect to db
connect(
    db=CONFIG.MONGO_DB_NAME,
    host=CONFIG.MONGO_HOST,
    port=CONFIG.MONGO_PORT,
    username=CONFIG.MONGO_USER,
    password=CONFIG.MONGO_PASSWORD,
    authentication_source=CONFIG.MONGO_AUTH_SOURCE
)

# ---------------------------
# Setup db
# ---------------------------
# Create default boss role if it doesn't exist
if not Role.objects(rolename="boss").first(): # type: ignore[attr-defined]
    boss_role = Role(
        rolename="boss",
        api_endpoints=[
            Endpoint(
                method=Method.ANY,
                path_filter="/*"
            )
        ]
    )
    print(boss_role.to_mongo())
    boss_role.save()

BOSS_ROLE = Role.objects(rolename="boss").first() # type: ignore[attr-defined]
if BOSS_ROLE is None:
    raise Exception("Boss role not found. Please reinitialize the database.")

# create a boss user if it doesn't exist
if not User.objects(username="boss").first(): # type: ignore[attr-defined]
    boss_user = User(
        username="boss",
        roles=[BOSS_ROLE]
    )
    boss_user.set_password("boss")
    boss_user.save()

# check if the boss user has the boss role, and add it if not
BOSS_USER = User.objects(username="boss").first() # type: ignore[attr-defined]
if not BOSS_ROLE in BOSS_USER.roles: # type: ignore[attr-defined]
    BOSS_USER.roles.append(BOSS_ROLE) # type: ignore[attr-defined]
    BOSS_USER.save()

# ---------------------------
# FastAPI App Initialization
# ---------------------------
# Identify the service by the Service-Name header or the IP address
async def service_name_identifier(request: Request) -> Union[str, Headers]:
    if request.client is None:
        return "unknown"
    return request.headers.get("Service-Name") or request.client.host  # Identify by IP if no header

async def rate_limit_exceeded_callback(request: Request, response: Response, pexpire: int) -> None:
    """
    default callback when too many requests
    :param request:
    :param pexpire: The remaining milliseconds
    :param response:
    :return:
    """
    expire = ceil(pexpire / 1000)

    raise HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        f"Too Many Requests. Retry after {expire} seconds.",
        headers={"Retry-After": str(expire)},
    )

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Connect to Redis
    redis_connection = redis.from_url(CONFIG.REDIS_URL, encoding="utf8", decode_responses=True)
    await FastAPILimiter.init(
        redis_connection,
        identifier=service_name_identifier,
        http_callback=rate_limit_exceeded_callback,
    )

    # Check for timeouts for WebRTC connections
    asyncio.create_task(APM.check_timeouts())

    try:
        yield
    finally:
        # Disconnect from MongoDB
        disconnect()
        # Close Redis connection
        await FastAPILimiter.close()

app = FastAPI(
    lifespan=lifespan,
    title="User Management API",
    description="An API for managing users, roles, authentication sessions, and API keys.",
    version="1.0",
    openapi_tags=[
        {
            "name": "Webpage",
            "description": "Webpage endpoints"
        },
        {
            "name": "System",
            "description": "System information endpoints"
        },
        {
            "name": "Authentication",
            "description": "User and API key authentication endpoints"
        },
        {
            "name": "Roles",
            "description": "Role management endpoints"
        },
        {
            "name": "Users",
            "description": "User management endpoints"
        },
        {
            "name": "API Keys",
            "description": "API key management endpoints"
        },
        {
            "name": "WebRTC",
            "description": "WebRTC communication endpoints"
        }
    ]
)

# ---------------------------
# CORS Middleware
# ---------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[CONFIG.EXTERNAL_URL],  # Allowed Origins from the frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------
# Add Routs
# ---------------------------
import api.auth.endpoints
import api.system.endpoints
import api.roles.endpoints
import api.users.endpoints
import api.api_keys.endpoints
import api.webrtc.endpoints

app.include_router(api.auth.endpoints.router)
app.include_router(api.system.endpoints.router)
app.include_router(api.roles.endpoints.router)
app.include_router(api.users.endpoints.router)
app.include_router(api.api_keys.endpoints.router)
app.include_router(api.webrtc.endpoints.router)


# ---------------------------
# Webpage
# ---------------------------
app.mount("/assets", StaticFiles(directory="frontend/dist/assets"), name="assets")

# Catch-all route: For any path, serve the index.html so React can handle routing.
@app.get(
    "/{full_path:path}",
    tags=["Webpage"],
    response_class=HTMLResponse,
    description="Catch-all route that serves the React application's index.html for any unspecified path."
)
async def serve_react_app(full_path: str) -> FileResponse:
    index_path = os.path.join("static-webrtc", "index.html")
    return FileResponse(index_path)


# ---------------------------
# Main
# ---------------------------
async def main() -> None:
    # Configure the server (this does not call asyncio.run() internally)
    config = uvicorn.Config(app, host=CONFIG.HOST, port=CONFIG.PORT, log_level="info")
    server = uvicorn.Server(config)
    # Run the server asynchronously
    await asyncio.gather(
        server.serve()
    )

if __name__ == "__main__":
    STATUS = "running"
    asyncio.run(main())
    STATUS = "stopped"