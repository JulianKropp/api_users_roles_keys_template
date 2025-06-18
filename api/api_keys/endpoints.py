import logging
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi_limiter.depends import RateLimiter
from pydantic import BaseModel
from typing import Union, List, Literal
from datetime import datetime, timezone
from models.user import User
from models.api_key import ApiKey
from session import SessionManager
from config import Config
from ..api_auth import SM, auth, no_auth, BOSS_ROLE, get_user_or_apikey_from_session, get_user_roles_by_session, compare_roles
from .schemas import APIKeyResponse, APIKeyCreateResponse, APIKeyCreateRequest, APIKeyPutRequest, WebRTCSession, OK
from webrtc import AudioPeerManager, AudioPeer, ErrorResponse, OfferRequest, OfferResponse, OggOpusRecorder, PeerIDRequest, StatusResponse, APM
from aiortc import RTCPeerConnection, RTCSessionDescription, MediaStreamTrack
from session import SessionUser, SessionAPIKey, SessionWebRTC
from models.role import Role

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CONFIG = Config()

router = APIRouter(tags=["API Keys"])

def _list_apikeys(user_id: str) -> List[APIKeyResponse]:
    user = User.objects(id=user_id).first() # type: ignore[attr-defined]
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return [
        APIKeyResponse(
            id=str(api_key.id),
            roles=[str(role.id) for role in api_key.roles],
            created_at=api_key.created_at,
            expiration=api_key.expiration,
        )
        for api_key in user.api_keys
    ]


def _get_apikey(user_id: str, apikey_id: str) -> APIKeyResponse:
    user = User.objects(id=user_id).first() # type: ignore[attr-defined]
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    api_key = ApiKey.objects(id=apikey_id).first() # type: ignore[attr-defined]
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    if api_key.user != user:
        raise HTTPException(status_code=403, detail="API key does not belong to the user")

    return APIKeyResponse(
        id=str(api_key.id),
        roles=[str(role.id) for role in api_key.roles],
        created_at=api_key.created_at,
        expiration=api_key.expiration,
    )


def _create_apikey(session: Union[SessionUser, SessionAPIKey], user_id: str, req: APIKeyCreateRequest) -> APIKeyCreateResponse:
    """Helper function to create a new API key for a user.
    
    Args:
        session: The current user session
        user_id: The ID of the user to create the API key for
        req: The API key creation request
        
    Returns:
        APIKeyCreateResponse with the new API key details
        
    Raises:
        HTTPException: If validation fails or an error occurs
    """
    try:
        # Check if expiration date is in the past
        now = datetime.now(timezone.utc)
        if req.expiration is not None and req.expiration < now:
            raise HTTPException(
                status_code=400, 
                detail="Expiration date cannot be in the past"
            )

        # Get the user
        user_obj = User.objects(id=user_id).first()  # type: ignore[attr-defined]
        if user_obj is None:
            raise HTTPException(status_code=404, detail="User not found")

        # Validate roles
        roles = []
        if req.roles:
            roles = list(Role.objects(id__in=req.roles))  # type: ignore[attr-defined]
            if len(roles) != len(req.roles):
                raise HTTPException(
                    status_code=400, 
                    detail="One or more roles do not exist"
                )

        # Check if the new roles are broader than the user's roles
        req_user_roles = get_user_roles_by_session(session)
        for r in roles:
            if not compare_roles(req_user_roles, r):
                raise HTTPException(
                    status_code=403, 
                    detail=(
                        "You do not have permission to create an API key with these roles. "
                        "The roles you assigned are broader than your current roles."
                    )
                )

        # Create the new API key
        api_key, raw_key = ApiKey.create_key(
            user=user_obj, 
            roles=roles, 
            expiration=req.expiration
        )

        # Add the new key to the user's list of keys and save
        user_obj.api_keys.append(api_key)
        user_obj.save()

        # Log the creation (without exposing the raw key)
        logger.info(f"Created API key {api_key.id} for user {user_id}")

        return APIKeyCreateResponse(
            id=str(api_key.id),
            key=raw_key,  # This is the only time the raw key is exposed
            roles=[str(role.id) for role in api_key.roles],
            created_at=api_key.created_at,
            expiration=api_key.expiration,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating API key for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while creating the API key"
        )


def _delete_apikey(user_id: str, apikey_id: str) -> OK:
    """Helper function to delete an API key.
    
    Args:
        user_id: The ID of the user who owns the API key
        apikey_id: The ID of the API key to delete
        
    Returns:
        OK response if successful
        
    Raises:
        HTTPException: If the user or API key is not found, or if an error occurs
    """
    try:
        # Get the user
        user = User.objects(id=user_id).first()  # type: ignore[attr-defined]
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Find the API key to get its details for logging
        api_key = ApiKey.objects(id=apikey_id).first()  # type: ignore[attr-defined]
        if not api_key:
            # The API key doesn't exist at all
            raise HTTPException(status_code=404, detail="API key not found")

        # Check if the API key belongs to the user
        if str(api_key.user.id) != user_id:  # type: ignore[attr-defined]
            raise HTTPException(
                status_code=403, 
                detail="API key does not belong to the specified user"
            )

        # Delete the API key document from the database
        ApiKey.objects(id=apikey_id).delete()  # type: ignore[attr-defined]
        
        logger.info(f"Deleted API key {apikey_id} for user {user_id}")
        return OK(ok=True)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting API key {apikey_id} for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while deleting the API key"
        )


def _update_apikey(user_id: str, apikey_id: str, req: APIKeyPutRequest) -> APIKeyResponse:
    """Helper function to update an existing API key.
    
    Args:
        user_id: The ID of the user who owns the API key
        apikey_id: The ID of the API key to update
        req: The update request containing new values
        
    Returns:
        APIKeyResponse with the updated API key details
        
    Raises:
        HTTPException: If validation fails or an error occurs
    """
    try:
        # Get the user
        user = User.objects(id=user_id).first()  # type: ignore[attr-defined]
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Find the API key document (not just the reference in user.api_keys)
        api_key = ApiKey.objects(id=apikey_id).first()  # type: ignore[attr-defined]
        if not api_key:
            raise HTTPException(status_code=404, detail="API key not found")
            
        # Verify the API key belongs to the user
        if str(api_key.user.id) != user_id:  # type: ignore[attr-defined]
            raise HTTPException(
                status_code=403, 
                detail="API key does not belong to the specified user"
            )

        # Check if the API key is in the user's list (should be, but verify)
        user_api_key = next((key for key in user.api_keys if str(key.id) == apikey_id), None)
        if not user_api_key:
            # This should not happen if the API key exists and belongs to the user
            raise HTTPException(
                status_code=404, 
                detail="API key not associated with this user"
            )

        # Update roles if provided
        if req.roles is not None:
            roles = list(Role.objects(id__in=req.roles))  # type: ignore[attr-defined]
            if len(roles) != len(req.roles):
                raise HTTPException(
                    status_code=400, 
                    detail="One or more roles do not exist"
                )
            api_key.roles = roles

        # Update expiration if provided
        if req.expiration is not None:
            # Check if the new expiration is in the past
            if req.expiration < datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=400, 
                    detail="Expiration date cannot be in the past"
                )
            api_key.expiration = req.expiration

        # Save the updated API key
        api_key.updated_at = datetime.now(timezone.utc)
        api_key.save()
        
        # Also update the reference in the user's api_keys list
        for key in user.api_keys:
            if str(key.id) == apikey_id:
                key.roles = api_key.roles
                key.expiration = api_key.expiration
                key.updated_at = api_key.updated_at
                break
        user.save()
        
        logger.info(f"Updated API key {apikey_id} for user {user_id}")

        return APIKeyResponse(
            id=str(api_key.id),
            roles=[str(role.id) for role in api_key.roles],
            created_at=api_key.created_at,
            expiration=api_key.expiration,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating API key {apikey_id} for user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while updating the API key"
        )


@router.get(
    "/api/v1/user/{user_id}/apikeys",
    response_model=List[APIKeyResponse],
    tags=["API Keys"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="List all API keys for a specific user (admin only)"
)
async def api_list_apikeys(
    user_id: str, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> List[APIKeyResponse]:
    """List all API keys for a specific user."""
    return _list_apikeys(user_id)


@router.get(
    "/api/v1/user/me/apikeys",
    response_model=List[APIKeyResponse],
    tags=["API Keys"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="List current user's API keys"
)
async def api_list_own_apikeys(
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> List[APIKeyResponse]:
    """List all API keys for the currently authenticated user."""
    if isinstance(session, SessionAPIKey):
        logger.warning(f"Attempt to list API keys using API key session: {session.id}")
        raise HTTPException(
            status_code=403,
            detail="You cannot list the API keys using an API key session. Please use a user session."
        )

    return _list_apikeys(session.user_id)


@router.get(
    "/api/v1/user/{user_id}/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    tags=["API Keys"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Get a specific API key for a user (admin only)"
)
async def api_get_apikey(
    user_id: str, 
    apikey_id: str, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> APIKeyResponse:
    """Get a specific API key for a user."""
    return _get_apikey(user_id, apikey_id)


@router.get(
    "/api/v1/user/me/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    tags=["API Keys"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Get a specific API key for the current user"
)
async def api_get_own_apikey(
    apikey_id: str, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> APIKeyResponse:
    """Get a specific API key for the currently authenticated user."""
    if isinstance(session, SessionAPIKey):
        logger.warning(f"Attempt to get API key using API key session: {session.id}")
        raise HTTPException(
            status_code=403,
            detail="You cannot get an API key using an API key session. Please use a user session."
        )
    return _get_apikey(session.user_id, apikey_id)


@router.post(
    "/api/v1/user/{user_id}/apikey",
    response_model=APIKeyCreateResponse,
    status_code=201,
    tags=["API Keys"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Create a new API key for a user (admin only)"
)
async def api_create_apikey(
    user_id: str,
    apikey: APIKeyCreateRequest,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE])),
) -> APIKeyCreateResponse:
    """Create a new API key for a user."""
    return _create_apikey(session, user_id, apikey)


@router.post(
    "/api/v1/user/me/apikey",
    response_model=APIKeyCreateResponse,
    status_code=201,
    tags=["API Keys"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Create a new API key for the current user"
)
async def api_create_own_apikey(
    apikey: APIKeyCreateRequest, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> APIKeyCreateResponse:
    """Create a new API key for the currently authenticated user."""
    if isinstance(session, SessionAPIKey):
        logger.warning(f"Attempt to create API key using API key session: {session.id}")
        raise HTTPException(
            status_code=403,
            detail="You cannot create an API key using an API key session. Please use a user session."
        )
    
    return _create_apikey(session, session.user_id, apikey)


@router.delete(
    "/api/v1/user/{user_id}/apikey/{apikey_id}",
    response_model=OK,
    tags=["API Keys"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Delete a specific API key for a user (admin only)"
)
async def api_delete_apikey(
    user_id: str, 
    apikey_id: str, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> OK:
    """Delete a specific API key for a user."""
    return _delete_apikey(user_id, apikey_id)


@router.delete(
    "/api/v1/user/me/apikey/{apikey_id}",
    response_model=OK,
    tags=["API Keys"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Delete a specific API key for the current user"
)
async def api_delete_own_apikey(
    apikey_id: str, 
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE]))
) -> OK:
    """Delete a specific API key for the currently authenticated user."""
    if isinstance(session, SessionAPIKey):
        logger.warning(f"Attempt to delete API key using API key session: {session.id}")
        raise HTTPException(
            status_code=403,
            detail="You cannot delete an API key using an API key session. Please use a user session."
        )

    return _delete_apikey(session.user_id, apikey_id)


@router.put(
    "/api/v1/user/{user_id}/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    tags=["API Keys"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Update a specific API key for a user (admin only)"
)
async def api_update_apikey(
    user_id: str,
    apikey_id: str,
    apikey: APIKeyPutRequest,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE])),
) -> APIKeyResponse:
    """Update a specific API key for a user."""
    return _update_apikey(user_id, apikey_id, apikey)


@router.put(
    "/api/v1/user/me/apikey/{apikey_id}",
    response_model=APIKeyResponse,
    tags=["API Keys"],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Update a specific API key for the current user"
)
async def api_update_own_apikey(
    apikey_id: str,
    apikey: APIKeyPutRequest,
    session: Union[SessionUser, SessionAPIKey] = Depends(auth([BOSS_ROLE])),
) -> APIKeyResponse:
    """Update a specific API key for the currently authenticated user."""
    if isinstance(session, SessionAPIKey):
        logger.warning(f"Attempt to update API key using API key session: {session.id}")
        raise HTTPException(
            status_code=403,
            detail="You cannot update an API key using an API key session. Please use a user session."
        )

    return _update_apikey(session.user_id, apikey_id, apikey)

@router.post(
        "/api/v1/webrtc/offer",
        response_model=OfferResponse,
        tags=["WebRTC"],
        responses={400: {"model": ErrorResponse}},
        dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
        description="Handle WebRTC offer and return an answer."
        )
async def offer(
    request_data: OfferRequest,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE])),
    ) -> OfferResponse:
    offer = RTCSessionDescription(
        sdp=request_data.sdp,
        type=request_data.type
    )

    webrtc_peer = await SM.login_webrtc(session)
    peer_id = webrtc_peer.id

    pc = RTCPeerConnection()

    @pc.on("connectionstatechange")
    async def on_connectionstatechange() -> None:
        logger.info(f"Connection state for peer {peer_id} is {pc.connectionState}")
        if pc.connectionState in ["failed", "closed"]:
            try:
                await APM.remove_peer(peer_id)
                try:
                    await SM.logout(peer_id)
                except Exception as e:
                    logger.error(f"Error logging out peer {peer_id}: {e}")
            except Exception as e:
                logger.error(f"Error cleaning up peer {peer_id}: {e}")

    async def on_close(webrtc_peer_id: str) -> None:
        logger.info(f"Peer {webrtc_peer_id} connection closed")
        try:
            await SM.logout(webrtc_peer_id)
        except Exception as e:
            logger.error(f"Error logging out peer {webrtc_peer_id}: {e}")

    # Call on_close after 5 seconds if the connection isnt astablished
    async def close_after_timeout() -> None:
        await asyncio.sleep(CONFIG.WEBRTC_TIMEOUT)
        await on_close(peer_id)
    init_time_out = asyncio.create_task(close_after_timeout())

    @pc.on("track")
    def on_track(track: MediaStreamTrack) -> None:
        logger.info(f"Received {track.kind} track for peer {peer_id}")
        if track.kind == "audio":
            # cancel the close_after_timeout task if we received a track
            init_time_out.cancel()
            # Create an AudioPeer object to handle the audio track
            peer_obj = AudioPeer(pc=pc, track=track, user_id=session.id, session_id=session.id, peer_id=peer_id, converter=OggOpusRecorder(file_name=peer_id), on_close=on_close)
            APM.add_peer(peer_obj)

    await pc.setRemoteDescription(offer)
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)

    return OfferResponse(
        sdp=pc.localDescription.sdp,
        type=pc.localDescription.type,
        peer_id=peer_id
    )

@router.post(
    "/api/v1/webrtc/{peer_id}/start_recording",
    response_model=StatusResponse,
    tags=["WebRTC"],
    responses={400: {"model": ErrorResponse}},
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Start recording for a specific peer."
)
async def start_recording(
    peer_id: str,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE])),
    ) -> StatusResponse:

    # get the webrtc sessions of this user
    webrtc_sessions = await SM.get_webrtc_sessions_from_session(session)

    if peer_id not in [ws.id for ws in webrtc_sessions]:
        raise HTTPException(status_code=403, detail="The peer does not belong to your WebRTC sessions.")

    ap = await APM.get_peer(peer_id)
    if not peer_id or ap is None:
        raise HTTPException(status_code=400, detail="Invalid peer ID")

    try:
        await ap.start_recording()
        return StatusResponse(status="Recording started")
    except Exception as e:
        logger.error(f"Error starting recording: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete(
    "/api/v1/webrtc/{peer_id}/stop_recording",
    tags=["WebRTC"],
    response_model=StatusResponse,
    responses={400: {"model": ErrorResponse}},
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)],
    description="Stop recording for a specific peer."
)
async def stop_recording(
    peer_id: str,
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE])),
    ) -> StatusResponse:
    ap = await APM.get_peer(peer_id)
    if not peer_id or ap is None:
        raise HTTPException(status_code=400, detail="Invalid peer ID")

    try:
        await ap.stop_recording()
        return StatusResponse(status="Recording stopped")
    except Exception as e:
        logger.error(f"Error stopping recording: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get(
    "/api/v1/webrtc/sessions",
    tags=["WebRTC"],
    response_model=List[WebRTCSession],
    dependencies=[Depends(CONFIG.API_LVL2_RATE_LIMITER)]
)
async def get_webrtc_sessions(
    user_id: str = "*",
    user_or_api_session_type: Literal["user", "api_key", "*"] = "*",
    session_id: str = "*",
    node_id: str = "*",
    webrtc_id: str = "*",
    session: Union[SessionUser, SessionAPIKey]= Depends(auth([BOSS_ROLE])),
) -> List[WebRTCSession]:
    """
    Retrieve a list of all WebRTC sessions according to the filters provided.
    """
    webrtc_sessions = await SM.get_webrtc_sessions(
        user_id=user_id,
        user_or_api_session_type=user_or_api_session_type,
        session_id=session_id,
        node_id=node_id,
        webrtc_id=webrtc_id
    )
    return_list = []
    for s in webrtc_sessions:
        return_list.append(WebRTCSession(
            id=s.id,
            expiration_date=s.expiration_date,
            creation_date=s.creation_date,
            user_id=s.user_id,
            parent_session_id=s.parent_session_id
        ))
    return return_list