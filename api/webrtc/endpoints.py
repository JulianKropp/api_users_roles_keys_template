from webrtc import AudioPeer, ErrorResponse, OfferRequest, OfferResponse, OggOpusRecorder, StatusResponse, APM
from aiortc import RTCPeerConnection, RTCSessionDescription, MediaStreamTrack

import logging
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from typing import Union, List, Literal
from config import Config
from ..api_auth import SM, auth, BOSS_ROLE
from .schemas import WebRTCSession
from session import SessionUser, SessionAPIKey

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CONFIG = Config()

router = APIRouter(tags=["WebRTC"])

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