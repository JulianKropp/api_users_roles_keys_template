import asyncio
import contextlib
import json
import logging
import os
from pathlib import Path
import subprocess
from datetime import datetime
import uuid
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from aiortc import RTCPeerConnection, RTCSessionDescription, MediaStreamTrack
from aiortc.contrib.media import MediaBlackhole, MediaRecorder
from typing import AsyncIterator, Callable, Dict, Set, Any, Optional, Tuple, Union, BinaryIO, Awaitable, cast
from abc import ABC, abstractmethod
import time
import numpy as np
from aiortc.mediastreams import MediaStreamError, Frame, Packet
import binascii
import secrets
import struct
import array
from collections import deque
import opuslib # type: ignore
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Converter(ABC):
    @abstractmethod
    async def _process_pcm(self, pcm: bytes) -> None:
        pass

    @abstractmethod
    def _on_track(self, page: bytes) -> None:
        pass

    @abstractmethod
    async def start(self) -> None:
        pass

    @abstractmethod
    async def stop(self) -> None:
        pass


class OggOpusRecorder(Converter):
    def __init__(self,
                    file_name: Optional[str] = None,
                    output_dir: Path = Path("."),
                    on_track: Optional[Callable[[bytes], None]] = None,
                    frame_ms: int = 20,
                    input_sample_rate: int = 96_000,
                    output_sample_rate: int = 48_000,
                    bytes_per_sample: int = 2,
                    channels: int = 1,
                ) -> None:

        self.file_name: Optional[str] = file_name
        self.output_dir: Path = output_dir
        self.on_track: Optional[Callable[[bytes], None]] = on_track
        self.frame_ms = frame_ms
        self.input_sample_rate = input_sample_rate
        self.output_sample_rate = output_sample_rate # 48kHz
        self.samples_per_frame = output_sample_rate * frame_ms // 1000 # 960
        self.input_samples_per_frame = input_sample_rate * frame_ms // 1000 # 1920
        self.bytes_per_sample = bytes_per_sample
        self.channels = channels

        self.output_file: Optional[BinaryIO] = None
        self.recording = False
        self.encoder = opuslib.Encoder(output_sample_rate, channels, opuslib.APPLICATION_AUDIO)
        self.serial = secrets.randbits(32)
        self.granpos = 0
        self.seq = 0
        self.pcm_buffer = bytearray()
        self.frame_bytes = self.samples_per_frame * channels * bytes_per_sample
        self.input_frame_bytes = self.input_samples_per_frame * channels * bytes_per_sample
        self.sent_headers = False

    def _on_track(self, page: bytes) -> None:
        """
        Called for each complete Ogg page. Opens the file on first call
        and appends every subsequent page.
        """
        # If we have a callback, call it with the page
        if self.on_track:
            self.on_track(page)

        if self.file_name is not None:
            if self.output_file is None:
                self.output_dir.mkdir(parents=True, exist_ok=True)
                out_path = self.output_dir / f"{self.file_name}.ogg"
                # Open in binary append mode
                self.output_file = open(out_path, "wb")
                logger.info(f"Opened output file: {out_path}")

            if self.output_file:
                self.output_file.write(page)
                self.output_file.flush()
        


    async def _process_pcm(self, pcm: bytes) -> None:
        """
        Process raw PCM data, buffer it until we have a full frame,
        then encode to Opus and create Ogg pages.
        """
        if not self.recording:
            return

        # Add new data to the buffer
        self.pcm_buffer.extend(pcm)
        
        # Process full frames
        while len(self.pcm_buffer) >= self.frame_bytes * 2:  # *2 because input is 96kHz, output is 48kHz
            # Extract a frame of 96kHz PCM data (twice as many samples as needed for 48kHz)
            frame_pcm = self.pcm_buffer[:self.input_frame_bytes]
            del self.pcm_buffer[:self.input_frame_bytes]
            
            # Send headers first if not yet sent
            if not self.sent_headers:
                # Send ID header
                id_header = self._create_opus_id_header(self.channels)
                id_page = self._make_ogg_page(
                    id_header,
                    page_sequence_number=self.seq,
                    granule_position=0,
                    serial_number=self.serial,
                    is_first_page=True
                )
                self._on_track(id_page)
                self.seq += 1
                
                # Send comment header
                comment_header = self._create_opus_comment_header()
                comment_page = self._make_ogg_page(
                    comment_header,
                    page_sequence_number=self.seq,
                    granule_position=0,
                    serial_number=self.serial
                )
                self._on_track(comment_page)
                self.seq += 1
                
                self.sent_headers = True
            
            # Convert to int16 samples
            pcm_int16 = np.frombuffer(frame_pcm, dtype='<i2')
            
            # Downsample from 96kHz to 48kHz (take every other sample)
            # This is a simple decimation - for better quality, a proper filter should be used
            pcm_int16_downsampled = pcm_int16[::2]
            
            # Ensure array is C-contiguous
            pcm_int16_downsampled = np.ascontiguousarray(pcm_int16_downsampled)
            
            # Encode to Opus
            opus_packet = self.encoder.encode(pcm_int16_downsampled.tobytes(), self.samples_per_frame)
            
            # Update granule position
            self.granpos += self.samples_per_frame
            
            # Create Ogg page
            page = self._make_ogg_page(
                opus_packet,
                page_sequence_number=self.seq,
                granule_position=self.granpos,
                serial_number=self.serial
            )
            
            # Pass to on_track
            self._on_track(page)
            self.seq += 1

    def _make_ogg_packet(self, data: bytes) -> Tuple[bytes, bytes]:
        """Return segmented packet data."""
        segments = []
        for i in range(0, len(data), 255):
            segments.append(data[i:i+255])
        
        segment_table = [min(len(s), 255) for s in segments]
        if segments and len(segments[-1]) == 255:
            segment_table.append(0)
        
        return bytes(segment_table), b''.join(segments)


    def _crc32(self, data: bytes) -> int:
        """Compute the correct CRC32 checksum for Ogg data."""
        crc_lookup = array.array('L', [0] * 256)
        for i in range(256):
            r = i << 24
            for j in range(8):
                if r & 0x80000000:
                    r = ((r << 1) ^ 0x04c11db7) & 0xffffffff
                else:
                    r = (r << 1) & 0xffffffff
            crc_lookup[i] = r
        
        crc = 0
        for byte in data:
            crc = ((crc << 8) & 0xffffffff) ^ crc_lookup[((crc >> 24) & 0xff) ^ byte]
        return crc


    def _make_ogg_page(self, data: bytes, page_sequence_number: int, granule_position: int, 
                    serial_number: int, is_first_page: bool = False, 
                    is_last_page: bool = False, is_continued: bool = False) -> bytes:
        """
        Create a properly formatted Ogg page from the given data.
        """
        segment_table, segments = self._make_ogg_packet(data)
        
        # Build header
        header_type = 0
        if is_continued:
            header_type |= 0x01
        if is_first_page:
            header_type |= 0x02
        if is_last_page:
            header_type |= 0x04
        
        # Assemble page header without CRC
        header = struct.pack("<4sBBQLLLB", 
                            b"OggS",                            # Ogg capture pattern
                            0,                                  # Stream structure version
                            header_type,                        # Header type flag
                            granule_position,                   # Granule position
                            serial_number,                      # Stream serial number
                            page_sequence_number,               # Page sequence number
                            0,                                  # CRC checksum (placeholder)
                            len(segment_table))                 # Number of segments
        
        # Compute CRC checksum over header+segments with placeholder CRC
        crc_data = header + segment_table + segments
        crc = self._crc32(crc_data)
        
        # Insert CRC into header
        header = struct.pack("<4sBBQLLLB", 
                            b"OggS",                            # Ogg capture pattern
                            0,                                  # Stream structure version
                            header_type,                        # Header type flag
                            granule_position,                   # Granule position
                            serial_number,                      # Stream serial number
                            page_sequence_number,               # Page sequence number
                            crc,                                # CRC checksum
                            len(segment_table))                 # Number of segments
        
        # Build complete page
        return header + segment_table + segments


    def _create_opus_id_header(self, channels: int, pre_skip: int = 0) -> bytes:
        """
        Create the Opus identification header packet.
        https://datatracker.ietf.org/doc/html/rfc7845.html#section-5.1
        """
        # Magic signature for Opus
        opus_id = b'OpusHead'
        
        # Version (1 byte), Channel count (1 byte), Pre-skip (2 bytes, little endian)
        # Original sample rate (4 bytes, little endian), Output gain (2 bytes, little endian)
        # Channel mapping family (1 byte)
        header = struct.pack('<BBHIhB', 
                            1,  # Version
                            channels,
                            pre_skip,
                            self.output_sample_rate,
                            0,  # Output gain
                            0)  # Channel mapping family (0 = mono/stereo)
        
        return opus_id + header


    def _create_opus_comment_header(self) -> bytes:
        """
        Create the Opus comment header packet.
        https://datatracker.ietf.org/doc/html/rfc7845.html#section-5.2
        """
        # Magic signature
        opus_comment = b'OpusTags'
        
        # Vendor string
        vendor = b'python-opuslib'
        vendor_len = len(vendor)
        
        # No user comments
        comment_count = 0
        
        header = struct.pack('<I', vendor_len) + vendor + struct.pack('<I', comment_count)
        
        return opus_comment + header

    async def start(self) -> None:
        """Start recording"""
        if self.recording:
            return
        
        self.recording = True
        self.pcm_buffer.clear()
        self.granpos = 0
        self.seq = 0
        self.sent_headers = False
        logger.info(f"Started Python Ogg/Opus recording for {self.file_name}")

    async def stop(self) -> None:
        """Stop recording and close file"""
        if not self.recording:
            return
        
        self.recording = False
        
        # If we have any remaining data in the buffer that's not a full frame,
        # we can optionally process it here (pad with silence)
        if self.pcm_buffer and len(self.pcm_buffer) > 0:
            # Create a final frame, pad with zeros
            remaining = len(self.pcm_buffer)
            if remaining < self.input_frame_bytes:
                padding = bytearray(self.input_frame_bytes - remaining)
                self.pcm_buffer.extend(padding)
                
            # Process this final frame
            frame_pcm = bytes(self.pcm_buffer)
            pcm_int16 = np.frombuffer(frame_pcm, dtype='<i2')
            
            # Downsample from 96kHz to 48kHz
            pcm_int16_downsampled = pcm_int16[::2]
            pcm_int16_downsampled = np.ascontiguousarray(pcm_int16_downsampled)
            
            opus_packet = self.encoder.encode(pcm_int16_downsampled.tobytes(), self.samples_per_frame)
            
            self.granpos += self.samples_per_frame
            
            # Create final Ogg page with EOS flag
            page = self._make_ogg_page(
                opus_packet,
                page_sequence_number=self.seq,
                granule_position=self.granpos,
                serial_number=self.serial,
                is_last_page=True
            )
            
            self._on_track(page)
        
        # Close the output file
        if self.output_file:
            self.output_file.close()
            self.output_file = None
            logger.info(f"Closed output file for peer {self.file_name}")








class AudioPeer(MediaStreamTrack):
    kind = "audio"

    def __init__(self,
                    pc: RTCPeerConnection,
                    track: MediaStreamTrack,
                    user_id: Optional[str] = None,
                    session_id: Optional[str] = None,
                    peer_id: Optional[str] = None,
                    converter: Optional[Converter] = None,
                    on_track: Optional[Callable[[str, bytes], Awaitable[None]]] = None,
                    on_start: Optional[Callable[[str], Awaitable[None]]] = None,
                    on_close: Optional[Callable[[str], Awaitable[None]]] = None
                 ) -> None:
        super().__init__()
        self.peer_connections: RTCPeerConnection = pc
        self.peer_connections.addTrack(self)

        self.track = track
        self.user_id = user_id
        self.session_id = session_id
        self.peer_id = peer_id if peer_id else f"PEER-{uuid.uuid4()}"

        self.converter = converter

        self.reader_task: Optional[asyncio.Task] = None

        self.recording: bool = False
        self.last_frame_time: float = time.time()

        self.on_track: Optional[Callable[[str, bytes], Awaitable[None]]] = on_track
        self.on_start: Optional[Callable[[str], Awaitable[None]]] = on_start
        self.on_close: Optional[Callable[[str], Awaitable[None]]] = on_close


    async def recv(self) -> Union[Frame, Packet]:
        frame = await self.track.recv()
        
        self.last_frame_time = time.time()

        if self.recording:
            try:
                # Only process if it's a Frame and has to_ndarray method
                if isinstance(frame, Frame) and hasattr(frame, 'to_ndarray'):
                    pcm = frame.to_ndarray()
                    
                    if pcm.ndim == 2:   # stereo → mono
                        pcm = pcm.mean(axis=0).astype("int16")
                    if self.on_track:
                        self.on_track(self.peer_id, pcm.tobytes())
                    if self.converter:
                        await asyncio.create_task(self.converter._process_pcm(pcm.tobytes()))
            except Exception as e:
                logger.error(f"PCM → ffmpeg failed for peer {self.peer_id}: {e}")

        return frame


    async def start_recording(self) -> None:
        if self.recording:
            return

        self.recording = True

        if self.converter:
            await self.converter.start()

        self.last_frame_time = time.time()

        if self.on_start:
            self.on_start(self.peer_id)

        logger.info(f"Started recording (streaming to callback) for peer {self.peer_id}")

    async def stop_recording(self) -> None:
        if not self.recording:
            return

        self.recording = False

        if self.converter:
            await self.converter.stop()

        await self.peer_connections.close()

        # stop the page-reader task
        if self.reader_task:
            self.reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.reader_task
            self.reader_task = None

        # call on_close
        if self.on_close:
            await self.on_close(self.peer_id)

        logger.info(f"Stopped recording (callback mode) for peer {self.peer_id}")


class AudioPeerManager:
    def __init__(self,
                    timeout: int = 5,
                    on_new_peer: Optional[Callable[[AudioPeer], None]] = None,
                    on_peer_removed: Optional[Callable[[AudioPeer], None]] = None,
                ) -> None:
        self.timeout = timeout
        self.on_new_peer = on_new_peer
        self.on_peer_removed = on_peer_removed

        self.audio_peers: Dict[str, AudioPeer] = {}

    def add_peer(self, peer_obj: AudioPeer) -> None:
        peer_id = peer_obj.peer_id
        self.audio_peers[peer_id] = peer_obj
        if self.on_new_peer:
            self.on_new_peer(peer_obj)

    async def remove_peer(self, peer_id: str) -> None:
        if peer_id in self.audio_peers:
            await self.audio_peers[peer_id].stop_recording()
            if self.on_peer_removed:
                self.on_peer_removed(self.audio_peers[peer_id])
            del self.audio_peers[peer_id]

    async def get_peer(self, peer_id: str) -> Optional[AudioPeer]:
        return self.audio_peers.get(peer_id)

    async def check_timeouts(self) -> None:
        """Background task to check for inactive recordings and stop them"""
        counter = 0
        while True:
            current_time = time.time()
            peers_to_cleanup: Set[str] = set()  # Track peers that need cleanup
            
            for peer_id, audio_stream_track in list(self.audio_peers.items()):
                last_time = audio_stream_track.last_frame_time
                if current_time - last_time > self.timeout:
                    logger.info(f"Timeout detected for peer {peer_id} after {self.timeout} seconds of inactivity")
                    peers_to_cleanup.add(peer_id)
            
            # Clean up peers outside the loop to avoid modifying the dictionary while iterating
            for peer_id in peers_to_cleanup:
                try:
                    # Clean up audio track
                    if peer_id in self.audio_peers:
                        await self.remove_peer(peer_id)
                        
                except Exception as e:
                    logger.error(f"Error handling timeout for peer {peer_id}: {e}")
                    if peer_id in self.audio_peers:
                        await self.remove_peer(peer_id)
            
            # Print every 10 seconds the number of active recordings
            if counter % 10 == 0:
                logger.info(f"Number of active recordings: {len(self.audio_peers)}")
            counter = (counter + 1) % 10

            await asyncio.sleep(1)  # Check every second

class OfferRequest(BaseModel):
    sdp: str
    type: str

class OfferResponse(BaseModel):
    sdp: str
    type: str
    peer_id: str

class PeerIDRequest(BaseModel):
    peer_id: str

class StatusResponse(BaseModel):
    status: str

class ErrorResponse(BaseModel):
    error: str

if __name__ == "__main__":
    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Start the timeout checker when the application starts"""
        asyncio.create_task(APM.check_timeouts())
        yield

    # Create FastAPI app
    app = FastAPI(
        lifespan=lifespan,
        title="WebRTC Audio Stream",
        description="WebRTC Audio Stream with FastAPI",
        version="1.0.0",
    )

    APM = AudioPeerManager()

    @app.post("/offer", response_model=OfferResponse)
    async def offer(request_data: OfferRequest) -> OfferResponse:
        offer = RTCSessionDescription(
            sdp=request_data.sdp,
            type=request_data.type
        )

        peer_id = f"PEER-{uuid.uuid4()}"
        pc = RTCPeerConnection()

        @pc.on("connectionstatechange")
        async def on_connectionstatechange() -> None:
            logger.info(f"Connection state for peer {peer_id} is {pc.connectionState}")
            if pc.connectionState in ["failed", "closed"]:
                try:
                    await APM.remove_peer(peer_id)
                except Exception as e:
                    logger.error(f"Error cleaning up peer {peer_id}: {e}")

        @pc.on("track")
        def on_track(track: MediaStreamTrack) -> None:
            logger.info(f"Received {track.kind} track for peer {peer_id}")
            if track.kind == "audio":
                peer_obj = AudioPeer(pc=pc, track=track, peer_id=peer_id, converter=OggOpusRecorder(file_name=peer_id))
                APM.add_peer(peer_obj)

        await pc.setRemoteDescription(offer)
        answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)

        return OfferResponse(
            sdp=pc.localDescription.sdp,
            type=pc.localDescription.type,
            peer_id=peer_id
        )

    @app.post(
        "/start_recording",
        response_model=StatusResponse,
        responses={400: {"model": ErrorResponse}}
    )
    async def start_recording(data: PeerIDRequest) -> StatusResponse:
        peer_id = data.peer_id
        ap = await APM.get_peer(peer_id)
        if not peer_id or ap is None:
            raise HTTPException(status_code=400, detail="Invalid peer ID")

        try:
            await ap.start_recording()
            return StatusResponse(status="Recording started")
        except Exception as e:
            logger.error(f"Error starting recording: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post(
        "/stop_recording",
        response_model=StatusResponse,
        responses={400: {"model": ErrorResponse}}
    )
    async def stop_recording(data: PeerIDRequest) -> StatusResponse:
        peer_id = data.peer_id
        ap = await APM.get_peer(peer_id)
        if not peer_id or ap is None:
            raise HTTPException(status_code=400, detail="Invalid peer ID")

        try:
            await ap.stop_recording()
            return StatusResponse(status="Recording stopped")
        except Exception as e:
            logger.error(f"Error stopping recording: {e}")
            raise HTTPException(status_code=500, detail=str(e))



    # Mount static files
    app.mount("/static", StaticFiles(directory="static-webrtc"), name="static")
    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        with open("static-webrtc/index.html") as f:
            return f.read()



    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)