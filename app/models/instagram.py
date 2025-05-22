from pydantic import BaseModel
from typing import Optional

class ConnectRequest(BaseModel):
    username: str
    password: str

class TwoFARequest(BaseModel):
    sessao_id: int
    codigo_2fa: str

class PostRequest(BaseModel):
    username: str
    type: str
    when: str
    schedule_date: str
    video_url: str  # Field for video URL
    caption: str
    hashtags: str

    class Config:
        # Ensure extra fields are forbidden to catch any naming errors
        extra = "forbid"

class DisconnectRequest(BaseModel):
    username: str

    class Config:
        # Ensure extra fields are forbidden to catch any naming errors
        extra = "forbid"

class InstagramSessionResponse(BaseModel):
    id: int
    username: str
    status: str
    is_active: bool
    expires_at: str
    created_at: str
    updated_at: str 