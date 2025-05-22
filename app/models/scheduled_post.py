from pydantic import BaseModel
from typing import Optional
from enum import Enum

class ScheduledPostStatus(str, Enum):
    """Status enum for scheduled posts"""
    PENDING = "pendente"
    PROCESSING = "processing"
    PUBLISHED = "published"
    ERROR = "error"

class ScheduledPostResponse(BaseModel):
    id: int
    username: str
    type: str
    schedule_for: str
    video_url: str
    caption: str
    tags: str
    status: str
    created_at: str
    updated_at: str

    class Config:
        # Allow extra fields from the database
        extra = "ignore"

class UpdateScheduledPostRequest(BaseModel):
    id: str
    type: Optional[str] = None
    schedule_date: Optional[str] = None
    caption: Optional[str] = None
    hashtags: Optional[str] = None

    class Config:
        # Ensure extra fields are forbidden to catch any naming errors
        extra = "forbid" 