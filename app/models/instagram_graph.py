from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class InstagramAuthRequest(BaseModel):
    """Request to start Instagram OAuth process"""
    redirect_uri: Optional[str] = None

class InstagramAuthResponse(BaseModel):
    """Response with OAuth authorization URL"""
    auth_url: str
    redirect_uri: str

class InstagramTokenResponse(BaseModel):
    """Model for Instagram access token response"""
    access_token: str
    user_id: str
    username: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    expires_at: Optional[str] = None
    
class InstagramAccountInfo(BaseModel):
    """Model for Instagram account information"""
    id: str
    username: str
    name: Optional[str] = None
    profile_picture: Optional[str] = None
    
class InstagramMediaResponse(BaseModel):
    """Response after publishing media to Instagram"""
    id: str
    permalink: Optional[str] = None
    status: str = "published"
    media_type: str
    media_url: Optional[str] = None
    
class InstagramSessionRequest(BaseModel):
    """Request to store Instagram session"""
    token_data: Dict[str, Any]
    user_info: Dict[str, Any]

class InstagramMediaContainerResponse(BaseModel):
    """Response with media container ID for multi-step publishing"""
    id: str
    status: str 