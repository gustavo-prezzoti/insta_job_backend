from pydantic import BaseModel
from typing import Optional, List

class LoginRequest(BaseModel):
    email: str
    password: str

class PasswordUpdateRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

class ForcePasswordUpdateRequest(BaseModel):
    current_password: str
    new_password: str

    class Config:
        # Ensure extra fields are forbidden to catch any naming errors
        extra = "forbid"

class UserUpdateRequest(BaseModel):
    name: Optional[str] = None  # Optional name update
    current_password: Optional[str] = None  # Required if updating password
    new_password: Optional[str] = None  # New password if updating

    class Config:
        # Ensure extra fields are forbidden to catch any naming errors
        extra = "forbid"

class UserResponse(BaseModel):
    id: str  # Alterado de int para str para suportar UUIDs
    email: str
    name: str
    sessions: List[str]
    force_password_change: bool
    is_active: bool
    has_subscription: bool
    subscription_end_date: Optional[str] = None 