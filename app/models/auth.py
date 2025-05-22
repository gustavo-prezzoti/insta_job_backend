from pydantic import BaseModel

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
    name: str = None  # Optional name update
    current_password: str = None  # Required if updating password
    new_password: str = None  # New password if updating

    class Config:
        # Ensure extra fields are forbidden to catch any naming errors
        extra = "forbid" 