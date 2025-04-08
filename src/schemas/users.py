from uuid import UUID
from pydantic import BaseModel

from src.models.roles import UserRole

class UserBase(BaseModel):
    username: str

class UserLogin(UserBase):
    password: str

class UserCreate(UserBase):
    email: str
    password: str

class UserOut(UserBase):
    user_id: UUID
    email: str

class UserData(UserOut):
    backup_email: str

class UserDetails(UserData):
    roles: list[UserRole]

class UserRoleAssign(BaseModel):
    role_id: UUID

class UserRoleRemove(BaseModel):
    role_id: UUID

class AccessCheckRequest(BaseModel):
    required_permissions: list[str]

class AccessCheckResponse(BaseModel):
    user_id: UUID
    has_access: bool
    missing_permissions: list[str]

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
