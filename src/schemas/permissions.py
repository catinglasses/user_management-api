from uuid import UUID
from pydantic import BaseModel

class PermissionBase(BaseModel):
    perm_name: str

class PermissionCreate(PermissionBase):
    pass

class PermissionResponse(PermissionBase):
    permission_id: UUID

    class Config:
        from_attributes = True