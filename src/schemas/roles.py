from uuid import UUID
from fastapi import Query
from pydantic import BaseModel

from src.schemas.permissions import PermissionResponse

class RoleBase(BaseModel):
    role_name: str

class RoleCreate(RoleBase):
    permission_names: list[str] = []

class RoleResponse(RoleBase):
    role_id: UUID

    class Config:
        from_attributes = True

class RoleWithPermissions(RoleResponse):
    permissions: list["PermissionResponse"]

class RoleUpdate(BaseModel):
    role_name: str | None = None

class RolePermissionsUpdate(BaseModel):
    permission_names: list[str]