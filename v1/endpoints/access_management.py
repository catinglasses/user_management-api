from uuid import UUID
from fastapi import APIRouter, Depends, status

from src.schemas.permissions import PermissionResponse
from src.schemas.users import UserRoleAssign, UserRoleRemove
from src.schemas.roles import RoleWithPermissions, RoleResponse
from src.services.role_service import RoleService, UserRoleService, PermissionService
from src.dependencies import get_role_service, get_permission_service, get_user_role_service

router = APIRouter(tags=["manage-access"])

# ------------------------------
# Permission Management
# ------------------------------

@router.post("/permissions/create-permission", response_model=RoleWithPermissions, status_code=status.HTTP_201_CREATED)
async def create_permission(
    permission_name: str, 
    permission_service: PermissionService = Depends(get_permission_service)
):
    """Endpoint to create a new permission."""
    return await permission_service.create_permission(permission_name)

@router.get("/permissions/{permission_name}", response_model=PermissionResponse)
async def get_permission_by_name(
    permission_name: str,
    permission_service: PermissionService = Depends(get_permission_service)
):
    """Endpoint to get a permission by name."""
    permission = await permission_service.get_permission_by_name(permission_name)
    return permission

@router.get("/permissions/", response_model=list[PermissionResponse])
async def get_all_permissions(
    permissions_service: PermissionService = Depends(get_permission_service)
):
    """Endpoint to list oll available permissions."""
    return await permissions_service.get_all_permissions()

@router.delete("/permissions/delete-permission/{permission_id}")
async def delete_permission(
    permission_id: UUID,
    permission_service: PermissionService = Depends(get_permission_service)
):
    """Endpoint to delete a permission by ID."""
    await permission_service.delete_permission(permission_id)
    return {"message": f"Permission {permission_id} deleted."}

# ------------------------------
# Role Management
# ------------------------------

@router.post("/roles/create-role", response_model=RoleWithPermissions)
async def create_role(
    role_name: str,
    permissions_names: list[str],
    role_service: RoleService = Depends(get_role_service)
):
    """Endpoint to create a new role with permissions."""
    return await role_service.create_role_with_permissions(
        role_name=role_name,
        permission_names=permissions_names
    )

@router.get("/roles/{role_name}", response_model=RoleWithPermissions)
async def get_role_by_name(
    role_name: str,
    role_service: RoleService = Depends(get_role_service)
):
    """Endpoint to get a role by name."""
    return await role_service.get_role_by_name(role_name)

@router.get("/roles/", response_model=list[RoleResponse])
async def get_all_roles(
    role_service: RoleService = Depends(get_role_service)
):
    """Endpoint to get all roles available."""
    return await role_service.get_all_roles()

@router.delete("/roles/delete-role/{role_id}")
async def delete_role(
    role_id: UUID,
    role_service: RoleService = Depends(get_role_service)
):
    """Endpoint to delete a role by ID."""
    await role_service.delete_role(role_id)
    return {"message": f"Role {role_id} deleted."}

@router.post("/roles/{role_id}/permissions/{permission_name}")
async def assign_permission_to_role(
    role_id: UUID,
    permission_name: str,
    role_service: RoleService = Depends(get_role_service)
):
    """Endpoint to assign permission to a role."""
    await role_service.assign_permission_to_role(
        role_id=role_id,
        permission_name=permission_name
    )
    return {"message": f"Permission {permission_name} assigned to role {role_id}"}

# ------------------------------
# UserRole Management
# ------------------------------

@router.get("/users/{user_id}/roles", response_model=list[RoleResponse])
async def get_user_roles(
    user_id: UUID,
    user_role_service: UserRoleService = Depends(get_user_role_service)
):
    """Endpoint to view all roles assigned to user."""
    roles = await user_role_service.get_user_roles(user_id)
    if not roles:
        return []
    return roles

@router.post("/users/{user_id}/assign-role/{role_name}", response_model=UserRoleAssign)
async def assign_role_to_user(
    user_id: UUID,
    role_name: str,
    user_role_service: UserRoleService = Depends(get_user_role_service)
):
    """Endpoint to assign a role to user."""
    return await user_role_service.assign_role_to_user(
        user_id=user_id,
        role_name=role_name
    )

@router.post("/users/{user_id}/remove-role/{role_name}", response_model=UserRoleRemove)
async def remove_role_from_user(
    user_id: UUID,
    role_name: str,
    user_role_service: UserRoleService = Depends(get_user_role_service)
):
    """Endpoint to remove a role from a user."""
    await user_role_service.remove_role_from_user(
        user_id=user_id,
        role_name=role_name
    )
    return {"message": f"Role {role_name} removed from the user {user_id}."}
