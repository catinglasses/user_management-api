from uuid import UUID
from fastapi.exceptions import HTTPException

from src.models.roles import Role, UserRole, Permission
from src.repositories.role_repository import RoleRepository, UserRoleRepository, PermissionRepository

class PermissionService:
    def __init__(self, permission_repository: PermissionRepository):
        self.permission_repository = permission_repository

    async def create_permission(self, name: str) -> Permission:
        try:
            return await self.permission_repository.create_permission(name)
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create permission: {str(e)}"
            )

    async def get_permission_or_404(self, permission_id: UUID) -> Permission:
        permission = await self.permission_repository.get_perm_by_id(permission_id)
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        return permission

    async def get_all_permissions(self) -> list[Permission]:
        return await self.permission_repository.get_all_perms()

    async def delete_permission(self, permission_id: UUID) -> dict:
        try:
            await self.permission_repository.delete_permission(permission_id)
            return {"message": f"Permission {permission_id} deleted"}
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

class RoleService:
    def __init__(
            self,
            role_repository: RoleRepository,
            permission_repository: PermissionRepository
    ):
        self.role_repository = role_repository
        self.permission_repository = permission_repository

    async def get_role_by_name(self, name: str) -> Role:
        return await self.role_repository.get_role_by_name(name)

    async def create_role_with_permissions(
            self,
            role_name: str,
            permission_names: list[str]
    ) -> Role:
        role = await self.role_repository.create_role(name=role_name)
        permissions = await self.permission_repository.get_permissions_by_names(permission_names)

        if len(permissions) != len(permission_names):
            found_names = {p.name for p in permissions}
            missing = set(permission_names) - found_names
            raise HTTPException(
                status_code=404,
                detail=f"Permissions not found: {', '.join(missing)}"
            )

        if permissions:
            await self.role_repository.add_permissions_to_role(
                role_id=role.role_id,
                permission_ids=[p.permission_id for p in permissions]
            )

        return role

    async def assign_permission_to_role(self, role_id: UUID, permission_name: str):
        permission = await self.permission_repository.get_perm_by_name(permission_name)
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        return await self.role_repository.assign_permission_to_role(role_id, permission.permission_id)

    async def get_all_roles(self) -> list[Role]:
        return await self.role_repository.get_all_roles()

    async def get_role_permissions(self, role_id: UUID) -> list[Permission]:
        return await self.role_repository.get_role_permissions(role_id=role_id)

    async def delete_role(self, role_id: UUID) -> dict:
        try:
            await self.role_repository.delete_role(role_id)
            return {"message": f"Role {role_id} deleted"}
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

class UserRoleService:
    def __init__(self, user_role_repository: UserRoleRepository, role_repository: RoleRepository):
        self.user_role_repository = user_role_repository
        self.role_repository = role_repository

    async def assign_role_to_user(self, user_id: UUID, role_name: str) -> UserRole:
        role = await self.role_repository.get_role_by_name(name=role_name)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        return await self.user_role_repository.assign_role_to_user(user_id=user_id, role_id=role.role_id)

    async def get_user_roles(self, user_id: UUID) -> list[Role]:
        return await self.user_role_repository.get_user_roles(user_id)

    async def remove_role_from_user(self, user_id: UUID, role_name: str) -> dict:
        try:
            role = await self.role_repository.get_role_by_name(role_name)
            if not role:
                raise ValueError(f"Role '{role_name}' not found")
            
            await self.user_role_repository.remove_user_role(
                user_id=user_id,
                role_id=role.role_id
            )
            return {"message": f"Role '{role_name} removed from user {user_id}"}
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
