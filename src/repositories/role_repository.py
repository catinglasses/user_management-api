from uuid import UUID
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.roles import Role, UserRole, Permission, RolePermission

class PermissionRepository:
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def create_permission(self, name: str) -> Permission:
        """Create a new permission in the database."""
        permission = Permission(perm_name=name)
        self.db_session.add(permission)
        await self.db_session.commit()
        return permission

    async def _get_permission(self, criteria) -> Permission:
        """Private method to retrieve a permission based on a given criteria."""
        stmt = select(Permission).where(criteria)
        result = await self.db_session.execute(stmt)
        permission = result.scalars().one_or_none()
        return permission

    async def get_perm_by_id(self, permission_id: UUID) -> Permission:
        """Retrieve permission by its name."""
        return await self._get_permission(Permission.permission_id == permission_id)

    async def get_perm_by_name(self, name: str) -> Permission:
        """Retrieve permission by its name."""
        return await self._get_permission(Permission.perm_name == name)

    async def get_permissions_by_names(self, names: list[str]) -> list[Permission]:
        result = await self.db_session.execute(
            select(Permission).where(Permission.perm_name.in_(names))
        )
        return result.scalars().all()

    async def get_all_perms(self) -> list[Permission]:
        """Retrieve all permissions from the database."""
        stmt = select(Permission)
        result = await self.db_session.execute(stmt)
        return result.scalars().all()

    async def delete_permission(self, permission_id: UUID) -> None:
        """Delete permission from the database by its ID."""
        stmt = delete(Permission).where(Permission.permission_id == permission_id)
        await self.db_session.execute(stmt)
        await self.db_session.commit

class RoleRepository:
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def create_role(self, name: str) -> Role:
        """Create a new role in the database."""
        role = Role(role_name=name)
        self.db_session.add(role)
        await self.db_session.commit()
        await self.db_session.refresh()
        return role

    async def _get_role(self, criteria) -> Role:
        """Private method to retrieve a role based on a given criteria."""
        stmt = select(Role).where(criteria)
        result = await self.db_session.execute(stmt)
        role = result.scalars().one_or_none()
        return role

    async def get_role_by_id(self, role_id: UUID) -> Role:
        """Retrieve role by its ID."""
        return await self._get_role(Role.role_id == role_id)

    async def get_role_by_name(self, name: str) -> Role:
        """Retrieve role by its name."""
        return await self._get_role(Role.role_name == name)

    async def get_all_roles(self) -> list[Role]:
        """Retrieve all roles from the database."""
        stmt = select(Role)
        result = await self.db_session.execute(stmt)
        return result.scalars().all()

    async def delete_role(self, role_id: UUID) -> None:
        """Delete a role from the database by its ID."""
        stmt = delete(Role).where(Role.role_id == role_id)
        await self.db_session.execute(stmt)
        await self.db_session.commit()

    async def add_permissions_to_role(
            self,
            role_id: UUID,
            permission_ids: list[UUID]
    ) -> list[RolePermission]:
        role_permissions = [
            RolePermission(role_id=role_id, permission_id=pid)
            for pid in permission_ids
        ]
        self.db_session.add_all(role_permissions)
        await self.db_session.flush()
        return role_permissions

    async def get_role_permissions(self, role_id: UUID) -> list[Permission]:
        """Retrieve all permissions related to the role with provided ID."""
        stmt = (
            select(Permission)
            .join(
                RolePermission, 
                RolePermission.permission_id == Permission.permission_id
            )
            .where(RolePermission.role_id == role_id)
        )
        result = await self.db_session.execute(stmt)

        return result.scalars().all()

class UserRoleRepository:
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def assign_role_to_user(
            self,
            user_id: UUID,
            role_id: UUID
    ) -> UserRole:
        user_role = UserRole(user_id=user_id, role_id=role_id)
        self.db_session.add(user_role)
        await self.db_session.commit()
        return user_role

    async def get_user_roles(
            self,
            user_id: UUID
    ) -> list[Role]:
        """Retrieve all roles related to the user with provided ID."""
        result = await self.db_session.execute(
            select(UserRole).where(UserRole.user_id == user_id)
        )
        user_roles = result.scalars().all()
        return [user_role.role for user_role in user_roles]

    async def remove_user_role(
            self,
            user_id: UUID,
            role_id: UUID
    ) -> None:
        """Remove assigned role from the user by IDs of both respectively."""
        stmt = delete(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id
        )
        await self.db_session.execute(stmt)
        await self.db_session.commit()
