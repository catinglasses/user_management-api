from uuid import UUID
from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.users import User
from src.models.database import get_db
from src.services.user_service import UserService
from src.repositories.user_repository import UserRepository
from src.models.roles import Role, UserRole, Permission, RolePermission
from src.services.role_service import RoleService, UserRoleService, PermissionService
from src.services.auth_service import TokenService, PasswordManager, UserAuthenticationManager
from src.repositories.role_repository import RoleRepository, UserRoleRepository, PermissionRepository

async def get_user_repository(
        db: AsyncSession = Depends(get_db)
) -> UserRepository:
    """Create UserRepository instance, dependency inject async db session."""
    return UserRepository(db)

async def get_role_repository(
        db: AsyncSession = Depends(get_db)
) -> RoleRepository:
    """Create RoleRepository instance, dependency inject async db session."""
    return RoleRepository(db)

async def get_permission_repository(
        db: AsyncSession = Depends(get_db)
) -> PermissionRepository:
    """Create PermissionRepository instance, DI async db session."""
    return PermissionRepository(db)

async def get_user_role_repository(
        db: AsyncSession = Depends(get_db)
) -> UserRoleRepository:
    """Create UserRoleRepository instance, DI async db session."""
    return UserRoleRepository(db)

async def get_password_manager(
        user_repository: UserRepository = Depends(get_user_repository)
) -> PasswordManager:
    """Create PasswordManager instance, DI UserRepository."""
    return PasswordManager(user_repository=user_repository)

async def get_user_service(
        user_repository: UserRepository = Depends(get_user_repository),
        password_manager: PasswordManager = Depends(get_password_manager)
) -> UserService:
    """Create UserService instance, DI UserRepository & PasswordManager."""
    return UserService(
        user_repository=user_repository,
        password_manager=password_manager
    )

async def get_token_service(
        user_repository: UserRepository = Depends(get_user_repository)
) -> UserRepository:
    """Create TokenService instance, DI UserRepository."""
    return TokenService(user_repository)

async def get_authentication_manager(
        token_service: TokenService = Depends(get_token_service),
        password_manager: PasswordManager = Depends(get_password_manager)
) -> UserAuthenticationManager:
    """Create UserAuthenticationManager instance,
    DI TokenService & PasswordManager."""
    return UserAuthenticationManager(
        token_service=token_service,
        password_manager=password_manager
    )

async def get_permission_service(
        permission_repository: PermissionRepository = Depends(get_permission_repository)
) -> PermissionService:
    """Create PermissionService instance, DI PermissionRepository."""
    return PermissionService(permission_repository=permission_repository)

async def get_role_service(
        role_repository: RoleRepository = Depends(get_role_repository),
        permission_repository: PermissionRepository = Depends(get_permission_repository)
) -> RoleService:
    """Create RoleService instance, DI RoleRepository & PermissionRepository."""
    return RoleService(
        role_repository=role_repository,
        permission_repository=permission_repository
    )

async def get_user_role_service(
        user_role_repository: UserRoleRepository = Depends(get_user_role_repository),
        role_repository: RoleRepository = Depends(get_role_repository)
) -> UserRoleService:
    """Create UserRoleService instance, DI UserRoleRepository & RoleRepository."""
    return UserRoleService(
        user_role_repository=user_role_repository,
        role_repository=role_repository
    )
