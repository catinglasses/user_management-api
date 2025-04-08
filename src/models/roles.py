from uuid import UUID
from sqlalchemy.sql import func
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.users import User
from src.models.database import Base

class Permission(Base):
    """Represents a permission that can be assigned to roles."""
    __tablename__ = "permissions"

    permission_id: Mapped[UUID] = mapped_column(primary_key=True, server_default=func.gen_random_uuid())
    perm_name: Mapped[str] = mapped_column(unique=True, nullable=False)

    roles = relationship('RolePermission', back_populates='permission')

class Role(Base):
    """Represents a role that can be assigned to users."""
    __tablename__ = "roles"

    role_id: Mapped[UUID] = mapped_column(primary_key=True, server_default=func.gen_random_uuid())
    role_name: Mapped[str] = mapped_column(unique=True, nullable=False)

    users: Mapped[list['UserRole']] = relationship('UserRole', back_populates='role')

    permissions = relationship('RolePermission', back_populates='role')

class RolePermission(Base):
    """Represents the association between roles and permissions (many-to-many)."""
    __tablename__ = "role_permissions"

    role_id: Mapped[UUID] = mapped_column(
        ForeignKey('roles.role_id', on_delete='CASCADE'),
        primary_key=True
    )
    permission_id: Mapped[UUID] = mapped_column(
        ForeignKey('permissions.permission_id', on_delete='CASCADE'),
        primary_key=True
    )

    role = relationship('Role', back_populates="permissions")
    permission = relationship('Permission', back_populates='roles')

class UserRole(Base):
    """Represents the association between users and roles (many-to-many)."""
    __tablename__ = "user_roles"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey('users.user_id', on_delete='CASCADE'),
        primary_key=True
    )
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey('roles.role_id', on_delete='CASCADE'),
        primary_key=True
    )

    user: Mapped['User'] = relationship('User', back_populates='roles')
    role: Mapped['Role'] = relationship('Role', back_populates='users')
