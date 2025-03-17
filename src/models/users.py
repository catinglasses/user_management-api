from uuid import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.database import Base
from src.models.roles import UserRole

class User(Base):
    """Represents a user in the system database."""
    __tablename__ = "users"

    user_id: Mapped[UUID] = mapped_column(primary_key=True, server_default=func.gen_random_uuid())
    username: Mapped[str] = mapped_column(unique=True, nullable=False)
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(nullable=False)
    backup_email: Mapped[str] = mapped_column(unique=True, nullable=True)
    is_admin: Mapped[bool] = mapped_column(default=False)

    roles: Mapped[list['UserRole']] = relationship('UserRole', back_populates='user')
