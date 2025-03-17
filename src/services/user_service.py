from uuid import UUID
from fastapi.exceptions import HTTPException

from src.models.users import User
from src.schemas.users import UserCreate
from src.services.auth_service import PasswordManager
from src.repositories.user_repository import UserRepository

class UserService:
    '''User management class. User-related operations like create, most getters/setters go here'''
    def __init__(self, user_repository: UserRepository, password_manager: PasswordManager):
        self.user_repository = user_repository
        self.password_manager = password_manager

    async def create_user(self, user_create: UserCreate) -> User:
        """Create a new User via user_repository"""
        new_user = User(
            username=user_create.username,
            email=user_create.email,
            password_hash=self.password_manager.set_password(user_create.password),
        )
        return await self.user_repository.create_user(new_user)

    async def get_user_or_404(self, user_id: UUID) -> User:
        """Get User by ID or raise 404 Not Found"""
        user = await self.user_repository.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user

    async def get_all_users(self) -> list[User]:
        """Get all existing User objects from the database"""
        return await self.user_repository.get_all_users()

    async def replace_user(self, user_id: UUID, user: User) -> User:
        """Completely replace an existing User by retrieving it with ID"""
        current_user = await self.get_user_or_404(user_id)
        user.user_id = current_user.user_id
        return await self.user_repository.update_user(user)

    async def update_user(self, user_id: UUID, updated_user: User, password: str) -> User:
        """Partially change an existing User by retrieving it with ID after password verification"""
        current_user = await self.get_user_or_404(user_id)

        if not PasswordManager.check_password(password, current_user):
            raise ValueError("Your password is incorrect")

        if updated_user.username is not None:
            current_user.username = updated_user.username
        if updated_user.email is not None:
            current_user.email = updated_user.email
        
        return await self.user_repository.update_user(current_user)

    async def update_password(self, user_id: UUID, current_password: str, new_password: str) -> User:
        """Update User's password after verifying the current password"""
        user = await self.get_user_or_404(user_id)
        return await self.password_manager.update_password(user, current_password, new_password)

    async def delete_user(self, user_id: UUID) -> dict:
        """Delete User object by retrieving it with ID"""
        await self.user_repository.delete_user(user_id)
        return {"detail": "User deleted successfully"}
