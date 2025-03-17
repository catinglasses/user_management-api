from uuid import UUID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.users import User

class UserRepository:
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def create_user(self, user_data: User) -> User:
        """Create a new user in the database (commit to db session)."""
        self.db_session.add(user_data)
        await self.db_session.commit()
        await self.db_session.refresh(user_data)
        return user_data

    async def _get_user(self, criteria) -> User:
        """Private method to retrieve a user based on a given criteria."""
        stmt = select(User).where(criteria)
        result = await self.db_session.execute(stmt)
        user = result.scalars().one_or_none()

        return user

    async def get_user_by_id(self, user_id: UUID) -> User:
        return await self._get_user(User.user_id == user_id)

    async def get_user_by_username(self, username: str) -> User:
        return await self._get_user(User.username == username)

    async def get_all_users(self) -> list[User]:
        stmt = select(User)
        result = await self.db_session.execute(stmt)
        return result.scalars().all()

    async def update_user(self, user_data: User) -> User:
        """Update existing user in the db by commiting a transaction."""
        await self.db_session.commit()
        return user_data

    async def delete_user(self, user_id: UUID) -> None:
        """Delete user by id."""
        user = await self.get_user_by_id(user_id)
        await self.db_session.delete(user)
        await self.db_session.commit()
