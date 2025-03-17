from typing import AsyncGenerator
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from settings import settings

engine = create_async_engine(url=settings.DATABASE_URL, echo=True)

async_session_maker = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Generator func for creating async db sessions."""
    async with async_session_maker() as session:
        yield session
