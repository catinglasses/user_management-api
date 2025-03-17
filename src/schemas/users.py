from uuid import UUID
from pydantic import BaseModel

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserOut(BaseModel):
    user_id: UUID
    username: str
    email: str
