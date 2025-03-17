import status
from uuid import UUID
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from src.models.users import User
from src.services.user_service import UserService
from src.schemas.users import UserCreate, UserLogin, UserOut
from src.services.auth_service import UserAuthenticationManager

