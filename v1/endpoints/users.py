import status
from uuid import UUID
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from src.models.users import User
from src.services.user_service import UserService
from src.services.auth_service import UserAuthenticationManager
from src.dependencies import get_user_service, get_authentication_manager, get_current_user
from src.schemas.users import UserCreate, UserLogin, UserOut, UserData, UserDetails, TokenResponse

router = APIRouter(tags=["users"])

@router.post("/token", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    auth_manager: UserAuthenticationManager = Depends(get_authentication_manager)
):
    user_login = UserLogin(username=form_data.username, password=form_data.password)

    user = await auth_manager.authenticate_user(user_login=user_login)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = auth_manager.token_service.create_access_token(
        data={"sub": user.username}
    )
    return {"access-token": access_token, "token_type": "bearer"}

@router.post("/create", response_model=UserOut)
async def register(
    user_create: UserCreate,
    user_service: UserService = Depends(get_user_service)
):
    return await user_service.create_user(user_create=user_create)

@router.put("/{user_id}/update-password")
async def update_user_password(
    current_password: str,
    new_password: str,
    current_user: User = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    return await user_service.update_password(
        user_id=current_user.user_id,
        current_password=current_password,
        new_password=new_password
    )

@router.get("/", response_model=list[UserData])
async def get_all_users(
    current_user: User = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
) -> list[UserData]:
    if not any (
        role.role.role_name == "ADMIN" for role in current_user.roles
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return await user_service.get_all_users()

@router.get("/{user_id}", response_model=UserDetails)
async def get_user(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    if not any (
        role.role.role_name == "ADMIN" for role in current_user.roles
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return await user_service.get_user_or_404(user_id=user_id)

@router.get("/profile", response_model=UserData)
async def get_current_user(
    current_user: User = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    return await user_service.get_user_or_404(user_id=current_user.user_id)

@router.delete("/{user_id}/delete")
async def delete_user(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    if not any(
        role.role.role_name == "ADMIN" for role in current_user.roles 
    ) or not (current_user.user_id == user_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform operations on this resource"
        )
    return await user_service.delete_user(user_id=user_id)
