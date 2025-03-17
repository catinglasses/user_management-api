import os
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from apscheduler.schedulers.background import BackgroundScheduler

from src.models.users import User
from src.schemas.users import UserLogin
from src.repositories.user_repository import UserRepository

PRIVATE_KEY = os.getenv("PRIVATE_KEY")
PUBLIC_KEY = os.getenv("PUBLIC_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/token")

class TokenService:
    """
    Handles all JWT-related operations:
    key management & rotation, token creation and validation.
    """
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
        self.private_key = self.load_private_key()
        self.public_key = self.load_public_key()
        self.previous_private_key = None

    def load_private_key(self):
        """Load the private key from environment variable or file."""
        return serialization.load_pem_private_key(
            PRIVATE_KEY.encode(),
            password=None,
        )

    def load_public_key(self):
        """Load the public key from enivornment variable or file."""
        return serialization.load_pem_public_key(
            PUBLIC_KEY.encode(),
        )

    def create_access_token(
        self,
        data: dict,
        expires_detla: timedelta | None = None
    ) -> str:
        """
        Creates a JWT with an expiration time and signs it using RS256.
        Accepts user data (e.g. username) and an optional expiration delta.
        """
        to_encode = data.copy()
        if expires_detla:
            expire = datetime.now() + expires_detla
        else:
            expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.private_key, algorithm="RS256")
        return encoded_jwt

    async def get_current_user(self, token: str) -> User:
        """
        Decodes the JWT using the public key.
        If valid, it retrieves the user associated with the token.
        If validation fails (e.g. token invalid/expired), raises HTTP Exception.
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            payload = jwt.decode(token, self.public_key, algorithms=["RS256"])
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception

            user = await self.user_repository.get_user_by_username(username)
            if user is None:
                raise credentials_exception

            return user

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        except jwt.PyJWTError:
            raise credentials_exception

    def rotate_private_key(self):
        """
        Rotate the private key every 90 days.
        Store the current private key as previous.
        Generate a new private key. Write it to env.
        """
        self.previous_private_key = self.private_key
        new_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.private_key = new_private_key

        # Update the environment variable with new private key
        os.environ["PRIVATE_KEY"] = new_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=None,
        ).decode()

    def schedule_key_rotation(self):
        """Create a background job to call rotate_private_key every 90 days."""
        scheduler = BackgroundScheduler()
        scheduler.add_job(self.rotate_private_key, "interval", days=90)
        scheduler.start()

class PasswordManager:
    """Handles password-related operations: hashing, verification and setting."""
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def set_password(self, password: str) -> str:
        """Set password after hashing it."""
        return self.hash_password(password)

    def hash_password(self, password: str) -> str:
        """Hash password for storage."""
        return self.pwd_context.hash(password)

    async def check_password(self, password: str, user: User) -> bool:
        """Check if provided password matches the hash."""
        return self.pwd_context.verify(password, user.password_hash)

    async def update_password(
        self,
        user: User,
        current_password: str,
        new_password: str
    ) -> User:
        """Update user's password after verifying the current password."""
        if not await self.check_password(current_password, user):
            raise ValueError("Incorrect password.")
        
        user.password_hash = self.set_password(new_password)
        await self.user_repository.update_user(user)
        return user

class UserAuthenticationManager(TokenService, PasswordManager):
    """Handles user authentication and token generation."""
    def __init__(self, token_service: TokenService, password_manager: PasswordManager):
        self.token_service = token_service
        self.password_manager = password_manager

    async def authenticate_user(self, user_login: UserLogin) -> User | None:
        """Authenticate a user using their username and password."""
        user = await self.token_service.user_repository.get_user_by_username(user_login.username)
        if user and await self.check_password(user_login.password, user):
            return user
        return None

    def generate_token(self, user: User) -> str:
        """Generate a token for authenticated user."""
        return self.token_service.create_access_token(data={"sub": user.username})

# Initialization of key rotation scheduler
token_service = TokenService()
token_service.schedule_key_rotation()
