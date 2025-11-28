# app/auth.py
import secrets # Ensure secrets is imported for password reset tokens
from datetime import timedelta
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext # Ensure CryptContext is imported
from jose import JWTError, jwt
from typing import Optional # Ensure Optional is imported
import logging # Add logging import

from app.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, logger, get_current_utc_time
from app.models import TokenData
from app.database import users_collection # Ensure users_collection is imported

# Password hashing context using bcrypt scheme
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto") 

# OAuth2PasswordBearer for handling token authentication
# `tokenUrl="token"` specifies the endpoint where clients can obtain a token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """
    Creates a JWT access token.

    Args:
        data (dict): The payload to encode into the token (e.g., {"sub": username, "role": role}).
        expires_delta (timedelta, optional): The duration for which the token will be valid.
                                             Defaults to ACCESS_TOKEN_EXPIRE_MINUTES if None.

    Returns:
        str: The encoded JWT token.`
    """
    to_encode = data.copy()
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Calculate the expiration time based on current UTC time
    expire = get_current_utc_time() + expires_delta
    to_encode.update({"exp": expire}) # Add expiration time to the payload
    
    # Encode the JWT token using the secret key and algorithm
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
    """
    Dependency to get the current authenticated user from the JWT token.

    Args:
        request (Request): The incoming request object.
        token (str): The JWT token extracted by OAuth2PasswordBearer (from Authorization header).

    Raises:
        HTTPException: If authentication fails (e.g., token missing, invalid, or user not found).

    Returns:
        dict: The user document from MongoDB.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Try to get the JWT token from the 'access_token' cookie first
    jwt_token = request.cookies.get("access_token")
    # Only log this in debug mode
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"JWT token from cookie: {jwt_token}")
    
    # If not in cookie, check if it was provided via the Authorization header (from oauth2_scheme)
    if not jwt_token and token:
        jwt_token = token
    
    # If no token is found, raise an authentication exception
    if not jwt_token:
        logger.error("JWT token not found in cookie or header.")
        raise credentials_exception

    try:
        # Decode the JWT token using the secret key and algorithm
        payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub") # Extract username (subject) from payload
        
        if username is None:
            logger.error("Username not found in JWT payload.")
            raise credentials_exception
        
        # Create TokenData object from payload, including role
        token_data = TokenData(username=username, role=payload.get("role"))
    except JWTError as e:
        # Catch any JWT decoding errors
        logger.error(f"JWT decode error: {e}")
        raise credentials_exception

    # Find the user in the database based on the username from the token
    user = users_collection.find_one({"email": token_data.username})
    if user is None:
        logger.error("User not found for given token data.")
        raise credentials_exception
    return user

async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    """
    Dependency to ensure the current user is active.
    Currently, all authenticated users are considered active.

    Args:
        current_user (dict): The user object from get_current_user.

    Raises:
        HTTPException: If the user is considered inactive (though not explicitly checked here).

    Returns:
        dict: The active user document.
    """
    if not current_user:
        # This condition might be more relevant if user documents had an 'is_active' field
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def verify_admin(current_user: dict = Depends(get_current_active_user)):
    """
    Dependency to verify if the current active user has 'admin' role.

    Args:
        current_user (dict): The active user object from get_current_active_user.

    Raises:
        HTTPException: If the user does not have 'admin' permissions.

    Returns:
        dict: The admin user document.
    """
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user