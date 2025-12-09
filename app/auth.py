from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime
from app.database import get_db
from app.models import User, APIKey
from app.utils import verify_token

security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> tuple[User, Optional[List[str]]]:
    """
    Authenticate user via JWT token or API key.
    Returns tuple of (user, permissions) where permissions is None for JWT auth
    """
    # Try API Key authentication first
    if x_api_key:
        api_key = db.query(APIKey).filter(
            APIKey.key == x_api_key,
            APIKey.is_active == True
        ).first()
        
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        
        # Check if expired
        if api_key.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired"
            )
        
        user = db.query(User).filter(User.id == api_key.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return user, api_key.permissions
    
    # Try JWT authentication
    if credentials:
        token = credentials.credentials
        payload = verify_token(token)
        
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return user, None  # JWT users have all permissions
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated"
    )


def require_permission(permission: str):
    """Dependency to check if user has required permission"""
    async def permission_checker(
        auth_result: tuple[User, Optional[List[str]]] = Depends(get_current_user)
    ):
        user, permissions = auth_result
        
        # JWT users have all permissions
        if permissions is None:
            return user
        
        # Check if API key has required permission
        if permission not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key does not have '{permission}' permission"
            )
        
        return user
    
    return permission_checker
