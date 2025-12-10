from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime
from app.database import get_db
from app.models import User, APIKey
from app.utils import verify_token, verify_api_key

security = HTTPBearer(auto_error=False)


async def get_current_user_jwt_only(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Authenticate user via JWT token ONLY.
    Used for API key management endpoints to prevent privilege escalation.
    
    Returns:
        User: Authenticated user object
    
    Raises:
        HTTPException: If authentication fails or API key is attempted
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT authentication required. API keys cannot manage other API keys.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    payload = verify_token(token)
    
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired JWT token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> tuple[User, Optional[List[str]]]:
    """
    Authenticate user via JWT token or API key.
    Used for wallet operations that support granular permissions.
    
    Args:
        credentials: Bearer token from Authorization header
        x_api_key: API key from x-api-key header
        db: Database session
    
    Returns:
        tuple[User, Optional[List[str]]]: User object and permissions list.
            Permissions is None for JWT auth (full access), or list of permissions for API key auth.
    
    Raises:
        HTTPException: If authentication fails
    """
    if x_api_key:
        key_prefix = APIKey.get_key_prefix(x_api_key)
        
        potential_keys = db.query(APIKey).filter(
            APIKey.key_prefix == key_prefix,
            APIKey.is_active == True
        ).all()
        
        api_key = None
        for pk in potential_keys:
            if verify_api_key(x_api_key, pk.key_hash):
                api_key = pk
                break
        
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        
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
    
    if credentials:
        token = credentials.credentials
        payload = verify_token(token)
        
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired JWT token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return user, None
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide either Bearer token or x-api-key header."
    )


def require_permission(permission: str):
    """
    Dependency factory to enforce permission-based access control.
    
    For JWT authentication: Grants full access (all permissions).
    For API key authentication: Checks if the key has the required permission.
    
    Args:
        permission: Required permission (e.g., 'deposit', 'transfer', 'read')
    
    Returns:
        Callable dependency that returns the authenticated User
    
    Raises:
        HTTPException: If API key lacks required permission
    """
    async def permission_checker(
        auth_result: tuple[User, Optional[List[str]]] = Depends(get_current_user)
    ):
        user, permissions = auth_result
        
        if permissions is None:
            return user
        
        if permission not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key lacks required '{permission}' permission. Available permissions: {', '.join(permissions)}"
            )
        
        return user
    
    return permission_checker
