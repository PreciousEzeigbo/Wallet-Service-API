from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import List, Optional

from app.database import get_db
from app.models import User, APIKey
from app.schemas import CreateAPIKeyRequest, CreateAPIKeyResponse, RolloverAPIKeyRequest, APIKeyResponse
from app.auth import get_current_user
from app.utils import parse_expiry, hash_api_key

router = APIRouter(prefix="/keys", tags=["API Keys"])


@router.post("/create", response_model=CreateAPIKeyResponse)
async def create_api_key(
    request: CreateAPIKeyRequest,
    auth_result: tuple[User, Optional[List[str]]] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new API key with specific permissions"""
    user, _ = auth_result
    
    # Check if user has reached the limit of 5 active keys
    active_keys_count = db.query(APIKey).filter(
        APIKey.user_id == user.id,
        APIKey.is_active == True,
        APIKey.expires_at > datetime.now(timezone.utc)
    ).count()
    
    if active_keys_count >= 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum of 5 active API keys allowed per user"
        )
    
    # Parse expiry
    expires_at = parse_expiry(request.expiry.value)
    
    # Generate API key
    api_key_value = APIKey.generate_key()

    # Hash the key for storage (hash_api_key handles truncation)
    key_hash = hash_api_key(api_key_value)
    key_prefix = APIKey.get_key_prefix(api_key_value)
    
    # Create API key (store hash, not plain key)
    api_key = APIKey(
        user_id=user.id,
        name=request.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        permissions=request.permissions,
        expires_at=expires_at
    )
    
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    
    # Return the plain key ONLY during creation (never again)
    return CreateAPIKeyResponse(
        api_key=api_key_value,  # Return plain key, not hash
        expires_at=api_key.expires_at.replace(tzinfo=timezone.utc)
    )


@router.post("/rollover", response_model=CreateAPIKeyResponse)
async def rollover_api_key(
    request: RolloverAPIKeyRequest,
    auth_result: tuple[User, Optional[List[str]]] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Rollover an expired API key with the same permissions"""
    user, _ = auth_result
    
    # Find the expired key
    expired_key = db.query(APIKey).filter(
        APIKey.id == request.expired_key_id,
        APIKey.user_id == user.id
    ).first()
    
    if not expired_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    # Check if the key is truly expired
    if expired_key.expires_at < datetime.now(timezone.utc): # Changed > to < for accurate check
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is not expired yet"
        )
    
    # Check if user has reached the limit of 5 active keys
    active_keys_count = db.query(APIKey).filter(
        APIKey.user_id == user.id,
        APIKey.is_active == True,
        APIKey.expires_at > datetime.now(timezone.utc)
    ).count()
    
    if active_keys_count >= 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum of 5 active API keys allowed per user"
        )
    
    # Parse new expiry
    new_expires_at = parse_expiry(request.expiry.value)
    
    # Generate new API key
    new_api_key_value = APIKey.generate_key()
    
    # Hash the new key (hash_api_key handles truncation)
    new_key_hash = hash_api_key(new_api_key_value)
    new_key_prefix = APIKey.get_key_prefix(new_api_key_value)
    
    # Create new API key with same permissions
    new_api_key = APIKey(
        user_id=user.id,
        name=expired_key.name,
        key_hash=new_key_hash,
        key_prefix=new_key_prefix,
        permissions=expired_key.permissions,
        expires_at=new_expires_at
    )
    
    db.add(new_api_key)
    db.commit()
    db.refresh(new_api_key)
    
    return CreateAPIKeyResponse(
        api_key=new_api_key_value,  # Return plain key only once
        expires_at=new_api_key.expires_at.replace(tzinfo=timezone.utc)
    )


@router.delete("/revoke/{key_id}")
async def revoke_api_key(
    key_id: str,
    auth_result: tuple[User, Optional[List[str]]] = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> dict[str, str]: # Explicitly define return type
    """Revoke an API key"""
    user, _ = auth_result
    
    # Find the key
    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.user_id == user.id
    ).first()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    # Revoke the key
    api_key.is_active = False # Direct assignment is fine for SQLAlchemy ORM
    db.commit()
    
    return {
        "message": "API key revoked successfully",
        "key_id": str(api_key.id),
        "name": str(api_key.name)
    }


@router.get("/list", response_model=List[APIKeyResponse]) # Explicitly define return type
async def list_api_keys(
    auth_result: tuple[User, Optional[List[str]]] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all API keys for the current user"""
    user, _ = auth_result
    
    # Get all keys for user
    keys = db.query(APIKey).filter(
        APIKey.user_id == user.id
    ).order_by(APIKey.created_at.desc()).all()
    
    return [
        APIKeyResponse(
            id=str(key.id),
            name=str(key.name),
            permissions=[str(p) for p in key.permissions],
            expires_at=key.expires_at.replace(tzinfo=timezone.utc),
            is_active=bool(key.is_active),
            is_expired=bool(key.expires_at < datetime.utcnow()),
            created_at=key.created_at.replace(tzinfo=timezone.utc),
            key_preview=f"{key.key_prefix}..."  # Only show prefix, never full key
        )
        for key in keys
    ]
