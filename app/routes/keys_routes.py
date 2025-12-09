from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime

from app.database import get_db
from app.models import User, APIKey
from app.schemas import CreateAPIKeyRequest, CreateAPIKeyResponse, RolloverAPIKeyRequest
from app.auth import get_current_user
from app.utils import parse_expiry

router = APIRouter(prefix="/keys", tags=["API Keys"])


@router.post("/create", response_model=CreateAPIKeyResponse)
async def create_api_key(
    request: CreateAPIKeyRequest,
    auth_result: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new API key with specific permissions"""
    user, _ = auth_result
    
    # Check if user has reached the limit of 5 active keys
    active_keys_count = db.query(APIKey).filter(
        APIKey.user_id == user.id,
        APIKey.is_active == True,
        APIKey.expires_at > datetime.utcnow()
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
    
    # Create API key
    api_key = APIKey(
        user_id=user.id,
        name=request.name,
        key=api_key_value,
        permissions=request.permissions,
        expires_at=expires_at
    )
    
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    
    return CreateAPIKeyResponse(
        api_key=api_key.key,
        expires_at=api_key.expires_at
    )


@router.post("/rollover", response_model=CreateAPIKeyResponse)
async def rollover_api_key(
    request: RolloverAPIKeyRequest,
    auth_result: tuple = Depends(get_current_user),
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
    if expired_key.expires_at > datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is not expired yet"
        )
    
    # Check if user has reached the limit of 5 active keys
    active_keys_count = db.query(APIKey).filter(
        APIKey.user_id == user.id,
        APIKey.is_active == True,
        APIKey.expires_at > datetime.utcnow()
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
    
    # Create new API key with same permissions
    new_api_key = APIKey(
        user_id=user.id,
        name=expired_key.name,
        key=new_api_key_value,
        permissions=expired_key.permissions,
        expires_at=new_expires_at
    )
    
    db.add(new_api_key)
    db.commit()
    db.refresh(new_api_key)
    
    return CreateAPIKeyResponse(
        api_key=new_api_key.key,
        expires_at=new_api_key.expires_at
    )
