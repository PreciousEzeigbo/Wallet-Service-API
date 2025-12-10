from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import List, Optional

from app.database import get_db
from app.models import User, APIKey
from app.schemas import CreateAPIKeyRequest, CreateAPIKeyResponse, RolloverAPIKeyRequest, APIKeyResponse
from app.auth import get_current_user_jwt_only
from app.utils import parse_expiry, hash_api_key

router = APIRouter(prefix="/keys", tags=["API Keys"])


@router.post(
    "/create",
    response_model=CreateAPIKeyResponse,
    summary="Create new API key",
    description="""Create a new API key with granular permissions for wallet operations. Maximum 5 active keys per user. Supports permissions: deposit (initialize Paystack deposits), transfer (send funds), read (view balance and transactions). API key shown only once during creation.""",
    responses={
        200: {"description": "API key created successfully"},
        400: {"description": "Maximum of 5 active keys reached"},
        401: {"description": "Invalid or missing JWT token"}
    },
    tags=["API Keys"]
)
async def create_api_key(
    request: CreateAPIKeyRequest,
    user: User = Depends(get_current_user_jwt_only),
    db: Session = Depends(get_db)
):
    """
    Create a new API key with specific permissions for wallet operations.
    
    Request Body Example:
        {
            "name": "wallet-service",
            "permissions": ["deposit", "transfer", "read"],
            "expiry": "1D"
        }
    
    - Only 5 active (not expired, not revoked) API keys allowed per user.
    - Permissions must be a subset of ["deposit", "transfer", "read"].
    - Expiry must be a valid option (1H, 1D, 1M, 1Y).
    - API key is returned only once in the response.
    """

    active_keys_count = db.query(APIKey).filter(
        APIKey.user_id == user.id,
        APIKey.is_active == True,
        APIKey.expires_at > datetime.now(timezone.utc)
    ).count()
    if active_keys_count >= 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum of 5 active API keys allowed per user. Revoke or let one expire before creating a new key."
        )

    valid_permissions = ["deposit", "transfer", "read"]
    for perm in request.permissions:
        if perm not in valid_permissions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid permission: {perm}. Valid permissions are: {valid_permissions}"
            )

    try:
        expires_at = parse_expiry(request.expiry.value)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid expiry value: {request.expiry}. Must be one of: 1H, 1D, 1M, 1Y."
        )

    api_key_value = APIKey.generate_key()
    key_hash = hash_api_key(api_key_value)
    key_prefix = APIKey.get_key_prefix(api_key_value)

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

    return CreateAPIKeyResponse(
        api_key=api_key_value,
        expires_at=api_key.expires_at.replace(tzinfo=timezone.utc)
    )


@router.post(
    "/rollover",
    response_model=CreateAPIKeyResponse,
    summary="Rollover expired API key",
    description="""Generate a new API key to replace an expired one, preserving the same permissions. Old key remains in database for audit trail. Original key must be truly expired.""",
    responses={
        200: {"description": "New API key created successfully"},
        400: {"description": "Key not expired or max keys reached"},
        401: {"description": "Invalid or missing JWT token"},
        404: {"description": "Key not found"}
    },
    tags=["API Keys"]
)
async def rollover_api_key(
    request: RolloverAPIKeyRequest,
    user: User = Depends(get_current_user_jwt_only),
    db: Session = Depends(get_db)
):
    """
    Generate a new API key to replace an expired one with same permissions.
    
    Args:
        request: Rollover parameters (expired key ID, new expiry duration)
        user: Authenticated user from JWT token
        db: Database session
    
    Returns:
        CreateAPIKeyResponse: New plain text API key and expiration date
    
    Raises:
        HTTPException 400: Key not expired or max keys reached
        HTTPException 401: Invalid or missing JWT token
        HTTPException 404: Key not found or doesn't belong to user
    """
    expired_key = db.query(APIKey).filter(
        APIKey.id == request.expired_key_id,
        APIKey.user_id == user.id
    ).first()
    
    if not expired_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    if expired_key.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is not expired yet"
        )
    
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
    
    new_expires_at = parse_expiry(request.expiry.value)
    new_api_key_value = APIKey.generate_key()
    new_key_hash = hash_api_key(new_api_key_value)
    new_key_prefix = APIKey.get_key_prefix(new_api_key_value)
    
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
        api_key=new_api_key_value,
        expires_at=new_api_key.expires_at.replace(tzinfo=timezone.utc)
    )


@router.delete(
    "/revoke/{key_id}",
    summary="Revoke API key",
    description="""Immediately revoke an active API key, preventing all future use. Key remains in database for audit purposes. Revocation is immediate and irreversible.""",
    responses={
        200: {"description": "API key revoked successfully"},
        401: {"description": "Invalid or missing JWT token"},
        404: {"description": "Key not found"}
    },
    tags=["API Keys"]
)
async def revoke_api_key(
    key_id: str,
    user: User = Depends(get_current_user_jwt_only),
    db: Session = Depends(get_db)
) -> dict[str, str]:
    """
    Revoke an API key immediately, preventing all future authentication attempts.
    
    Args:
        key_id: UUID of the API key to revoke
        user: Authenticated user from JWT token
        db: Database session
    
    Returns:
        dict: Confirmation message with key details
    
    Raises:
        HTTPException 401: Invalid or missing JWT token
        HTTPException 404: Key not found or doesn't belong to user
    """
    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.user_id == user.id
    ).first()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    api_key.is_active = False
    db.commit()
    
    return {
        "message": "API key revoked successfully",
        "key_id": str(api_key.id),
        "name": str(api_key.name)
    }


@router.get(
    "/list",
    response_model=List[APIKeyResponse],
    summary="List all API keys",
    description="""Retrieve all API keys associated with your account, including active, expired, and revoked keys. Full API key values are never returned, only the prefix is shown for identification. Results sorted by creation date (newest first).""",
    responses={
        200: {"description": "List of all API keys with metadata"},
        401: {"description": "Invalid or missing JWT token"}
    },
    tags=["API Keys"]
)
async def list_api_keys(
    user: User = Depends(get_current_user_jwt_only),
    db: Session = Depends(get_db)
):
    """
    List all API keys for the authenticated user with full metadata.
    
    Args:
        user: Authenticated user from JWT token
        db: Database session
    
    Returns:
        List[APIKeyResponse]: All API keys with status and permissions
    
    Raises:
        HTTPException 401: Invalid or missing JWT token
    """
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
            key_preview=f"{key.key_prefix}..."
        )
        for key in keys
    ]
