 nfrom pydantic import BaseModel, Field, validator
from typing import List, Optional
from datetime import datetime
from enum import Enum


class TransactionType(str, Enum):
    DEPOSIT = "deposit"
    TRANSFER = "transfer"


class TransactionStatus(str, Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"


class ExpiryOption(str, Enum):
    ONE_HOUR = "1H"
    ONE_DAY = "1D"
    ONE_MONTH = "1M"
    ONE_YEAR = "1Y"


class GoogleAuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class CreateAPIKeyRequest(BaseModel):
    name: str = Field(..., description="A name for the API key (e.g., 'wallet-service')")
    permissions: List[str] = Field(..., description="List of permissions: any of ['deposit', 'transfer', 'read']")
    expiry: ExpiryOption = Field(..., description="Expiry duration: one of '1H', '1D', '1M', '1Y'")

    @validator('permissions')
    def validate_permissions(cls, v):
        valid_permissions = ["deposit", "transfer", "read"]
        for perm in v:
            if perm not in valid_permissions:
                raise ValueError(f"Invalid permission: {perm}. Valid permissions are: {valid_permissions}")
        return v


class CreateAPIKeyResponse(BaseModel):
    api_key: str
    expires_at: datetime


class RolloverAPIKeyRequest(BaseModel):
    expired_key_id: str
    expiry: ExpiryOption


class APIKeyResponse(BaseModel):
    id: str
    name: str
    permissions: List[str]
    expires_at: datetime
    is_active: bool
    is_expired: bool
    created_at: datetime
    key_preview: str

    class Config:
        from_attributes = True


class DepositRequest(BaseModel):
    amount: int = Field(..., gt=0, description="Amount in kobo (100 kobo = ₦1). Must be greater than 0.")


class DepositResponse(BaseModel):
    reference: str
    authorization_url: str


class DepositStatusResponse(BaseModel):
    reference: str
    status: TransactionStatus
    amount: int


class BalanceResponse(BaseModel):
    balance: int
    wallet_number: str


class TransferRequest(BaseModel):
    wallet_number: str
    amount: int = Field(..., gt=0, description="Amount in kobo (100 kobo = ₦1). Must be greater than 0.")


class TransferResponse(BaseModel):
    status: str
    message: str


class TransactionResponse(BaseModel):
    id: str
    type: TransactionType
    amount: int
    status: TransactionStatus
    reference: str
    created_at: datetime
    transaction_metadata: Optional[str] = None
    
    class Config:
        from_attributes = True


class WebhookResponse(BaseModel):
    status: bool
