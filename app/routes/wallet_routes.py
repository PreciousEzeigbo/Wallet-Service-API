from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from sqlalchemy.orm import Session
from typing import List
import uuid
import secrets

from app.database import get_db
from app.models import User, Wallet, Transaction, TransactionType, TransactionStatus
from app.schemas import (
    DepositRequest, DepositResponse, DepositStatusResponse,
    BalanceResponse, TransferRequest, TransferResponse,
    TransactionResponse, WebhookResponse
)
from app.auth import get_current_user, require_permission
from app.paystack import PaystackClient

router = APIRouter(prefix="/wallet", tags=["Wallet"])
paystack = PaystackClient()


@router.post("/deposit", response_model=DepositResponse)
async def deposit(
    request: DepositRequest,
    user: User = Depends(require_permission("deposit")),
    db: Session = Depends(get_db)
):
    """Initialize a deposit transaction with Paystack"""
    
    # Get user's wallet
    wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found"
        )
    
    # Generate unique reference
    reference = f"DEP_{uuid.uuid4().hex[:12].upper()}"
    
    # Check if reference already exists
    existing_transaction = db.query(Transaction).filter(
        Transaction.reference == reference
    ).first()
    
    if existing_transaction:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Duplicate transaction reference"
        )
    
    # Create pending transaction
    transaction = Transaction(
        reference=reference,
        type=TransactionType.DEPOSIT,
        amount=request.amount,
        status=TransactionStatus.PENDING,
        recipient_wallet_id=wallet.id
    )
    db.add(transaction)
    db.commit()
    
    try:
        # Initialize Paystack transaction (amount in kobo - multiply by 100)
        paystack_response = await paystack.initialize_transaction(
            email=user.email,
            amount=int(request.amount * 100),
            reference=reference
        )
        
        return DepositResponse(
            reference=reference,
            authorization_url=paystack_response["authorization_url"]
        )
    except Exception as e:
        # Mark transaction as failed
        transaction.status = TransactionStatus.FAILED
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to initialize payment: {str(e)}"
        )


@router.post("/paystack/webhook", response_model=WebhookResponse)
async def paystack_webhook(
    request: Request,
    x_paystack_signature: str = Header(None),
    db: Session = Depends(get_db)
):
    """
    Handle Paystack webhook events
    This endpoint credits the wallet after successful payment
    """
    
    # Get raw body for signature verification
    body = await request.body()
    
    # Verify signature
    if not x_paystack_signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing signature"
        )
    
    if not PaystackClient.verify_webhook_signature(body, x_paystack_signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid signature"
        )
    
    # Parse webhook data from the raw body (can't call request.json() after body())
    import json
    data = json.loads(body.decode('utf-8'))
    event = data.get("event")
    
    if event == "charge.success":
        event_data = data.get("data", {})
        reference = event_data.get("reference")
        amount = event_data.get("amount", 0) / 100  # Convert from kobo to naira
        paystack_status = event_data.get("status")
        
        if not reference:
            return WebhookResponse(status=True)
        
        # Find transaction
        transaction = db.query(Transaction).filter(
            Transaction.reference == reference
        ).first()
        
        if not transaction:
            # Log but don't fail - might be a test webhook
            return WebhookResponse(status=True)
        
        # Idempotency check - don't credit twice
        if transaction.status == TransactionStatus.SUCCESS:
            return WebhookResponse(status=True)
        
        # Update transaction and credit wallet
        if paystack_status == "success":
            transaction.status = TransactionStatus.SUCCESS
            
            # Credit wallet
            wallet = db.query(Wallet).filter(
                Wallet.id == transaction.recipient_wallet_id
            ).first()
            
            if wallet:
                wallet.balance += amount
            
            db.commit()
        else:
            transaction.status = TransactionStatus.FAILED
            db.commit()
    
    return WebhookResponse(status=True)


@router.get("/deposit/{reference}/status", response_model=DepositStatusResponse)
async def get_deposit_status(
    reference: str,
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """
    Get deposit transaction status
    This endpoint does NOT credit wallets - only the webhook does that
    """
    
    transaction = db.query(Transaction).filter(
        Transaction.reference == reference,
        Transaction.type == TransactionType.DEPOSIT
    ).first()
    
    if not transaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Transaction not found"
        )
    
    # Verify the transaction belongs to the user
    wallet = db.query(Wallet).filter(
        Wallet.id == transaction.recipient_wallet_id,
        Wallet.user_id == user.id
    ).first()
    
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized access to transaction"
        )
    
    return DepositStatusResponse(
        reference=transaction.reference,
        status=transaction.status,
        amount=transaction.amount
    )


@router.get("/balance", response_model=BalanceResponse)
async def get_balance(
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """Get wallet balance"""
    
    wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found"
        )
    
    return BalanceResponse(balance=wallet.balance)


@router.post("/transfer", response_model=TransferResponse)
async def transfer(
    request: TransferRequest,
    user: User = Depends(require_permission("transfer")),
    db: Session = Depends(get_db)
):
    """Transfer funds to another wallet"""
    
    # Get sender's wallet
    sender_wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    if not sender_wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found"
        )
    
    # Check sufficient balance
    if sender_wallet.balance < request.amount:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Insufficient balance"
        )
    
    # Get recipient's wallet
    recipient_wallet = db.query(Wallet).filter(
        Wallet.wallet_number == request.wallet_number
    ).first()
    
    if not recipient_wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient wallet not found"
        )
    
    # Prevent self-transfer
    if sender_wallet.id == recipient_wallet.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot transfer to your own wallet"
        )
    
    # Generate unique reference
    reference = f"TRF_{uuid.uuid4().hex[:12].upper()}"
    
    # Create transaction
    transaction = Transaction(
        reference=reference,
        type=TransactionType.TRANSFER,
        amount=request.amount,
        status=TransactionStatus.PENDING,
        sender_wallet_id=sender_wallet.id,
        recipient_wallet_id=recipient_wallet.id
    )
    db.add(transaction)
    
    try:
        # Perform atomic transfer
        sender_wallet.balance -= request.amount
        recipient_wallet.balance += request.amount
        transaction.status = TransactionStatus.SUCCESS
        
        db.commit()
        
        return TransferResponse(
            status="success",
            message="Transfer completed"
        )
    except Exception as e:
        db.rollback()
        transaction.status = TransactionStatus.FAILED
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Transfer failed: {str(e)}"
        )


@router.get("/transactions", response_model=List[TransactionResponse])
async def get_transactions(
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """Get transaction history"""
    
    # Get user's wallet
    wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found"
        )
    
    # Get all transactions where user is sender or recipient
    transactions = db.query(Transaction).filter(
        (Transaction.sender_wallet_id == wallet.id) |
        (Transaction.recipient_wallet_id == wallet.id)
    ).order_by(Transaction.created_at.desc()).all()
    
    return [TransactionResponse.from_orm(t) for t in transactions]
