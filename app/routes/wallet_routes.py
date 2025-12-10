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


@router.post(
    "/deposit",
    response_model=DepositResponse,
    summary="Initialize Paystack deposit",
    description="""Initialize a deposit transaction via Paystack payment gateway. Returns a payment URL where the user completes the payment. Amount is specified in Naira (₦), automatically converted to kobo for Paystack. Webhook automatically credits wallet upon successful payment.""",
    responses={
        200: {"description": "Payment URL generated successfully"},
        400: {"description": "Invalid request or payment initialization failed"},
        401: {"description": "Invalid or missing authentication"},
        403: {"description": "API key lacks 'deposit' permission"},
        404: {"description": "Wallet not found"}
    }
)
async def deposit(
    request: DepositRequest,
    user: User = Depends(require_permission("deposit")),
    db: Session = Depends(get_db)
):
    """
    Initialize a Paystack deposit transaction for the authenticated user's wallet.
    
    Args:
        request: Deposit parameters (amount in Naira)
        user: Authenticated user (requires 'deposit' permission for API keys)
        db: Database session
    
    Returns:
        DepositResponse: Unique transaction reference and Paystack authorization URL
    
    Raises:
        HTTPException 400: Duplicate reference or Paystack initialization failed
        HTTPException 401: Invalid authentication
        HTTPException 403: Insufficient permissions
        HTTPException 404: Wallet not found
    
    Note:
        Wallet is credited automatically via webhook after successful payment.
        Do not manually credit wallet - use /deposit/{reference}/status to check status.
    """
    
    wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found"
        )
    
    reference = f"DEP_{uuid.uuid4().hex[:12].upper()}"
    
    existing_transaction = db.query(Transaction).filter(
        Transaction.reference == reference
    ).first()
    
    if existing_transaction:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Duplicate transaction reference"
        )
    
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
        transaction.status = TransactionStatus.FAILED
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to initialize payment: {str(e)}"
        )


@router.post(
    "/paystack/webhook",
    response_model=WebhookResponse,
    summary="Paystack webhook handler",
    description="""Receives and processes Paystack payment notifications. Automatically credits wallet after successful payment verification. This endpoint validates Paystack signature and ensures idempotency (no double-crediting). Public endpoint - no authentication required (signature verification provides security).""",
    responses={
        200: {"description": "Webhook processed successfully"},
        401: {"description": "Missing or invalid Paystack signature"}
    }
)
async def paystack_webhook(
    request: Request,
    x_paystack_signature: str = Header(None),
    db: Session = Depends(get_db)
):
    """
    Process Paystack webhook events and credit wallet on successful payment.
    
    Args:
        request: Raw HTTP request containing webhook payload
        x_paystack_signature: HMAC SHA-512 signature from Paystack
        db: Database session
    
    Returns:
        WebhookResponse: Success confirmation
    
    Raises:
        HTTPException 401: Missing or invalid signature
    
    Note:
        This endpoint implements idempotency - duplicate webhooks are safely ignored.
        Only charge.success events result in wallet credits.
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
    
    import json
    data = json.loads(body.decode('utf-8'))
    event = data.get("event")
    
    if event == "charge.success":
        event_data = data.get("data", {})
        reference = event_data.get("reference")
        amount = event_data.get("amount", 0) / 100
        paystack_status = event_data.get("status")
        
        if not reference:
            return WebhookResponse(status=True)
        
        transaction = db.query(Transaction).filter(
            Transaction.reference == reference
        ).first()
        
        if not transaction:
            return WebhookResponse(status=True)
        
        if transaction.status == TransactionStatus.SUCCESS:
            return WebhookResponse(status=True)
        
        if paystack_status == "success":
            transaction.status = TransactionStatus.SUCCESS
            
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


@router.get(
    "/deposit/{reference}/status",
    response_model=DepositStatusResponse,
    summary="Check deposit status",
    description="""Query the status of a deposit transaction by reference. Returns current transaction status (PENDING, SUCCESS, FAILED). Does NOT credit wallet - only webhook credits wallet automatically.""",
    responses={
        200: {"description": "Transaction status retrieved"},
        401: {"description": "Invalid or missing authentication"},
        403: {"description": "Transaction belongs to different user or insufficient permissions"},
        404: {"description": "Transaction not found"}
    }
)
async def get_deposit_status(
    reference: str,
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """
    Retrieve deposit transaction status by reference code.
    
    Args:
        reference: Transaction reference (format: DEP_XXXXXXXXXXXX)
        user: Authenticated user (requires 'read' permission for API keys)
        db: Database session
    
    Returns:
        DepositStatusResponse: Transaction reference, status, and amount
    
    Raises:
        HTTPException 401: Invalid authentication
        HTTPException 403: Unauthorized access to transaction
        HTTPException 404: Transaction not found
    
    Note:
        This is a read-only endpoint. Wallet crediting happens automatically via webhook.
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


@router.get(
    "/balance",
    response_model=BalanceResponse,
    summary="Get wallet balance",
    description="""Retrieve current wallet balance and wallet number. Balance is in Naira (₦). Wallet number is the unique 10-digit identifier for receiving transfers.""",
    responses={
        200: {"description": "Balance and wallet number retrieved"},
        401: {"description": "Invalid or missing authentication"},
        403: {"description": "API key lacks 'read' permission"},
        404: {"description": "Wallet not found"}
    }
)
async def get_balance(
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """
    Get authenticated user's wallet balance and wallet number.
    
    Args:
        user: Authenticated user (requires 'read' permission for API keys)
        db: Database session
    
    Returns:
        BalanceResponse: Current balance (Naira) and 10-digit wallet number
    
    Raises:
        HTTPException 401: Invalid authentication
        HTTPException 403: Insufficient permissions
        HTTPException 404: Wallet not found
    """
    
    wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found"
        )
    
    return BalanceResponse(
        balance=wallet.balance,
        wallet_number=wallet.wallet_number
    )


@router.post(
    "/transfer",
    response_model=TransferResponse,
    summary="Transfer funds to another wallet",
    description="""Send money from your wallet to another user's wallet using their 10-digit wallet number. Transfer is atomic (either completes fully or fails completely). Amount specified in Naira (₦).""",
    responses={
        200: {"description": "Transfer completed successfully"},
        400: {"description": "Insufficient balance, invalid recipient, or self-transfer attempted"},
        401: {"description": "Invalid or missing authentication"},
        403: {"description": "API key lacks 'transfer' permission"},
        404: {"description": "Sender or recipient wallet not found"},
        500: {"description": "Transfer failed due to system error"}
    }
)
async def transfer(
    request: TransferRequest,
    user: User = Depends(require_permission("transfer")),
    db: Session = Depends(get_db)
):
    """
    Transfer funds atomically from authenticated user's wallet to recipient wallet.
    
    Args:
        request: Transfer parameters (recipient wallet number, amount in Naira)
        user: Authenticated user (requires 'transfer' permission for API keys)
        db: Database session
    
    Returns:
        TransferResponse: Success status and confirmation message
    
    Raises:
        HTTPException 400: Insufficient balance, self-transfer, or invalid recipient
        HTTPException 401: Invalid authentication
        HTTPException 403: Insufficient permissions
        HTTPException 404: Wallet not found
        HTTPException 500: Database or system error (rollback performed)
    
    Note:
        Transfer is atomic - both wallets are updated or neither is modified.
        Transaction record is created for audit trail regardless of outcome.
    """
    
    sender_wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    if not sender_wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found"
        )
    
    if sender_wallet.balance < request.amount:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Insufficient balance"
        )
    
    recipient_wallet = db.query(Wallet).filter(
        Wallet.wallet_number == request.wallet_number
    ).first()
    
    if not recipient_wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient wallet not found"
        )
    
    if sender_wallet.id == recipient_wallet.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot transfer to your own wallet"
        )
    
    reference = f"TRF_{uuid.uuid4().hex[:12].upper()}"
    
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


@router.get(
    "/transactions",
    response_model=List[TransactionResponse],
    summary="Get transaction history",
    description="""Retrieve complete transaction history for authenticated user's wallet. Includes deposits, transfers (sent and received), with status and timestamps. Results sorted by date (newest first).""",
    responses={
        200: {"description": "List of transactions retrieved"},
        401: {"description": "Invalid or missing authentication"},
        403: {"description": "API key lacks 'read' permission"},
        404: {"description": "Wallet not found"}
    }
)
async def get_transactions(
    user: User = Depends(require_permission("read")),
    db: Session = Depends(get_db)
):
    """
    Retrieve all transactions for authenticated user's wallet.
    
    Args:
        user: Authenticated user (requires 'read' permission for API keys)
        db: Database session
    
    Returns:
        List[TransactionResponse]: All transactions (deposits and transfers) sorted by date
    
    Raises:
        HTTPException 401: Invalid authentication
        HTTPException 403: Insufficient permissions
        HTTPException 404: Wallet not found
    
    Note:
        Includes both incoming and outgoing transactions.
        Use sender_wallet_id and recipient_wallet_id to determine transaction direction.
    """
    
    wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found"
        )
    
    transactions = db.query(Transaction).filter(
        (Transaction.sender_wallet_id == wallet.id) |
        (Transaction.recipient_wallet_id == wallet.id)
    ).order_by(Transaction.created_at.desc()).all()
    
    return [TransactionResponse.from_orm(t) for t in transactions]
