from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Enum as SQLEnum, Boolean, ARRAY
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.database import Base
import secrets
import uuid


class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    google_id = Column(String, unique=True, index=True)
    name = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    wallet = relationship("Wallet", back_populates="user", uselist=False)
    api_keys = relationship("APIKey", back_populates="user")


class Wallet(Base):
    __tablename__ = "wallets"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), unique=True, nullable=False)
    wallet_number = Column(String, unique=True, index=True, nullable=False)
    balance = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="wallet")
    transactions_sent = relationship("Transaction", foreign_keys="Transaction.sender_wallet_id", back_populates="sender_wallet")
    transactions_received = relationship("Transaction", foreign_keys="Transaction.recipient_wallet_id", back_populates="recipient_wallet")


class TransactionType(str, enum.Enum):
    DEPOSIT = "deposit"
    TRANSFER = "transfer"


class TransactionStatus(str, enum.Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"


class Transaction(Base):
    __tablename__ = "transactions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    reference = Column(String, unique=True, index=True, nullable=False)
    type = Column(SQLEnum(TransactionType), nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(SQLEnum(TransactionStatus), default=TransactionStatus.PENDING)
    sender_wallet_id = Column(String, ForeignKey("wallets.id"), nullable=True)
    recipient_wallet_id = Column(String, ForeignKey("wallets.id"), nullable=True)
    metadata = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    sender_wallet = relationship("Wallet", foreign_keys=[sender_wallet_id], back_populates="transactions_sent")
    recipient_wallet = relationship("Wallet", foreign_keys=[recipient_wallet_id], back_populates="transactions_received")


class APIKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    key = Column(String, unique=True, index=True, nullable=False)
    permissions = Column(ARRAY(String), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    @staticmethod
    def generate_key():
        return f"sk_live_{secrets.token_urlsafe(32)}"
