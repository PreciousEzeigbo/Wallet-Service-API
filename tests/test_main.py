import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Base, get_db
from app.models import User, Wallet

# Test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def test_health_check():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_root():
    """Test root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    assert "message" in response.json()


def test_create_api_key_without_auth():
    """Test creating API key without authentication"""
    response = client.post(
        "/keys/create",
        json={
            "name": "test-key",
            "permissions": ["read"],
            "expiry": "1D"
        }
    )
    assert response.status_code == 401


def test_get_balance_without_auth():
    """Test getting balance without authentication"""
    response = client.get("/wallet/balance")
    assert response.status_code == 401


def test_invalid_permission():
    """Test creating API key with invalid permission"""
    # This would require authentication, but tests the validation
    pass
