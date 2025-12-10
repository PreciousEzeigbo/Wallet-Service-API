from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
import bcrypt
from app.config import get_settings

settings = get_settings()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt


def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError:
        return None


def parse_expiry(expiry: str) -> datetime:
    """Parse expiry string (1H, 1D, 1M, 1Y) into datetime"""
    now = datetime.utcnow()
    
    if expiry == "1H":
        return now + timedelta(hours=1)
    elif expiry == "1D":
        return now + timedelta(days=1)
    elif expiry == "1M":
        return now + timedelta(days=30)
    elif expiry == "1Y":
        return now + timedelta(days=365)
    else:
        raise ValueError(f"Invalid expiry format: {expiry}")


def hash_api_key(api_key: str) -> str:
    """Hash an API key for secure storage using bcrypt (automatically truncates to 72 bytes)"""
    # Bcrypt has a 72 byte limit, so truncate the key to 72 bytes
    api_key_bytes = api_key.encode('utf-8')[:72]
    # Generate salt and hash
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(api_key_bytes, salt)
    return hashed.decode('utf-8')


def verify_api_key(plain_key: str, hashed_key: str) -> bool:
    """Verify an API key against its hash using bcrypt (automatically truncates to 72 bytes)"""
    # Truncate the plain key to 72 bytes to match how it was hashed
    plain_key_bytes = plain_key.encode('utf-8')[:72]
    hashed_key_bytes = hashed_key.encode('utf-8')
    return bcrypt.checkpw(plain_key_bytes, hashed_key_bytes)
