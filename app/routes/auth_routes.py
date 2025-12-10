from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from datetime import timedelta
import secrets

from app.database import get_db
from app.models import User, Wallet
from app.schemas import GoogleAuthResponse
from app.utils import create_access_token
from app.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["Authentication"])

# OAuth setup
config = Config(environ={
    "GOOGLE_CLIENT_ID": settings.google_client_id,
    "GOOGLE_CLIENT_SECRET": settings.google_client_secret,
})

oauth = OAuth(config)
oauth.register(
    name='google',
    client_id=settings.google_client_id,
    client_secret=settings.google_client_secret,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)


@router.get("/google")
async def google_login(request: Request):
    """Initiate Google OAuth flow"""
    redirect_uri = settings.google_redirect_uri
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    """Handle Google OAuth callback"""
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        
        if not user_info:
            raise HTTPException(status_code=400, detail="Failed to get user info from Google")
        
        # Check if user exists
        user = db.query(User).filter(User.email == user_info['email']).first()
        
        if not user:
            # Create new user
            user = User(
                email=user_info['email'],
                google_id=user_info['sub'],
                name=user_info.get('name')
            )
            db.add(user)
            db.flush()
            
            # Create wallet for new user
            wallet_number = generate_wallet_number()
            wallet = Wallet(
                user_id=user.id,
                wallet_number=wallet_number
            )
            db.add(wallet)
            db.commit()
            db.refresh(user)
        
        # Create JWT token
        access_token = create_access_token(
            data={"sub": user.id, "email": user.email}
        )
        
        # Check if request wants JSON response (for testing)
        if request.query_params.get('format') == 'json':
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "name": user.name
                }
            }
        
        # Redirect to frontend with token
        frontend_url = f"{settings.frontend_url}?token={access_token}"
        return RedirectResponse(url=frontend_url)
        
    except Exception as e:
        # More detailed error handling
        error_detail = str(e)
        if "mismatching_state" in error_detail:
            raise HTTPException(
                status_code=400, 
                detail="OAuth state mismatch. Please try again by visiting /auth/google directly in your browser (not through API docs)."
            )
        raise HTTPException(status_code=400, detail=f"Authentication failed: {error_detail}")


def generate_wallet_number() -> str:
    """Generate a unique 10-digit wallet number"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(10)])


@router.post("/test-login")
async def test_login(email: str, db: Session = Depends(get_db)):
    """
    Test endpoint to create/login a user without Google OAuth.
    Only for development/testing purposes.
    """
    # Check if user exists
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        # Create new user
        user = User(
            email=email,
            google_id=f"test_{secrets.token_hex(8)}",
            name=email.split('@')[0]
        )
        db.add(user)
        db.flush()
        
        # Create wallet for new user
        wallet_number = generate_wallet_number()
        wallet = Wallet(
            user_id=user.id,
            wallet_number=wallet_number,
            balance=0.0
        )
        db.add(wallet)
        db.commit()
        db.refresh(user)
    
    # Get wallet info
    wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    
    # Create JWT token
    access_token = create_access_token(
        data={"sub": user.id, "email": user.email}
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "wallet_number": wallet.wallet_number if wallet else None
        }
    }
