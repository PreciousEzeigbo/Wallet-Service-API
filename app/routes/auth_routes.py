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


@router.get(
    "/google",
    summary="Initiate Google OAuth login",
    description="""Start Google OAuth authentication flow to obtain JWT token. 
    
    **IMPORTANT - How to use:**
    1. Copy this endpoint URL: `https://pez.name.ng/auth/google`
    2. Paste it in a NEW browser tab (NOT in Swagger/Postman)
    3. Complete Google sign-in
    4. You'll receive JWT token as JSON response
    5. Use the `access_token` in Authorization header: `Bearer <token>`
    
    **Why not use Swagger UI?**
    OAuth requires browser redirects and cookies which Swagger cannot handle properly.
    
    **First-time users:**
    Automatically creates wallet with unique 10-digit wallet number.
    """,
    responses={
        302: {"description": "Redirect to Google OAuth consent screen"}
    }
)
async def google_login(request: Request):
    """
    Initiate Google OAuth flow to obtain JWT access token.
    
    Args:
        request: HTTP request object
    
    Returns:
        RedirectResponse: Redirects to Google OAuth consent screen
    
    Note:
        Must be accessed via browser, not API testing tools.
    """
    redirect_uri = settings.google_redirect_uri
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get(
    "/google/callback",
    summary="Google OAuth callback",
    description="""Handle Google OAuth callback and return JWT token. This endpoint is automatically called by Google after successful authentication. Returns JWT token as JSON (no frontend redirect).""",
    responses={
        200: {"description": "JWT token and user information"},
        400: {"description": "OAuth failed or state mismatch"}
    }
)
async def google_callback(request: Request, db: Session = Depends(get_db)):
    """
    Process Google OAuth callback and return JWT token with user details.
    
    Args:
        request: HTTP request with OAuth authorization code
        db: Database session
    
    Returns:
        dict: JWT access token, token type, and user information
    
    Raises:
        HTTPException 400: OAuth validation failed or missing user info
    
    Note:
        Creates new user and wallet if first-time login.
    """
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        
        if not user_info:
            raise HTTPException(status_code=400, detail="Failed to get user info from Google")
        
        user = db.query(User).filter(User.email == user_info['email']).first()
        
        if not user:
            user = User(
                email=user_info['email'],
                google_id=user_info['sub'],
                name=user_info.get('name')
            )
            db.add(user)
            db.flush()
            
            wallet_number = generate_wallet_number()
            wallet = Wallet(
                user_id=user.id,
                wallet_number=wallet_number
            )
            db.add(wallet)
            db.commit()
            db.refresh(user)
        
        access_token = create_access_token(
            data={"sub": user.id, "email": user.email}
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name
            }
        }
        
    except Exception as e:
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


@router.post(
    "/login",
    summary="Email-based login (development/testing)",
    description="""Quick authentication endpoint for development and testing without Google OAuth. Provide any email address to instantly receive a JWT token. Creates new user and wallet if email doesn't exist, or logs in existing user.
    
    **Use cases:**
    - Local development and testing
    - Automated testing and CI/CD pipelines
    - Quick API exploration without OAuth setup
    
    **Production note:**
    Disable this endpoint in production environments. Use Google OAuth (`/auth/google`) for production authentication.
    """,
    responses={
        200: {"description": "JWT token, user details, and wallet number"}
    }
)
async def login(email: str, db: Session = Depends(get_db)):
    """
    Authenticate or create user with email, returning JWT token immediately.
    
    Args:
        email: User email address (any valid email format)
        db: Database session
    
    Returns:
        dict: JWT access token, user information, and wallet number
    
    Note:
        Automatically creates user and wallet for new email addresses.
        For testing/development only - not recommended for production.
    """
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        user = User(
            email=email,
            google_id=f"test_{secrets.token_hex(8)}",
            name=email.split('@')[0]
        )
        db.add(user)
        db.flush()
        
        wallet_number = generate_wallet_number()
        wallet = Wallet(
            user_id=user.id,
            wallet_number=wallet_number,
            balance=0
        )
        db.add(wallet)
        db.commit()
        db.refresh(user)
    
    wallet = db.query(Wallet).filter(Wallet.user_id == user.id).first()
    
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
