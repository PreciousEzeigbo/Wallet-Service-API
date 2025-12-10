from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from starlette.middleware.sessions import SessionMiddleware
from app.routes import auth_routes, keys_routes, wallet_routes
from app.config import get_settings

settings = get_settings()

app = FastAPI(
    title="Wallet Service API",
    description="""
# Wallet Service API

A production-ready wallet service with Paystack payment integration, OAuth authentication, and granular API key permissions.


### Step 1: Get Your JWT Token (First Time Setup)

**Option A: Google OAuth (Recommended)**
1. Copy this URL: `https://pez.name.ng/auth/google`
2. Paste it in a new browser tab (NOT in Swagger UI)
3. Complete Google sign-in
4. You'll receive a JSON response with your `access_token`
5. Copy the token value

**Option B: Quick Login (Testing)**
- Use `/auth/login` endpoint with your email
- Get instant JWT token

### Step 2: Authorize in Swagger
1. Click the green "Authorize" button at the top
2. In the "bearerAuth" field, paste your JWT token (without "Bearer " prefix)
3. Leave "apiKeyAuth" empty for now
4. Click "Authorize" then "Close"

### Step 3: Create API Keys (Optional)
- Now you can use `/keys/create` to generate API keys with specific permissions

### JWT Bearer Token
- Full access to everything
- Manage API keys, perform all wallet operations
- Required for: `/keys/*` endpoints

### API Key
- Limited permissions: `deposit`, `transfer`, `read`
- Cannot create or manage other keys (security)
- Optional for: `/wallet/*` endpoints (you can use JWT instead)

## Amounts

All amounts in requests/responses are in **Naira (₦)**. System automatically converts to kobo for Paystack.
    """,
    version="1.0.0",
    openapi_tags=[
        {
            "name": "Authentication",
            "description": "Google OAuth and test authentication endpoints"
        },
        {
            "name": "API Keys",
            "description": "Manage API keys with granular permissions (requires JWT authentication only)"
        },
        {
            "name": "Wallet",
            "description": "Wallet operations including deposits, transfers, and balance management (supports both JWT and API key auth)"
        }
    ]
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    max_age=3600,
    same_site="lax",
    https_only=False
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)}
    )


app.include_router(auth_routes.router)
app.include_router(keys_routes.router)
app.include_router(wallet_routes.router)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags
    )
    
    openapi_schema["components"]["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "**JWT Token (Required for /keys/* endpoints)**\n\nGet your token from `/auth/google` or `/auth/login`, then paste it here (without 'Bearer ' prefix)."
        },
        "apiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "x-api-key",
            "description": "**Optional for /wallet/* endpoints** (you can use JWT instead)\n\nCreate API keys via `/keys/create` after authenticating with JWT. Leave empty unless you created an API key."
        }
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


@app.get("/")
async def root():
    return {
        "message": "Wallet Service API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
