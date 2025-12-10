from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, APIKeyHeader
from starlette.middleware.sessions import SessionMiddleware
from app.routes import auth_routes, keys_routes, wallet_routes
from app.config import get_settings

settings = get_settings()

security_schemes = {
    "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "JWT token obtained from Google OAuth login or test-login endpoint. Use for all operations including API key management."
    },
    "apiKeyAuth": {
        "type": "apiKey",
        "in": "header",
        "name": "x-api-key",
        "description": "API key for wallet operations with granular permissions (deposit, transfer, read). Cannot be used for key management endpoints."
    }
}

app = FastAPI(
    title="Wallet Service API",
    description="""
# Wallet Service API

A production-ready wallet service with Paystack payment integration, OAuth authentication, and granular API key permissions.

## Authentication

This API supports two authentication methods:

### 1. JWT Bearer Token (Required for Key Management)
- Obtain via Google OAuth (`/auth/google`) or test login (`/auth/test-login`)
- Full access to all endpoints including API key creation and management
- Use for: Creating, listing, revoking, and rolling over API keys

### 2. API Key (For Wallet Operations Only)
- Create via `/keys/create` endpoint using JWT auth
- Supports granular permissions: `deposit`, `transfer`, `read`
- Cannot be used to manage API keys (prevents privilege escalation)
- Pass in `x-api-key` header

## Paystack Integration

All monetary amounts are handled in **Naira** (₦) in API requests/responses. The system automatically converts to kobo (smallest unit) for Paystack transactions.

## Workflow

1. Authenticate via `/auth/google` to get JWT token
2. Create API keys with specific permissions via `/keys/create`
3. Use API keys for wallet operations (deposits, transfers, balance checks)
4. Paystack webhooks automatically credit wallets on successful payments
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

app.openapi_schema = None

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = app.openapi()
    openapi_schema["components"]["securitySchemes"] = security_schemes
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

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
