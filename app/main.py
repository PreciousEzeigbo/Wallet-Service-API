from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.routes import auth_routes, keys_routes, wallet_routes
from app.config import get_settings

settings = get_settings()

app = FastAPI(
    title="Wallet Service API",
    description="A comprehensive wallet service with Paystack integration, JWT authentication, and API key management",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)}
    )


# Include routers
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
