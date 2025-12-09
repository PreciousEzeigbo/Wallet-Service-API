# Wallet Service API

A comprehensive wallet service with Paystack integration, JWT authentication, and API key management.

## Features

- Google OAuth authentication with JWT
- Wallet creation and management
- Paystack deposit integration with webhook handling
- Wallet-to-wallet transfers
- Transaction history
- API key system for service-to-service access
- Permission-based API key access
- API key expiration and rollover

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create a `.env` file based on `.env.example` and fill in your credentials.

3. Run database migrations:
```bash
alembic upgrade head
```

4. Start the server:
```bash
uvicorn app.main:app --reload
```

## API Documentation

Once the server is running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: Secret key for JWT signing
- `GOOGLE_CLIENT_ID`: Google OAuth client ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
- `PAYSTACK_SECRET_KEY`: Paystack secret key
- `PAYSTACK_WEBHOOK_SECRET`: Paystack webhook secret

## API Endpoints

### Authentication
- `GET /auth/google` - Initiate Google sign-in
- `GET /auth/google/callback` - Google OAuth callback

### API Keys
- `POST /keys/create` - Create a new API key
- `POST /keys/rollover` - Rollover an expired API key

### Wallet Operations
- `POST /wallet/deposit` - Initialize a deposit
- `POST /wallet/paystack/webhook` - Paystack webhook handler
- `GET /wallet/deposit/{reference}/status` - Check deposit status
- `GET /wallet/balance` - Get wallet balance
- `POST /wallet/transfer` - Transfer funds to another wallet
- `GET /wallet/transactions` - Get transaction history

## Authentication

The API supports two authentication methods:

1. **JWT Token**: Use `Authorization: Bearer <token>` header
2. **API Key**: Use `x-api-key: <key>` header

## API Key Permissions

- `deposit`: Allow deposit operations
- `transfer`: Allow transfer operations
- `read`: Allow reading wallet data

## API Key Expiry

Valid expiry formats:
- `1H` - 1 hour
- `1D` - 1 day
- `1M` - 1 month
- `1Y` - 1 year
