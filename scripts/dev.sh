#!/bin/bash

# Development startup script
echo "Starting Wallet Service in Development Mode..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "Error: .env file not found!"
    echo "Please copy .env.example to .env and configure it."
    exit 1
fi

# Install/update dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Run migrations
echo "Running database migrations..."
alembic upgrade head

# Start server
echo "Starting server on http://localhost:8000"
echo "API docs available at http://localhost:8000/docs"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
