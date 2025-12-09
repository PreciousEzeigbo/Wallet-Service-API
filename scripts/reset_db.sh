#!/bin/bash

# Database reset script (for development only)
echo "WARNING: This will reset your database!"
read -p "Are you sure? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

# Drop all tables
echo "Dropping all tables..."
alembic downgrade base

# Run migrations
echo "Running migrations..."
alembic upgrade head

echo "Database reset complete!"
