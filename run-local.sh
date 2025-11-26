#!/bin/bash
set -e

# Check if binary exists, if not run build
if [ ! -f "dist/nostr-oidc" ]; then
    echo "❌ Binary not found. Running build first..."
    ./build-local.sh
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Copying from .env.example..."
    cp .env.example .env
    echo "✅ Created .env file. Please edit it with your configuration."
    echo ""
fi

# Check if gnome-keyring is running (optional, won't fail if not)
if ! pgrep -x "gnome-keyring-d" > /dev/null; then
    echo "⚠️  gnome-keyring doesn't appear to be running."
    echo "   Secret storage may not work properly."
    echo ""
fi

echo "🚀 Starting nostr-oidc..."
echo ""
dist/nostr-oidc