#!/bin/bash
set -e

echo "🚀 Starting local deployment..."

# Check if required tools are installed
command -v go >/dev/null 2>&1 || { echo "❌ Go is not installed. Please install Go first."; exit 1; }
command -v pnpm >/dev/null 2>&1 || { echo "❌ pnpm is not installed. Installing..."; npm install -g pnpm; }

# Install templ if not already installed
if ! command -v templ >/dev/null 2>&1; then
    echo "📦 Installing templ..."
    go install github.com/a-h/templ/cmd/templ@latest
fi

# Download Go dependencies
echo "📦 Downloading Go dependencies..."
go mod download

# Generate templ files
echo "🔨 Generating templ files..."
templ generate

# Build frontend assets
echo "🎨 Building frontend assets..."
cd web/static
pnpm install
pnpm run build
pnpm run build:tailwind
cd ../..

# Build the application
echo "🔨 Building application..."
CGO_ENABLED=1 go build -o dist/nostr-oidc .

echo "✅ Build complete!"
echo ""
echo "To run the application:"
echo "  dist/nostr-oidc"
echo ""
echo "Make sure you have:"
echo "  - A .env file configured (copy from .env.example)"
echo "  - gnome-keyring running (for secret storage)"
