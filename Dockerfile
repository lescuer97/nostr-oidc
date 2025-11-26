# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev sqlite-dev nodejs npm

WORKDIR /app

# Copy source code
COPY . .

# Download dependencies
RUN go mod download

# Install templ CLI
RUN go install github.com/a-h/templ/cmd/templ@latest

# Generate templ files
RUN templ generate

# Install pnpm and build static assets
RUN npm install -g pnpm@10.21.0 && \
    cd web/static && \
    pnpm install && \
    pnpm run build && \
    pnpm run build:tailwind && \
    cd ../..

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o nostr-oidc .

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates sqlite-libs dbus dbus-x11 libsecret gnome-keyring

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/nostr-oidc .

# Copy migration files
COPY --from=builder /app/storage/database/migrations ./storage/database/migrations

# Copy entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Create dbus directory
RUN mkdir -p /var/run/dbus

# Expose port
EXPOSE 8082

# Use entrypoint script
ENTRYPOINT ["/docker-entrypoint.sh"]
