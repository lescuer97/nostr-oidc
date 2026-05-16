# Set templ version, defaulting to v0.3.1020 if not provided
ARG TEMPL_VERSION=v0.3.1020

# https://templ.guide/quick-start/installation#docker
FROM ghcr.io/a-h/templ:${TEMPL_VERSION} AS generate-templ
#USER root
COPY --chown=65532:65532 . /app
WORKDIR /app
RUN ["templ", "generate"]

# https://pnpm.io/docker#example-3-build-on-cicd
FROM node:24-slim AS generate-static-files
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

WORKDIR /app
COPY --from=generate-templ /app/web/static/package.json /app/web/static/pnpm-lock.yaml /app/web/static/
RUN cd web/static && \
    pnpm install --frozen-lockfile
#COPY --from=generate-templ --chown=0:0 /app .
COPY --from=generate-templ /app .
RUN cd web/static && \
    pnpm run build && \
    pnpm run build:tailwind


FROM golang:1.26-alpine AS builder
ARG TEMPL_VERSION
WORKDIR /app
RUN apk add --no-cache git gcc musl-dev sqlite-dev libsecret-dev
# Copy dependency files first for better caching
COPY --from=generate-static-files /app/go.* .
RUN go mod download
RUN go get github.com/a-h/templ@${TEMPL_VERSION}
# used `/app/.` to not delete `go.sum` created by `go mod download`
COPY --from=generate-static-files /app/. ./
RUN CGO_ENABLED=1 go mod tidy && \
    CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o nostr-oidc .


FROM alpine:latest
WORKDIR /app
RUN apk --no-cache add ca-certificates sqlite-libs dbus dbus-x11 libsecret gnome-keyring
COPY --from=builder /app/nostr-oidc .
COPY --from=builder /app/storage/database/migrations ./storage/database/migrations
COPY --from=builder /app/container-entrypoint.sh /container-entrypoint.sh
RUN chmod +x /container-entrypoint.sh
RUN mkdir -p /var/run/dbus
EXPOSE 8082
ENTRYPOINT ["/container-entrypoint.sh"]
