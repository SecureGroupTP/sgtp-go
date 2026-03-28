# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build relay server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/sgtp-server ./cmd/server

# Build web bridge
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/sgtp-webbridge ./cmd/webbridge

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /out/sgtp-server      ./sgtp-server
COPY --from=builder /out/sgtp-webbridge   ./sgtp-webbridge
COPY web/                                 ./web/

# Optional: mount /data/whitelist at runtime to add server-side trusted keys
VOLUME ["/data/whitelist"]

EXPOSE 77 5735
