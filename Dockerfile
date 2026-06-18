# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /cerberus-lint ./cmd/cerberus-lint

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /cerberus-lint .

# Copy config example
COPY --from=builder /app/config.yaml .

# Add non-root user
RUN adduser -D -g '' cerberus
USER cerberus

ENTRYPOINT ["./cerberus-lint"]
CMD ["--help"]