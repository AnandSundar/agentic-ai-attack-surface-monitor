# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install certificates for HTTPS
RUN apk --no-cache add ca-certificates tzdata

# Create data directory
RUN mkdir -p /app/data

# Copy binary from builder
COPY --from=builder /app/server /app/server

# Copy data directory for SQLite
COPY --from=builder /app/data /app/data

# Expose port
EXPOSE 8080

# Environment variables
ENV PORT=8080
ENV DATA_DIR=/app/data

# Run the server
CMD ["/app/server"]
