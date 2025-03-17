ARG PLATFORM=linux/arm64
# --------------------------------------------------
# 1) BUILD STAGE
FROM --platform=$PLATFORM golang:1.24 AS builder
ENV CGO_ENABLED=0
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go .
RUN go build -o tls-proxy

# --------------------------------------------------
# 2) RUNTIME STAGE
# --------------------------------------------------
FROM --platform=$PLATFORM alpine:3.21 AS runner
RUN adduser -D appuser
USER appuser
WORKDIR /app
COPY --from=builder /app/tls-proxy /app/tls-proxy
EXPOSE 8080
ENTRYPOINT ["/app/tls-proxy"]