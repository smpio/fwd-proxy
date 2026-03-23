# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder
WORKDIR /src

RUN apk add --no-cache ca-certificates

# Copy only what we need for a cached Go module build.
COPY go.mod ./
COPY main.go ./

RUN go mod download

RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o /out/fwd-proxy .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
  && addgroup -S app \
  && adduser -S app -G app

WORKDIR /app
COPY --from=builder /out/fwd-proxy /app/fwd-proxy
USER app

EXPOSE 8080
ENTRYPOINT ["/app/fwd-proxy"]
