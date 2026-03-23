# fwd-proxy

Simple HTTP forward proxy in Go with basic SSRF protections.

## Features

- Accepts incoming HTTP requests and forwards them to a target URL.
- Supports methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`.
- Reads target from query parameter `url` or header `X-Target-URL`.
- Blocks localhost, private, link-local, multicast, and other reserved IP ranges.
- Rejects unsupported methods and hop-by-hop headers.
- Adds/extends `X-Forwarded-For`.

## Requirements

- Go `1.26.1` or newer (as declared in `go.mod`).

## Run

```bash
go run .
```

The server listens on `:8080`.

## Usage

Send a request to the proxy and provide the destination URL:

```bash
curl "http://localhost:8080/?url=https://httpbin.org/get"
```

You can also pass the target in a header:

```bash
curl -H "X-Target-URL: https://httpbin.org/anything" "http://localhost:8080/"
```

Forward a JSON `POST` body:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Target-URL: https://httpbin.org/post" \
  -d '{"hello":"world"}' \
  "http://localhost:8080/"
```

## Response behavior

- Upstream response status code is preserved.
- Upstream response body is streamed back to the client.
- Hop-by-hop headers are stripped from both request and response.

## Security notes

- Only `http` and `https` target schemes are allowed.
- Target URLs with userinfo (`user:pass@host`) are rejected.
- `localhost` and `.localhost` hosts are blocked.
- Direct IP targets are validated against blocked ranges.
- DNS-resolved IPs are validated before dialing.
- Maximum incoming request body size is `10 MiB`.

These checks help reduce SSRF risk but do not replace network-level egress controls.

## Configuration

Current configuration is defined in constants in `main.go`:

- `listenAddr` (default `:8080`)
- `maxRequestBody` (default `10 MiB`)
- `upstreamTimeout` (default `30s`)

## Development

```bash
go test ./...
```

No tests are currently included.
