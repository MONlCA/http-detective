# HTTP Detective 🔎

A small, dependency-free Python CLI for investigating what happens when you make an HTTP request.

Give it a URL and HTTP Detective reports the response status, latency, redirects, content metadata, server header, and a basic security-header checklist.

## Features

- HTTP status and reason
- Request latency
- Redirect chain tracing
- HTTP protocol version
- Content type and content length
- Server header inspection
- Basic security-header checks
- Optional full response-header output
- JSON output for scripts and automation
- Sensible exit codes for failed requests
- No third-party dependencies

## Quick start

Python 3.9+ recommended.

```bash
python3 http_detective.py https://example.com
```

You can also omit the scheme:

```bash
python3 http_detective.py example.com
```

## Options

Show every response header:

```bash
python3 http_detective.py https://example.com --headers
```

Return JSON:

```bash
python3 http_detective.py https://example.com --json
```

Change the timeout:

```bash
python3 http_detective.py https://example.com --timeout 3
```

## Security header checks

HTTP Detective checks whether these response headers are present:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`

This is a quick diagnostic checklist, not a full security audit. Whether a header is appropriate depends on the application and how it is deployed.

## Tests

```bash
python3 -m unittest -v
```

## Why this exists

HTTP problems can hide behind redirects, status codes, latency, proxy behavior, or unexpected headers. HTTP Detective puts several of those first-line troubleshooting signals into one terminal command.

## Roadmap

- DNS resolution details
- TLS certificate information
- Request methods other than GET
- Custom request headers
- Response body preview
- Timing breakdowns
- Compare two endpoints

## License

MIT
