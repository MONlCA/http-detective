#!/usr/bin/env python3
"""HTTP Detective: inspect redirects, headers, latency, and basic security headers."""

import argparse
import http.client
import json
import time
import urllib.error
import urllib.request

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


class RedirectRecorder(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.redirects = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirects.append({"from": req.full_url, "status": code, "to": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def human_size(value):
    if value is None:
        return "unknown"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def inspect_url(url, timeout=5.0):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    recorder = RedirectRecorder()
    opener = urllib.request.build_opener(recorder)
    request = urllib.request.Request(url, headers={"User-Agent": "http-detective/1.0"})
    start = time.perf_counter()

    try:
        with opener.open(request, timeout=timeout) as response:
            latency_ms = round((time.perf_counter() - start) * 1000)
            headers = dict(response.headers.items())
            status = response.status
            reason = response.reason
            final_url = response.geturl()
            version = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(response.version, f"HTTP/{response.version}")
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.perf_counter() - start) * 1000)
        headers = dict(exc.headers.items())
        status = exc.code
        reason = exc.reason
        final_url = exc.geturl()
        version = "unknown"
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return {"url": url, "error": str(reason)}

    header_lookup = {key.lower(): value for key, value in headers.items()}
    security = {name: name.lower() in header_lookup for name in SECURITY_HEADERS}

    return {
        "url": url,
        "final_url": final_url,
        "status": status,
        "reason": str(reason),
        "latency_ms": latency_ms,
        "protocol": version,
        "content_type": header_lookup.get("content-type", "unknown"),
        "server": header_lookup.get("server", "not disclosed"),
        "content_length": header_lookup.get("content-length"),
        "redirects": recorder.redirects,
        "security_headers": security,
        "headers": headers,
    }


def print_report(result, show_headers=False):
    if "error" in result:
        print(f"\nHTTP DETECTIVE\n{'─' * 58}\n✗ Request failed: {result['error']}\n")
        return

    print("\nHTTP DETECTIVE")
    print("─" * 58)
    print(f"URL          {result['final_url']}")
    print(f"Status       {result['status']} {result['reason']}")
    print(f"Latency      {result['latency_ms']} ms")
    print(f"Protocol     {result['protocol']}")
    print(f"Content-Type {result['content_type']}")
    print(f"Server       {result['server']}")
    print(f"Size         {human_size(result['content_length'])}")

    print("\nREDIRECTS")
    print("─" * 58)
    if result["redirects"]:
        for item in result["redirects"]:
            print(item["from"])
            print(f"  ↓ {item['status']}")
        print(result["final_url"])
    else:
        print("No redirects.")

    print("\nSECURITY HEADERS")
    print("─" * 58)
    for name, present in result["security_headers"].items():
        print(f"{'✓' if present else '✗'} {name}")

    missing = sum(not present for present in result["security_headers"].values())
    verdict = "All checked security headers present" if missing == 0 else f"{missing} checked security header(s) missing"
    print(f"\nVerdict: {verdict}")

    if show_headers:
        print("\nRESPONSE HEADERS")
        print("─" * 58)
        for key, value in sorted(result["headers"].items()):
            print(f"{key}: {value}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Inspect an HTTP endpoint from the terminal.")
    parser.add_argument("url", help="URL or hostname to inspect")
    parser.add_argument("--timeout", type=float, default=5.0, help="request timeout in seconds")
    parser.add_argument("--headers", action="store_true", help="show all response headers")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    result = inspect_url(args.url, args.timeout)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result, args.headers)

    raise SystemExit(1 if "error" in result or result.get("status", 500) >= 400 else 0)


if __name__ == "__main__":
    main()
