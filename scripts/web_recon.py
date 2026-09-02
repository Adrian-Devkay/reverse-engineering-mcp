#!/usr/bin/env python3
"""Perform bounded, GET-only, scope-controlled web collection for an authorized case."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import socket
import sys
import time
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPHandler, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from urllib.robotparser import RobotFileParser


USER_AGENT = "ApexAuthorizedWebRecon/1.0"
MAX_PAGES = 100
MAX_DEPTH = 3
MAX_RESPONSE_BYTES = 1_048_576
MAX_TOTAL_BYTES = 33_554_432
MAX_LINKS_PER_PAGE = 200
MAX_ROBOTS_BYTES = 128 * 1024
MAX_REDIRECTS = 3
SAFE_HEADERS = (
    "content-type",
    "content-length",
    "location",
    "server",
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cache-control",
    "etag",
    "last-modified",
)


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _validated_address(host: str, allow_private_network: bool) -> str:
    """Resolve once and connect to that exact IP to prevent DNS rebinding."""
    if not allow_private_network:
        _assert_network_destination(host, allow_private_network=False)
    addresses = sorted(_resolved_addresses(host), key=str)
    if not addresses:
        raise ValueError("URL host could not be resolved")
    return str(addresses[0])


class _PinnedHTTPConnection(HTTPConnection):
    def __init__(self, *args, address: str, **kwargs):
        super().__init__(*args, **kwargs)
        self._pinned_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_address, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(HTTPSConnection):
    def __init__(self, *args, address: str, **kwargs):
        super().__init__(*args, **kwargs)
        self._pinned_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_address, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


class _PinnedHTTPHandler(HTTPHandler):
    def __init__(self, allow_private_network: bool):
        super().__init__()
        self._allow_private_network = allow_private_network

    def http_open(self, request):
        host = urlsplit(request.full_url).hostname or ""
        address = _validated_address(host, self._allow_private_network)
        return self.do_open(_PinnedHTTPConnection, request, address=address)


class _PinnedHTTPSHandler(HTTPSHandler):
    def __init__(self, allow_private_network: bool):
        super().__init__()
        self._allow_private_network = allow_private_network

    def https_open(self, request):
        host = urlsplit(request.full_url).hostname or ""
        address = _validated_address(host, self._allow_private_network)
        return self.do_open(
            _PinnedHTTPSConnection,
            request,
            context=self._context,
            check_hostname=self._check_hostname,
            address=address,
        )


def _build_opener(allow_private_network: bool):
    # An empty ProxyHandler prevents environment proxy settings from changing
    # the destination or receiving the collected request.
    return build_opener(
        ProxyHandler({}),
        _NoRedirectHandler(),
        _PinnedHTTPHandler(allow_private_network),
        _PinnedHTTPSHandler(allow_private_network),
    )


class LinkExtractor(HTMLParser):
    """Extract links without executing JavaScript or submitting forms."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.lower() in {"href", "src"} and value:
                self.links.append((tag.lower(), name.lower(), value.strip()))


def _canonical_host(host: str) -> str:
    if not host:
        raise ValueError("URL has no host")
    try:
        return host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("URL host is invalid") from exc


def _scope_matches(host: str, scopes: list[str]) -> bool:
    return any(host == scope or host.endswith("." + scope) for scope in scopes)


def _resolved_addresses(host: str) -> set[object]:
    try:
        return {ipaddress.ip_address(host)}
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError("URL host could not be resolved") from exc
        return {ipaddress.ip_address(item[4][0]) for item in infos}


def _assert_network_destination(host: str, allow_private_network: bool) -> None:
    if allow_private_network:
        return
    addresses = _resolved_addresses(host)
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("private, loopback, link-local, reserved, or non-global destinations are blocked")


def normalize_url(
    raw_url: str,
    scopes: list[str],
    *,
    allow_private_network: bool = False,
    allow_nonstandard_port: bool = False,
) -> str:
    try:
        parsed = urlsplit(raw_url.strip())
        username = parsed.username
        password = parsed.password
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL is malformed") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("only http and https URLs are allowed")
    if username is not None or password is not None:
        raise ValueError("credentials in URLs are not allowed")
    host = _canonical_host(parsed.hostname or "")
    if not _scope_matches(host, scopes):
        raise ValueError("URL is outside the authorized web scope")
    if port is not None and port not in {80, 443} and not allow_nonstandard_port:
        raise ValueError("non-standard ports require explicit lab opt-in")
    _assert_network_destination(host, allow_private_network)
    netloc = host
    if port is not None and port not in {80, 443}:
        netloc = f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def redact_url(url: str) -> str:
    parsed = urlsplit(url)
    query = ""
    if parsed.query:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        query = urlencode([(key, "[REDACTED]") for key, _ in pairs]) if pairs else "[REDACTED]"
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, ""))


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _safe_headers(headers) -> dict[str, str]:
    selected = {name.lower(): value for name, value in headers.items() if name.lower() in SAFE_HEADERS}
    if "location" in selected:
        selected["location"] = redact_url(selected["location"])
    return selected


def _fetch(url: str, timeout_seconds: int, max_bytes: int, *, allow_private_network: bool) -> dict[str, object]:
    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.5,*/*;q=0.1",
            "Accept-Encoding": "identity",
            "Connection": "close",
        },
        method="GET",
    )
    response = None
    try:
        response = _build_opener(allow_private_network).open(request, timeout=timeout_seconds)
        status = int(getattr(response, "status", response.getcode()))
        headers = _safe_headers(response.headers)
        body = response.read(max_bytes + 1)
        return {"status": status, "headers": headers, "body": body[:max_bytes], "truncated": len(body) > max_bytes, "error": None}
    except HTTPError as exc:
        headers = _safe_headers(exc.headers)
        body = exc.read(max_bytes + 1)
        return {"status": int(exc.code), "headers": headers, "body": body[:max_bytes], "truncated": len(body) > max_bytes, "error": None}
    except (OSError, URLError, TimeoutError) as exc:
        return {"status": None, "headers": {}, "body": b"", "truncated": False, "error": type(exc).__name__}
    finally:
        if response is not None:
            response.close()


def _robots_for(
    url: str,
    scopes: list[str],
    *,
    timeout_seconds: int,
    allow_private_network: bool,
    allow_nonstandard_port: bool,
    ignore_robots: bool,
    robots_cache: dict[str, RobotFileParser | None],
) -> tuple[RobotFileParser | None, int]:
    origin = _origin(url)
    if ignore_robots:
        return None, 0
    if origin in robots_cache:
        return robots_cache[origin], 0
    robots_url = normalize_url(
        origin + "/robots.txt",
        scopes,
        allow_private_network=allow_private_network,
        allow_nonstandard_port=allow_nonstandard_port,
    )
    result = _fetch(robots_url, timeout_seconds, MAX_ROBOTS_BYTES, allow_private_network=allow_private_network)
    body = result["body"]
    consumed = len(body)
    parser = RobotFileParser(robots_url)
    if result["status"] in {404, 410}:
        parser.parse([])
    elif result["status"] == 200 and not result["truncated"]:
        parser.parse(body.decode("utf-8", errors="replace").splitlines())
    else:
        parser.parse(["User-agent: *", "Disallow: /"])
    robots_cache[origin] = parser
    return parser, consumed


def _extract_links(base_url: str, body: bytes, scopes: list[str], *, allow_private_network: bool, allow_nonstandard_port: bool) -> tuple[list[str], list[str]]:
    parser = LinkExtractor()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except Exception:
        return [], []
    discovered: list[str] = []
    navigational: list[str] = []
    for tag, attribute, raw_link in parser.links[:MAX_LINKS_PER_PAGE]:
        try:
            candidate = normalize_url(
                urljoin(base_url, raw_link),
                scopes,
                allow_private_network=allow_private_network,
                allow_nonstandard_port=allow_nonstandard_port,
            )
        except ValueError:
            continue
        if candidate not in discovered:
            discovered.append(candidate)
        if tag in {"a", "area", "iframe", "frame"} and attribute == "href" and candidate not in navigational:
            navigational.append(candidate)
    return [redact_url(item) for item in discovered], navigational


def crawl(
    seeds: list[str],
    scopes: list[str],
    *,
    max_pages: int = MAX_PAGES,
    max_depth: int = 2,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    timeout_seconds: int = 10,
    delay_seconds: float = 0.5,
    ignore_robots: bool = False,
    allow_private_network: bool = False,
    allow_nonstandard_port: bool = False,
) -> dict[str, object]:
    if not 1 <= max_pages <= MAX_PAGES:
        raise ValueError(f"max_pages must be between 1 and {MAX_PAGES}")
    if not 0 <= max_depth <= MAX_DEPTH:
        raise ValueError(f"max_depth must be between 0 and {MAX_DEPTH}")
    if not 1024 <= max_response_bytes <= MAX_RESPONSE_BYTES:
        raise ValueError(f"max_response_bytes must be between 1024 and {MAX_RESPONSE_BYTES}")
    if not max_response_bytes <= max_total_bytes <= MAX_TOTAL_BYTES:
        raise ValueError("max_total_bytes must be between max_response_bytes and the configured total limit")
    if not 1 <= timeout_seconds <= 30:
        raise ValueError("timeout_seconds must be between 1 and 30")
    if not 0 <= delay_seconds <= 60:
        raise ValueError("delay_seconds must be between 0 and 60")

    started_utc = datetime.now(timezone.utc).isoformat()
    normalized_seeds = [
        normalize_url(
            seed,
            scopes,
            allow_private_network=allow_private_network,
            allow_nonstandard_port=allow_nonstandard_port,
        )
        for seed in seeds
    ]
    queue = deque((seed, 0, 0) for seed in normalized_seeds)
    visited: set[str] = set()
    pages: list[dict[str, object]] = []
    events: list[dict[str, object]] = []
    robots_cache: dict[str, RobotFileParser | None] = {}
    last_request_at: dict[str, float] = {}
    total_bytes = 0

    while queue and len(pages) < max_pages and total_bytes < max_total_bytes:
        url, depth, redirect_count = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        try:
            robots, robots_bytes = _robots_for(
                url,
                scopes,
                timeout_seconds=timeout_seconds,
                allow_private_network=allow_private_network,
                allow_nonstandard_port=allow_nonstandard_port,
                ignore_robots=ignore_robots,
                robots_cache=robots_cache,
            )
        except ValueError as exc:
            events.append({"type": "robots_blocked", "url": redact_url(url), "reason": str(exc)})
            continue
        total_bytes += robots_bytes
        if total_bytes >= max_total_bytes:
            events.append({"type": "budget_exhausted", "reason": "total response byte limit"})
            break
        if robots is not None and not robots.can_fetch(USER_AGENT, url):
            events.append({"type": "robots_disallowed", "url": redact_url(url)})
            continue

        host_key = _origin(url)
        elapsed = time.monotonic() - last_request_at.get(host_key, 0.0)
        if elapsed < delay_seconds:
            time.sleep(delay_seconds - elapsed)
        last_request_at[host_key] = time.monotonic()
        remaining = min(max_response_bytes, max_total_bytes - total_bytes)
        result = _fetch(url, timeout_seconds, remaining, allow_private_network=allow_private_network)
        body = result["body"]
        total_bytes += len(body)
        page: dict[str, object] = {
            "url": redact_url(url),
            "depth": depth,
            "status": result["status"],
            "headers": result["headers"],
            "response_bytes": len(body),
            "response_sha256": hashlib.sha256(body).hexdigest() if body else None,
            "response_truncated": result["truncated"],
            "error": result["error"],
        }
        pages.append(page)

        location = result["headers"].get("location") if isinstance(result["headers"], dict) else None
        if location and isinstance(result["status"], int) and 300 <= result["status"] < 400 and redirect_count < MAX_REDIRECTS:
            try:
                redirect_url = normalize_url(
                    urljoin(url, location),
                    scopes,
                    allow_private_network=allow_private_network,
                    allow_nonstandard_port=allow_nonstandard_port,
                )
            except ValueError as exc:
                page["redirect_blocked"] = str(exc)
            else:
                page["redirect_to"] = redact_url(redirect_url)
                queue.append((redirect_url, depth, redirect_count + 1))

        content_type = str(result["headers"].get("content-type", "")).split(";", 1)[0].strip().lower()
        if content_type in {"text/html", "application/xhtml+xml", ""} and body and depth < max_depth:
            discovered, navigational = _extract_links(
                url,
                body,
                scopes,
                allow_private_network=allow_private_network,
                allow_nonstandard_port=allow_nonstandard_port,
            )
            page["discovered_links"] = discovered
            page["queued_links"] = [redact_url(item) for item in navigational]
            for next_url in navigational:
                if next_url not in visited:
                    queue.append((next_url, depth + 1, 0))

    return {
        "schema": "apex-reverse-engineering/web-recon-v1",
        "started_utc": started_utc,
        "ended_utc": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "method": "GET",
            "robots": "ignored" if ignore_robots else "respected",
            "credentials": False,
            "cookies": False,
            "max_pages": max_pages,
            "max_depth": max_depth,
            "max_response_bytes": max_response_bytes,
            "max_total_bytes": max_total_bytes,
            "timeout_seconds": timeout_seconds,
            "delay_seconds": delay_seconds,
            "allow_private_network": allow_private_network,
            "allow_nonstandard_port": allow_nonstandard_port,
        },
        "scope": {"allowed_domains": scopes, "seeds": [redact_url(item) for item in normalized_seeds]},
        "summary": {
            "pages_observed": len(pages),
            "events": len(events),
            "response_bytes": total_bytes,
            "queue_remaining": len(queue),
        },
        "pages": pages,
        "events": events,
    }


def _load_case(case_dir: Path) -> dict[str, object]:
    manifest = case_dir / "web-case.json"
    if not manifest.is_file():
        raise ValueError("web-case.json is required; create it with init_web_case.py first")
    try:
        record = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("web-case.json is invalid or unreadable") from exc
    if record.get("schema") != "apex-reverse-engineering/web-case-v1":
        raise ValueError("unsupported web case schema")
    scope = record.get("scope")
    if not isinstance(scope, dict) or not str(scope.get("authorization", "")).strip():
        raise ValueError("web-case.json has no authorization basis")
    domains = scope.get("allowed_domains")
    if not isinstance(domains, list) or not domains or not all(isinstance(item, str) for item in domains):
        raise ValueError("web-case.json has no allowed domains")
    policy = record.get("network_policy")
    if not isinstance(policy, dict):
        raise ValueError("web-case.json has no network policy")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_dir", type=Path, help="Existing directory containing web-case.json")
    parser.add_argument("seeds", nargs="+", help="Seed URLs; each must be inside the manifest scope")
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-response-bytes", type=int, default=MAX_RESPONSE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=MAX_TOTAL_BYTES)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument("--delay-seconds", type=float, default=0.5)
    parser.add_argument("--ignore-robots", action="store_true", help="Only for explicitly authorized testing; default is to respect robots.txt")
    parser.add_argument("--allow-private-network", action="store_true", help="Only for an isolated local lab; public web recon must leave this disabled")
    parser.add_argument("--allow-nonstandard-port", action="store_true", help="Only for an explicitly authorized lab target")
    args = parser.parse_args()

    case_dir = args.case_dir.expanduser().resolve()
    if not case_dir.is_dir():
        parser.error("case_dir must already exist")
    try:
        case = _load_case(case_dir)
        domains = [str(item) for item in case["scope"]["allowed_domains"]]
        policy = case["network_policy"]
        if args.ignore_robots and policy.get("allow_ignore_robots") is not True:
            parser.error("--ignore-robots is not authorized by web-case.json")
        if args.allow_private_network and policy.get("allow_private_network") is not True:
            parser.error("--allow-private-network is not authorized by web-case.json")
        if args.allow_nonstandard_port and policy.get("allow_nonstandard_port") is not True:
            parser.error("--allow-nonstandard-port is not authorized by web-case.json")
        result = crawl(
            args.seeds,
            domains,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            max_response_bytes=args.max_response_bytes,
            max_total_bytes=args.max_total_bytes,
            timeout_seconds=args.timeout_seconds,
            delay_seconds=args.delay_seconds,
            ignore_robots=args.ignore_robots,
            allow_private_network=args.allow_private_network,
            allow_nonstandard_port=args.allow_nonstandard_port,
        )
    except ValueError as exc:
        parser.error(str(exc))

    output = case_dir / "web-recon.json"
    if output.exists():
        parser.error(f"refusing to overwrite existing report: {output}")
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
