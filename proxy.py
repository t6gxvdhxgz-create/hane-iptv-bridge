#!/usr/bin/env python3
"""
HaNe IPTV Proxy v4.1
==================
A resilient, zero-dependency HTTPS -> HTTP bridge for Xtream/HLS/video streams.

Python: 3.9+

Endpoints
---------
GET/HEAD /p?u=<url>                     Direct proxy with Range support
GET      /probe?src=<url>               Stream/audio/subtitle metadata
GET      /subs?src=<url>&index=0         Embedded subtitle -> WebVTT
GET      /fix?src=<url>&audio=0&t=0      Browser-compatible fragmented MP4
GET/HEAD /apk                            Serve APK configured by APK_PATH
GET      /health                         Health/readiness JSON
GET      /metrics                        Prometheus-style metrics

Security
--------
Set PROXY_TOKEN before exposing this service publicly. Rewritten HLS URLs use
short-lived HMAC signatures, so the master token is never copied into segment
URLs, browser history, or player logs.
"""
from __future__ import annotations

import glob
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import random
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Deque, Dict, IO, Iterable, List, Mapping, Optional, Tuple, cast


# ---------------------------------------------------------------------------
# Build information
# ---------------------------------------------------------------------------

SERVICE_NAME = "hane-iptv-bridge"
VERSION = "4.1.0"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise SystemExit(f"{name} must be between {minimum} and {maximum}")
    return value


def env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a number, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise SystemExit(f"{name} must be between {minimum} and {maximum}")
    return value


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "1" if default else "0").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise SystemExit(f"{name} must be 0/1, true/false, yes/no, or on/off")


PORT = int(sys.argv[1]) if len(sys.argv) > 1 else env_int("PORT", 8899, 1, 65535)
BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0").strip() or "0.0.0.0"
CHUNK_SIZE = env_int("CHUNK_SIZE", 128 * 1024, 16 * 1024, 4 * 1024 * 1024)
CONNECT_TIMEOUT = env_float("CONNECT_TIMEOUT", 12.0, 1.0, 120.0)
READ_TIMEOUT = env_float("READ_TIMEOUT", 45.0, 1.0, 600.0)
CLIENT_TIMEOUT = env_float("CLIENT_TIMEOUT", 60.0, 1.0, 600.0)
UPSTREAM_RETRIES = env_int("UPSTREAM_RETRIES", 2, 0, 8)
MAX_REDIRECTS = env_int("MAX_REDIRECTS", 5, 0, 12)
MAX_CONNECTIONS = env_int("MAX_CONNECTIONS", 64, 4, 4096)
MAX_FFMPEG_JOBS = env_int("MAX_FFMPEG_JOBS", 1 if os.environ.get("RENDER") else 3, 1, 64)
MAX_PROBE_JOBS = env_int("MAX_PROBE_JOBS", 1 if os.environ.get("RENDER") else 2, 1, 32)
FFMPEG_START_TIMEOUT = env_float("FFMPEG_START_TIMEOUT", 20.0, 1.0, 120.0)
FFPROBE_TIMEOUT = env_float("FFPROBE_TIMEOUT", 35.0, 1.0, 180.0)
FFMPEG_RW_TIMEOUT_US = env_int("FFMPEG_RW_TIMEOUT_US", 30_000_000, 1_000_000, 600_000_000)
MAX_PLAYLIST_BYTES = env_int("MAX_PLAYLIST_BYTES", 8 * 1024 * 1024, 64 * 1024, 64 * 1024 * 1024)
MAX_PROBE_OUTPUT = env_int("MAX_PROBE_OUTPUT", 4 * 1024 * 1024, 64 * 1024, 32 * 1024 * 1024)
MAX_URL_LENGTH = env_int("MAX_URL_LENGTH", 16 * 1024, 1024, 128 * 1024)
HLS_SIGNATURE_TTL = env_int("HLS_SIGNATURE_TTL", 12 * 60 * 60, 60, 7 * 24 * 60 * 60)
ALLOW_PRIVATE_TARGETS = env_bool("ALLOW_PRIVATE_TARGETS", False)
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*").strip() or "*"
PUBLIC_STATUS = env_bool("PUBLIC_STATUS", True)
PUBLIC_METRICS = env_bool("PUBLIC_METRICS", False)
PLATFORM_DEPLOYMENT = bool(
    os.environ.get("RENDER")
    or os.environ.get("RAILWAY_ENVIRONMENT")
    or os.environ.get("FLY_APP_NAME")
)
REQUIRE_PROXY_TOKEN = env_bool("REQUIRE_PROXY_TOKEN", PLATFORM_DEPLOYMENT)
SERVER_BACKLOG = env_int("SERVER_BACKLOG", 256, 16, 65535)
PROXY_TOKEN = os.environ.get("PROXY_TOKEN", "").strip()
SIGNING_SECRET = os.environ.get("PROXY_SIGNING_SECRET", "").strip() or PROXY_TOKEN
APK_PATH = os.environ.get("APK_PATH", "").strip()

ALLOWED_HOST_PATTERNS = tuple(
    item.strip().lower().rstrip(".")
    for item in os.environ.get("ALLOWED_HOSTS", "").split(",")
    if item.strip()
)
ALLOWED_PORTS = {
    int(item.strip())
    for item in os.environ.get("ALLOWED_PORTS", "").split(",")
    if item.strip().isdigit()
}

FORWARD_REQUEST_HEADERS = (
    "range",
    "user-agent",
    "accept",
    "accept-language",
    "if-none-match",
    "if-modified-since",
    "cache-control",
    "referer",
)
FORWARD_RESPONSE_HEADERS = (
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "last-modified",
    "etag",
    "cache-control",
    "expires",
    "content-disposition",
)
RETRYABLE_HTTP_CODES = {408, 425, 429, 500, 502, 503, 504}
REDIRECT_HTTP_CODES = {301, 302, 303, 307, 308}
NO_BODY_STATUS_CODES = {204, 304}


# ---------------------------------------------------------------------------
# Metrics and logging
# ---------------------------------------------------------------------------


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: Dict[str, int] = {
            "requests_total": 0,
            "errors_total": 0,
            "upstream_retries_total": 0,
            "upstream_redirects_total": 0,
            "bytes_to_clients_total": 0,
            "active_connections": 0,
            "active_upstreams": 0,
            "active_ffmpeg": 0,
            "rejected_connections_total": 0,
            "rejected_ffmpeg_total": 0,
        }

    def add(self, name: str, delta: int = 1) -> None:
        with self._lock:
            self._values[name] = self._values.get(name, 0) + delta

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._values)


METRICS = Metrics()
STARTED_AT = time.time()
FFMPEG_SLOTS = threading.BoundedSemaphore(MAX_FFMPEG_JOBS)
PROBE_SLOTS = threading.BoundedSemaphore(MAX_PROBE_JOBS)


def log_event(level: str, event: str, **fields: object) -> None:
    payload: Dict[str, object] = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "event": event,
    }
    payload.update(fields)
    sys.stderr.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Binary discovery and process management
# ---------------------------------------------------------------------------


def find_binary(env_name: str, binary_name: str) -> Optional[str]:
    configured = os.environ.get(env_name, "").strip()
    candidates = [configured, shutil.which(binary_name)]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return os.path.abspath(candidate)

    if os.name == "nt":
        pattern = os.path.expandvars(
            rf"%LOCALAPPDATA%\Microsoft\WinGet\Packages\Gyan.FFmpeg*\**\bin\{binary_name}.exe"
        )
        matches = glob.glob(pattern, recursive=True)
        if matches:
            return os.path.abspath(matches[0])
    return None


FFMPEG = find_binary("FFMPEG_PATH", "ffmpeg")
FFPROBE = find_binary("FFPROBE_PATH", "ffprobe")
if not FFPROBE and FFMPEG:
    for filename in ("ffprobe.exe", "ffprobe"):
        candidate = os.path.join(os.path.dirname(FFMPEG), filename)
        if os.path.isfile(candidate):
            FFPROBE = candidate
            break


WINDOWS_CREATION_FLAGS = (
    getattr(subprocess, "CREATE_NO_WINDOW", 0)
    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
) if os.name == "nt" else 0


def run_captured_process(
    command: List[str],
    timeout: float,
) -> subprocess.CompletedProcess[bytes]:
    """Run a child process with byte pipes and platform-safe group handling."""
    if os.name == "nt":
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            creationflags=WINDOWS_CREATION_FLAGS,
        )
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        start_new_session=True,
    )


def stop_process(proc: subprocess.Popen[bytes], grace: float = 2.0) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=grace)
        return
    except Exception:
        pass

    try:
        if os.name != "nt":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
        proc.wait(timeout=grace)
    except Exception:
        pass


class StderrCollector:
    """Drain stderr continuously to prevent FFmpeg pipe deadlocks."""

    def __init__(self, stream: Optional[IO[bytes]], limit: int = 8192) -> None:
        self._stream = stream
        self._limit = limit
        self._chunks: Deque[bytes] = deque()
        self._size = 0
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        if self._stream is None:
            return
        try:
            while True:
                data = self._stream.read(1024)
                if not data:
                    break
                with self._lock:
                    self._chunks.append(data)
                    self._size += len(data)
                    while self._size > self._limit and self._chunks:
                        removed = self._chunks.popleft()
                        self._size -= len(removed)
        except Exception:
            pass

    def text(self) -> str:
        with self._lock:
            data = b"".join(self._chunks)[-self._limit :]
        return data.decode("utf-8", "replace").strip()


def read_once_with_timeout(stream: IO[bytes], size: int, timeout: float) -> Tuple[Optional[bytes], Optional[BaseException]]:
    result_queue: "queue.Queue[Tuple[Optional[bytes], Optional[BaseException]]]" = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            result_queue.put((stream.read(size), None))
        except BaseException as exc:  # thread must report all read failures
            result_queue.put((None, exc))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        return result_queue.get(timeout=timeout)
    except queue.Empty:
        return None, TimeoutError("process produced no output before startup timeout")


# ---------------------------------------------------------------------------
# URL validation, authorization, redirects, and HLS signing
# ---------------------------------------------------------------------------


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


URL_OPENER = urllib.request.build_opener(NoRedirectHandler())


def safe_header_value(value: str) -> str:
    return value.replace("\r", "").replace("\n", "")


def host_matches_allowlist(host: str) -> bool:
    if not ALLOWED_HOST_PATTERNS:
        return True
    for pattern in ALLOWED_HOST_PATTERNS:
        if pattern.startswith("*."):
            suffix = pattern[1:]  # includes leading dot
            if host.endswith(suffix) and host != suffix[1:]:
                return True
        elif host == pattern:
            return True
    return False


def validate_target(url: str) -> Tuple[bool, str]:
    if not url:
        return False, "missing target URL"
    if len(url) > MAX_URL_LENGTH:
        return False, "target URL is too long"

    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        return False, "invalid target URL"

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return False, "target URL must use http or https"
    if parsed.username is not None or parsed.password is not None:
        return False, "credentials in target URLs are not allowed"

    host = parsed.hostname.lower().rstrip(".")
    if not host_matches_allowlist(host):
        return False, "target host is not allowed"

    effective_port = port or (443 if scheme == "https" else 80)
    if ALLOWED_PORTS and effective_port not in ALLOWED_PORTS:
        return False, "target port is not allowed"

    if ALLOW_PRIVATE_TARGETS:
        return True, ""

    try:
        addresses = socket.getaddrinfo(host, effective_port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False, "target hostname could not be resolved"

    if not addresses:
        return False, "target hostname resolved to no addresses"

    for item in addresses:
        try:
            ip = ipaddress.ip_address(item[4][0])
        except ValueError:
            return False, "target resolved to an invalid address"
        if not ip.is_global:
            return False, "private, local, reserved, or non-global targets are disabled"
    return True, ""


def sign_target(target: str, expires: int) -> str:
    if not SIGNING_SECRET:
        return ""
    message = f"{expires}\n{target}".encode("utf-8")
    return hmac.new(SIGNING_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_target_signature(target: str, expires_raw: str, signature: str) -> bool:
    if not SIGNING_SECRET or not expires_raw or not signature:
        return False
    try:
        expires = int(expires_raw)
    except ValueError:
        return False
    now = int(time.time())
    if expires < now or expires > now + HLS_SIGNATURE_TTL + 300:
        return False
    expected = sign_target(target, expires)
    return hmac.compare_digest(expected, signature)


def parse_query(parsed: urllib.parse.ParseResult) -> Mapping[str, List[str]]:
    return urllib.parse.parse_qs(parsed.query, keep_blank_values=True, max_num_fields=50)


def parse_int_param(
    query: Mapping[str, List[str]],
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = query.get(name, [str(default)])[0]
    try:
        value = int(raw or default)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def clone_request(request: urllib.request.Request, url: str, method: str) -> urllib.request.Request:
    headers = {key: value for key, value in request.header_items()}
    return urllib.request.Request(url, headers=headers, method=method)


def set_upstream_read_timeout(response: object, timeout: float) -> None:
    """Best-effort socket timeout update after connection establishment."""
    candidates = [response]
    seen = set()
    for _ in range(8):
        next_candidates = []
        for obj in candidates:
            if obj is None or id(obj) in seen:
                continue
            seen.add(id(obj))
            if isinstance(obj, socket.socket):
                obj.settimeout(timeout)
                return
            for attr in ("fp", "raw", "_sock", "sock"):
                try:
                    child = getattr(obj, attr, None)
                except Exception:
                    child = None
                if child is not None:
                    next_candidates.append(child)
        candidates = next_candidates


# ---------------------------------------------------------------------------
# Bounded HTTP server
# ---------------------------------------------------------------------------


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = SERVER_BACKLOG

    def __init__(self, server_address, handler_class):  # type: ignore[no-untyped-def]
        self._connection_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(server_address, handler_class)

    def process_request(self, request, client_address):  # type: ignore[no-untyped-def]
        if not self._connection_slots.acquire(blocking=False):
            METRICS.add("rejected_connections_total")
            client_socket = cast(socket.socket, request)
            try:
                client_socket.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Type: text/plain; charset=utf-8\r\n"
                    b"Content-Length: 18\r\n\r\n"
                    b"Proxy is too busy\n"
                )
            except Exception:
                pass
            finally:
                try:
                    client_socket.close()
                except Exception:
                    pass
            return

        METRICS.add("active_connections", 1)
        try:
            super().process_request(request, client_address)
        except Exception:
            METRICS.add("active_connections", -1)
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):  # type: ignore[no-untyped-def]
        try:
            super().process_request_thread(request, client_address)
        finally:
            METRICS.add("active_connections", -1)
            self._connection_slots.release()


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"HaNeIPTVProxy/{VERSION}"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(CLIENT_TIMEOUT)
        self.request_id = secrets.token_hex(6)
        self._response_started = False

    # ----- response helpers -------------------------------------------------

    def _start_response(self, code: int, content_type: Optional[str] = None) -> None:
        self.send_response(code)
        self._response_started = True
        self._cors_headers()
        self.send_header("X-Request-ID", self.request_id)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if content_type:
            self.send_header("Content-Type", content_type)

    def _cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Range, Content-Type, Authorization, X-Proxy-Token, If-None-Match, If-Modified-Since",
        )
        self.send_header(
            "Access-Control-Expose-Headers",
            "Content-Range, Content-Length, Accept-Ranges, ETag, X-Request-ID",
        )
        self.send_header("Access-Control-Max-Age", "86400")

    def _send_bytes(
        self,
        code: int,
        body: bytes,
        content_type: str,
        head_only: bool = False,
        cache_control: str = "no-store",
        extra_headers: Iterable[Tuple[str, str]] = (),
    ) -> None:
        self._start_response(code, content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        for key, value in extra_headers:
            self.send_header(key, safe_header_value(value))
        self.end_headers()
        if not head_only and body:
            self._write(body)

    def _send_error_text(self, code: int, message: str, head_only: bool = False) -> None:
        METRICS.add("errors_total")
        log_event("warning" if code < 500 else "error", "request_failed", request_id=self.request_id, code=code, message=message[:300])
        self._send_bytes(code, message.encode("utf-8", "replace"), "text/plain; charset=utf-8", head_only)

    def _write(self, data: bytes) -> None:
        self.wfile.write(data)
        METRICS.add("bytes_to_clients_total", len(data))

    def _copy_stream(self, source: IO[bytes], initial: bytes = b"") -> None:
        if initial:
            self._write(initial)
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            self._write(chunk)

    # ----- auth and URL helpers --------------------------------------------

    def _master_token_valid(self, query: Mapping[str, List[str]]) -> bool:
        if not PROXY_TOKEN:
            return not REQUIRE_PROXY_TOKEN
        candidates = [
            query.get("token", [""])[0],
            self.headers.get("X-Proxy-Token", ""),
        ]
        authorization = self.headers.get("Authorization", "")
        if authorization.lower().startswith("bearer "):
            candidates.append(authorization[7:].strip())
        return any(candidate and hmac.compare_digest(candidate, PROXY_TOKEN) for candidate in candidates)

    def _authorized(self, parsed: urllib.parse.ParseResult, query: Mapping[str, List[str]]) -> bool:
        if not PROXY_TOKEN:
            return not REQUIRE_PROXY_TOKEN
        if self._master_token_valid(query):
            return True
        if parsed.path == "/p":
            target = query.get("u", [""])[0]
            expires = query.get("exp", [""])[0]
            signature = query.get("sig", [""])[0]
            return verify_target_signature(target, expires, signature)
        return False

    def _validated_url(self, url: str) -> Optional[str]:
        ok, reason = validate_target(url)
        if not ok:
            self._send_error_text(400, reason)
            return None
        return url

    def _signed_proxy_path(self, target: str) -> str:
        params = {"u": target}
        if PROXY_TOKEN:
            expires = int(time.time()) + HLS_SIGNATURE_TTL
            params["exp"] = str(expires)
            params["sig"] = sign_target(target, expires)
        return "/p?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)

    def _rewrite_m3u8(self, text: str, base_url: str) -> str:
        def wrap(uri: str) -> str:
            cleaned = uri.strip()
            parsed_uri = urllib.parse.urlsplit(cleaned)
            if parsed_uri.scheme and parsed_uri.scheme.lower() not in {"http", "https"}:
                return cleaned
            absolute = urllib.parse.urljoin(base_url, cleaned)
            return self._signed_proxy_path(absolute)

        output: List[str] = []
        uri_attribute = re.compile(r'(?i)(URI\s*=\s*)"([^"]+)"')
        for line in text.lstrip("\ufeff").splitlines():
            stripped = line.strip()
            if not stripped:
                output.append(line)
            elif stripped.startswith("#"):
                output.append(uri_attribute.sub(lambda match: f'{match.group(1)}"{wrap(match.group(2))}"', line))
            else:
                output.append(wrap(stripped))
        return "\n".join(output) + "\n"

    # ----- upstream network -------------------------------------------------

    def _open_once_with_redirects(self, request: urllib.request.Request):
        current = request
        for redirect_number in range(MAX_REDIRECTS + 1):
            target = current.full_url
            ok, reason = validate_target(target)
            if not ok:
                raise ValueError(f"redirect rejected: {reason}")

            try:
                response = URL_OPENER.open(current, timeout=CONNECT_TIMEOUT)
                set_upstream_read_timeout(response, READ_TIMEOUT)
                return response
            except urllib.error.HTTPError as exc:
                if exc.code not in REDIRECT_HTTP_CODES:
                    raise
                location = exc.headers.get("Location")
                if not location:
                    raise
                if redirect_number >= MAX_REDIRECTS:
                    exc.close()
                    raise urllib.error.URLError("too many upstream redirects")

                new_url = urllib.parse.urljoin(target, location)
                ok, reason = validate_target(new_url)
                if not ok:
                    exc.close()
                    raise ValueError(f"redirect rejected: {reason}")

                method = current.get_method()
                if exc.code == 303 and method != "HEAD":
                    method = "GET"
                exc.close()
                METRICS.add("upstream_redirects_total")
                current = clone_request(current, new_url, method)

        raise urllib.error.URLError("too many upstream redirects")

    def _open_upstream(self, request: urllib.request.Request):
        last_error: Optional[BaseException] = None
        for attempt in range(UPSTREAM_RETRIES + 1):
            try:
                return self._open_once_with_redirects(request)
            except urllib.error.HTTPError as exc:
                last_error = exc
                retryable = exc.code in RETRYABLE_HTTP_CODES
                if not retryable or attempt >= UPSTREAM_RETRIES:
                    raise
                try:
                    exc.close()
                except Exception:
                    pass
            except (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError, OSError) as exc:
                last_error = exc
                if attempt >= UPSTREAM_RETRIES:
                    raise

            METRICS.add("upstream_retries_total")
            delay = min(0.35 * (2 ** attempt), 3.0) + random.uniform(0.0, 0.15)
            time.sleep(delay)

        if last_error:
            raise last_error
        raise urllib.error.URLError("upstream request failed")

    # ----- HTTP methods and routing ----------------------------------------

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._response_started = True
        self._cors_headers()
        self.send_header("X-Request-ID", self.request_id)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:
        self._route(head_only=True)

    def do_GET(self) -> None:
        self._route(head_only=False)

    def _method_not_allowed(self) -> None:
        self._start_response(405, "text/plain; charset=utf-8")
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_CONNECT = _method_not_allowed
    do_TRACE = _method_not_allowed

    def _route(self, head_only: bool) -> None:
        METRICS.add("requests_total")
        started = time.monotonic()
        try:
            if len(self.path) > MAX_URL_LENGTH + 2048:
                return self._send_error_text(414, "Request target is too long", head_only)

            parsed = urllib.parse.urlparse(self.path)
            query = parse_query(parsed)
            path = parsed.path or "/"

            public_paths = {"/", "/health", "/live", "/ready", "/favicon.ico"}
            is_public = PUBLIC_STATUS and path in public_paths
            if path == "/metrics" and PUBLIC_METRICS:
                is_public = True

            if not is_public:
                if REQUIRE_PROXY_TOKEN and not PROXY_TOKEN:
                    return self._send_error_text(503, "Proxy authentication is not configured", head_only)
                if not self._authorized(parsed, query):
                    return self._send_error_text(401, "Unauthorized", head_only)

            if path == "/":
                return self._handle_root(head_only)
            if path == "/favicon.ico":
                return self._handle_favicon()
            if path == "/health":
                return self._handle_health(head_only)
            if path == "/live":
                return self._handle_live(head_only)
            if path == "/ready":
                return self._handle_ready(head_only)
            if path == "/metrics":
                return self._handle_metrics(head_only)
            if path == "/p":
                return self._handle_proxy(query, head_only)
            if path == "/probe":
                return self._handle_probe(query, head_only)
            if path == "/subs":
                return self._handle_subtitles(query, head_only)
            if path == "/fix":
                return self._handle_fix(query, head_only)
            if path == "/apk":
                return self._handle_apk(head_only)
            return self._send_error_text(404, "Unknown endpoint", head_only)
        except ValueError as exc:
            if not self._response_started:
                return self._send_error_text(400, str(exc), head_only)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, socket.timeout):
            log_event("info", "client_disconnected", request_id=self.request_id)
        except Exception as exc:
            log_event(
                "error",
                "unhandled_request_exception",
                request_id=self.request_id,
                error_type=type(exc).__name__,
                error=str(exc)[:500],
            )
            if not self._response_started:
                return self._send_error_text(500, "Internal proxy error", head_only)
        finally:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            if elapsed_ms > 10_000:
                log_event("info", "slow_request", request_id=self.request_id, elapsed_ms=elapsed_ms)

    # ----- endpoint handlers -----------------------------------------------

    def _handle_root(self, head_only: bool) -> None:
        payload = {
            "service": SERVICE_NAME,
            "name": "HaNe IPTV Bridge",
            "version": VERSION,
            "status": "online",
            "health": "/health",
            "live": "/live",
            "ready": "/ready",
            "authentication_required": REQUIRE_PROXY_TOKEN,
            "authentication_configured": bool(PROXY_TOKEN),
            "ffmpeg": bool(FFMPEG),
            "ffprobe": bool(FFPROBE),
        }
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(
            200,
            body,
            "application/json; charset=utf-8",
            head_only,
            cache_control="no-store",
        )

    def _handle_favicon(self) -> None:
        self._start_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()

    def _handle_live(self, head_only: bool) -> None:
        body = b'{"status":"alive"}'
        self._send_bytes(200, body, "application/json; charset=utf-8", head_only)

    def _handle_ready(self, head_only: bool) -> None:
        ready = not (REQUIRE_PROXY_TOKEN and not PROXY_TOKEN)
        payload = {
            "status": "ready" if ready else "not_ready",
            "authentication_configured": bool(PROXY_TOKEN),
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._send_bytes(
            200 if ready else 503,
            body,
            "application/json; charset=utf-8",
            head_only,
        )

    def _handle_health(self, head_only: bool) -> None:
        snapshot = METRICS.snapshot()
        status = "ok"
        reasons: List[str] = []
        if not FFMPEG:
            status = "degraded"
            reasons.append("ffmpeg not found: /fix and /subs unavailable")
        if not FFPROBE:
            status = "degraded"
            reasons.append("ffprobe not found: /probe unavailable")
        if REQUIRE_PROXY_TOKEN and not PROXY_TOKEN:
            status = "degraded"
            reasons.append("PROXY_TOKEN is required but not configured")

        payload = {
            "status": status,
            "service": SERVICE_NAME,
            "version": VERSION,
            "uptime_seconds": int(time.time() - STARTED_AT),
            "authentication_required": REQUIRE_PROXY_TOKEN,
            "authentication_configured": bool(PROXY_TOKEN),
            "ffmpeg": bool(FFMPEG),
            "ffprobe": bool(FFPROBE),
            "active_connections": snapshot.get("active_connections", 0),
            "active_ffmpeg": snapshot.get("active_ffmpeg", 0),
            "reasons": reasons,
        }
        self._send_bytes(200, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", head_only)

    def _handle_metrics(self, head_only: bool) -> None:
        snapshot = METRICS.snapshot()
        snapshot["uptime_seconds"] = int(time.time() - STARTED_AT)
        lines = [
            "# HELP hane_proxy_info Static proxy build information.",
            "# TYPE hane_proxy_info gauge",
            f'hane_proxy_info{{service="{SERVICE_NAME}",version="{VERSION}"}} 1',
        ]
        for name in sorted(snapshot):
            metric_name = "hane_proxy_" + re.sub(r"[^a-zA-Z0-9_:]", "_", name)
            lines.append(f"{metric_name} {snapshot[name]}")
        body = ("\n".join(lines) + "\n").encode("utf-8")
        self._send_bytes(200, body, "text/plain; version=0.0.4; charset=utf-8", head_only)

    def _handle_proxy(self, query: Mapping[str, List[str]], head_only: bool) -> None:
        target = self._validated_url(query.get("u", [""])[0])
        if target is None:
            return

        request = urllib.request.Request(target, method="HEAD" if head_only else "GET")
        for header in FORWARD_REQUEST_HEADERS:
            value = self.headers.get(header)
            if value:
                request.add_header(header, safe_header_value(value))
        request.add_header("Accept-Encoding", "identity")
        if not request.has_header("User-agent"):
            request.add_header("User-Agent", f"HaNeIPTV/{VERSION}")

        try:
            upstream = self._open_upstream(request)
        except urllib.error.HTTPError as exc:
            code = exc.code if 400 <= exc.code <= 599 else 502
            try:
                exc.close()
            except Exception:
                pass
            return self._send_error_text(code, f"Upstream returned HTTP {code}", head_only)
        except ValueError as exc:
            return self._send_error_text(400, str(exc), head_only)
        except Exception as exc:
            return self._send_error_text(502, f"Cannot reach upstream: {type(exc).__name__}", head_only)

        METRICS.add("active_upstreams", 1)
        try:
            status = int(getattr(upstream, "status", 200))
            content_type = upstream.headers.get("Content-Type", "")
            final_url = upstream.geturl()
            is_playlist = "mpegurl" in content_type.lower() or final_url.split("?", 1)[0].lower().endswith(".m3u8")

            if is_playlist and not head_only and status not in NO_BODY_STATUS_CODES:
                raw = upstream.read(MAX_PLAYLIST_BYTES + 1)
                if len(raw) > MAX_PLAYLIST_BYTES:
                    return self._send_error_text(502, "HLS playlist exceeds configured size limit")
                rewritten = self._rewrite_m3u8(raw.decode("utf-8", "replace"), final_url).encode("utf-8")
                return self._send_bytes(
                    200 if status < 400 else status,
                    rewritten,
                    "application/vnd.apple.mpegurl; charset=utf-8",
                    cache_control="no-store",
                )

            self._start_response(status)
            sent_content_length = False
            for header in FORWARD_RESPONSE_HEADERS:
                value = upstream.headers.get(header)
                if value is None:
                    continue
                self.send_header(header, safe_header_value(value))
                if header == "content-length":
                    sent_content_length = True
            if not sent_content_length and status not in NO_BODY_STATUS_CODES:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()

            if not head_only and status not in NO_BODY_STATUS_CODES:
                self._copy_stream(upstream)
        finally:
            METRICS.add("active_upstreams", -1)
            try:
                upstream.close()
            except Exception:
                pass

    def _handle_probe(self, query: Mapping[str, List[str]], head_only: bool) -> None:
        if not FFPROBE:
            return self._send_error_text(501, "ffprobe not found", head_only)
        source = self._validated_url(query.get("src", [""])[0])
        if source is None:
            return
        if head_only:
            return self._send_bytes(200, b"", "application/json; charset=utf-8", True)
        if not PROBE_SLOTS.acquire(blocking=False):
            return self._send_error_text(429, "Too many probe jobs; retry shortly")

        command = [
            FFPROBE,
            "-v", "error",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            "-analyzeduration", "15000000",
            "-probesize", "15000000",
            "-rw_timeout", str(FFMPEG_RW_TIMEOUT_US),
            source,
        ]
        try:
            result = run_captured_process(command, FFPROBE_TIMEOUT)
        except subprocess.TimeoutExpired:
            return self._send_error_text(504, "ffprobe timed out")
        finally:
            PROBE_SLOTS.release()

        if result.returncode != 0:
            detail = result.stderr[-1000:].decode("utf-8", "replace").strip()
            return self._send_error_text(502, "ffprobe failed" + (f": {detail}" if detail else ""))
        if len(result.stdout) > MAX_PROBE_OUTPUT:
            return self._send_error_text(502, "ffprobe output exceeds configured size limit")

        try:
            raw = json.loads(result.stdout.decode("utf-8", "replace") or "{}")
        except json.JSONDecodeError:
            return self._send_error_text(502, "ffprobe produced invalid JSON")

        audio: List[Dict[str, object]] = []
        subtitles: List[Dict[str, object]] = []
        video: List[Dict[str, object]] = []
        relative_audio = 0
        relative_subtitle = 0
        for stream in raw.get("streams", []):
            tags = stream.get("tags") or {}
            disposition = stream.get("disposition") or {}
            entry: Dict[str, object] = {
                "stream_index": stream.get("index"),
                "codec": stream.get("codec_name") or "",
                "language": tags.get("language") or "",
                "title": tags.get("title") or "",
                "default": bool(disposition.get("default")),
            }
            stream_type = stream.get("codec_type")
            if stream_type == "audio":
                entry.update({
                    "index": relative_audio,
                    "channels": stream.get("channels"),
                    "channel_layout": stream.get("channel_layout") or "",
                    "sample_rate": stream.get("sample_rate") or "",
                })
                relative_audio += 1
                audio.append(entry)
            elif stream_type == "subtitle":
                entry["index"] = relative_subtitle
                relative_subtitle += 1
                subtitles.append(entry)
            elif stream_type == "video":
                entry.update({
                    "width": stream.get("width"),
                    "height": stream.get("height"),
                    "frame_rate": stream.get("avg_frame_rate") or "",
                })
                video.append(entry)

        format_info = raw.get("format") or {}
        payload = {
            "video": video,
            "audio": audio,
            "subtitles": subtitles,
            "duration": format_info.get("duration"),
            "format": format_info.get("format_name") or "",
            "bit_rate": format_info.get("bit_rate"),
        }
        self._send_bytes(200, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _spawn_ffmpeg(
        self,
        command: List[str],
    ) -> Tuple[subprocess.Popen[bytes], StderrCollector]:
        if os.name == "nt":
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                creationflags=WINDOWS_CREATION_FLAGS,
            )
        else:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                start_new_session=True,
            )
        collector = StderrCollector(process.stderr)
        return process, collector

    def _acquire_ffmpeg_slot(self) -> bool:
        if not FFMPEG_SLOTS.acquire(blocking=False):
            METRICS.add("rejected_ffmpeg_total")
            return False
        METRICS.add("active_ffmpeg", 1)
        return True

    def _release_ffmpeg_slot(self) -> None:
        METRICS.add("active_ffmpeg", -1)
        FFMPEG_SLOTS.release()

    def _base_ffmpeg_input_args(self, source: str) -> List[str]:
        return [
            FFMPEG or "ffmpeg",
            "-hide_banner",
            "-nostdin",
            "-loglevel", "error",
            "-rw_timeout", str(FFMPEG_RW_TIMEOUT_US),
            "-reconnect", "1",
            "-reconnect_streamed", "1",
            "-reconnect_at_eof", "1",
            "-reconnect_delay_max", "5",
            "-fflags", "+genpts+discardcorrupt",
            "-i", source,
        ]

    def _handle_subtitles(self, query: Mapping[str, List[str]], head_only: bool) -> None:
        if not FFMPEG:
            return self._send_error_text(501, "ffmpeg not found", head_only)
        source = self._validated_url(query.get("src", [""])[0])
        if source is None:
            return
        index = parse_int_param(query, "index", 0, 0, 99)
        if head_only:
            return self._send_bytes(200, b"", "text/vtt; charset=utf-8", True)
        if not self._acquire_ffmpeg_slot():
            return self._send_error_text(429, "Too many FFmpeg jobs; retry shortly")

        command = self._base_ffmpeg_input_args(source)
        command += ["-map", f"0:s:{index}", "-f", "webvtt", "pipe:1"]
        process: Optional[subprocess.Popen[bytes]] = None
        try:
            process, stderr = self._spawn_ffmpeg(command)
            assert process.stdout is not None
            first, read_error = read_once_with_timeout(process.stdout, 512, FFMPEG_START_TIMEOUT)
            if read_error is not None or not first:
                stop_process(process)
                detail = stderr.text()
                message = "Subtitle extraction timed out" if isinstance(read_error, TimeoutError) else f"No subtitle stream at index {index}"
                if detail:
                    message += f": {detail}"
                return self._send_error_text(404 if not isinstance(read_error, TimeoutError) else 504, message)

            self._start_response(200, "text/vtt; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            self._copy_stream(process.stdout, first)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, socket.timeout):
            pass
        except Exception as exc:
            if not self._response_started:
                self._send_error_text(500, f"FFmpeg subtitle failure: {type(exc).__name__}")
        finally:
            if process is not None:
                stop_process(process)
            self._release_ffmpeg_slot()

    def _handle_fix(self, query: Mapping[str, List[str]], head_only: bool) -> None:
        if not FFMPEG:
            return self._send_error_text(501, "ffmpeg not found", head_only)
        source = self._validated_url(query.get("src", [""])[0])
        if source is None:
            return

        start = parse_int_param(query, "t", 0, 0, 7 * 24 * 60 * 60)
        audio_index = parse_int_param(query, "audio", 0, 0, 99)
        profile = query.get("profile", [""])[0].strip().lower()
        if not profile:
            profile = "enhance" if query.get("enhance", ["0"])[0] == "1" else "copy"
        if profile not in {"copy", "compat", "enhance"}:
            raise ValueError("profile must be copy, compat, or enhance")

        if head_only:
            return self._send_bytes(200, b"", "video/mp4", True)
        if not self._acquire_ffmpeg_slot():
            return self._send_error_text(429, "Too many FFmpeg jobs; retry shortly")

        command = [
            FFMPEG,
            "-hide_banner",
            "-nostdin",
            "-loglevel", "error",
            "-rw_timeout", str(FFMPEG_RW_TIMEOUT_US),
            "-reconnect", "1",
            "-reconnect_streamed", "1",
            "-reconnect_at_eof", "1",
            "-reconnect_delay_max", "5",
            "-fflags", "+genpts+discardcorrupt",
        ]
        if start > 0:
            command += ["-ss", str(start)]
        command += ["-i", source, "-map", "0:v:0?", "-map", f"0:a:{audio_index}?"]

        if profile == "copy":
            command += ["-c:v", "copy"]
        elif profile == "compat":
            command += [
                "-c:v", "libx264",
                "-preset", "veryfast",
                "-crf", "22",
                "-pix_fmt", "yuv420p",
            ]
        else:  # enhance
            command += [
                "-vf", "hqdn3d=1.2:1.2:4.5:4.5,unsharp=5:5:0.55:5:5:0.0",
                "-c:v", "libx264",
                "-preset", "veryfast",
                "-crf", "20",
                "-pix_fmt", "yuv420p",
            ]

        command += [
            "-c:a", "aac",
            "-b:a", "192k",
            "-ac", "2",
            "-ar", "48000",
            "-max_interleave_delta", "0",
            "-avoid_negative_ts", "make_zero",
            "-f", "mp4",
            "-movflags", "frag_keyframe+empty_moov+default_base_moof+faststart",
            "pipe:1",
        ]

        process: Optional[subprocess.Popen[bytes]] = None
        try:
            process, stderr = self._spawn_ffmpeg(command)
            assert process.stdout is not None
            first, read_error = read_once_with_timeout(process.stdout, 4096, FFMPEG_START_TIMEOUT)
            if read_error is not None or not first:
                stop_process(process)
                detail = stderr.text()
                message = "FFmpeg startup timed out" if isinstance(read_error, TimeoutError) else "FFmpeg produced no playable output"
                if detail:
                    message += f": {detail}"
                return self._send_error_text(504 if isinstance(read_error, TimeoutError) else 502, message)

            self._start_response(200, "video/mp4")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.send_header("Accept-Ranges", "none")
            self.close_connection = True
            self.end_headers()
            self._copy_stream(process.stdout, first)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, socket.timeout):
            pass
        except Exception as exc:
            if not self._response_started:
                self._send_error_text(500, f"FFmpeg conversion failure: {type(exc).__name__}")
        finally:
            if process is not None:
                stop_process(process)
            self._release_ffmpeg_slot()

    def _handle_apk(self, head_only: bool) -> None:
        path = APK_PATH
        if not path:
            legacy = os.path.normpath(
                os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "..",
                    "hane-iptv-apk",
                    "app-release-signed.apk",
                )
            )
            path = legacy
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            return self._send_error_text(404, "APK not found; set APK_PATH to the signed APK")

        size = os.path.getsize(path)
        start = 0
        end = size - 1
        status = 200
        range_header = self.headers.get("Range", "")
        if range_header:
            match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_header.strip())
            if not match:
                return self._send_error_text(416, "Only a single byte range is supported", head_only)
            left, right = match.groups()
            if not left and not right:
                return self._send_error_text(416, "Invalid byte range", head_only)
            if left:
                start = int(left)
                end = int(right) if right else size - 1
            else:
                suffix = int(right)
                if suffix <= 0:
                    return self._send_error_text(416, "Invalid suffix range", head_only)
                start = max(0, size - suffix)
                end = size - 1
            if start >= size or end < start:
                self._start_response(416, "text/plain; charset=utf-8")
                self.send_header("Content-Range", f"bytes */{size}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            end = min(end, size - 1)
            status = 206

        length = end - start + 1
        self._start_response(status, "application/vnd.android.package-archive")
        self.send_header("Content-Disposition", 'attachment; filename="HaNeIPTV.apk"')
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(length))
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.send_header("Cache-Control", "private, max-age=3600")
        self.end_headers()
        if head_only:
            return

        with open(path, "rb") as file_handle:
            file_handle.seek(start)
            remaining = length
            while remaining > 0:
                chunk = file_handle.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    break
                self._write(chunk)
                remaining -= len(chunk)

    def log_message(self, format: str, *args: object) -> None:
        # Deliberately suppress BaseHTTPRequestHandler's request-line logging.
        # Target URLs may contain IPTV credentials. Structured logs above never
        # print the target URL or query string.
        return


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    if PROXY_TOKEN and len(PROXY_TOKEN) < 24:
        log_event("warning", "weak_proxy_token", message="Use a random token of at least 24 characters")
    if REQUIRE_PROXY_TOKEN and not PROXY_TOKEN:
        log_event(
            "error",
            "authentication_required_but_missing",
            message="Public status endpoints will work, but proxy endpoints stay disabled until PROXY_TOKEN is set",
        )
    elif not PROXY_TOKEN:
        log_event("warning", "authentication_disabled", message="Set PROXY_TOKEN before exposing the proxy publicly")
    if ALLOW_PRIVATE_TARGETS and not ALLOWED_HOST_PATTERNS:
        log_event(
            "warning",
            "broad_target_access",
            message="Private targets and all hosts are allowed; configure PROXY_TOKEN and ALLOWED_HOSTS",
        )

    server = LimitedThreadingHTTPServer((BIND_HOST, PORT), ProxyHandler)
    shutdown_started = threading.Event()

    def request_shutdown(signum=None, frame=None):  # type: ignore[no-untyped-def]
        if shutdown_started.is_set():
            return
        shutdown_started.set()
        log_event("info", "shutdown_requested", signal=signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    for signal_name in ("SIGINT", "SIGTERM"):
        signal_value = getattr(signal, signal_name, None)
        if signal_value is not None:
            try:
                signal.signal(signal_value, request_shutdown)
            except (ValueError, OSError):
                pass

    log_event(
        "info",
        "proxy_started",
        service=SERVICE_NAME,
        version=VERSION,
        bind=BIND_HOST,
        port=PORT,
        ffmpeg=FFMPEG or "not-found",
        ffprobe=FFPROBE or "not-found",
        max_connections=MAX_CONNECTIONS,
        max_ffmpeg_jobs=MAX_FFMPEG_JOBS,
        authentication_required=REQUIRE_PROXY_TOKEN,
        authentication_configured=bool(PROXY_TOKEN),
        allow_private_targets=ALLOW_PRIVATE_TARGETS,
        allowed_hosts=list(ALLOWED_HOST_PATTERNS),
    )

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        log_event("info", "proxy_stopped")


if __name__ == "__main__":
    main()
