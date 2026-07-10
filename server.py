#!/usr/bin/env python3
"""
HaNe IPTV deployment launcher for Render, Railway, Fly.io, and containers.

This is intentionally a native HTTP-server launcher, not a WSGI adapter.
``BaseHTTPRequestHandler`` is not a WSGI application, and pretending that it
is one can break long-lived HLS/video streams, Range requests, and disconnect
handling.

The launcher keeps all proxy behaviour in ``proxy.py`` and provides:

* strict HOST/PORT validation;
* exact sibling-module loading (avoids importing the wrong ``proxy`` module);
* compatibility with both ``Proxy`` and ``ProxyHandler`` handler names;
* automatic use of the proxy's own production server and ``main()`` when
  available;
* a hardened threaded fallback server for older proxy versions;
* SIGINT/SIGTERM graceful shutdown;
* line-buffered, structured startup/error logs;
* clear startup failures for deployment platforms.

Expected layout::

    app/
      proxy.py
      render_server.py

Run locally::

    python render_server.py

Render / Railway start command::

    python render_server.py

Environment variables::

    PORT=8899                 Platform-provided listening port
    BIND_HOST=0.0.0.0         Listening interface
    PROXY_MODULE_PATH=proxy.py
    SERVER_BACKLOG=256        Fallback server listen backlog
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import socket
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterator, Optional, Type, cast

APP_NAME = "hane-iptv-bridge"
APP_VERSION = "4.0"
DEFAULT_PORT = 8899
DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_BACKLOG = 256


def _configure_stdio() -> None:
    """Make logs appear immediately in container/platform log streams."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(line_buffering=True, write_through=True)
            except (OSError, ValueError):
                pass


def _log(level: str, event: str, **fields: object) -> None:
    payload: Dict[str, object] = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "service": APP_NAME,
        "version": APP_VERSION,
        "event": event,
    }
    payload.update(fields)
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), flush=True)


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


def _resolve_bind_host() -> str:
    host = os.environ.get("BIND_HOST", DEFAULT_BIND_HOST).strip()
    if not host:
        raise RuntimeError("BIND_HOST cannot be empty")
    if any(character.isspace() for character in host):
        raise RuntimeError(f"BIND_HOST cannot contain whitespace: {host!r}")
    return host


def _resolve_proxy_path() -> Path:
    base_dir = Path(__file__).resolve().parent
    configured = os.environ.get("PROXY_MODULE_PATH", "proxy.py").strip() or "proxy.py"
    path = Path(configured)
    if not path.is_absolute():
        path = base_dir / path
    path = path.resolve()

    if path == Path(__file__).resolve():
        raise RuntimeError("PROXY_MODULE_PATH points to the launcher itself")
    if not path.is_file():
        raise RuntimeError(f"Proxy module not found: {path}")
    if path.suffix.lower() != ".py":
        raise RuntimeError(f"PROXY_MODULE_PATH must point to a .py file: {path}")
    return path


@contextmanager
def _safe_import_argv() -> Iterator[None]:
    """
    Hide platform/launcher arguments while importing legacy proxy.py files.

    Older versions inspect ``sys.argv[1]`` at import time and assume it is a
    numeric port. Platform-injected arguments would otherwise crash import.
    """
    previous = sys.argv[:]
    sys.argv[:] = [previous[0] if previous else "render_server.py"]
    try:
        yield
    finally:
        sys.argv[:] = previous


def _load_proxy_module(path: Path, port: int, bind_host: str) -> ModuleType:
    # Set these before import because proxy.py commonly reads them into module
    # globals at import time.
    os.environ["PORT"] = str(port)
    os.environ["BIND_HOST"] = bind_host

    module_name = "hane_proxy_runtime"
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to create an import specification for {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        with _safe_import_argv():
            spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise

    # Patch globals as a compatibility safeguard for proxy modules that cached
    # configuration during import.
    setattr(module, "PORT", port)
    if hasattr(module, "BIND_HOST"):
        setattr(module, "BIND_HOST", bind_host)
    return module


def _find_handler(module: ModuleType) -> Type[BaseHTTPRequestHandler]:
    for name in ("ProxyHandler", "Proxy"):
        candidate = getattr(module, name, None)
        if isinstance(candidate, type) and issubclass(candidate, BaseHTTPRequestHandler):
            return cast(Type[BaseHTTPRequestHandler], candidate)
    raise RuntimeError(
        "proxy.py must expose a BaseHTTPRequestHandler subclass named "
        "ProxyHandler or Proxy"
    )


class DeploymentThreadingHTTPServer(ThreadingHTTPServer):
    """Hardened compatibility server used only by legacy proxy modules."""

    daemon_threads = True
    allow_reuse_address = True
    block_on_close = False

    def __init__(
        self,
        server_address: Any,
        request_handler_class: Type[BaseHTTPRequestHandler],
        backlog: int,
    ) -> None:
        self.request_queue_size = backlog
        super().__init__(server_address, request_handler_class, bind_and_activate=False)
        try:
            self.server_bind()
            self.server_activate()
        except BaseException:
            self.server_close()
            raise

    def handle_error(self, request: object, client_address: object) -> None:
        # Do not allow one broken client/handler thread to terminate the server.
        _log(
            "error",
            "request_thread_failed",
            client=str(client_address),
            error=traceback.format_exc(limit=12),
        )


class _GracefulShutdown:
    def __init__(self, server: ThreadingHTTPServer) -> None:
        self._server = server
        self._started = threading.Event()

    def __call__(self, signum: int, _frame: object) -> None:
        if self._started.is_set():
            _log("warning", "shutdown_already_in_progress", signal=signum)
            return
        self._started.set()
        _log("info", "shutdown_requested", signal=signum)

        # BaseServer.shutdown() must be called from a thread different from the
        # one executing serve_forever(), otherwise it deadlocks.
        thread = threading.Thread(
            target=self._server.shutdown,
            name="graceful-shutdown",
            daemon=True,
        )
        thread.start()


def _install_signal_handlers(server: ThreadingHTTPServer) -> None:
    handler = _GracefulShutdown(server)
    for signal_name in ("SIGINT", "SIGTERM"):
        signal_value = getattr(signal, signal_name, None)
        if signal_value is None:
            continue
        try:
            signal.signal(signal_value, handler)
        except (OSError, RuntimeError, ValueError):
            # Signal registration can fail outside the main thread or on a
            # platform that only partially implements POSIX signals.
            pass


def _run_legacy_proxy(
    module: ModuleType,
    bind_host: str,
    port: int,
    backlog: int,
) -> None:
    handler = _find_handler(module)

    # Prefer the proxy's specialised server class when it exposes one. This
    # preserves bounded concurrency/metrics in newer proxy.py versions even if
    # they do not expose main().
    server_type = getattr(module, "LimitedThreadingHTTPServer", None)
    if isinstance(server_type, type) and issubclass(server_type, ThreadingHTTPServer):
        server = server_type((bind_host, port), handler)
    else:
        server = DeploymentThreadingHTTPServer((bind_host, port), handler, backlog)

    typed_server = cast(ThreadingHTTPServer, server)
    _install_signal_handlers(typed_server)

    host, bound_port = typed_server.server_address[:2]
    _log(
        "info",
        "server_started",
        mode="compatibility",
        bind=str(host),
        port=int(bound_port),
        handler=handler.__name__,
        server=type(typed_server).__name__,
        pid=os.getpid(),
    )

    try:
        typed_server.serve_forever(poll_interval=0.5)
    finally:
        typed_server.server_close()
        _log("info", "server_stopped")


def _delegate_to_proxy_main(module: ModuleType, bind_host: str, port: int) -> bool:
    main_function = getattr(module, "main", None)
    if not callable(main_function):
        return False

    # Keep both environment and module globals consistent before delegation.
    os.environ["PORT"] = str(port)
    os.environ["BIND_HOST"] = bind_host
    setattr(module, "PORT", port)
    if hasattr(module, "BIND_HOST"):
        setattr(module, "BIND_HOST", bind_host)

    _log(
        "info",
        "delegating_to_proxy_main",
        bind=bind_host,
        port=port,
        module=getattr(module, "__file__", "proxy.py"),
        pid=os.getpid(),
    )
    main_function()
    return True


def main() -> int:
    _configure_stdio()

    try:
        port = _env_int("PORT", DEFAULT_PORT, 1, 65535)
        backlog = _env_int("SERVER_BACKLOG", DEFAULT_BACKLOG, 16, 65535)
        bind_host = _resolve_bind_host()
        proxy_path = _resolve_proxy_path()

        module = _load_proxy_module(proxy_path, port, bind_host)

        # Best path: let the production proxy own its server lifecycle. The
        # fallback exists for the older simple proxy.py supplied by the app.
        if not _delegate_to_proxy_main(module, bind_host, port):
            _run_legacy_proxy(module, bind_host, port, backlog)
        return 0

    except KeyboardInterrupt:
        _log("info", "keyboard_interrupt")
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        error_fields: Dict[str, object] = {
            "error_type": type(exc).__name__,
            "message": str(exc),
        }
        if isinstance(exc, OSError):
            error_fields["errno"] = exc.errno
            if exc.errno in {getattr(socket, "EADDRINUSE", 98), 48, 10048}:
                error_fields["hint"] = "The configured port is already in use"
        _log("critical", "startup_failed", **error_fields)
        return 1
    except BaseException as exc:
        _log(
            "critical",
            "unexpected_fatal_error",
            error_type=type(exc).__name__,
            message=str(exc),
            traceback=traceback.format_exc(limit=20),
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
