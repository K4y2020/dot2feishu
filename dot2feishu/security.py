"""Standard Webhooks signing and SSRF-resistant, bounded HTTPS callbacks.

The callback transport does not use environment proxies, connection pooling, or
redirects. Each call resolves the allowlisted hostname afresh, rejects the whole
answer if *any* address is non-public, and connects to one of those numeric IPs
while verifying TLS against the original hostname. Inject a ``WebhookTransport``
implementation into application services to test delivery without network I/O.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import http.client
import ipaddress
import math
import queue
import re
import socket
import ssl
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import SplitResult, urlsplit

MAX_BODY_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
_MAX_URL_LENGTH = 8192
_MAX_HEADER_BYTES = 16 * 1024
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_RESOLVER_SLOTS = threading.BoundedSemaphore(8)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class SecurityError(ValueError):
    """Invalid signing material, unsafe callback destination, or unsafe input."""


class TransportError(RuntimeError):
    """A callback could not finish; ``reason`` is safe for a public error code."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class WebhookResponse:
    status: int
    body: bytes


class WebhookTransport(Protocol):
    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> WebhookResponse: ...


def validate_secret(secret: str) -> bytes:
    """Decode a canonical, standard-base64 ``whsec_`` key of 24–64 bytes."""
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        raise SecurityError("Signing secret must start with whsec_")
    encoded = secret[6:]
    if not 32 <= len(encoded) <= 88:
        raise SecurityError("Signing key must contain 24 to 64 bytes")
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise SecurityError("Signing secret must use standard base64") from None
    if not 24 <= len(key) <= 64:
        raise SecurityError("Signing key must contain 24 to 64 bytes")
    if base64.b64encode(key).decode("ascii") != encoded:
        raise SecurityError("Signing secret must use canonical base64")
    return key


def _header_token(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(not 33 <= ord(char) <= 126 for char in value)
    ):
        raise SecurityError(f"Invalid {name}")
    return value


def _timestamp_text(timestamp: int | str) -> str:
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, str)):
        raise SecurityError("Signing timestamp must be Unix seconds")
    text = str(timestamp)
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", text):
        raise SecurityError("Signing timestamp must be Unix seconds")
    return text


def sign_webhook(secret: str, webhook_id: str, timestamp: int | str, body: bytes) -> str:
    """Sign the exact bytes sent on the wire using Standard Webhooks v1."""
    if not isinstance(body, bytes):
        raise SecurityError("Webhook body must be immutable bytes")
    if len(body) > MAX_BODY_BYTES:
        raise SecurityError("Webhook body exceeds 256 KiB")
    key = validate_secret(secret)
    webhook_id = _header_token(webhook_id, "webhook ID")
    stamp = _timestamp_text(timestamp)
    message = webhook_id.encode("ascii") + b"." + stamp.encode("ascii") + b"." + body
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return "v1," + base64.b64encode(digest).decode("ascii")


def signed_headers(
    secret: str,
    webhook_id: str,
    timestamp: int | str,
    body: bytes,
    subscription_id: str,
    *,
    previous_secret: str | None = None,
) -> dict[str, str]:
    """Build headers, optionally signing with both keys during rotation.

    The caller owns rotation-window expiration. Duplicate keys produce only one
    signature. All signatures use the same ID, timestamp, and exact body bytes.
    """
    signature = sign_webhook(secret, webhook_id, timestamp, body)
    if previous_secret is not None and previous_secret != secret:
        signature += " " + sign_webhook(previous_secret, webhook_id, timestamp, body)
    return {
        "Content-Type": "application/json",
        "webhook-id": webhook_id,
        "webhook-timestamp": _timestamp_text(timestamp),
        "webhook-signature": signature,
        "X-MCP-Subscription-Id": _header_token(subscription_id, "subscription ID"),
    }


def _hostname(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise SecurityError("Invalid allowed hostname")
    host = value.lower()
    if not host.isascii() or any(not _HOST_LABEL.fullmatch(label) for label in host.split(".")):
        raise SecurityError("Callback host must be an exact ASCII DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SecurityError("Callback IP literals are not allowed")
    return host


def validate_callback_url(url: str, allowed_hosts: Iterable[str]) -> SplitResult:
    """Validate URL syntax and exact hostname allowlist; no DNS or network I/O.

    Unicode hosts must be configured and supplied as ASCII IDNA hostnames.
    Public DNS validation is deliberately repeated by every ``post`` call.
    """
    if isinstance(allowed_hosts, str):
        raise SecurityError("Allowed hosts must be an iterable of hostnames")
    allowed = frozenset(_hostname(host) for host in allowed_hosts)
    if not allowed:
        raise SecurityError("At least one allowed callback hostname is required")
    if (
        not isinstance(url, str)
        or not 1 <= len(url) <= _MAX_URL_LENGTH
        or not url.isascii()
        or any(ord(char) <= 32 or ord(char) == 127 for char in url)
        or "\\" in url
        or "#" in url
    ):
        raise SecurityError("Invalid callback URL")
    try:
        parts = urlsplit(url)
        port = parts.port
        if parts.scheme != "https" or not parts.hostname:
            raise SecurityError("Callbacks require HTTPS")
        if parts.username is not None or parts.password is not None:
            raise SecurityError("Callback URLs must not contain credentials")
        host = _hostname(parts.hostname)
        if port not in (None, 443):
            raise SecurityError("Callbacks require port 443")
        if parts.netloc.lower() not in (host, host + ":443"):
            raise SecurityError("Invalid callback authority")
        if host not in allowed:
            raise SecurityError("Callback hostname is not allowed")
    except ValueError as exc:
        if isinstance(exc, SecurityError):
            raise
        raise SecurityError("Invalid callback URL") from None
    return parts


def _public_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise SecurityError("DNS returned an invalid IP address") from None
    if (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
    ):
        raise SecurityError("Callback DNS must contain only public addresses")
    if isinstance(address, ipaddress.IPv6Address) and (
        address.scope_id is not None
        or address.is_site_local
        or address.ipv4_mapped is not None
        or address.sixtofour is not None
        or address.teredo is not None
        or address in _NAT64
    ):
        raise SecurityError("Callback DNS must not use scoped or transition addresses")
    return address


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TransportError("timeout")
    return left


def _resolve_public_addresses(host: str, deadline: float) -> list[tuple[int, tuple]]:
    """Bound system DNS latency and the number of unresolved worker threads.

    libc DNS resolution cannot be cancelled portably. A bounded number of daemon
    workers prevents a stuck resolver from blocking shutdown or growing without
    limit. Such workers perform DNS only; they never initiate a callback.
    """
    _remaining(deadline)
    slots = _RESOLVER_SLOTS
    if not slots.acquire(blocking=False):
        raise TransportError("dns_busy")
    result: queue.Queue = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            records = socket.getaddrinfo(
                host,
                443,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
            result.put((records, None))
        except Exception as exc:  # noqa: BLE001 - redact arbitrary resolver failures
            result.put((None, exc))
        finally:
            slots.release()

    worker = threading.Thread(target=resolve, name="webhook-dns", daemon=True)
    try:
        worker.start()
    except Exception:  # noqa: BLE001 - boundary must redact arbitrary SDK/transport exceptions
        slots.release()
        raise TransportError("dns_failed") from None
    try:
        records, error = result.get(timeout=_remaining(deadline))
    except queue.Empty:
        raise TransportError("timeout") from None
    if error is not None or not records:
        raise TransportError("dns_failed")
    addresses: list[tuple[int, tuple]] = []
    for family, socktype, proto, _canonical, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6) or socktype != socket.SOCK_STREAM:
            raise SecurityError("DNS returned an unsupported address")
        address = _public_address(sockaddr[0])
        if family == socket.AF_INET and address.version == 4:
            pinned = (str(address), 443)
        elif family == socket.AF_INET6 and address.version == 6:
            if len(sockaddr) != 4 or sockaddr[3] != 0:
                raise SecurityError("DNS returned a scoped address")
            pinned = (str(address), 443, 0, 0)
        else:
            raise SecurityError("DNS returned an inconsistent address family")
        item = (family, pinned)
        if item not in addresses:
            addresses.append(item)
    _remaining(deadline)
    return addresses


class _BoundedMetadataReader:
    """Cap status, header, chunk-size, and trailer lines while parsing them."""

    def __init__(self, reader):
        self._reader = reader
        self._remaining_metadata = _MAX_HEADER_BYTES

    def readline(self, size: int = -1) -> bytes:
        limit = self._remaining_metadata + 1
        if size >= 0:
            limit = min(limit, size)
        line = self._reader.readline(limit)
        self._remaining_metadata -= len(line)
        if self._remaining_metadata < 0:
            raise TransportError("response_too_large")
        return line

    def __getattr__(self, name):
        return getattr(self._reader, name)


class _BoundedHTTPResponse(http.client.HTTPResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fp = _BoundedMetadataReader(self.fp)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    response_class = _BoundedHTTPResponse

    def __init__(self, host: str, addresses: list[tuple[int, tuple]], deadline: float):
        super().__init__(host, 443, timeout=_remaining(deadline), context=ssl.create_default_context())
        self._addresses = addresses
        self._deadline = deadline
        # HTTPConnection detaches self.sock for Connection: close responses.
        # Retain it so the hard deadline also interrupts the response body.
        self._active_socket = None

    def connect(self) -> None:
        # No hostname is handed to a TCP connection helper: no second DNS lookup.
        # Do not retry an HTTP POST here. Address fallback is connection-only.
        for family, sockaddr in self._addresses:
            raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self.sock = raw
            self._active_socket = raw
            try:
                raw.settimeout(_remaining(self._deadline))
                raw.connect(sockaddr)
                raw.settimeout(_remaining(self._deadline))
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                self._active_socket = self.sock
                self.sock.settimeout(_remaining(self._deadline))
                return
            except (OSError, TransportError):
                if self._active_socket is not None:
                    self._active_socket.close()
                raw.close()
                self.sock = None
                self._active_socket = None
                _remaining(self._deadline)
        raise TransportError("connection_failed")

    def abort(self) -> None:
        """Interrupt even a peer trickling bytes below an inactivity timeout."""
        sock = self._active_socket
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


def _request_headers(headers: Mapping[str, str], host: str) -> dict[str, str]:
    outgoing: dict[str, str] = {}
    seen: set[str] = set()
    length = 0
    reserved = {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "upgrade",
        "te",
        "trailer",
        "expect",
        "accept-encoding",
    }
    if len(headers) > 100:
        raise SecurityError("Too many callback headers")
    for name, value in headers.items():
        if (
            not isinstance(name, str)
            or not _HEADER_NAME.fullmatch(name)
            or not isinstance(value, str)
            or not value.isascii()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise SecurityError("Invalid callback header")
        lower = name.lower()
        if lower in reserved or lower in seen:
            raise SecurityError("Conflicting callback header")
        seen.add(lower)
        length += len(name) + len(value) + 4
        if length > _MAX_HEADER_BYTES:
            raise SecurityError("Callback headers are too large")
        outgoing[name] = value
    outgoing.update({"Host": host, "Connection": "close", "Accept-Encoding": "identity"})
    return outgoing


class SafeWebhookTransport:
    """A small synchronous HTTPS transport with a hard per-call time budget.

    ``allowed_hosts`` must be operator-configured exact DNS hostnames, not values
    copied from untrusted subscription requests. Limits may be reduced, but not
    raised above the protocol's 256 KiB request/response safety cap. A redirect is
    returned as an ordinary non-success response and is never followed.
    """

    def __init__(
        self,
        allowed_hosts: Iterable[str],
        *,
        timeout: float = 10.0,
        max_body_bytes: int = MAX_BODY_BYTES,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ):
        if isinstance(allowed_hosts, str):
            raise SecurityError("Allowed hosts must be an iterable of hostnames")
        self.allowed_hosts = frozenset(_hostname(host) for host in allowed_hosts)
        if not self.allowed_hosts:
            raise SecurityError("At least one allowed callback hostname is required")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 60
        ):
            raise SecurityError("Callback timeout must be finite and between 0 and 60 seconds")
        for limit in (max_body_bytes, max_response_bytes):
            if isinstance(limit, bool) or not isinstance(limit, int) or not 0 < limit <= MAX_BODY_BYTES:
                raise SecurityError("Callback size limits must be between 1 byte and 256 KiB")
        self.timeout = float(timeout)
        self.max_body_bytes = max_body_bytes
        self.max_response_bytes = max_response_bytes

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> WebhookResponse:
        if not isinstance(body, bytes) or len(body) > self.max_body_bytes:
            raise SecurityError("Webhook body must be bytes within the configured size limit")
        parts = validate_callback_url(url, self.allowed_hosts)
        assert parts.hostname is not None
        host = parts.hostname.lower()
        outgoing = _request_headers(headers, host)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        deadline = time.monotonic() + self.timeout
        addresses = _resolve_public_addresses(host, deadline)
        connection = _PinnedHTTPSConnection(host, addresses, deadline)
        expired = threading.Event()

        def abort() -> None:
            expired.set()
            connection.abort()

        timer = threading.Timer(_remaining(deadline), abort)
        timer.daemon = True
        timer.start()
        response = None
        try:
            connection.request("POST", path, body=body, headers=outgoing)
            response = connection.getresponse()
            declared_length = response.getheader("Content-Length")
            if declared_length and re.fullmatch(r"[0-9]+", declared_length):
                # Compare decimal strings rather than parsing an arbitrarily
                # large integer supplied by a hostile server.
                declared_length = declared_length.lstrip("0") or "0"
                limit = str(self.max_response_bytes)
                if len(declared_length) > len(limit) or (
                    len(declared_length) == len(limit) and declared_length > limit
                ):
                    raise TransportError("response_too_large")
            data = response.read(self.max_response_bytes + 1)
            if len(data) > self.max_response_bytes:
                raise TransportError("response_too_large")
            _remaining(deadline)
            return WebhookResponse(status=response.status, body=data)
        except (OSError, http.client.HTTPException, TransportError) as exc:
            if expired.is_set() or time.monotonic() >= deadline or isinstance(exc, TimeoutError):
                raise TransportError("timeout") from None
            if isinstance(exc, TransportError):
                raise
            raise TransportError("connection_failed") from None
        finally:
            timer.cancel()
            if response is not None:
                response.close()
            connection.close()
