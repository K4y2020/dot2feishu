"""Offline security regression tests: sockets and DNS are always replaced."""

import base64
import http.client
import io
import socket
import ssl
import threading
import time

import pytest

from dot2feishu import security
from dot2feishu.security import (
    SafeWebhookTransport,
    SecurityError,
    TransportError,
    WebhookResponse,
    sign_webhook,
    signed_headers,
    validate_callback_url,
    validate_secret,
)

SECRET = "whsec_" + base64.b64encode(b"0123456789abcdefghijklmn").decode()
PREVIOUS = "whsec_" + base64.b64encode(b"p" * 32).decode()
HOST = "receiver.example.com"
URL = f"https://{HOST}/events?token=example"
BODY = b'{"data":"hello"}'
PUBLIC_V4 = "8.8.8.8"
PUBLIC_V6 = "2001:4860:4860::8888"


@pytest.fixture(autouse=True)
def prohibit_live_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Unit tests must not access DNS or sockets")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "socket", blocked)


@pytest.mark.parametrize("size", [24, 25, 32, 48, 63, 64])
def test_secret_accepted_boundaries(size):
    key = b"x" * size
    assert validate_secret("whsec_" + base64.b64encode(key).decode()) == key


@pytest.mark.parametrize(
    "secret",
    [
        None,
        42,
        b"whsec_abc",
        "",
        "x" * 32,
        "whsec_",
        "whsec_" + "!" * 32,
        "whsec_" + base64.b64encode(b"a" * 23).decode(),
        "whsec_" + base64.b64encode(b"a" * 65).decode(),
        SECRET + "=",
        SECRET + "\n",
        SECRET.replace("M", "é", 1),
        "whsec_" + base64.urlsafe_b64encode(b"\xff" * 32).decode(),
        "whsec_" + base64.b64encode(b"x" * 25).decode().rstrip("="),
        "whsec_" + base64.b64encode(b"x" * 25).decode()[:-3] + "B==",
    ],
)
def test_secret_rejected(secret):
    with pytest.raises(SecurityError):
        validate_secret(secret)


def test_standard_webhooks_fixed_vector():
    # Independent fixed vector: HMAC-SHA256(key, b'evt_123.1720000000.' + BODY).
    assert sign_webhook(SECRET, "evt_123", 1720000000, BODY) == (
        "v1,ux26gV4BCd/Rlu42NucAkzBCbta84kuBdH4eJqhWR1c="
    )
    assert sign_webhook(SECRET, "evt_123", "1720000000", BODY) == sign_webhook(
        SECRET, "evt_123", 1720000000, BODY
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", ""),
        ("id", "a\r\nInjected: x"),
        ("id", "a b"),
        ("id", "é"),
        ("id", "a" * 257),
        ("id", 1),
        ("timestamp", True),
        ("timestamp", -1),
        ("timestamp", "01"),
        ("timestamp", "1.0"),
        ("timestamp", 1.0),
        ("timestamp", "1\n"),
        ("body", "hello"),
        ("body", bytearray(b"hello")),
        ("body", b"x" * (256 * 1024 + 1)),
    ],
)
def test_signature_rejects_unsafe_inputs(field, value):
    values = {"id": "evt_123", "timestamp": 1720000000, "body": BODY}
    values[field] = value
    with pytest.raises(SecurityError):
        sign_webhook(SECRET, values["id"], values["timestamp"], values["body"])


def test_signature_covers_exact_body_id_and_timestamp():
    original = sign_webhook(SECRET, "evt_123", 1720000000, BODY)
    assert original != sign_webhook(SECRET, "evt_124", 1720000000, BODY)
    assert original != sign_webhook(SECRET, "evt_123", 1720000001, BODY)
    assert original != sign_webhook(SECRET, "evt_123", 1720000000, BODY + b" ")


def test_single_and_dual_signed_headers():
    single = signed_headers(SECRET, "evt_123", 1720000000, BODY, "sub_123")
    assert single == {
        "Content-Type": "application/json",
        "webhook-id": "evt_123",
        "webhook-timestamp": "1720000000",
        "webhook-signature": sign_webhook(SECRET, "evt_123", 1720000000, BODY),
        "X-MCP-Subscription-Id": "sub_123",
    }
    dual = signed_headers(SECRET, "evt_123", 1720000000, BODY, "sub_123", previous_secret=PREVIOUS)
    assert dual["webhook-signature"].split(" ") == [
        sign_webhook(SECRET, "evt_123", 1720000000, BODY),
        sign_webhook(PREVIOUS, "evt_123", 1720000000, BODY),
    ]
    assert signed_headers(SECRET, "evt_123", 1720000000, BODY, "sub_123", previous_secret=SECRET) == single
    with pytest.raises(SecurityError):
        signed_headers(SECRET, "evt_123", 1720000000, BODY, "sub_123\n")
    with pytest.raises(SecurityError):
        signed_headers(SECRET, "evt_123", 1720000000, BODY, "sub_123", previous_secret="invalid")


@pytest.mark.parametrize(
    "url",
    [
        URL,
        f"https://{HOST}:443/callback",
        f"HTTPS://{HOST.upper()}/callback",
        f"https://{HOST}",
        f"https://{HOST}/some%20path?q=a%2Fb",
    ],
)
def test_callback_url_accepts_exact_hostname(url):
    assert validate_callback_url(url, [HOST]).hostname.lower() == HOST


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        f"http://{HOST}/",
        f"ftp://{HOST}/",
        f"//{HOST}/",
        f"https://user@{HOST}/",
        f"https://user:password@{HOST}/",
        f"https://{HOST}:444/",
        f"https://{HOST}:0443/",
        f"https://{HOST}:/",
        f"https://{HOST}:invalid/",
        f"https://{HOST}/#",
        f"https://{HOST}/#x",
        f"https://{HOST}.evil.com/",
        f"https://sub.{HOST}/",
        f"https://{HOST}./",
        f"https://{HOST}%2e/",
        f"https://{HOST}/\nabc",
        f" https://{HOST}/",
        f"https://{HOST}/a b",
        f"https://{HOST}/a\x7fb",
        f"https://{HOST}\\evil.com/",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://[2001:4860:4860::8888]/",
        "https://8.8.8.8/",
        "https://réceiver.example.com/",
        "https://[broken/",
        f"https://{HOST}/" + "x" * 8192,
    ],
)
def test_callback_url_rejects_unsafe_syntax_and_destinations(url):
    with pytest.raises(SecurityError):
        validate_callback_url(url, [HOST])


@pytest.mark.parametrize(
    "hosts",
    [
        [],
        HOST,
        ["*.example.com"],
        ["https://example.com"],
        ["8.8.8.8"],
        ["example.com."],
        ["bad_label.com"],
        ["-bad.example"],
    ],
)
def test_invalid_allowlist_fails_closed(hosts):
    with pytest.raises(SecurityError):
        SafeWebhookTransport(hosts)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": float("inf")},
        {"timeout": float("nan")},
        {"timeout": True},
        {"timeout": 61},
        {"max_body_bytes": 262145},
        {"max_response_bytes": 262145},
        {"max_response_bytes": 0},
        {"max_body_bytes": True},
    ],
)
def test_transport_limits_cannot_be_disabled(kwargs):
    with pytest.raises(SecurityError):
        SafeWebhookTransport([HOST], **kwargs)


def dns_record(address):
    if ":" in address:
        return socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443, 0, 0)
    return socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443)


def test_dns_accepts_public_addresses_and_deduplicates(monkeypatch):
    calls = []

    def resolver(*args, **kwargs):
        calls.append((args, kwargs))
        return [dns_record(PUBLIC_V4), dns_record(PUBLIC_V6), dns_record(PUBLIC_V4)]

    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    actual = security._resolve_public_addresses(HOST, time.monotonic() + 2)
    assert actual == [
        (socket.AF_INET, (PUBLIC_V4, 443)),
        (socket.AF_INET6, (PUBLIC_V6, 443, 0, 0)),
    ]
    assert calls == [
        ((HOST, 443), {"family": socket.AF_UNSPEC, "type": socket.SOCK_STREAM, "proto": socket.IPPROTO_TCP})
    ]


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "224.0.0.1",
        "239.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "::ffff:8.8.8.8",
        "2002:7f00:1::",
        "2002:0808:0808::",
        "64:ff9b::7f00:1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "2001:4860:4860::8888%eth0",
        "not-an-ip",
    ],
)
def test_one_nonpublic_dns_answer_rejects_entire_destination(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [dns_record(PUBLIC_V4), dns_record(address)])
    with pytest.raises(SecurityError):
        security._resolve_public_addresses(HOST, time.monotonic() + 2)


def test_dns_timeout_is_bounded_without_waiting_for_libc(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: release.wait(2))
    start = time.monotonic()
    try:
        with pytest.raises(TransportError, match="timeout"):
            security._resolve_public_addresses(HOST, start + 0.02)
        assert time.monotonic() - start < 0.5
    finally:
        release.set()


def test_dns_concurrency_is_bounded(monkeypatch):
    monkeypatch.setattr(security, "_RESOLVER_SLOTS", threading.BoundedSemaphore(1))
    assert security._RESOLVER_SLOTS.acquire(False)
    with pytest.raises(TransportError, match="dns_busy"):
        security._resolve_public_addresses(HOST, time.monotonic() + 1)


@pytest.mark.parametrize(
    "records",
    [
        [],
        [dns_record(PUBLIC_V4)[:1] + (socket.SOCK_DGRAM,) + dns_record(PUBLIC_V4)[2:]],
        [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (PUBLIC_V6, 443, 0, 1))],
    ],
)
def test_dns_missing_or_unsupported_records_fail(monkeypatch, records):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: records)
    with pytest.raises((TransportError, SecurityError)):
        security._resolve_public_addresses(HOST, time.monotonic() + 2)


def test_dns_exception_is_sanitized(monkeypatch):
    def resolver(*a, **k):
        raise socket.gaierror("sensitive hostname details")

    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    with pytest.raises(TransportError) as caught:
        security._resolve_public_addresses(HOST, time.monotonic() + 2)
    assert str(caught.value) == "dns_failed"


class FakeResponse:
    def __init__(self, status=200, body=b'{"challenge":"ok"}', declared=None):
        self.status, self.body, self.declared = status, body, declared
        self.read_sizes = []
        self.closed = False

    def getheader(self, name):
        assert name == "Content-Length"
        return self.declared

    def read(self, limit):
        self.read_sizes.append(limit)
        return self.body[:limit]

    def close(self):
        self.closed = True


@pytest.fixture
def fake_transport_io(monkeypatch):
    class FakeConnection:
        calls = []  # noqa: RUF012 - fixture-local fake queue
        resolutions = []  # noqa: RUF012 - fixture-local fake queue
        response = FakeResponse()
        failure = None

        def __init__(self, host, addresses, deadline):
            self.host, self.addresses, self.deadline = host, addresses, deadline
            self.closed = self.aborted = False
            self.calls.append(self)

        def request(self, method, path, body, headers):
            self.request_args = method, path, body, headers
            if self.failure:
                raise self.failure

        def getresponse(self):
            return self.response

        def abort(self):
            self.aborted = True

        def close(self):
            self.closed = True

    def resolve(host, deadline):
        FakeConnection.resolutions.append((host, deadline))
        return [(socket.AF_INET, (PUBLIC_V4, 443))]

    monkeypatch.setattr(security, "_resolve_public_addresses", resolve)
    monkeypatch.setattr(security, "_PinnedHTTPSConnection", FakeConnection)
    return FakeConnection


def test_transport_preserves_exact_body_and_hostname(fake_transport_io):
    body = b'{"text":"Unicode \\u2603"}\n'
    headers = signed_headers(SECRET, "evt_123", 1720000000, body, "sub_1")
    result = SafeWebhookTransport([HOST]).post(URL, body, headers)
    assert result == WebhookResponse(200, b'{"challenge":"ok"}')
    conn = fake_transport_io.calls[0]
    method, path, sent, outbound = conn.request_args
    assert (method, path) == ("POST", "/events?token=example")
    assert sent is body
    assert outbound["Host"] == HOST
    assert outbound["Connection"] == "close"
    assert outbound["Accept-Encoding"] == "identity"
    assert outbound["webhook-signature"] == headers["webhook-signature"]
    assert conn.closed
    assert conn.response.closed
    assert conn.response.read_sizes == [262145]


def test_transport_resolves_every_delivery(fake_transport_io):
    transport = SafeWebhookTransport([HOST])
    transport.post(URL, BODY, {})
    transport.post(URL, BODY, {})
    assert len(fake_transport_io.resolutions) == len(fake_transport_io.calls) == 2


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308, 410, 413, 429, 500])
def test_transport_returns_status_without_redirect_or_retry(fake_transport_io, status):
    fake_transport_io.response = FakeResponse(status, b"")
    assert SafeWebhookTransport([HOST]).post(URL, BODY, {}).status == status
    assert len(fake_transport_io.calls) == 1


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "evil.example"},
        {"CONTENT-LENGTH": "0"},
        {"Transfer-Encoding": "chunked"},
        {"Proxy-Authorization": "secret"},
        {"Accept-Encoding": "gzip"},
        {"Connection": "upgrade"},
        {"X-Test": "x\r\nHost: evil.example"},
        {"Bad\nName": "test"},
        {"X-Test": "é"},
        {"X-Test": "ok", "x-test": "other"},
        {"X-Test": "\x00"},
        {"X-Test": "x" * 16385},
        {f"X-{i}": "x" for i in range(101)},
    ],
)
def test_transport_rejects_header_injection_before_dns(fake_transport_io, headers):
    with pytest.raises(SecurityError):
        SafeWebhookTransport([HOST]).post(URL, BODY, headers)
    assert not fake_transport_io.resolutions


def test_transport_enforces_request_limit_before_dns(fake_transport_io):
    with pytest.raises(SecurityError):
        SafeWebhookTransport([HOST]).post(URL, b"x" * 262145, {})
    assert not fake_transport_io.resolutions
    assert SafeWebhookTransport([HOST]).post(URL, b"x" * 262144, {}).status == 200


@pytest.mark.parametrize("declared", [None, "262145"])
def test_transport_bounds_response(fake_transport_io, declared):
    fake_transport_io.response = FakeResponse(body=b"x" * 262145, declared=declared)
    with pytest.raises(TransportError, match="response_too_large"):
        SafeWebhookTransport([HOST]).post(URL, BODY, {})
    assert fake_transport_io.calls[0].closed
    if declared:
        assert fake_transport_io.response.read_sizes == []


def test_transport_rejects_huge_decimal_content_length(fake_transport_io):
    fake_transport_io.response = FakeResponse(body=b"", declared="9" * 5000)
    with pytest.raises(TransportError, match="response_too_large"):
        SafeWebhookTransport([HOST]).post(URL, BODY, {})
    assert fake_transport_io.response.closed


@pytest.mark.parametrize("declared", ["0" * 5000 + "2", "²", "-1", "invalid"])
def test_transport_handles_invalid_or_zero_padded_lengths(fake_transport_io, declared):
    fake_transport_io.response = FakeResponse(body=b"ok", declared=declared)
    assert SafeWebhookTransport([HOST]).post(URL, BODY, {}).body == b"ok"


def test_transport_permits_exact_response_boundary(fake_transport_io):
    fake_transport_io.response = FakeResponse(body=b"x" * 262144)
    assert len(SafeWebhookTransport([HOST]).post(URL, BODY, {}).body) == 262144


@pytest.mark.parametrize(
    "error,reason",
    [
        (TimeoutError("details"), "timeout"),
        (OSError("details"), "connection_failed"),
        (http.client.BadStatusLine("secret details"), "connection_failed"),
    ],
)
def test_transport_errors_sanitized_and_connection_closed(fake_transport_io, error, reason):
    fake_transport_io.failure = error
    with pytest.raises(TransportError) as caught:
        SafeWebhookTransport([HOST]).post(URL, BODY, {})
    assert str(caught.value) == reason
    assert fake_transport_io.calls[0].closed


def test_hard_deadline_interrupts_trickling_response(fake_transport_io):
    class SlowResponse(FakeResponse):
        def read(self, limit):
            end = time.monotonic() + 0.5
            while time.monotonic() < end:
                if fake_transport_io.calls[0].aborted:
                    raise OSError("closed")
                time.sleep(0.002)
            raise AssertionError("hard timer failed to abort")

    fake_transport_io.response = SlowResponse()
    with pytest.raises(TransportError, match="timeout"):
        SafeWebhookTransport([HOST], timeout=0.02).post(URL, BODY, {})
    assert fake_transport_io.calls[0].aborted
    assert fake_transport_io.calls[0].closed


def test_connection_pins_numeric_ip_and_keeps_tls_hostname(monkeypatch):
    created, wrapped = [], []

    class FakeSocket:
        def __init__(self, family, kind, proto):
            self.args = family, kind, proto
            self.timeouts = []
            self.closed = False
            created.append(self)

        def settimeout(self, timeout):
            self.timeouts.append(timeout)

        def connect(self, target):
            self.target = target

        def close(self):
            self.closed = True

        def shutdown(self, how):
            self.shutdown_how = how

    class FakeContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, sock, server_hostname):
            wrapped.append((sock, server_hostname))
            return sock

    monkeypatch.setattr(socket, "socket", FakeSocket)
    monkeypatch.setattr(ssl, "create_default_context", FakeContext)
    conn = security._PinnedHTTPSConnection(HOST, [(socket.AF_INET, (PUBLIC_V4, 443))], time.monotonic() + 2)
    conn.connect()
    assert created[0].args == (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    assert created[0].target == (PUBLIC_V4, 443)
    assert wrapped == [(created[0], HOST)]
    assert all(0 < timeout <= 2 for timeout in created[0].timeouts)
    conn.abort()
    assert created[0].shutdown_how == socket.SHUT_RDWR
    assert created[0].closed

    # getresponse() can detach the socket for Connection: close. The deadline
    # must still be able to interrupt its file-backed HTTPResponse reader.
    del created[0].shutdown_how
    conn.sock = None
    conn.abort()
    assert created[0].shutdown_how == socket.SHUT_RDWR


def test_production_tls_context_verifies_certificates():
    conn = security._PinnedHTTPSConnection(HOST, [(socket.AF_INET, (PUBLIC_V4, 443))], time.monotonic() + 2)
    assert conn._context.verify_mode == ssl.CERT_REQUIRED
    assert conn._context.check_hostname is True
    conn.close()


class WireSocket:
    def __init__(self, wire):
        self.reader = io.BytesIO(wire)

    def makefile(self, mode):
        assert mode == "rb"
        return self.reader


def test_real_http_parser_uses_bounded_metadata_reader():
    sock = WireSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    response = security._BoundedHTTPResponse(sock)
    response.begin()
    assert response.status == 200
    assert response.read(262145) == b"ok"
    response.close()
    assert sock.reader.closed


@pytest.mark.parametrize(
    "wire",
    [
        b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 16384 + b"\r\n\r\n",
        (b"HTTP/1.1 100 Continue\r\nX-Fill: " + b"x" * 256 + b"\r\n\r\n") * 100,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        + b"1;"
        + b"x" * 16384
        + b"\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: " + b"x" * 16384 + b"\r\n\r\n",
    ],
    ids=["large-header", "many-interim", "large-chunk-extension", "large-trailer"],
)
def test_real_http_parser_bounds_headers_interim_responses_and_chunk_metadata(wire):
    response = security._BoundedHTTPResponse(WireSocket(wire))
    try:
        with pytest.raises(TransportError, match="response_too_large"):
            response.begin()
            response.read(262145)
    finally:
        response.close()


@pytest.mark.parametrize("slow_body", [False, True])
def test_transport_real_http_connection_close_flow_keeps_deadline(monkeypatch, slow_body):
    """Exercise the real stdlib connection/parser with a wholly offline socket."""
    interrupted = threading.Event()
    wire = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
    created = []

    class Reader(io.BytesIO):
        def read(self, size=-1):
            if slow_body:
                if not interrupted.wait(0.5):
                    raise AssertionError("Detached response socket missed hard deadline")
                raise OSError("socket shut down")
            return super().read(size)

    class OfflineSocket:
        def __init__(self, family, kind, proto):
            self.reader = Reader(wire)
            self.sent = []
            self.closed = False
            created.append(self)

        def settimeout(self, value):
            self.timeout = value

        def connect(self, target):
            assert target == (PUBLIC_V4, 443)

        def sendall(self, data):
            self.sent.append(data)

        def makefile(self, mode):
            return self.reader

        def close(self):
            # Like a real socket: makefile retains the underlying descriptor.
            self.closed = True

        def shutdown(self, how):
            interrupted.set()

    class TLSContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, sock, server_hostname):
            assert server_hostname == HOST
            return sock

    monkeypatch.setattr(socket, "socket", OfflineSocket)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [dns_record(PUBLIC_V4)])
    monkeypatch.setattr(ssl, "create_default_context", TLSContext)
    transport = SafeWebhookTransport([HOST], timeout=0.03)
    if slow_body:
        with pytest.raises(TransportError, match="timeout"):
            transport.post(URL, BODY, {})
        assert interrupted.is_set()
    else:
        assert transport.post(URL, BODY, {}) == WebhookResponse(200, b"ok")
    assert created[0].closed
    assert created[0].reader.closed
    request = b"".join(created[0].sent)
    assert b"Host: receiver.example.com\r\n" in request
    assert request.endswith(b"\r\n\r\n" + BODY)
