"""Offline timing tests: synthetic records and callback transport only."""

import base64
import dataclasses
import json
import socket
import sqlite3
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dot2feishu.core import TIMING_SAMPLE_LIMIT, Bridge, Store
from dot2feishu.security import TransportError


@dataclasses.dataclass
class Message:
    event_id: str = "synthetic-event"
    message_id: str = "synthetic-message"
    chat_id: str = "synthetic-chat"
    sender_id: str = "synthetic-person"
    text: str = "MESSAGE-CONTENT-CANARY"
    occurred_at: str = "2026-10-08T00:00:00Z"


class Transport:
    def __init__(self):
        self.error = None
        self.status = 200

    def post(self, url, body, headers):
        if self.error:
            raise self.error
        value = json.loads(body)
        return SimpleNamespace(
            status=self.status, body=json.dumps({"challenge": value.get("challenge")}).encode()
        )


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Timing tests must not use network")

    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)


@pytest.fixture
def system(tmp_path):
    key = Fernet.generate_key()
    store = Store(tmp_path / "test.sqlite", key)
    transport = Transport()
    wall = [1000.0]
    bridge = Bridge(store, transport, principal="owner", chat_id="synthetic-chat", clock=lambda: wall[0])
    secret = "whsec_" + base64.b64encode(b"SECRET-CANARY-32-01234567890123456").decode()
    bridge.subscribe(
        "owner",
        {
            "name": "message.created",
            "arguments": {"chat_id": "synthetic-chat"},
            "delivery": {
                "mode": "webhook",
                "url": "https://example.com/CALLBACK-URL-CANARY",
                "secret": secret,
            },
            "cursor": None,
        },
    )
    yield store, bridge, transport, wall, key, secret
    store.close()


def sample(store):
    result = store.delivery_timings()
    assert result["clock"] == "same_process_monotonic"
    assert result["source_to_receiver"] == "unknown"
    return result["samples"][0]


def install_ticks(store, values):
    ticks = iter(values)
    store.monotonic_ns = lambda: next(ticks) * 1_000_000


def test_exact_same_process_stage_durations_and_no_sensitive_data(system, caplog, capsys):
    store, bridge, _, wall, _, secret = system
    install_ticks(store, [103, 150, 154, 184])
    assert store.ingest(Message(), now=wall[0], record_received_ns=100_000_000)
    assert bridge.deliver_once()
    value = sample(store)
    assert value == {
        "run_id": store.timing_run_id,
        "sequence": 1,
        "attempt": 1,
        "http_status": 200,
        "outcome": "delivered",
        "source_to_receiver_ms": None,
        "source_to_receiver": "unknown",
        "record_to_commit_ms": 3.0,
        "commit_to_claim_ms": 47.0,
        "claim_to_post_ms": 4.0,
        "post_ms": 30.0,
        "record_to_post_end_ms": 84.0,
    }
    output = json.dumps(store.delivery_timings()) + caplog.text + capsys.readouterr().out
    for forbidden in [
        Message().text,
        Message().event_id,
        Message().message_id,
        Message().chat_id,
        Message().sender_id,
        secret,
        "CALLBACK-URL-CANARY",
    ]:
        assert forbidden not in output
    assert set(value) == {
        "run_id",
        "sequence",
        "attempt",
        "http_status",
        "outcome",
        "source_to_receiver_ms",
        "source_to_receiver",
        "record_to_commit_ms",
        "commit_to_claim_ms",
        "claim_to_post_ms",
        "post_ms",
        "record_to_post_end_ms",
    }


def test_commit_timestamp_is_after_commit_and_before_unlock(system):
    store, _, _, wall, *_ = system
    seen = []

    def commit_clock():
        seen.append((store.db.in_transaction, store.lock._is_owned()))
        return 101_000_000

    store.monotonic_ns = commit_clock
    assert store.ingest(Message(), now=wall[0], record_received_ns=100_000_000)
    assert seen == [(False, True)]


def test_monotonic_durations_ignore_wall_clock_jump(system):
    store, bridge, _, wall, *_ = system
    install_ticks(store, [103, 150, 154, 184])
    store.ingest(Message(), now=wall[0], record_received_ns=100_000_000)
    wall[0] = 1012.0
    assert bridge.deliver_once()
    assert sample(store)["record_to_post_end_ms"] == 84.0


@pytest.mark.parametrize(
    "error", [TransportError("timeout"), OSError("ERROR-SECRET-CANARY"), TimeoutError("ERROR-SECRET-CANARY")]
)
def test_failure_and_retry_have_safe_separate_attempt_samples(system, error, caplog, capsys):
    store, bridge, transport, wall, *_ = system
    install_ticks(store, [103, 150, 154, 184, 2150, 2154, 2184])
    store.ingest(Message(), now=wall[0], record_received_ns=100_000_000)
    transport.error = error
    assert bridge.deliver_once()
    first = sample(store)
    assert first["http_status"] == 0 and first["outcome"] == "pending" and first["attempt"] == 1
    assert first["post_ms"] == 30.0
    transport.error = None
    wall[0] += 3
    assert bridge.deliver_once()
    values = store.delivery_timings()["samples"]
    assert [item["attempt"] for item in values] == [2, 1]
    assert values[0]["commit_to_claim_ms"] == 2047.0
    assert values[0]["outcome"] == "delivered"
    assert "ERROR-SECRET-CANARY" not in json.dumps(values) + caplog.text + capsys.readouterr().out


def test_reopen_preserves_samples_but_never_reuses_monotonic_ingress(system, tmp_path):
    store, bridge, transport, wall, key, _ = system
    install_ticks(store, [103, 150, 154, 184, 203])
    store.ingest(Message(), now=wall[0], record_received_ns=100_000_000)
    bridge.deliver_once()
    old_run = store.timing_run_id
    store.ingest(
        dataclasses.replace(Message(), event_id="event-two", message_id="message-two"),
        now=wall[0],
        record_received_ns=200_000_000,
    )
    reopened = Store(tmp_path / "test.sqlite", key)
    try:
        assert reopened.timing_run_id != old_run
        assert sample(reopened)["run_id"] == old_run
        install_ticks(reopened, [50, 54, 84])
        other_bridge = Bridge(
            reopened, transport, principal="owner", chat_id="synthetic-chat", clock=lambda: wall[0]
        )
        assert other_bridge.deliver_once()
        value = sample(reopened)
        assert value["run_id"] == reopened.timing_run_id
        assert value["record_to_commit_ms"] is None
        assert value["commit_to_claim_ms"] is None
        assert value["record_to_post_end_ms"] is None
        assert value["post_ms"] == 30.0
    finally:
        reopened.close()


def test_retention_and_ingress_cache_are_bounded(system):
    store, bridge, _, wall, *_ = system
    for n in range(TIMING_SAMPLE_LIMIT + 6):
        store.ingest(
            dataclasses.replace(Message(), event_id=f"event-{n}", message_id=f"message-{n}"),
            now=wall[0],
            record_received_ns=store.monotonic_ns(),
        )
    assert len(store._ingress_timings) == TIMING_SAMPLE_LIMIT
    assert bridge.deliver_once()
    assert sample(store)["record_to_commit_ms"] is None
    assert sample(store)["commit_to_claim_ms"] is None
    for _ in range(TIMING_SAMPLE_LIMIT + 5):
        assert bridge.deliver_once()
    assert store.db.execute("SELECT count(*) FROM delivery_timings").fetchone()[0] == TIMING_SAMPLE_LIMIT
    values = store.delivery_timings()["samples"]
    assert len(values) == TIMING_SAMPLE_LIMIT
    assert values[-1]["sequence"] == 7 and values[0]["sequence"] == 70


@pytest.mark.parametrize("received", [None, "100", True, -1, 104_000_000])
def test_missing_or_invalid_ingress_is_explicitly_unknown(system, received):
    store, bridge, _, wall, *_ = system
    install_ticks(store, [103, 150, 154, 184])
    store.ingest(Message(), now=wall[0], record_received_ns=received)
    bridge.deliver_once()
    value = sample(store)
    assert value["record_to_commit_ms"] is None
    assert value["record_to_post_end_ms"] is None
    assert value["commit_to_claim_ms"] == 47.0


def test_duplicate_does_not_replace_original_receive_time(system):
    store, bridge, _, wall, *_ = system
    install_ticks(store, [103, 150, 154, 184])
    assert store.ingest(Message(), now=wall[0], record_received_ns=100_000_000)
    assert not store.ingest(Message(), now=wall[0], record_received_ns=130_000_000)
    bridge.deliver_once()
    assert sample(store)["record_to_post_end_ms"] == 84.0


def test_failed_ingest_does_not_record_commit_or_payload(system):
    store, _, _, wall, *_ = system
    with store.db:
        store.db.execute("""CREATE TRIGGER block_insert BEFORE INSERT ON messages
            BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        store.ingest(Message(), now=wall[0], record_received_ns=100_000_000)
    assert not store._ingress_timings
    assert store.delivery_timings()["samples"] == []


@pytest.mark.parametrize("blocked_operation", ["INSERT", "DELETE"])
def test_telemetry_database_failure_cannot_undo_callback_result(system, blocked_operation):
    store, bridge, _, wall, *_ = system
    if blocked_operation == "DELETE":
        with store.db:
            store.db.executemany(
                "INSERT INTO delivery_timings(sample) VALUES(?)", [("{}",)] * TIMING_SAMPLE_LIMIT
            )
    with store.db:
        store.db.execute(f"""CREATE TRIGGER block_timing BEFORE {blocked_operation} ON delivery_timings
            BEGIN SELECT RAISE(ABORT, 'ERROR-SECRET-CANARY'); END""")
    store.ingest(Message(), now=wall[0], record_received_ns=store.monotonic_ns())
    assert bridge.deliver_once()
    row = store.db.execute("SELECT state,attempts,last_reason FROM deliveries").fetchone()
    assert tuple(row) == ("delivered", 1, "http_200")
    assert not bridge.deliver_once()
    assert store.db.execute("SELECT count(*) FROM delivery_timings").fetchone()[0] <= TIMING_SAMPLE_LIMIT


def test_telemetry_whole_transaction_abort_keeps_delivery_result(system):
    store, bridge, _, wall, *_ = system
    with store.db:
        store.db.execute("""CREATE TRIGGER abort_timing BEFORE INSERT ON delivery_timings
            BEGIN SELECT RAISE(ROLLBACK, 'ERROR-SECRET-CANARY'); END""")
    store.ingest(Message(), now=wall[0], record_received_ns=store.monotonic_ns())
    assert bridge.deliver_once()
    assert tuple(store.db.execute("SELECT state,attempts,last_reason FROM deliveries").fetchone()) == (
        "delivered",
        1,
        "http_200",
    )
    assert not bridge.deliver_once()
    assert store.delivery_timings()["samples"] == []


def test_real_sqlite_full_does_not_undo_callback_result(system):
    store, bridge, _, wall, *_ = system
    store.ingest(Message(), now=wall[0], record_received_ns=store.monotonic_ns())
    connection = store.db
    page_size = connection.execute("PRAGMA page_size").fetchone()[0]
    with connection:
        connection.execute(
            "INSERT INTO delivery_timings(sample) VALUES(?)",
            (json.dumps("x" * (page_size - 198)),),
        )
    page_count = connection.execute("PRAGMA page_count").fetchone()[0]
    assert connection.execute(f"PRAGMA max_page_count={page_count}").fetchone()[0] == page_count
    errors = []

    class ConnectionProxy:
        def __getattr__(self, name):
            return getattr(connection, name)

        def __enter__(self):
            connection.__enter__()
            return self

        def __exit__(self, *args):
            return connection.__exit__(*args)

        def execute(self, sql, parameters=()):
            try:
                return connection.execute(sql, parameters)
            except sqlite3.Error as exc:
                errors.append(exc.sqlite_errorcode)
                raise

    store.db = ConnectionProxy()
    try:
        assert bridge.deliver_once()
        assert errors == [sqlite3.SQLITE_FULL]
        assert tuple(connection.execute("SELECT state,attempts,last_reason FROM deliveries").fetchone()) == (
            "delivered",
            1,
            "http_200",
        )
        assert not bridge.deliver_once()
        assert connection.execute("SELECT COUNT(*) FROM delivery_timings").fetchone()[0] == 1
    finally:
        store.db = connection
