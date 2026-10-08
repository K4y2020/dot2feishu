import base64
import hashlib
import json
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dot2feishu.core import Bridge, BridgeError, Store

SECRET = "whsec_" + base64.b64encode(b"test-only-signing-material-32-byte").decode()
SECRET2 = "whsec_" + base64.b64encode(b"another-test-signing-material-32xx").decode()


@dataclass
class Message:
    event_id: str = "feishu-event-1"
    message_id: str = "message-1"
    chat_id: str = "private-chat"
    sender_id: str = "allowed-user"
    text: str = "private text that must be encrypted"
    occurred_at: str = "2026-10-08T04:00:00Z"


class FakeTransport:
    def __init__(self):
        self.requests = []
        self.status = 200
        self.bad_challenge = False

    def post(self, url, body, headers):
        self.requests.append((url, body, headers))
        data = json.loads(body)
        response = {"challenge": "bad" if self.bad_challenge else data.get("challenge")}
        return SimpleNamespace(status=self.status, body=json.dumps(response).encode())


@pytest.fixture
def setup(tmp_path):
    key = Fernet.generate_key()
    store = Store(tmp_path / "bridge.sqlite", key)
    transport = FakeTransport()
    now = [1000.0]
    bridge = Bridge(store, transport, principal="owner", chat_id="private-chat", clock=lambda: now[0])
    yield bridge, store, transport, now, key
    store.close()


def params(**kw):
    value = {
        "name": "message.created",
        "arguments": {"chat_id": "private-chat"},
        "delivery": {"mode": "webhook", "url": "https://callback.example/test", "secret": SECRET},
        "cursor": None,
    }
    value.update(kw)
    return value


def test_subscription_challenge_idempotency_and_encryption(setup):
    b, s, t, _now, _ = setup
    first = b.subscribe("owner", params())
    assert first["cursor"] is None
    assert first["refreshBefore"] == "1970-01-02T00:16:40Z"
    assert json.loads(t.requests[0][1])["type"] == "verification"
    assert t.requests[0][2]["X-MCP-Subscription-Id"] == first["id"]
    assert b.subscribe("owner", params())["id"] == first["id"]
    assert len(t.requests) == 1
    row = s.db.execute("SELECT * FROM subscriptions").fetchone()
    assert SECRET.encode() not in row["secret"]
    assert b"callback.example" not in row["callback"]


def test_challenge_failed_not_activated(setup):
    b, s, t, _, _ = setup
    t.bad_challenge = True
    with pytest.raises(BridgeError) as caught:
        b.subscribe("owner", params())
    assert caught.value.code == -32015
    assert s.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] == 0


@pytest.mark.parametrize(
    "change",
    [
        {"name": "other"},
        {"arguments": {"chat_id": "other"}},
        {"arguments": {"chat_id": "private-chat", "recipient": "other"}},
        {"cursor": "invented"},
        {"ttlMs": True},
        {"ttlMs": -3},
        {"delivery": {"mode": "webhook", "url": "https://callback.example", "secret": "bad"}},
    ],
)
def test_invalid_subscription_rejected(setup, change):
    with pytest.raises(BridgeError):
        setup[0].subscribe("owner", params(**change))


def test_wrong_principal_rejected(setup):
    b = setup[0]
    for action in [
        lambda: b.definition("attacker"),
        lambda: b.subscribe("attacker", params()),
        lambda: b.unsubscribe("attacker", params()),
    ]:
        with pytest.raises(BridgeError):
            action()


def test_durable_dedup_retry_order_and_small_payload(setup):
    b, s, t, now, _ = setup
    b.subscribe("owner", params())
    assert s.ingest(Message(), now=now[0])
    assert not s.ingest(Message(), now=now[0])
    assert not s.ingest(Message(event_id="redelivery-new-envelope"), now=now[0])
    assert s.ingest(Message(event_id="event-2", message_id="message-2"), now=now[0])
    t.status = 503
    assert b.deliver_once()
    first = t.requests[-1]
    assert not b.deliver_once()  # second event cannot jump a retrying first event
    now[0] += 4
    t.status = 200
    assert b.deliver_once()
    second = t.requests[-1]
    assert first[1] == second[1]
    assert first[2]["webhook-id"] == second[2]["webhook-id"]
    assert first[2]["webhook-signature"] != second[2]["webhook-signature"]
    assert b.deliver_once()
    data = json.loads(second[1])
    assert data["name"] == "message.created" and data["cursor"] is None
    assert "text" not in data["data"] and "type" not in data
    assert s.message("message-1")["text"] == Message().text
    assert Message().text.encode() not in s.db.execute("SELECT body FROM messages LIMIT 1").fetchone()[0]


def test_stop_expire_and_revocation(setup):
    b, s, t, now, _ = setup
    b.subscribe("owner", params(ttlMs=60000))
    s.ingest(Message(), now=now[0])
    assert b.unsubscribe("owner", params()) == {}
    assert b.unsubscribe("owner", params()) == {}
    assert not b.deliver_once()
    b.subscribe("owner", params(ttlMs=60000))
    s.ingest(Message(event_id="event-2", message_id="message-2"), now=now[0])
    now[0] += 61
    assert not b.deliver_once()
    b.subscribe("owner", params())
    b.authorized = lambda p, c: False
    assert b.deliver_once()
    assert not b.deliver_once()
    assert len(t.requests) == 1


def test_rotation_signs_both_secrets(setup):
    b, s, t, now, _ = setup
    first = b.subscribe("owner", params())
    new = params()
    new["delivery"]["secret"] = SECRET2
    assert b.subscribe("owner", new)["id"] == first["id"]
    s.ingest(Message(), now=now[0])
    b.deliver_once()
    assert len(t.requests[-1][2]["webhook-signature"].split(" ")) == 2
    now[0] += 301
    s.ingest(Message(event_id="event-2", message_id="message-2"), now=now[0])
    b.deliver_once()
    assert len(t.requests[-1][2]["webhook-signature"].split(" ")) == 1


@pytest.mark.parametrize("status", [410, 413, 400, 403, 301])
def test_terminal_callback_errors_do_not_retry(setup, status):
    b, s, t, now, _ = setup
    b.subscribe("owner", params())
    s.ingest(Message(), now=now[0])
    t.status = status
    b.deliver_once()
    now[0] += 10000
    assert not b.deliver_once()
    assert s.db.execute("SELECT state FROM deliveries").fetchone()[0] == "failed"


def test_retries_bounded(setup):
    b, s, t, now, _ = setup
    b.subscribe("owner", params())
    s.ingest(Message(), now=now[0])
    t.status = 503
    for i in range(8):
        assert b.deliver_once()
        now[0] += 1000
    assert not b.deliver_once()
    assert s.db.execute("SELECT attempts,state FROM deliveries").fetchone()[:] == (8, "failed")


def test_persistence_after_restart(tmp_path):
    key = Fernet.generate_key()
    path = tmp_path / "db"
    s = Store(path, key)
    t = FakeTransport()
    b = Bridge(s, t, principal="owner", chat_id="private-chat", clock=lambda: 1000)
    sid = b.subscribe("owner", params())["id"]
    s.ingest(Message(), now=1000)
    s.close()
    s = Store(path, key)
    b = Bridge(s, t, principal="owner", chat_id="private-chat", clock=lambda: 1001)
    assert b.subscribe("owner", params())["id"] == sid
    assert len(t.requests) == 1 and b.deliver_once()
    s.close()


def test_reply_bound_deduplicated_and_uncertain_failclosed(setup):
    b, s, _t, _now, _ = setup
    s.ingest(Message(), now=1000)

    class Reply:
        calls = 0

        def reply(self, mid, text, rid):
            assert mid == "message-1"
            self.calls += 1
            return "bot-reply-1"

    b.replier = Reply()
    assert b.reply_to_message("owner", "message-1", "hello")["duplicate"] is False
    assert b.reply_to_message("owner", "message-1", "hello")["duplicate"] is True
    assert b.replier.calls == 1
    with pytest.raises(BridgeError):
        b.reply_to_message("owner", "message-1", "different")
    with pytest.raises(BridgeError):
        b.reply_to_message("owner", "unrelated-message", "hello")
    with pytest.raises(BridgeError):
        b.reply_to_message("attacker", "message-1", "hello")
    s.ingest(Message(event_id="e2", message_id="m2"), now=1000)
    b.replier.reply = lambda *a: (_ for _ in ()).throw(TimeoutError())
    with pytest.raises(BridgeError) as caught:
        b.reply_to_message("owner", "m2", "hello")
    assert caught.value.code == -32010
    with pytest.raises(BridgeError):
        b.reply_to_message("owner", "m2", "hello")


def test_messages_before_subscription_are_not_replayed(setup):
    b, s, _t, _now, _ = setup
    s.ingest(Message(), now=1000)
    b.subscribe("owner", params())
    assert not b.deliver_once()


def test_concurrent_duplicate_ingest_is_one_transaction(setup):
    from concurrent.futures import ThreadPoolExecutor

    b, s, _t, _now, _ = setup
    b.subscribe("owner", params())
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: s.ingest(Message(), now=1000), range(40)))
    assert sum(outcomes) == 1
    assert s.db.execute("SELECT count(*) FROM messages").fetchone()[0] == 1
    assert s.db.execute("SELECT count(*) FROM deliveries").fetchone()[0] == 1


def test_interrupted_reply_never_resends(setup):
    b, s, _t, _now, _ = setup
    s.ingest(Message(), now=1000)
    digest = hashlib.sha256(b"hello").hexdigest()
    with s.db:
        s.db.execute(
            "INSERT INTO replies VALUES(?,?,?,'sending',NULL,?)",
            ("message-1", digest, "old-request-id", 1000),
        )
    b.replier = object()
    with pytest.raises(BridgeError) as caught:
        b.reply_to_message("owner", "message-1", "hello")
    assert caught.value.code == -32010


def test_arbitrarily_large_ttl_is_safely_capped(setup):
    b, _s, _t, now, _key = setup
    result = b.subscribe("owner", params(ttlMs=10**1000))
    from dot2feishu.core import iso

    assert result["refreshBefore"] == iso(now[0] + 7 * 86400)


@pytest.mark.parametrize("invalid_text", ["contains\x00nul", "\t" * 15999 + "x"])
def test_invalid_reply_preflight_does_not_poison_corrected_reply(setup, invalid_text):
    b, s, _t, _now, _key = setup
    s.ingest(Message(), now=1000)

    class Reply:
        calls = 0

        def reply(self, *_args):
            self.calls += 1
            return "bot-reply-corrected"

    b.replier = Reply()
    with pytest.raises(BridgeError) as caught:
        b.reply_to_message("owner", "message-1", invalid_text)
    assert caught.value.code == -32602
    assert s.db.execute("SELECT count(*) FROM replies").fetchone()[0] == 0
    assert b.replier.calls == 0
    assert b.reply_to_message("owner", "message-1", "corrected")["message_id"] == "bot-reply-corrected"
    assert b.replier.calls == 1
