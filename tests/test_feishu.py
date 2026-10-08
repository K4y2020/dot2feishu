"""Offline adapter tests: fake credentials only; no sockets or authentication."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import traceback
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from lark_oapi.api.im.v1 import P2ImMessageReceiveV1, ReplyMessageResponse
from lark_oapi.core.enum import AccessTokenType, AppType, LogLevel

from dot2feishu.feishu import (
    FeishuAdapter,
    FeishuError,
    FeishuPolicy,
    InboundMessage,
    PersistenceError,
    ReplyVerificationError,
    normalize_event,
)

NOW = datetime(2026, 10, 8, 4, 40, tzinfo=UTC)
NOW_MS = int(NOW.timestamp() * 1000)
POLICY = FeishuPolicy("cli_test", "tenant_test", "ou_allowed", "oc_allowed")


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Tests must never initiate network requests")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr("requests.post", blocked)
    monkeypatch.setattr("requests.sessions.Session.request", blocked)


def payload(now_ms=NOW_MS):
    return {
        "schema": "2.0",
        "header": {
            "event_id": "evt_123",
            "event_type": "im.message.receive_v1",
            "app_id": "cli_test",
            "tenant_key": "tenant_test",
            "create_time": str(now_ms - 1000),
        },
        "event": {
            "sender": {
                "sender_id": {"open_id": "ou_allowed", "user_id": "user_unused"},
                "sender_type": "user",
                "tenant_key": "tenant_test",
            },
            "message": {
                "message_id": "om_original",
                "chat_id": "oc_allowed",
                "chat_type": "p2p",
                "message_type": "text",
                "create_time": str(now_ms - 1000),
                "content": json.dumps({"text": "你好, dot\nsecond line"}),
            },
        },
    }


def normalized():
    return normalize_event(P2ImMessageReceiveV1(payload()), POLICY, now=NOW)


def response(**overrides):
    data = {"message_id": "om_reply", "chat_id": "oc_allowed", "msg_type": "text", "parent_id": "om_original"}
    data.update(overrides)
    return ReplyMessageResponse({"code": 0, "msg": "success", "data": data})


def adapter(*, on_message=None, lookup=None, result=None):
    reply = Mock(return_value=result if result is not None else response())
    client = SimpleNamespace(im=SimpleNamespace(v1=SimpleNamespace(message=SimpleNamespace(reply=reply))))
    ws_factory = Mock(return_value=SimpleNamespace(start=Mock()))
    instance = FeishuAdapter(
        "cli_test",
        "fake_secret_never_live",
        POLICY,
        on_message if on_message is not None else Mock(),
        lookup if lookup is not None else Mock(return_value=normalized()),
        client=client,
        ws_client_factory=ws_factory,
    )
    return instance, reply, ws_factory


def change(raw, path, value):
    target = raw
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return raw


def test_normalizes_only_text_and_preserves_unicode():
    result = normalized()
    assert result == InboundMessage(
        "evt_123",
        "om_original",
        "oc_allowed",
        "ou_allowed",
        "你好, dot\nsecond line",
        "2026-10-08T04:39:59+00:00",
    )
    assert "你好" not in repr(result)


@pytest.mark.parametrize(
    "path,value",
    [
        (("schema",), "p2"),
        (("schema",), None),
        (("header", "event_type"), "im.message.reaction.created_v1"),
        (("header", "app_id"), "cli_other"),
        (("header", "tenant_key"), "tenant_other"),
        (("header", "event_id"), None),
        (("header", "event_id"), "../secret"),
        (("event", "sender", "sender_type"), "app"),
        (("event", "sender", "sender_type"), "bot"),
        (("event", "sender", "sender_type"), None),
        (("event", "sender", "tenant_key"), "tenant_other"),
        (("event", "sender", "sender_id", "open_id"), "ou_other"),
        (("event", "message", "chat_id"), "oc_other"),
        (("event", "message", "chat_type"), "group"),
        (("event", "message", "message_type"), "image"),
        (("event", "message", "message_type"), "post"),
        (("event", "message", "message_id"), "om_test/reply"),
        (("event", "message", "message_id"), "om_%2e%2e"),
        (("event", "message", "message_id"), 123),
        (("event", "message", "content"), None),
        (("event", "message", "content"), []),
    ],
)
def test_rejects_wrong_identity_type_or_structure(path, value):
    event = P2ImMessageReceiveV1(change(payload(), path, value))
    assert normalize_event(event, POLICY, now=NOW) is None


@pytest.mark.parametrize(
    "value",
    [
        None,
        "not JSON",
        "[]",
        '"hi"',
        "{}",
        '{"text": 1}',
        '{"text": null}',
        '{"text":"first","text":"second"}',
        '{"text":"hi","extra":"x"}',
        '{"text":NaN}',
        '{"text":""}',
        '{"text":"  \\n"}',
        '{"text":"\\ud800"}',
        '{"text":"\\u0000"}',
        json.dumps({"text": "中" * 5334}),
        " " * 100001,
        "[" * 1500 + "]" * 1500,
    ],
)
def test_rejects_malformed_and_oversized_text(value):
    event = P2ImMessageReceiveV1(change(payload(), ("event", "message", "content"), value))
    assert normalize_event(event, POLICY, now=NOW) is None


def test_utf8_limit_not_character_limit_and_exact_boundary():
    raw = change(payload(), ("event", "message", "content"), json.dumps({"text": "中" * 5333}))
    assert normalize_event(P2ImMessageReceiveV1(raw), POLICY, now=NOW) is not None


@pytest.mark.parametrize("path", [("header", "create_time"), ("event", "message", "create_time")])
@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        NOW_MS * 1.0,
        str(NOW_MS // 1000),
        "1e12",
        "0",
        "-1",
        str(NOW_MS + 1),
        NOW_MS + 1,
        str(NOW_MS - 600001),
        "99999999999999999999",
    ],
)
def test_rejects_invalid_old_and_future_times(path, value):
    event = P2ImMessageReceiveV1(change(payload(), path, value))
    assert normalize_event(event, POLICY, now=NOW) is None


def test_timestamp_boundary_and_integer_sdk_values():
    raw = change(payload(), ("header", "create_time"), NOW_MS)
    change(raw, ("event", "message", "create_time"), NOW_MS - 600000)
    assert normalize_event(P2ImMessageReceiveV1(raw), POLICY, now=NOW) is not None


def test_raw_dict_is_not_an_authenticated_sdk_event():
    assert normalize_event(payload(), POLICY, now=NOW) is None
    assert normalize_event(None, POLICY, now=NOW) is None


def test_naive_clock_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        normalize_event(P2ImMessageReceiveV1(payload()), POLICY, now=NOW.replace(tzinfo=None))


def test_dispatcher_registers_only_receive_and_persists_before_return():
    received = []
    instance, _, factory = adapter(on_message=received.append)
    kwargs = factory.call_args.kwargs
    assert kwargs["auto_reconnect"] is True
    assert kwargs["domain"] == "https://open.feishu.cn"
    assert kwargs["log_level"] is LogLevel.CRITICAL
    handler = kwargs["event_handler"]
    assert set(handler._processorMap) == {"p2.im.message.receive_v1"}
    assert handler._callback_processor_map == {}
    raw = payload(int(datetime.now(UTC).timestamp() * 1000))
    handler._do_without_validation(json.dumps(raw).encode())
    assert len(received) == 1
    assert received[0].message_id == "om_original"
    assert "fake_secret" not in repr(instance)


def test_rejected_event_does_not_touch_store():
    callback = Mock()
    instance, _, _ = adapter(on_message=callback)
    raw = change(payload(), ("event", "message", "chat_id"), "oc_other")
    instance._handle_event(P2ImMessageReceiveV1(raw))
    callback.assert_not_called()


def test_storage_failure_propagates_safely_to_sdk():
    callback = Mock(side_effect=OSError("fake_secret_never_live private message"))
    _instance, _, factory = adapter(on_message=callback)
    handler = factory.call_args.kwargs["event_handler"]
    raw = payload(int(datetime.now(UTC).timestamp() * 1000))
    with pytest.raises(PersistenceError) as caught:
        handler._do_without_validation(json.dumps(raw).encode())
    rendered = "".join(traceback.format_exception(caught.value))
    assert "fake_secret_never_live" not in rendered
    assert "private message" not in rendered


def test_async_durable_callback_forbidden():
    async def wrong(_):
        pass

    with pytest.raises(ValueError, match="synchronous"):
        adapter(on_message=wrong)
    instance, _, _ = adapter(on_message=lambda event: wrong(event))
    event = P2ImMessageReceiveV1(payload(int(datetime.now(UTC).timestamp() * 1000)))
    with pytest.raises(PersistenceError):
        instance._handle_event(event)


def test_reply_forces_tenant_token_original_message_and_stable_uuid():
    instance, send, _ = adapter()
    assert instance.reply("om_original", "你好", "request_123") == "om_reply"
    request = send.call_args.args[0]
    assert request.token_types == {AccessTokenType.TENANT}
    assert request.message_id == "om_original"
    assert request.paths == {"message_id": "om_original"}
    assert json.loads(request.body.content) == {"text": "你好"}
    assert request.body.uuid == "request_123"
    assert request.body.msg_type == "text"
    assert request.body.reply_in_thread is False
    assert send.call_args.kwargs == {}
    instance.reply("om_original", "你好", "request_123")
    assert send.call_args.args[0].body.uuid == "request_123"


@pytest.mark.parametrize(
    "record",
    [
        None,
        {},
        replace(normalized(), chat_id="oc_other"),
        replace(normalized(), sender_id="ou_other"),
        replace(normalized(), message_id="om_other"),
        replace(normalized(), event_id=""),
    ],
)
def test_no_arbitrary_or_mismatched_reply_target(record):
    instance, send, _ = adapter(lookup=Mock(return_value=record))
    with pytest.raises(FeishuError, match="permitted durable"):
        instance.reply("om_original", "hello", "request_123")
    send.assert_not_called()


@pytest.mark.parametrize(
    "message_id,text,request_id",
    [
        ("../om_other", "hello", "request_123"),
        ("om_original", "", "request_123"),
        ("om_original", "x" * 16001, "request_123"),
        ("om_original", "\ud800", "request_123"),
        ("om_original", "hello", ""),
        ("om_original", "hello", "x" * 51),
        ("om_original", "hello", "../../secret"),
    ],
)
def test_reply_validation_prevents_api_calls(message_id, text, request_id):
    instance, send, _ = adapter()
    with pytest.raises(FeishuError):
        instance.reply(message_id, text, request_id)
    send.assert_not_called()


@pytest.mark.parametrize(
    "overrides",
    [
        {"chat_id": "oc_other"},
        {"chat_id": None},
        {"message_id": None},
        {"message_id": "om_original"},
        {"message_id": "../invalid"},
        {"msg_type": "image"},
        {"parent_id": "om_other"},
    ],
)
def test_post_send_response_identity_failures_are_ambiguous(overrides):
    instance, send, _ = adapter(result=response(**overrides))
    with pytest.raises(ReplyVerificationError):
        instance.reply("om_original", "hello", "request_123")
    send.assert_called_once()


def test_api_errors_are_sanitized():
    instance, send, _ = adapter()
    send.side_effect = RuntimeError("SECRET and PRIVATE TEXT")
    with pytest.raises(FeishuError) as caught:
        instance.reply("om_original", "hello", "request_123")
    assert "SECRET" not in "".join(traceback.format_exception(caught.value))
    send.side_effect = None
    send.return_value = ReplyMessageResponse({"code": 999, "msg": "SECRET"})
    with pytest.raises(FeishuError) as caught:
        instance.reply("om_original", "hello", "request_123")
    assert "SECRET" not in str(caught.value)


def test_start_blocks_on_sdk_and_forbids_repeat():
    instance, _, factory = adapter()
    instance.start()  # fake start only
    factory.return_value.start.assert_called_once()
    with pytest.raises(FeishuError, match="twice"):
        instance.start()


def test_start_forbids_active_event_loop_and_worker_thread():
    instance, _, factory = adapter()

    async def run():
        with pytest.raises(FeishuError, match="async loop"):
            instance.start()

    asyncio.run(run())
    errors = []

    def worker():
        try:
            instance.start()
        except FeishuError as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    assert errors == ["Feishu websocket start requires the main thread"]
    factory.return_value.start.assert_not_called()


def test_real_sdk_constructor_is_offline_and_uses_supplied_bot_identity():
    factory = Mock(return_value=SimpleNamespace(start=Mock()))
    instance = FeishuAdapter("cli_test", "fake_secret", POLICY, Mock(), Mock(), ws_client_factory=factory)
    config = instance._client._config
    assert config.app_id == "cli_test"
    assert config.app_secret == "fake_secret"
    assert config.app_type is AppType.SELF
    assert config.enable_set_token is False
    assert config.domain == "https://open.feishu.cn"
    assert config.log_level is LogLevel.CRITICAL
    assert config.client_assertion_provider is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_text_bytes": 0},
        {"max_text_bytes": 16001},
        {"max_text_bytes": True},
        {"max_event_age_seconds": 0},
        {"max_event_age_seconds": 86401},
        {"allowed_chat_id": "oc_../../evil"},
        {"app_id": ""},
    ],
)
def test_policy_fails_closed_on_bad_configuration(kwargs):
    with pytest.raises(ValueError):
        replace(POLICY, **kwargs)


@pytest.mark.parametrize("disk_fails,expected_code", [(False, 200), (True, 500)])
def test_actual_sdk_frame_ack_follows_durable_callback(disk_fails, expected_code, monkeypatch):
    """Exercise SDK's real frame dispatcher/writer boundary without a connection."""
    from lark_oapi.ws.client import Client
    from lark_oapi.ws.const import (
        HEADER_MESSAGE_ID,
        HEADER_SEQ,
        HEADER_SUM,
        HEADER_TRACE_ID,
        HEADER_TYPE,
    )
    from lark_oapi.ws.pb.pbbp2_pb2 import Frame

    order = []

    def persist(_):
        order.append("persist")
        if disk_fails:
            raise OSError("simulated disk full")

    _, _, factory = adapter(on_message=persist)
    # Single-frame test does not need the SDK's background fragment cache.
    monkeypatch.setattr("lark_oapi.ws.client.ExpiringCache", lambda **kwargs: {})
    sdk = Client(
        "cli_test",
        "fake_secret",
        log_level=LogLevel.CRITICAL,
        event_handler=factory.call_args.kwargs["event_handler"],
    )

    async def capture(data):
        order.append("write_ack")
        frame = Frame()
        frame.ParseFromString(data)
        assert json.loads(frame.payload)["code"] == expected_code

    sdk._write_message = capture
    frame = Frame(SeqID=1, LogID=1, service=1, method=1)
    for key, value in {
        HEADER_MESSAGE_ID: "frame_123",
        HEADER_TRACE_ID: "trace_123",
        HEADER_SUM: "1",
        HEADER_SEQ: "0",
        HEADER_TYPE: "event",
    }.items():
        header = frame.headers.add()
        header.key = key
        header.value = value
    now_ms = int(datetime.now(UTC).timestamp() * 1000)
    frame.payload = json.dumps(payload(now_ms)).encode()
    asyncio.run(sdk._handle_data_frame(frame))
    assert order == ["persist", "write_ack"]


@pytest.mark.parametrize("update_time", [True, "invalid", str(NOW_MS + 1), str(NOW_MS - 2000)])
def test_supplied_update_timestamp_must_be_well_formed_and_not_future(update_time):
    raw = change(payload(), ("event", "message", "update_time"), update_time)
    assert normalize_event(P2ImMessageReceiveV1(raw), POLICY, now=NOW) is None


def test_reply_checks_json_encoded_size_before_sending():
    instance, send, _ = adapter()
    with pytest.raises(FeishuError, match="Encoded reply content"):
        instance.reply("om_original", "a" + "\\" * 15999, "request_123")
    send.assert_not_called()
