"""Offline pinned CLI-format tests; no subprocess, network, or authentication."""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta, tzinfo
from types import SimpleNamespace

import pytest
from lark_oapi.api.im.v1 import P2ImMessageReceiveV1

from dot2feishu.cli_normalize import normalize_cli_event
from dot2feishu.feishu import FeishuPolicy, InboundMessage, normalize_event

NOW = datetime(2026, 10, 8, 4, 40, tzinfo=UTC)
NOW_MS = int(NOW.timestamp() * 1000)
POLICY = FeishuPolicy("cli_test", "tenant_test", "ou_allowed", "oc_allowed")


@pytest.fixture(autouse=True)
def forbid_external_operations(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("CLI normalizer tests must stay offline and must not launch processes")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr("requests.sessions.Session.request", blocked)


def payload(**overrides):
    result = {
        "type": "im.message.receive_v1",
        "event_id": "evt_123",
        "message_id": "om_original",
        "chat_id": "oc_allowed",
        "chat_type": "p2p",
        "sender_id": "ou_allowed",
        "sender_type": "user",
        "message_type": "text",
        "content": "你好, dot\nsecond line",
        "create_time": str(NOW_MS - 1000),
        "timestamp": str(NOW_MS - 500),
    }
    result.update(overrides)
    return result


def sdk_payload():
    return {
        "schema": "2.0",
        "header": {
            "event_id": "evt_123",
            "event_type": "im.message.receive_v1",
            "app_id": "cli_test",
            "tenant_key": "tenant_test",
            "create_time": str(NOW_MS - 500),
        },
        "event": {
            "sender": {
                "sender_id": {"open_id": "ou_allowed"},
                "sender_type": "user",
                "tenant_key": "tenant_test",
            },
            "message": {
                "message_id": "om_original",
                "chat_id": "oc_allowed",
                "chat_type": "p2p",
                "message_type": "text",
                "content": json.dumps({"text": "hello"}),
                "create_time": str(NOW_MS - 1000),
            },
        },
    }


def test_normalizes_real_flat_shape_without_app_or_tenant():
    raw = payload()
    assert "app_id" not in raw and "tenant_key" not in raw
    result = normalize_cli_event(raw, POLICY, now=NOW)
    assert result == InboundMessage(
        "evt_123",
        "om_original",
        "oc_allowed",
        "ou_allowed",
        "你好, dot\nsecond line",
        "2026-10-08T04:39:59+00:00",
    )
    assert "你好" not in repr(result)


def test_accepts_matching_legacy_alias_but_does_not_mutate_payload():
    raw = payload(id="om_original")
    before = raw.copy()
    assert normalize_cli_event(raw, POLICY, now=NOW) is not None
    assert raw == before


@pytest.mark.parametrize("field", list(payload()))
def test_every_required_field_is_required(field):
    raw = payload(id="om_original")
    raw.pop(field)
    assert normalize_cli_event(raw, POLICY, now=NOW) is None


@pytest.mark.parametrize("field", list(payload()))
@pytest.mark.parametrize("bad", [None, True, False, 1, 1.0, [], {}, b"text"])
def test_required_fields_reject_wrong_scalar_or_container_types(field, bad):
    assert normalize_cli_event(payload(**{field: bad}), POLICY, now=NOW) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("type", "p2.im.message.receive_v1"),
        ("type", "im.message.reaction.created_v1"),
        ("type", "IM.MESSAGE.RECEIVE_V1"),
        ("chat_type", "group"),
        ("chat_type", "P2P"),
        ("sender_id", "ou_other"),
        ("sender_id", "user_allowed"),
        ("sender_id", "ou_allowed "),
        ("chat_id", "oc_other"),
        ("chat_id", "oc_allowed "),
        ("sender_type", "app"),
        ("sender_type", "bot"),
        ("sender_type", "system"),
        ("sender_type", "User"),
        ("message_type", "image"),
        ("message_type", "post"),
        ("message_type", "interactive"),
        ("message_type", "Text"),
    ],
)
def test_rejects_out_of_scope_events_identities_and_bot_loops(field, value):
    assert normalize_cli_event(payload(**{field: value}), POLICY, now=NOW) is None


@pytest.mark.parametrize("field", ["event_id", "message_id"])
@pytest.mark.parametrize(
    "value", ["", "x" * 257, "../secret", "om/x", "om%2fsecret", "a b", "x\n", "x\x00", "中文", "é"]
)
def test_rejects_malformed_identifiers(field, value):
    assert normalize_cli_event(payload(**{field: value}), POLICY, now=NOW) is None


@pytest.mark.parametrize("field", ["event_id", "message_id"])
@pytest.mark.parametrize("value", ["x", "A_z-09", "x" * 256])
def test_identifier_boundaries(field, value):
    assert normalize_cli_event(payload(**{field: value}), POLICY, now=NOW) is not None


@pytest.mark.parametrize("value", [None, True, 1, [], {}, "", "om_other", "om_original\n"])
def test_legacy_alias_must_match_if_present(value):
    assert normalize_cli_event(payload(id=value), POLICY, now=NOW) is None


@pytest.mark.parametrize(
    "text",
    [
        "  text\n\t ",
        '{"text":"do not unwrap this"}',
        '{"text":"first","text":"second"}',
        '{"text":"hello","extra":1}',
        '{"text":NaN}',
        '{"text":"\\ud800"}',
        '{"text":"\\u0000"}',
        "{}",
        "[]",
        "null",
        "true",
        '"quoted"',
        "not JSON",
        "[" * 16000,
    ],
)
def test_content_is_literal_pre_rendered_text_not_json(text):
    result = normalize_cli_event(payload(content=text), POLICY, now=NOW)
    assert result is not None
    assert result.text == text


@pytest.mark.parametrize(
    "text",
    [
        "",
        " \n\t\r",
        "\u2003",
        "a\x00b",
        chr(0xD800),
        chr(0xDC00),
        chr(0xD83D) + chr(0xDE00),
        "x" * 16001,
        "中" * 5334,
        "😀" * 4001,
    ],
)
def test_rejects_empty_nul_malformed_unicode_and_oversize_text(text):
    assert normalize_cli_event(payload(content=text), POLICY, now=NOW) is None


@pytest.mark.parametrize("text", ["x" * 16000, "中" * 5333 + "x", "😀" * 4000])
def test_utf8_exact_byte_boundary(text):
    assert len(text.encode("utf-8")) == 16000
    assert normalize_cli_event(payload(content=text), POLICY, now=NOW) is not None


def test_custom_smaller_text_limit():
    policy = replace(POLICY, max_text_bytes=3)
    assert normalize_cli_event(payload(content="中"), policy, now=NOW) is not None
    assert normalize_cli_event(payload(content="中x"), policy, now=NOW) is None


@pytest.mark.parametrize("field", ["create_time", "timestamp", "update_time"])
@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        NOW_MS,
        float(NOW_MS),
        [],
        {},
        "",
        "0",
        "-1",
        "1e12",
        "NaN",
        str(NOW_MS // 1000),
        str(NOW_MS) + ".0",
        " " + str(NOW_MS),
        str(NOW_MS) + "\n",
        "+" + str(NOW_MS),
        "0" + str(NOW_MS),
        "999999999999",
        "10000000000000",
        "９" * 13,
        str(NOW_MS + 1),
        "9999999999999",
    ],
)
def test_rejects_malformed_or_future_timestamp_strings(field, value):
    assert normalize_cli_event(payload(**{field: value}), POLICY, now=NOW) is None


@pytest.mark.parametrize("field", ["create_time", "timestamp"])
@pytest.mark.parametrize("age", [0, 1, 599999, 600000])
def test_both_time_fields_independently_accept_fresh_boundary(field, age):
    assert normalize_cli_event(payload(**{field: str(NOW_MS - age)}), POLICY, now=NOW) is not None


@pytest.mark.parametrize("field", ["create_time", "timestamp"])
def test_both_time_fields_independently_reject_stale_values(field):
    assert normalize_cli_event(payload(**{field: str(NOW_MS - 600001)}), POLICY, now=NOW) is None


def test_policy_age_limit_is_used():
    policy = replace(POLICY, max_event_age_seconds=1)
    assert normalize_cli_event(payload(), policy, now=NOW) is not None
    assert normalize_cli_event(payload(create_time=str(NOW_MS - 1001)), policy, now=NOW) is None
    assert normalize_cli_event(payload(timestamp=str(NOW_MS - 1001)), policy, now=NOW) is None


@pytest.mark.parametrize("offset", [0, 500, 1000])
def test_optional_update_time_is_between_creation_and_now(offset):
    assert normalize_cli_event(payload(update_time=str(NOW_MS - offset)), POLICY, now=NOW) is not None


def test_update_time_cannot_predate_creation_or_refresh_stale_creation():
    assert normalize_cli_event(payload(update_time=str(NOW_MS - 1001)), POLICY, now=NOW) is None
    raw = payload(create_time=str(NOW_MS - 600001), update_time=str(NOW_MS))
    assert normalize_cli_event(raw, POLICY, now=NOW) is None


def test_occurrence_uses_message_time_not_event_or_update_time():
    raw = payload(create_time=str(NOW_MS - 1234), update_time=str(NOW_MS))
    result = normalize_cli_event(raw, POLICY, now=NOW)
    assert result.occurred_at == "2026-10-08T04:39:58.766000+00:00"


def test_unused_metadata_cannot_override_identity_or_reply_routing():
    raw = payload(
        mentions=[{"id": "ou_other", "name": "another person"}],
        reply_to="om_other",
        root_id="om_root",
        thread_id="omt_thread",
        extra={"sender_id": "ou_other", "chat_id": "oc_other", "content": "wrong"},
    )
    assert normalize_cli_event(raw, POLICY, now=NOW) == normalize_cli_event(payload(), POLICY, now=NOW)
    raw["sender_id"] = "ou_other"
    raw["extra"]["sender_id"] = "ou_allowed"
    assert normalize_cli_event(raw, POLICY, now=NOW) is None


def test_app_tenant_cannot_be_inferred_or_authenticated_from_cli_metadata():
    expected = normalize_cli_event(payload(), POLICY, now=NOW)
    alternate = replace(POLICY, app_id="cli_other", tenant_key="tenant_other")
    assert normalize_cli_event(payload(), alternate, now=NOW) == expected
    raw = payload(app_id="untrusted_assertion", tenant_key="untrusted_assertion")
    assert normalize_cli_event(raw, POLICY, now=NOW) == expected


@pytest.mark.parametrize("field", ["schema", "header", "event"])
@pytest.mark.parametrize("value", [None, "2.0", {}])
def test_rejects_mixed_sdk_envelope_fields(field, value):
    assert normalize_cli_event(payload(**{field: value}), POLICY, now=NOW) is None


def test_sdk_and_cli_normalizers_do_not_accept_each_others_envelopes():
    raw_sdk = sdk_payload()
    sdk = P2ImMessageReceiveV1(raw_sdk)
    assert normalize_event(sdk, POLICY, now=NOW) is not None
    assert normalize_cli_event(raw_sdk, POLICY, now=NOW) is None
    assert normalize_cli_event(sdk, POLICY, now=NOW) is None
    assert normalize_event(payload(), POLICY, now=NOW) is None
    assert normalize_event(P2ImMessageReceiveV1(payload()), POLICY, now=NOW) is None


@pytest.mark.parametrize("value", [None, True, 1, [], "{}", b"{}", SimpleNamespace(**payload())])
def test_non_dict_payloads_are_rejected(value):
    assert normalize_cli_event(value, POLICY, now=NOW) is None


def test_dict_and_string_subclasses_are_not_decoded_json_scalars():
    class DictSubclass(dict):
        pass

    class StringSubclass(str):
        pass

    assert normalize_cli_event(DictSubclass(payload()), POLICY, now=NOW) is None
    for key, value in payload().items():
        assert normalize_cli_event(payload(**{key: StringSubclass(value)}), POLICY, now=NOW) is None
    assert normalize_cli_event(payload(id=StringSubclass("om_original")), POLICY, now=NOW) is None


def test_naive_and_non_offset_clock_are_rejected():
    class MissingOffset(tzinfo):
        def utcoffset(self, dt):
            return None

    for now in [NOW.replace(tzinfo=None), NOW.replace(tzinfo=MissingOffset())]:
        with pytest.raises(ValueError, match="timezone-aware"):
            normalize_cli_event(payload(), POLICY, now=now)


def test_aware_non_utc_clock_produces_same_utc_occurrence():
    from datetime import timezone

    now = NOW.astimezone(timezone(timedelta(hours=8)))
    assert normalize_cli_event(payload(), POLICY, now=now) == normalize_cli_event(payload(), POLICY, now=NOW)


def test_default_clock_is_utc_and_offline(monkeypatch):
    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz is UTC
            return NOW

    monkeypatch.setattr("dot2feishu.cli_normalize.datetime", FixedClock)
    assert normalize_cli_event(payload(), POLICY) == normalize_cli_event(payload(), POLICY, now=NOW)
