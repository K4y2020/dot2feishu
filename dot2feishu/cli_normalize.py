"""Pure normalizer for the official Feishu CLI v1.0.97 consume stream.

The flat ``im.message.receive_v1`` NDJSON format is not an SDK event. Its
``content`` is already rendered text, and it carries no app or tenant identity.
Provenance must be supplied by the parent adapter, which independently verifies
the fixed CLI profile's bot identity before launching the exact trusted command.
This module does not authenticate input, launch the CLI, inspect credentials,
fabricate app/tenant fields, or construct SDK events. Never expose it directly
to an unauthenticated HTTP endpoint or arbitrary process/file input.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .feishu import FeishuPolicy, InboundMessage, _milliseconds, _text_size, _valid_id

_EVENT_TYPE = "im.message.receive_v1"
_SDK_ENVELOPE_FIELDS = frozenset({"schema", "header", "event"})


def _cli_milliseconds(value: Any) -> int | None:
    # Unlike SDK models, the pinned CLI format uses decimal strings only.
    return _milliseconds(value) if type(value) is str else None


def normalize_cli_event(
    payload: dict, policy: FeishuPolicy, *, now: datetime | None = None
) -> InboundMessage | None:
    """Filter one already authenticated, decoded flat CLI consume record.

    The parent adapter independently verifies the fixed CLI profile's bot
    identity before launching the exact trusted command and supplies provenance.
    App/tenant identity is absent from this format; ``policy.app_id`` and
    ``policy.tenant_key`` cannot be verified here. Added metadata asserting those
    identities is not authentication. No SDK envelope is accepted or synthesized.

    Return ``None`` for unsupported, malformed, stale, future, or out-of-scope
    records. Require the exact allowed human sender and p2p chat, text messages,
    and bounded UTF-8 text. Preserve rendered text literally, including text that
    resembles JSON. Ignore unused CLI metadata such as mentions or reply/thread
    identifiers; it cannot replace any required field or change reply routing.
    ``now`` must be timezone-aware when supplied for deterministic offline tests.
    """
    if type(payload) is not dict or _SDK_ENVELOPE_FIELDS.intersection(payload):
        return None
    expected = {
        "type": _EVENT_TYPE,
        "chat_type": "p2p",
        "sender_type": "user",
        "message_type": "text",
        "sender_id": policy.allowed_user_open_id,
        "chat_id": policy.allowed_chat_id,
    }
    if any(type(payload.get(key)) is not str or payload[key] != value for key, value in expected.items()):
        return None

    event_id = payload.get("event_id")
    message_id = payload.get("message_id")
    if not _valid_id(event_id) or not _valid_id(message_id):
        return None
    # The legacy alias must never supply a missing message_id or disagree with it.
    if "id" in payload and (type(payload["id"]) is not str or payload["id"] != message_id):
        return None

    message_time = _cli_milliseconds(payload.get("create_time"))
    event_time = _cli_milliseconds(payload.get("timestamp"))
    if message_time is None or event_time is None:
        return None
    current = now if now is not None else datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    current_ms = int(current.timestamp() * 1000)
    oldest_ms = current_ms - policy.max_event_age_seconds * 1000
    if not (oldest_ms <= message_time <= current_ms and oldest_ms <= event_time <= current_ms):
        return None
    if "update_time" in payload:
        updated_ms = _cli_milliseconds(payload["update_time"])
        if updated_ms is None or not message_time <= updated_ms <= current_ms:
            return None

    text = payload.get("content")
    if not _text_size(text, policy.max_text_bytes):
        return None
    occurred_at = datetime.fromtimestamp(message_time / 1000, UTC).isoformat()
    return InboundMessage(
        event_id, message_id, policy.allowed_chat_id, policy.allowed_user_open_id, text, occurred_at
    )
