"""Narrow Feishu bot adapter. Never use this normalizer as HTTP authentication.

Only the official app-secret-authenticated Feishu websocket feeds this module.
No callback HTTP route, user tokens, arbitrary recipient send API, CLI credential
lookup, or automatic app registration is implemented. Constructors are offline;
``start`` and ``reply`` are the only operations that initiate network requests.

Reviewed against lark-oapi 1.7.3 and the official API/SDK references:
https://open.feishu.cn/document/server-docs/im-v1/message/events/receive
https://open.feishu.cn/document/server-docs/im-v1/message/reply
https://github.com/larksuite/oapi-sdk-python
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

_EVENT_TYPE = "im.message.receive_v1"
_FEISHU_DOMAIN = "https://open.feishu.cn"
_ID = re.compile(r"[A-Za-z0-9_-]{1,256}\Z", re.ASCII)
_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,50}\Z", re.ASCII)
_MAX_CONTENT_BYTES = 100_000
_MAX_REPLY_CONTENT_BYTES = 20_000


@dataclass(frozen=True)
class InboundMessage:
    event_id: str
    message_id: str
    chat_id: str
    sender_id: str
    text: str = field(repr=False)
    occurred_at: str


@dataclass(frozen=True)
class FeishuPolicy:
    app_id: str
    tenant_key: str
    allowed_user_open_id: str
    allowed_chat_id: str
    max_text_bytes: int = 16_000
    max_event_age_seconds: int = 600

    def __post_init__(self) -> None:
        for name in ("app_id", "tenant_key", "allowed_user_open_id", "allowed_chat_id"):
            if not _valid_id(getattr(self, name)):
                raise ValueError(f"Invalid Feishu policy {name}")
        if type(self.max_text_bytes) is not int or not 1 <= self.max_text_bytes <= 16_000:
            raise ValueError("max_text_bytes must be between 1 and 16000")
        if type(self.max_event_age_seconds) is not int or not 1 <= self.max_event_age_seconds <= 86_400:
            raise ValueError("max_event_age_seconds must be between 1 and 86400")


class FeishuError(RuntimeError):
    """Safe-to-log error. Never includes an API body, token, or message content."""


class PersistenceError(FeishuError):
    """Causes the SDK to respond with failure instead of acknowledging receipt."""


class ReplyVerificationError(FeishuError):
    """A reply may have been sent; the durable caller must keep its UUID on retry."""


def _valid_id(value: Any) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _text_size(value: Any, limit: int) -> bool:
    if type(value) is not str or len(value) > limit or not value.strip() or "\x00" in value:
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= limit
    except UnicodeEncodeError:
        return False


def validate_reply_text(text: Any, max_text_bytes: int = 16_000) -> None:
    """Pure preflight; callers run this before reserving a durable send."""
    if not _text_size(text, max_text_bytes):
        raise FeishuError("Reply text is empty, malformed, or too large")
    content = json.dumps({"text": text}, ensure_ascii=False)
    if len(content.encode("utf-8")) > _MAX_REPLY_CONTENT_BYTES:
        raise FeishuError("Encoded reply content is too large")


def _milliseconds(value: Any) -> int | None:
    # Event headers use decimal strings; SDK message models may retain either
    # decimal strings or integers. Never coerce floats, booleans, or exponents.
    if type(value) is int:
        parsed = value
    elif type(value) is str and re.fullmatch(r"[0-9]{13}", value, re.ASCII):
        parsed = int(value)
    else:
        return None
    return parsed if 1_000_000_000_000 <= parsed <= 9_999_999_999_999 else None


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise ValueError("non-standard JSON constant")


def normalize_event(
    event: Any, policy: FeishuPolicy, *, now: datetime | None = None
) -> InboundMessage | None:
    """Filter an already authenticated SDK event; return None for rejected input.

    This is NOT signature verification: callers must never feed unauthenticated
    HTTP payloads here. SDK websocket transport authentication establishes the
    source. The adapter additionally checks both tenant fields, app ID, sender,
    exact p2p chat, event type, schema, text size, and bounded past timestamps.
    ``now`` is an aware datetime intended for deterministic offline tests.
    """
    from lark_oapi.api.im.v1 import P2ImMessageReceiveV1

    if type(event) is not P2ImMessageReceiveV1 or event.schema != "2.0":
        return None
    header = event.header
    data = event.event
    if (
        getattr(header, "event_type", None) != _EVENT_TYPE
        or getattr(header, "app_id", None) != policy.app_id
        or getattr(header, "tenant_key", None) != policy.tenant_key
    ):
        return None
    sender = getattr(data, "sender", None)
    message = getattr(data, "message", None)
    sender_id = getattr(getattr(sender, "sender_id", None), "open_id", None)
    if (
        getattr(sender, "sender_type", None) != "user"
        or getattr(sender, "tenant_key", None) != policy.tenant_key
        or sender_id != policy.allowed_user_open_id
        or getattr(message, "chat_type", None) != "p2p"
        or getattr(message, "chat_id", None) != policy.allowed_chat_id
        or getattr(message, "message_type", None) != "text"
    ):
        return None
    event_id = getattr(header, "event_id", None)
    message_id = getattr(message, "message_id", None)
    if not _valid_id(event_id) or not _valid_id(message_id):
        return None
    header_time = _milliseconds(getattr(header, "create_time", None))
    message_time = _milliseconds(getattr(message, "create_time", None))
    if header_time is None or message_time is None:
        return None
    current = now if now is not None else datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    current_ms = int(current.timestamp() * 1000)
    oldest_ms = current_ms - policy.max_event_age_seconds * 1000
    if not (oldest_ms <= header_time <= current_ms and oldest_ms <= message_time <= current_ms):
        return None
    update_time = getattr(message, "update_time", None)
    if update_time is not None:
        updated_ms = _milliseconds(update_time)
        if updated_ms is None or not message_time <= updated_ms <= current_ms:
            return None
    content = getattr(message, "content", None)
    if type(content) is not str:
        return None
    try:
        # Bound the JSON before parsing, including escaped-character overhead.
        if len(content) > _MAX_CONTENT_BYTES or len(content.encode("utf-8")) > _MAX_CONTENT_BYTES:
            return None
        body = json.loads(
            content, object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant
        )
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return None
    if type(body) is not dict or set(body) != {"text"}:
        return None
    text = body["text"]
    if not _text_size(text, policy.max_text_bytes):
        return None
    occurred_at = datetime.fromtimestamp(message_time / 1000, UTC).isoformat()
    return InboundMessage(
        event_id, message_id, policy.allowed_chat_id, policy.allowed_user_open_id, text, occurred_at
    )


class FeishuAdapter:
    """App-identity-only websocket listener and original-message reply adapter.

    ``on_message`` MUST synchronously commit to durable storage before returning;
    an existing durable duplicate is success. A callback exception is sanitized
    and propagated to the SDK, which returns an error ACK (500), not success.
    ``lookup_message`` MUST use that same trusted durable store. No MCP argument
    may supply or replace the record returned by the lookup.

    ``start()`` blocks forever, runs only in the main thread with no active async
    loop, and uses the SDK's automatic reconnect. The SDK has no public stop()
    contract; run it in a dedicated supervised process and stop the process for
    shutdown. Do not invoke start from uvicorn's/asyncio's event loop. The SDK's
    reconnect does not promise replay of every event from a long outage.

    Dependency injection is for offline tests; production must leave ``client``
    and ``ws_client_factory`` unset. No request options or domain override are
    exposed. SDK logs use CRITICAL because lower levels can contain payloads,
    connection URLs, or raw API error text.
    """

    def __init__(
        self,
        app_id: str,
        app_secret: str,
        policy: FeishuPolicy,
        on_message: Callable[[InboundMessage], Any],
        lookup_message: Callable[[str], InboundMessage | None],
        *,
        client: Any = None,
        ws_client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if app_id != policy.app_id:
            raise ValueError("App ID must match Feishu policy")
        if type(app_secret) is not str or not app_secret.strip():
            raise ValueError("An explicitly supplied app secret is required")
        if not callable(on_message) or inspect.iscoroutinefunction(on_message):
            raise ValueError("on_message must be a synchronous durable callback")
        if not callable(lookup_message) or inspect.iscoroutinefunction(lookup_message):
            raise ValueError("lookup_message must be synchronous")
        import lark_oapi as lark
        from lark_oapi.core.enum import AppType

        self._policy = policy
        self._on_message = on_message
        self._lookup_message = lookup_message
        self._started = False
        self._client = (
            client
            if client is not None
            else (
                lark.Client.builder()
                .app_id(app_id)
                .app_secret(app_secret)
                .app_type(AppType.SELF)
                .domain(_FEISHU_DOMAIN)
                .enable_set_token(False)
                .timeout(15)
                .log_level(lark.LogLevel.CRITICAL)
                .build()
            )
        )
        handler = (
            lark.EventDispatcherHandler.builder("", "", lark.LogLevel.CRITICAL)
            .register_p2_im_message_receive_v1(self._handle_event)
            .build()
        )
        # Empty webhook tokens are only appropriate here because this dispatcher
        # is private to the authenticated SDK websocket, never an HTTP endpoint.
        factory = ws_client_factory if ws_client_factory is not None else lark.ws.Client
        self._ws_client = factory(
            app_id,
            app_secret,
            event_handler=handler,
            domain=_FEISHU_DOMAIN,
            log_level=lark.LogLevel.CRITICAL,
            auto_reconnect=True,
        )

    def _handle_event(self, event: Any) -> None:
        normalized = normalize_event(event, self._policy)
        if normalized is None:
            return
        try:
            result = self._on_message(normalized)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise PersistenceError("Inbound event was not synchronously persisted")
        except Exception:  # noqa: BLE001 - boundary must redact arbitrary SDK/transport exceptions
            raise PersistenceError("Inbound event could not be durably persisted") from None

    def start(self) -> None:
        """Run on the main thread until process shutdown; never starts in tests."""
        if threading.current_thread() is not threading.main_thread():
            raise FeishuError("Feishu websocket start requires the main thread")
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise FeishuError("Feishu websocket start requires no running async loop")
        if self._started:
            raise FeishuError("Feishu websocket start cannot be called twice")
        self._started = True
        try:
            self._ws_client.start()
        except Exception:  # noqa: BLE001 - boundary must redact arbitrary SDK/transport exceptions
            raise FeishuError("Feishu websocket stopped; inspect service health") from None

    def reply(self, message_id: str, text: str, request_id: str) -> str:
        """Reply solely to a durable allowed inbound message, with stable UUID.

        A timeout or verification failure is an ambiguous send. The durable
        caller owns exactly-once/idempotency state and must never invent a fresh
        UUID when retrying. Feishu deduplication is time-limited (one hour), so
        the caller must bound automatic ambiguous retries accordingly.
        """
        if not _valid_id(message_id):
            raise FeishuError("Invalid original message ID")
        validate_reply_text(text, self._policy.max_text_bytes)
        if type(request_id) is not str or _REQUEST_ID.fullmatch(request_id) is None:
            raise FeishuError("Invalid reply request ID")
        try:
            original = self._lookup_message(message_id)
        except Exception:  # noqa: BLE001 - boundary must redact arbitrary SDK/transport exceptions
            raise FeishuError("Original message lookup failed") from None
        if (
            type(original) is not InboundMessage
            or original.message_id != message_id
            or original.chat_id != self._policy.allowed_chat_id
            or original.sender_id != self._policy.allowed_user_open_id
            or not _valid_id(original.event_id)
        ):
            raise FeishuError("Reply target is not a permitted durable inbound message")
        from lark_oapi.api.im.v1 import ReplyMessageRequest, ReplyMessageRequestBody
        from lark_oapi.core.enum import AccessTokenType

        content = json.dumps({"text": text}, ensure_ascii=False)
        if len(content.encode("utf-8")) > _MAX_REPLY_CONTENT_BYTES:
            raise FeishuError("Encoded reply content is too large")
        body = (
            ReplyMessageRequestBody.builder()
            .msg_type("text")
            .content(content)
            .reply_in_thread(False)
            .uuid(request_id)
            .build()
        )
        request = ReplyMessageRequest.builder().message_id(original.message_id).request_body(body).build()
        # Generated SDK requests also allow USER; remove it rather than relying
        # on the default choice. No user-access-token field is ever supplied.
        request.token_types = {AccessTokenType.TENANT}
        try:
            response = self._client.im.v1.message.reply(request)
            success = response.success()
        except Exception:  # noqa: BLE001 - boundary must redact arbitrary SDK/transport exceptions
            raise FeishuError("Feishu reply failed or its result is unknown") from None
        if not success:
            raise FeishuError("Feishu rejected the reply request")
        data = getattr(response, "data", None)
        if getattr(data, "chat_id", None) != original.chat_id:
            raise ReplyVerificationError("Reply response did not verify the original chat")
        reply_id = getattr(data, "message_id", None)
        if not _valid_id(reply_id) or reply_id == message_id:
            raise ReplyVerificationError("Reply response did not contain a valid new message ID")
        if getattr(data, "msg_type", None) != "text":
            raise ReplyVerificationError("Reply response did not verify the message type")
        parent_id = getattr(data, "parent_id", None)
        if parent_id not in (None, "", original.message_id):
            raise ReplyVerificationError("Reply response did not verify the original message")
        return reply_id
