"""MCP 2.0 HTTP endpoint using the official Python SDK; secrets supplied at runtime."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json

import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .core import BridgeError

PROTOCOL = "2026-07-28"


from .contracts import tool_definitions
from .models import EventParams, ListParams, StrictParams, UnsubscribeParams


def error(exc: BridgeError) -> MCPError:
    return MCPError(
        types.ErrorData(code=exc.code, message=str(exc), data={"reason": exc.reason} if exc.reason else None)
    )


def build_server(runtime) -> Server:
    bridge = runtime.bridge
    def principal(ctx) -> str:
        if ctx.protocol_version != PROTOCOL:
            raise MCPError(types.ErrorData(code=-32600, message="MCP 2026-07-28 is required"))
        request = ctx.request
        who = request.scope.get("bridge_principal") if request is not None else None
        if not who:
            raise MCPError(types.ErrorData(code=-32001, message="Authenticated HTTP request required"))
        bridge.authorize(who, bridge.chat_id)
        return who

    async def discover(ctx, params):
        principal(ctx)
        # The Events capability is restored by the public middleware after SDK serialization.
        return {
            "resultType": "complete",
            "ttlMs": 0,
            "cacheScope": "private",
            "supportedVersions": [PROTOCOL],
            "capabilities": {"tools": {}, "events": {}},
        }

    async def event_list(ctx, params):
        who = principal(ctx)
        if params.cursor is not None:
            raise error(BridgeError("Unknown event catalog cursor"))
        return {"events": [bridge.definition(who)]}

    async def subscribe(ctx, params):
        who = principal(ctx)
        payload = params.model_dump(by_alias=True, exclude={"meta"})
        payload["delivery"]["secret"] = (
            params.delivery.secret.get_secret_value() if params.delivery.secret else None
        )
        try:
            return await asyncio.to_thread(bridge.subscribe, who, payload)
        except BridgeError as exc:
            raise error(exc) from None
        except Exception:  # noqa: BLE001 - redact arbitrary external exceptions
            raise MCPError(types.ErrorData(code=-32603, message="Bridge operation failed")) from None

    async def unsubscribe(ctx, params):
        who = principal(ctx)
        try:
            return bridge.unsubscribe(who, params.model_dump(by_alias=True, exclude={"meta"}))
        except BridgeError as exc:
            raise error(exc) from None
        except Exception:  # noqa: BLE001 - redact arbitrary external exceptions
            raise MCPError(types.ErrorData(code=-32603, message="Bridge operation failed")) from None

    async def list_tools(ctx, params):
        principal(ctx)
        return types.ListToolsResult(tools=[types.Tool.model_validate(item) for item in tool_definitions()])

    async def call_tool(ctx, params):
        who = principal(ctx)
        args = params.arguments or {}
        try:
            if type(args) is not dict:
                raise BridgeError("Invalid tool arguments")
            if (params.name == "feishu_get_message" and
                    (not args or (set(args) == {"message_id"} and type(args["message_id"]) is str))):
                result = await asyncio.to_thread(bridge.get_message, who, args.get("message_id"))
            elif (params.name == "feishu_reply_to_message" and set(args) == {"message_id", "text"}
                  and type(args["message_id"]) is str and type(args["text"]) is str):
                result = await asyncio.to_thread(bridge.reply_to_message, who, args["message_id"], args["text"])
            elif params.name == "feishu_bridge_status" and not args:
                result = await asyncio.to_thread(runtime.status)
            else:
                raise BridgeError("Unknown tool or invalid arguments")
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=json.dumps(result, ensure_ascii=False))],
                structured_content=result,
            )
        except BridgeError as exc:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(exc))], is_error=True
            )

        except Exception:  # noqa: BLE001 - redact arbitrary external exceptions
            return types.CallToolResult(content=[types.TextContent(type="text", text="Bridge operation failed")], is_error=True)

    server = Server(
        "dot2feishu",
        version="0.1.0rc1",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )

    async def event_capability_middleware(ctx, call_next):
        # Official SDK 2.3.0 serializes known methods through its base schema,
        # which currently omits draft Events. The public middleware hook runs
        # after that serialization; advertise the exact OpenAI Events contract
        # here without modifying the installed SDK or its global schema tables.
        principal(ctx)
        result = await call_next(ctx)
        if ctx.method == "server/discover" and isinstance(result, dict):
            result.setdefault("capabilities", {})["events"] = {}
        return result

    server.middleware.append(event_capability_middleware)
    server.add_request_handler("server/discover", StrictParams, discover)
    server.add_request_handler("events/list", ListParams, event_list)
    server.add_request_handler("events/subscribe", EventParams, subscribe)
    server.add_request_handler("events/unsubscribe", UnsubscribeParams, unsubscribe)
    return server


def build_app(runtime, *, token: str, allowed_hosts: list[str] | None = None):
    bridge = runtime.bridge
    if len(token.encode()) < 32:
        raise ValueError("MCP bearer credential must contain at least 32 bytes")
    server = build_server(runtime)
    app = server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=65536,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts or ["127.0.0.1:*", "localhost:*"],
            allowed_origins=[],
        ),
    )
    expected = hashlib.sha256(token.encode()).digest()

    async def authentication(request: Request, call_next):
        authorization = request.headers.get("authorization", "")
        candidate = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not hmac.compare_digest(hashlib.sha256(candidate.encode()).digest(), expected):
            return JSONResponse(
                {"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"}
            )
        if not bridge.delivery_healthy:
            return JSONResponse({"error": "durable delivery unavailable"}, status_code=503)
        try:
            bridge.authorize(bridge.principal, bridge.chat_id)
        except BridgeError:
            return JSONResponse({"error": "access revoked"}, status_code=403)
        request.scope["bridge_principal"] = bridge.principal
        return await call_next(request)

    app.add_middleware(BaseHTTPMiddleware, dispatch=authentication)
    return app

