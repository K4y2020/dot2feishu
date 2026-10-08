"""Standalone MCP HTTP contract exercised entirely in-process with fake state."""

import json
import logging
import time

import pytest
from starlette.testclient import TestClient
from test_runtime import BINDING, SECRET, accept, msg, subscription
from test_runtime import deployment as deployment_fixture

from dot2feishu.app import build_app
from dot2feishu.runtime import EVENT_NAME

deployment = deployment_fixture

PROTOCOL = "2026-07-28"
TOKEN = "offline-example-bearer-token-not-a-real-credential"
HEADERS = {
    "Authorization": "Bearer " + TOKEN,
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": PROTOCOL,
}
META = {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
    "io.modelcontextprotocol/clientCapabilities": {},
}
TOOLS = ["feishu_get_message", "feishu_reply_to_message", "feishu_bridge_status"]


@pytest.fixture
def client(deployment):
    runtime, *_ = deployment
    app = build_app(runtime, token=TOKEN, allowed_hosts=["testserver"])
    with TestClient(app) as c:
        yield c, runtime


def response(client, method, params=None, *, headers=None):
    params = dict(params or {})
    params["_meta"] = META
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": "offline-request", "method": method, "params": params},
        headers={
            **(HEADERS if headers is None else headers),
            "MCP-Method": method,
            **({"MCP-Name": params["name"]} if "name" in params else {}),
        },
    )


def rpc(client, method, params=None):
    result = response(client, method, params)
    assert result.status_code in {200, 400, 404}, result.text
    return result.json()


def test_http_discovery_tools_and_event_lifecycle(client):
    c, runtime = client
    discover = rpc(c, "server/discover")["result"]
    assert discover["supportedVersions"] == [PROTOCOL]
    assert discover["capabilities"]["events"] == {}
    tools = rpc(c, "tools/list")["result"]["tools"]
    assert [tool["name"] for tool in tools] == TOOLS
    assert [event["name"] for event in rpc(c, "events/list")["result"]["events"]] == [EVENT_NAME]
    params = subscription()
    first = rpc(c, "events/subscribe", params)["result"]
    assert first["id"] == rpc(c, "events/subscribe", params)["result"]["id"]
    runtime.cutoff = time.time() - 1
    message = msg()
    assert runtime.ingest(message)
    fetched = rpc(c, "tools/call", {"name": TOOLS[0], "arguments": {"message_id": message.message_id}})["result"]
    assert fetched["structuredContent"]["text"] == message.text
    reply_params = {"name": TOOLS[1], "arguments": {"message_id": message.message_id, "text": "approved"}}
    reply = rpc(c, "tools/call", reply_params)["result"]
    assert reply["structuredContent"]["duplicate"] is False
    assert rpc(c, "tools/call", reply_params)["result"]["structuredContent"]["duplicate"] is True
    assert len(runtime.adapter.replies) == 1
    unsub = {key: value for key, value in params.items() if key not in {"cursor", "ttlMs"}}
    unsub["delivery"] = {key: value for key, value in unsub["delivery"].items() if key != "secret"}
    assert "error" not in rpc(c, "events/unsubscribe", unsub)
    assert runtime.status()["active_subscriptions"] == 0


def test_http_requires_bearer_auth_for_discovery_tools_and_events(client):
    c, runtime = client
    for method in ("server/discover", "tools/list", "events/list"):
        assert response(c, method, headers={}).status_code == 401
        assert response(c, method, headers={**HEADERS, "Authorization": "Bearer wrong"}).status_code == 401
    assert not runtime.adapter.started.is_set()
    assert not runtime.adapter.replies


def test_http_rejects_unapproved_host(client):
    c, _ = client
    result = response(c, "tools/list", headers={**HEADERS, "Host": "unapproved.example.com"})
    assert result.status_code in {400, 403, 421}


def test_http_build_does_not_start_cli_listener(client):
    _, runtime = client
    assert not runtime.adapter.started.is_set()
    assert runtime.status()["listener_state"] == "not_started"


@pytest.mark.parametrize("change", [
    "other_chat", "extra", "badsecret", "badmode", "ttl_bool", "history",
    "unknown_event", "delivery_extra", "arguments_extra", "secret_list", "ttl_secret",
])
def test_http_event_rejects_malformed_requests_without_secret_leak(client, change, caplog):
    c, runtime = client
    params = subscription()
    if change == "other_chat":
        params["arguments"]["chat_id"] = "oc_other"
    elif change == "extra":
        params["unexpected"] = SECRET
    elif change == "badsecret":
        params["delivery"]["secret"] = {"value": SECRET}
    elif change == "badmode":
        params["delivery"]["mode"] = "arbitrary"
    elif change == "ttl_bool":
        params["ttlMs"] = True
    elif change == "history":
        params["cursor"] = "past"
    elif change == "unknown_event":
        params["name"] = "unknown.event"
    elif change == "delivery_extra":
        params["delivery"]["unexpected"] = SECRET
    elif change == "arguments_extra":
        params["arguments"]["unexpected"] = SECRET
    elif change == "secret_list":
        params["delivery"]["secret"] = [SECRET]
    elif change == "ttl_secret":
        params["ttlMs"] = SECRET
    with caplog.at_level(logging.DEBUG):
        result = rpc(c, "events/subscribe", params)
    assert "error" in result
    assert SECRET not in json.dumps(result)
    assert SECRET not in caplog.text
    assert runtime.status()["active_subscriptions"] == 0


@pytest.mark.parametrize("method,params", [
    ("events/list", {"unexpected": SECRET}),
    ("events/unsubscribe", {"name": EVENT_NAME, "arguments": {"chat_id": BINDING["chat_id"]},
                            "delivery": {"mode": "webhook", "url": "https://receiver.example.com/events",
                                         "secret": SECRET}}),
])
def test_http_other_event_models_redact_invalid_fields(client, method, params, caplog):
    c, _ = client
    with caplog.at_level(logging.DEBUG):
        result = rpc(c, method, params)
    assert "error" in result
    assert SECRET not in json.dumps(result)
    assert SECRET not in caplog.text


@pytest.mark.parametrize("name,args", [
    (TOOLS[0], {"message_id": "om_other"}),
    (TOOLS[0], {"message_id": "om_other", "chat_id": "oc_other"}),
    (TOOLS[1], {"message_id": "om_other", "text": "no"}),
    (TOOLS[1], {"message_id": "om_other", "text": "no", "chat_id": "oc_other"}),
    (TOOLS[2], {"include_secrets": True}),
])
def test_http_tool_scope_rejection(client, name, args):
    c, runtime = client
    assert rpc(c, "tools/call", {"name": name, "arguments": args})["result"]["isError"]
    assert not runtime.adapter.replies


def test_http_revoked_bridge_rejects_all_remote_access(client, deployment):
    c, runtime = client
    _, path, config, _ = deployment
    message = accept(runtime)
    config["enabled"] = False
    path.write_text(json.dumps(config))
    for name in TOOLS:
        result = response(c, "tools/call", {"name": name})
        assert result.status_code == 403
        assert message.text not in result.text
        assert SECRET not in result.text
    status = runtime.status()
    assert status["enabled"] is False and status["pending_events"] == []
    assert not runtime.adapter.replies


def test_http_pending_get_schema_is_optional_and_narrow(client):
    c, _ = client
    definitions = {tool["name"]: tool for tool in rpc(c, "tools/list")["result"]["tools"]}
    assert list(definitions) == TOOLS
    getter = definitions[TOOLS[0]]["inputSchema"]
    assert getter.get("required", []) == []
    assert set(getter["properties"]) == {"message_id"}
    assert getter["additionalProperties"] is False
    assert definitions[TOOLS[1]]["inputSchema"]["required"] == ["message_id", "text"]


def test_http_pending_get_returns_empty_body_and_blocked_in_one_call(client):
    c, runtime = client

    def fetch():
        result = rpc(c, "tools/call", {"name": TOOLS[0]})["result"]
        assert not result["isError"]
        return result["structuredContent"]

    assert fetch() == {"status": "empty", "message": None}
    message = accept(runtime)
    assert fetch() == {"status": "empty", "message": None}
    runtime.bridge.deliver_once()
    result = fetch()
    assert result["status"] == "ready" and result["message"]["message_id"] == message.message_id
    assert result["message"]["text"] == message.text
    with runtime.store.db:
        runtime.store.db.execute("INSERT INTO replies VALUES(?,'hash','request','sending',NULL,0)",
                                 (message.message_id,))
    assert fetch()["status"] == "blocked"
    assert not runtime.adapter.replies


@pytest.mark.parametrize("args", [
    {"message_id": None}, {"message_id": True}, {"message_id": 5},
    {"chat_id": "oc_other"}, {"message_id": "om_other", "principal": "other"},
])
def test_http_pending_get_rejects_invalid_or_expanded_scope(client, args):
    c, runtime = client
    assert rpc(c, "tools/call", {"name": TOOLS[0], "arguments": args})["result"]["isError"]
    assert not runtime.adapter.replies


def test_http_unknown_method_and_tool_are_rejected(client):
    c, runtime = client
    assert "error" in rpc(c, "arbitrary/exec", {"command": "no"})
    result = rpc(c, "tools/call", {"name": "arbitrary_tool", "arguments": {}})
    assert "error" in result or result["result"]["isError"]
    assert not runtime.adapter.replies


def test_http_unhealthy_delivery_worker_fails_closed(client):
    c, runtime = client
    runtime.bridge.delivery_healthy = False
    for method in ("server/discover", "tools/list", "events/list"):
        assert response(c, method).status_code == 503
    assert not runtime.adapter.replies


def test_http_rejects_short_bearer_credential(deployment):
    runtime, *_ = deployment
    with pytest.raises(ValueError, match="32 bytes"):
        build_app(runtime, token="short-example", allowed_hosts=["testserver"])


@pytest.mark.parametrize("params", [
    {"name": TOOLS[0], "arguments": SECRET},
    {"name": TOOLS[0], "arguments": [SECRET]},
    {"name": TOOLS[1], "arguments": {"message_id": {"secret": SECRET}, "text": SECRET}},
    {"name": TOOLS[2], "arguments": {"unexpected": SECRET}},
])
def test_http_malformed_tools_do_not_echo_secret_values(client, params, caplog):
    c, runtime = client
    with caplog.at_level(logging.DEBUG):
        result = rpc(c, "tools/call", params)
    assert "error" in result or result["result"]["isError"]
    assert SECRET not in json.dumps(result)
    assert SECRET not in caplog.text
    assert not runtime.adapter.replies


def test_http_malformed_json_does_not_echo_secret_values(client, caplog):
    c, runtime = client
    with caplog.at_level(logging.DEBUG):
        result = c.post("/mcp", content='{"secret":"' + SECRET + '",broken',
                        headers={**HEADERS, "Content-Type": "application/json", "MCP-Method": "events/subscribe"})
    assert result.status_code == 400
    assert SECRET not in result.text
    assert SECRET not in caplog.text
    assert not runtime.adapter.replies
