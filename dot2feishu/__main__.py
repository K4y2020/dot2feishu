"""Operator-only setup, offline diagnosis and foreground container lifecycle."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import logging
import os
import signal
import socket
import threading
from pathlib import Path

from .cli import CLIConfig, OfficialCLIRunner
from .core import BridgeError
from .feishu import FeishuError
from .runtime import Runtime, check_private, create_private, load_config, private_read


def setup(root: Path):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private(root, directory=True)
    path = root / "config.json"
    if path.exists() or path.is_symlink():
        raise BridgeError("Configuration already exists; setup never overwrites state")
    print("Enter your own verified bot/private-chat binding. No Feishu credentials are requested here.")
    binding = {key: input(f"{key}: ").strip() for key in
               ("app_id", "bot_open_id", "user_open_id", "tenant_key", "chat_id")}
    principal = input("Local MCP owner label: ").strip()
    callback = input("Verified MCP host callback hostname (no URL): ").strip().lower()
    public_host = input("Your HTTPS MCP endpoint hostname (no URL): ").strip().lower()
    binary = Path(input("Official native CLI path [/usr/local/bin/lark-cli]: ").strip() or
                  "/usr/local/bin/lark-cli")
    with binary.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    cli = CLIConfig(str(binary), digest, binding["app_id"], str(root / "config"),
                    str(root / "data"), binding["bot_open_id"])
    OfficialCLIRunner(cli)._command(["--version"])  # validate only, never execute/login
    token = getpass.getpass("Existing owner-chosen MCP bearer (at least 32 bytes, stored privately): ")
    if len(token.encode()) < 32:
        raise BridgeError("MCP bearer must contain at least 32 bytes")
    config = {"version": 1, "enabled": False, "principal": principal, "binding": binding,
              "cli": vars(cli), "callback_hosts": [callback],
              "mcp_http_hosts": [public_host, "localhost:8765", "127.0.0.1:8765"], "port": 8765}
    enabled = input("Enable this exact single-owner binding after local CLI authorization? Type YES: ") == "YES"
    config["enabled"] = enabled
    create_private(path, json.dumps(config, indent=2).encode())
    try:
        load_config(path, root)
    except Exception:
        path.unlink()  # only the newly-created invalid file
        raise
    for name in ("config", "data"):
        (root / name).mkdir(mode=0o700, exist_ok=True)
        check_private(root / name, directory=True)
    create_private(root / "mcp-bearer", token.encode())
    runtime = Runtime(path, root=root, initialize=True)
    runtime.close()
    print(json.dumps({"configured": True, "enabled": enabled,
                      "next": "Authorize the official CLI locally, then doctor and serve"}))


def doctor(root: Path):
    check_private(root, directory=True)
    config = load_config(root / "config.json", root)
    token = private_read(root / "mcp-bearer")
    if len(token) < 32:
        raise BridgeError("MCP bearer is too short")
    OfficialCLIRunner(CLIConfig(**config["cli"]))._command(["--version"])
    runtime = Runtime(root / "config.json", root=root)
    try:
        print(json.dumps({"ok": True, "checks": "offline_config_private_storage_binary_binding",
                          "network_or_bot_authorization_verified": False, "status": runtime.status()}))
    finally:
        runtime.close()


def serve(root: Path, *, runtime_factory=Runtime, server_factory=None):
    import uvicorn

    from .app import build_app

    check_private(root, directory=True)
    runtime = runtime_factory(root / "config.json", root=root)
    stop = threading.Event()
    failed = threading.Event()
    listener = None
    sock = None
    server = None
    old_handlers = {}
    try:
        if not runtime.config["enabled"]:
            raise BridgeError("Bridge is disabled")
        token = private_read(root / "mcp-bearer").decode()
        app = build_app(runtime, token=token, allowed_hosts=runtime.config["mcp_http_hosts"])
        # Bind before CLI startup: failed ingress must not silently consume Feishu events.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", runtime.config["port"]))
        sock.listen(128)
        server = (server_factory or uvicorn.Server)(uvicorn.Config(
            app, host="0.0.0.0", port=runtime.config["port"], access_log=False,
            log_level="warning", timeout_graceful_shutdown=15))

        # Uvicorn re-raises captured signals after restoring prior handlers.
        # Keep our prior handlers cooperative so SIGTERM reaches this finally.
        def shutdown(*_):
            stop.set()
            server.should_exit = True

        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGTERM, signal.SIGINT):
                old_handlers[signum] = signal.signal(signum, shutdown)

        def listen():
            try:
                runtime.run(stop)
            except Exception:  # noqa: BLE001 - redact arbitrary external exceptions
                failed.set()
                runtime.bridge.delivery_healthy = False
            finally:
                server.should_exit = True

        listener = threading.Thread(target=listen, name="bridge-runtime", daemon=True)
        listener.start()
        server.run(sockets=[sock])  # Main thread: Uvicorn handles SIGINT/SIGTERM.
    finally:
        stop.set()
        if listener:
            listener.join(timeout=30)
        if sock:
            sock.close()
        # Do not close a DB that a stuck worker can still access.
        try:
            if listener and listener.is_alive():
                raise BridgeError("Shutdown unconfirmed; operator reconciliation required")
            runtime.close()
        finally:
            for signum, handler in old_handlers.items():
                signal.signal(signum, handler)
    if failed.is_set() or (server is not None and not server.started):
        raise BridgeError("Bridge stopped or HTTP startup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/data"))
    parser.add_argument("command", choices=("setup", "doctor", "serve"))
    args = parser.parse_args()
    os.umask(0o077)
    logging.getLogger("Lark").setLevel(logging.CRITICAL)
    try:
        {"setup": setup, "doctor": doctor, "serve": serve}[args.command](args.root.resolve())
    except (BridgeError, FeishuError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    except Exception:  # noqa: BLE001 - redact arbitrary external exceptions
        # Arbitrary library/CLI/config exceptions may contain secrets. Never print them.
        print('{"ok":false,"error":"operation_failed_check_private_configuration_and_local_status"}')
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
