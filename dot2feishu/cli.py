"""Constrained official-CLI adapter; no credential-file parsing or generic exec tool.

CLI output has no app/tenant envelope fields. Provenance comes from a pinned
native binary, explicit profile and --as bot, and independent identity checks.
Unlike the SDK adapter, upstream ACK can precede this process's SQLite commit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .cli_normalize import normalize_cli_event
from .feishu import FeishuError, FeishuPolicy, InboundMessage, _valid_id, validate_reply_text

MAX_OUTPUT = 262144
EVENT_KEY = "im.message.receive_v1"
READY = b"[event] ready event_key=im.message.receive_v1"


class FeishuCLIError(FeishuError):
    """Sanitized subprocess/provenance failure; never includes raw stderr."""


@dataclass(frozen=True)
class CLIConfig:
    binary: str
    binary_sha256: str
    profile: str
    config_dir: str
    data_dir: str
    expected_bot_open_id: str

    def __post_init__(self):
        if not re.fullmatch(r"[a-f0-9]{64}", self.binary_sha256):
            raise ValueError("A reviewed native CLI SHA256 is required")
        for path in (self.binary, self.config_dir, self.data_dir):
            if not isinstance(path, str) or not Path(path).is_absolute() or "\x00" in path:
                raise ValueError("CLI paths must be explicit absolute paths")
        if not _valid_id(self.profile) or not _valid_id(self.expected_bot_open_id):
            raise ValueError("CLI profile and bot identity must be verified IDs")


class OfficialCLIRunner:
    """Private fixed-argv process transport. No arguments come from arbitrary MCP commands."""

    def __init__(self, config: CLIConfig):
        self.config = config
        self._process = None
        self._stop = threading.Event()
        self.ready = threading.Event()
        self._children = set()
        self._children_lock = threading.Lock()

    def _command(self, args: list[str]) -> list[str]:
        path = Path(self.config.binary)
        # Deliberately target the native binary, not the npm auto-install launcher.
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_mode & 0o022
            or not os.access(path, os.X_OK)
        ):
            raise FeishuCLIError("CLI binary must be a reviewed non-writable native file")
        with path.open("rb") as binary:
            if binary.read(4) != b"\x7fELF":
                raise FeishuCLIError("Only the reviewed native ELF CLI is supported")
            binary.seek(0)
            digest = hashlib.file_digest(binary, "sha256").hexdigest()
        if digest != self.config.binary_sha256:
            raise FeishuCLIError("CLI binary changed; re-review its version and hash")
        return [str(path), "--profile", self.config.profile, *args]

    def _environment(self) -> dict[str, str]:
        # Preserve only OS/keyring context. Never inherit token/app-secret flags,
        # preload hooks, profile selection, proxies or debugging environment.
        permitted = ("HOME", "PATH", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "LANG")
        env = {key: os.environ[key] for key in permitted if key in os.environ}
        env.update(
            {
                "TZ": "UTC",
                "LARKSUITE_CLI_CONFIG_DIR": self.config.config_dir,
                "LARKSUITE_CLI_DATA_DIR": self.config.data_dir,
            }
        )
        return env

    @property
    def children_exit_confirmed(self):
        with self._children_lock:
            return not self._children

    def _spawn(self, args):
        process = subprocess.Popen(
            self._command(args),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._environment(),
            shell=False,
            start_new_session=True,
            bufsize=0,
        )
        with self._children_lock:
            self._children.add(process)
        return process

    def _close(self, process):
        if process.stdin and not process.stdin.closed:
            process.stdin.close()  # Official unbounded consumer's graceful shutdown contract.
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                raise FeishuCLIError(
                    "CLI did not stop after graceful shutdown; operator action required"
                ) from None
        finally:
            if process.poll() is not None:
                with self._children_lock:
                    self._children.discard(process)
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()

    def _run_bytes(self, args, input_bytes=b"", timeout=20.0):
        process = self._spawn(args)
        out, err = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        input_position = 0
        try:
            with selectors.DefaultSelector() as selector:
                for stream, label in ((process.stdout, "out"), (process.stderr, "err")):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, label)
                if input_bytes:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, "in")
                else:
                    process.stdin.close()
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise FeishuCLIError("CLI request timed out; send outcome may be unknown")
                    for key, _ in selector.select(min(remaining, 0.2)):
                        if key.data == "in":
                            try:
                                input_position += os.write(
                                    key.fd, input_bytes[input_position : input_position + 8192]
                                )
                            except BrokenPipeError:
                                input_position = len(input_bytes)
                            if input_position == len(input_bytes):
                                selector.unregister(key.fileobj)
                                process.stdin.close()
                            continue
                        data = os.read(key.fd, 8192)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        target = out if key.data == "out" else err
                        target.extend(data)
                        if len(target) > MAX_OUTPUT:
                            raise FeishuCLIError("CLI output exceeded its safe bound")
            if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                raise FeishuCLIError("CLI request failed")
            return bytes(out)
        except (OSError, subprocess.SubprocessError):
            raise FeishuCLIError("CLI request failed or its result is unknown") from None
        finally:
            self._close(process)

    def run_json(self, args, input_bytes=b"") -> dict:
        try:
            value = json.loads(self._run_bytes(args, input_bytes))
        except (ValueError, UnicodeError):
            raise FeishuCLIError("CLI returned malformed JSON") from None
        if type(value) is not dict:
            raise FeishuCLIError("CLI returned an unexpected response")
        return value

    def stop(self):
        self._stop.set()
        process = self._process
        if process is not None and process.stdin and not process.stdin.closed:
            process.stdin.close()

    def consume(self, on_event: Callable, startup_timeout=30.0, *, include_timing=False):
        """Wait for exact ready marker; keep stdin open; parse bounded NDJSON."""
        if self._process is not None:
            raise FeishuCLIError("CLI consumer already started")
        process = self._spawn(["event", "consume", EVENT_KEY, "--as", "bot"])
        self._process = process
        deadline = time.monotonic() + startup_timeout
        ready = False
        buffers = {"out": bytearray(), "err": bytearray()}
        pending = []
        pending_bytes = 0
        try:
            with selectors.DefaultSelector() as selector:
                for stream, label in ((process.stdout, "out"), (process.stderr, "err")):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, label)
                while selector.get_map():
                    if self._stop.is_set():
                        return
                    if not ready and time.monotonic() >= deadline:
                        raise FeishuCLIError("CLI consumer did not become ready")
                    for key, _ in selector.select(0.2):
                        chunk = os.read(key.fd, 8192)
                        chunk_received_ns = time.monotonic_ns()
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        buffer = buffers[key.data]
                        buffer.extend(chunk)
                        if len(buffer) > MAX_OUTPUT:
                            raise FeishuCLIError("CLI event or diagnostic exceeded its safe bound")
                        while b"\n" in buffer:
                            raw, _, remaining = buffer.partition(b"\n")
                            buffer[:] = remaining
                            if key.data == "err":
                                if raw == READY:
                                    ready = True
                                    self.ready.set()
                                    for item, received_ns in pending:
                                        if include_timing:
                                            on_event(item, received_ns)
                                        else:
                                            on_event(item)
                                    pending.clear()
                                    pending_bytes = 0
                                elif raw.startswith(b"{"):
                                    try:
                                        diagnostic = json.loads(raw)
                                    except ValueError:
                                        raise FeishuCLIError("Malformed CLI diagnostic") from None
                                    if diagnostic.get("ok") is False:
                                        raise FeishuCLIError("CLI consumer reported a runtime failure")
                                elif (
                                    raw.startswith((b"WARN", b"ERROR", b"[WARN", b"[ERROR"))
                                    or b"drop" in raw.lower()
                                ):
                                    raise FeishuCLIError("CLI consumer reported possible event loss")
                                continue
                            if not raw:
                                continue
                            # Every complete record in this chunk shares the read
                            # time, including records waiting behind an earlier ingest.
                            # This is CLI pipe receipt, not websocket arrival.
                            received_ns = chunk_received_ns
                            try:
                                value = json.loads(raw)
                            except (ValueError, UnicodeError):
                                raise FeishuCLIError("CLI event JSON is malformed") from None
                            if type(value) is not dict:
                                raise FeishuCLIError("CLI event is not an object")
                            if ready:
                                if include_timing:
                                    on_event(value, received_ns)
                                else:
                                    on_event(value)
                            else:
                                pending.append((value, received_ns))
                                pending_bytes += len(raw)
                                if pending_bytes > MAX_OUTPUT:
                                    raise FeishuCLIError("CLI events arrived before readiness")
            if not self._stop.is_set():
                raise FeishuCLIError("CLI consumer stopped; supervisor recovery required")
        except (OSError, subprocess.SubprocessError):
            raise FeishuCLIError("CLI consumer I/O failed") from None
        finally:
            self._close(process)
            self._process = None


class FeishuCLIAdapter:
    def __init__(
        self,
        config: CLIConfig,
        policy: FeishuPolicy,
        on_message,
        lookup_message,
        *,
        runner=None,
        authorized=None,
        record_timing=False,
    ):
        if config.profile != policy.app_id:
            raise ValueError("Explicit CLI profile must equal the verified app ID")
        self.config, self.policy = config, policy
        self.on_message, self.lookup_message = on_message, lookup_message
        self.runner = runner or OfficialCLIRunner(config)
        self.authorized = authorized or (lambda: True)
        self.record_timing = record_timing
        self._started = False

    def verify_identity(self):
        identity = self.runner.run_json(["whoami", "--as", "bot"])
        expected = {
            "profile": self.config.profile,
            "appId": self.policy.app_id,
            "brand": "feishu",
            "identity": "bot",
            "identitySource": "flag",
            "available": True,
            "tokenStatus": "ready",
        }
        if any(type(identity.get(k)) is not type(v) or identity.get(k) != v for k, v in expected.items()):
            raise FeishuCLIError("CLI profile/app/bot identity did not match the reviewed binding")
        response = self.runner.run_json(["api", "GET", "/open-apis/bot/v3/info", "--as", "bot"])
        data = response.get("data")
        if (
            response.get("ok") is not True
            or response.get("identity") != "bot"
            or type(data) is not dict
            or data.get("open_id") != self.config.expected_bot_open_id
            or type(data.get("activate_status")) is not int
            or data.get("activate_status") != 2
        ):
            raise FeishuCLIError("CLI bot identity is inactive or differs from the reviewed bot")
        # Tenant is deliberately not invented: CLI does not return it here.
        # Reviewed app ID + bot open ID + profile form this adapter's provenance.

    def start(self):
        if self._started:
            raise FeishuCLIError("CLI adapter already started")
        self.verify_identity()
        if not self.authorized():
            raise FeishuCLIError("Bridge authorization was revoked before listening")
        self._started = True

        def accept(payload, record_received_ns=None):
            message = normalize_cli_event(payload, self.policy)
            if message is not None:
                try:
                    if self.record_timing:
                        self.on_message(message, record_received_ns=record_received_ns)
                    else:
                        self.on_message(message)
                except Exception:  # noqa: BLE001 - redact durable storage failure details
                    raise FeishuCLIError("CLI message could not be durably persisted") from None

        if self.record_timing:
            self.runner.consume(accept, include_timing=True)
        else:
            self.runner.consume(accept)

    def stop(self):
        self.runner.stop()

    def reply(self, message_id, text, request_id):
        validate_reply_text(text, self.policy.max_text_bytes)
        if not _valid_id(message_id) or not re.fullmatch(r"[A-Za-z0-9_-]{1,50}", request_id):
            raise FeishuCLIError("Invalid reply identifiers")
        original = self.lookup_message(message_id)
        if (
            type(original) is not InboundMessage
            or original.message_id != message_id
            or original.chat_id != self.policy.allowed_chat_id
            or original.sender_id != self.policy.allowed_user_open_id
        ):
            raise FeishuCLIError("Reply requires a verified original private-chat message")
        self.verify_identity()  # Fail closed if the official CLI profile changed between calls.
        if not self.authorized():
            raise FeishuCLIError("Bridge authorization was revoked before sending")
        response = self.runner.run_json(
            [
                "im",
                "+messages-reply",
                "--as",
                "bot",
                "--message-id",
                original.message_id,
                "--text",
                "-",
                "--idempotency-key",
                request_id,
            ],
            text.encode(),
        )
        data = response.get("data")
        if (
            response.get("ok") is not True
            or response.get("identity") != "bot"
            or type(data) is not dict
            or data.get("chat_id") != original.chat_id
            or not _valid_id(data.get("message_id"))
            or data.get("message_id") == original.message_id
        ):
            raise FeishuCLIError("CLI reply result did not verify the original chat")
        return data["message_id"]
