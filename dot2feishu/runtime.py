"""Private single-owner foreground CLI runtime, with durable configuration binding."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import threading
import time
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet

from .cli import CLIConfig, FeishuCLIAdapter
from .core import Bridge, BridgeError, Store, canonical
from .feishu import FeishuPolicy, InboundMessage, _valid_id
from .security import SafeWebhookTransport

EVENT_NAME = "feishu.message.received"


def check_private(path: Path, *, directory=False):
    value = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(value.st_mode) or value.st_uid != os.getuid()
            or value.st_mode & 0o077 or (not directory and value.st_nlink != 1)):
        raise BridgeError("Bridge storage permissions are unsafe", -32003)


def private_read(path: Path) -> bytes:
    check_private(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        value = source.read(65537)
    if len(value) > 65536:
        raise BridgeError("Bridge configuration exceeds its bound", -32003)
    return value


def create_private(path: Path, content: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def load_config(path: Path, root: Path):
    value = json.loads(private_read(path))
    required = {"version", "enabled", "principal", "binding", "cli", "callback_hosts", "mcp_http_hosts", "port"}
    if (type(value) is not dict or set(value) != required or type(value["version"]) is not int
            or value["version"] != 1 or type(value["enabled"]) is not bool
            or type(value["principal"]) is not str or not value["principal"]):
        raise BridgeError("Invalid bridge configuration", -32003)
    binding = value["binding"]
    if type(binding) is not dict or set(binding) != {"app_id", "bot_open_id", "user_open_id", "tenant_key", "chat_id"}:
        raise BridgeError("Invalid account binding", -32003)
    if not all(_valid_id(v) and "REPLACE" not in v for v in binding.values()):
        raise BridgeError("Complete the account binding before initialization", -32003)
    cli = CLIConfig(**value["cli"])
    if (cli.profile != binding["app_id"] or cli.expected_bot_open_id != binding["bot_open_id"]
            or cli.config_dir != str(root / "config") or cli.data_dir != str(root / "data")):
        raise BridgeError("CLI paths or identity differ from the approved binding", -32003)
    for key in ("callback_hosts", "mcp_http_hosts"):
        if (type(value[key]) is not list or not value[key] or
                any(type(h) is not str or not h or "/" in h or "*" in h or h != h.lower() for h in value[key])):
            raise BridgeError("Explicit hostname allowlists are required", -32003)
    if type(value["port"]) is not int or not 1024 <= value["port"] <= 65535:
        raise BridgeError("Invalid HTTP port", -32003)
    return value


def config_digest(config):
    return hashlib.sha256(canonical({k: v for k, v in config.items() if k != "enabled"}).encode()).hexdigest()


class Runtime:
    def __init__(self, path, *, root, owner=None, initialize=False,
                 transport=None, adapter_factory=FeishuCLIAdapter):
        self.supervision = "foreground"
        self.path, self.root = Path(path), Path(root)
        self.unsafe_shutdown = False
        self._retained_lock = None
        check_private(self.root, directory=True)
        for directory in (self.root / "config", self.root / "data"):
            if initialize:
                directory.mkdir(mode=0o700, exist_ok=True)
            check_private(directory, directory=True)
        self.config = load_config(self.path, self.root)
        self.binding = self.config["binding"]
        self.digest = config_digest(self.config)
        self.principal = self.config["principal"]
        if owner is not None and owner != self.principal:
            raise BridgeError("MCP owner differs from the approved bridge owner", -32001)
        self.state = self.root / "bridge-state"
        if initialize:
            self.state.mkdir(mode=0o700, exist_ok=True)
        check_private(self.state, directory=True)
        keypath = self.state / "storage.key"
        if initialize and not keypath.exists():
            create_private(keypath, Fernet.generate_key())
        key = private_read(keypath)
        database = self.state / "bridge.sqlite3"
        if initialize and not database.exists():
            create_private(database, b"")
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = Path(str(database) + suffix)
            if suffix == "" or candidate.exists() or candidate.is_symlink():
                check_private(candidate)
        self.store = Store(database, key, recover_inflight=False)
        try:
            with self.store.lock, self.store.db:
                self.store.db.execute("CREATE TABLE IF NOT EXISTS bridge_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
                old = self.store.db.execute("SELECT value FROM bridge_meta WHERE key='binding'").fetchone()
                if old and old[0] != self.digest:
                    raise BridgeError("Existing bridge state belongs to another binding", -32001)
                if not old:
                    if not initialize:
                        raise BridgeError("Bridge state is not initialized", -32003)
                    self.store.db.execute("INSERT INTO bridge_meta VALUES('binding',?)", (self.digest,))
            policy = FeishuPolicy(self.binding["app_id"], self.binding["tenant_key"],
                                  self.binding["user_open_id"], self.binding["chat_id"])
            self.cutoff = None
            self.adapter = adapter_factory(CLIConfig(**self.config["cli"]), policy,
                                           self.ingest, self.store.message_record,
                                           authorized=lambda: self.authorized(self.principal, self.binding["chat_id"]),
                                           record_timing=True)
            self.bridge = Bridge(self.store, transport or SafeWebhookTransport(self.config["callback_hosts"]),
                                 principal=self.principal, chat_id=self.binding["chat_id"],
                                 authorized=self.authorized, replier=self.adapter, event_name=EVENT_NAME)
        except Exception:
            self.store.close()
            raise

    def authorized(self, principal, chat_id):
        try:
            check_private(self.root, directory=True)
            check_private(self.root / "config", directory=True)
            check_private(self.root / "data", directory=True)
            live = load_config(self.path, self.root)
            return (live["enabled"] and config_digest(live) == self.digest
                    and principal == self.principal and chat_id == self.binding["chat_id"])
        except Exception:  # noqa: BLE001 - redact data at the runtime/CLI boundary
            return False

    def ingest(self, message, *, record_received_ns=None):
        # The CLI adapter already normalizes and verifies provenance; check the
        # immutable receiver boundary again before allowing a durable write.
        if (type(message) is not InboundMessage or message.chat_id != self.binding["chat_id"]
                or message.sender_id != self.binding["user_open_id"]):
            return False
        if not self.authorized(self.principal, message.chat_id):
            raise BridgeError("Bridge authorization was revoked", -32001)
        if self.cutoff is None or datetime.fromisoformat(message.occurred_at).timestamp() < self.cutoff:
            return False
        with self.store.lock:
            active = self.store.db.execute(
                "SELECT 1 FROM subscriptions WHERE principal=? AND chat_id=? AND active=1 AND expires>? LIMIT 1",
                (self.principal, self.binding["chat_id"], time.time()),
            ).fetchone()
        if not active:
            return False
        return self.store.ingest(message, record_received_ns=record_received_ns)

    def heartbeat(self, state):
        # Metadata only; never CLI stderr, auth material or message content.
        value = canonical({"state": state, "at": time.time(), "pid": os.getpid(),
                           "supervision": self.supervision})
        with self.store.lock, self.store.db:
            self.store.db.execute("INSERT OR REPLACE INTO bridge_meta VALUES('listener',?)", (value,))

    def status(self):
        now = time.time()
        enabled = self.authorized(self.principal, self.binding["chat_id"])
        with self.store.lock:
            row = self.store.db.execute("SELECT value FROM bridge_meta WHERE key='listener'").fetchone()
            info = json.loads(row[0]) if row else {"state": "not_started", "at": 0}
            counts = {row[0]: row[1] for row in self.store.db.execute(
                "SELECT state,count(*) FROM deliveries GROUP BY state")}
            replies = {row[0]: row[1] for row in self.store.db.execute(
                "SELECT state,count(*) FROM replies GROUP BY state")}
            active = self.store.db.execute(
                "SELECT count(*) FROM subscriptions WHERE active=1 AND expires>?", (now,)).fetchone()[0]
            messages = self.store.db.execute("SELECT count(*) FROM messages").fetchone()[0]
            # Metadata recovery for a host wake that omits its event payload.
            # No message decryption, callback, signing secret or auth read.
            pending = self.store.db.execute(
                """SELECT DISTINCT m.message_id,m.chat_id,m.occurred_at,m.seq,
                    COALESCE(r.state,'not_started') AS reply_state
                FROM messages m JOIN deliveries d ON d.seq=m.seq
                JOIN subscriptions s ON s.id=d.subscription_id
                LEFT JOIN replies r ON r.message_id=m.message_id
                WHERE d.state='delivered' AND s.principal=? AND m.chat_id=?
                    AND (r.state IS NULL OR r.state!='sent')
                ORDER BY m.seq LIMIT 11""",
                (self.principal, self.binding["chat_id"]),
            ).fetchall() if enabled else []
        pending_events = [{"event_id": "evt_" + hashlib.sha256(row["message_id"].encode()).hexdigest(),
                           "message_id": row["message_id"], "chat_id": row["chat_id"],
                           "sender_id": self.binding["user_open_id"], "occurred_at": row["occurred_at"],
                           "sequence": row["seq"], "reply_state": row["reply_state"]}
                          for row in pending[:10]]
        fresh = now - info["at"] < 15
        state = info["state"] if fresh or info["state"] in {"not_started", "stopped", "failed", "unsafe_shutdown"} else "stale"
        return {"enabled": enabled, "event_name": EVENT_NAME,
                "listener_state": state, "listener_heartbeat_fresh": fresh,
                "active_subscriptions": active, "accepted_messages": messages,
                "deliveries": counts, "replies": replies,
                "delivery_timings": self.store.delivery_timings() if enabled else None,
                "pending_events": pending_events, "pending_events_truncated": len(pending) > 10,
                "source_delivery": "live_only_cli_ack_can_precede_commit",
                "restart_policy": "clean_stop_only_unclean_exit_requires_reconciliation"}

    def run(self, stop=None):
        stop = stop or threading.Event()
        if stop.is_set():
            return
        self.bridge.authorize(self.principal, self.binding["chat_id"])
        lockpath = self.state / "listener.lock"
        if not lockpath.exists():
            try:
                create_private(lockpath, b"")
            except FileExistsError:
                pass
        check_private(lockpath)
        descriptor = os.open(lockpath, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            raise BridgeError("Another listener already owns this bridge state", -32003) from None
        with self.store.lock:
            previous = self.store.db.execute("SELECT value FROM bridge_meta WHERE key='listener'").fetchone()
        if previous and json.loads(previous[0])["state"] not in {"stopped", "failed"}:
            os.close(descriptor)
            raise BridgeError("Previous listener exit is unconfirmed; operator reconciliation required", -32003)
        failed = threading.Event()

        def listen():
            try:
                if stop.is_set():
                    return
                self.bridge.authorize(self.principal, self.binding["chat_id"])
                self.adapter.start()
            except Exception:  # noqa: BLE001 - redact data at the runtime/CLI boundary
                failed.set()
            finally:
                stop.set()

        thread = None
        try:
            if stop.is_set():
                return
            self.bridge.authorize(self.principal, self.binding["chat_id"])
            with self.store.lock, self.store.db:
                self.store.db.execute("UPDATE deliveries SET state='pending' WHERE state='sending'")
            # No history/list API is ever called. Drop records predating this
            # explicitly started session; an MCP reload does not change cutoff.
            self.cutoff = int(time.time() * 1000) / 1000
            self.heartbeat("starting")
            thread = threading.Thread(target=listen, name="feishu-cli-consumer", daemon=True)
            thread.start()
            while not stop.is_set():
                self.bridge.authorize(self.principal, self.binding["chat_id"])
                self.heartbeat("running" if self.adapter.runner.ready.is_set() else "starting")
                worked = self.bridge.deliver_once()
                stop.wait(0.05 if worked else 1.0)
            if failed.is_set():
                raise BridgeError("Feishu listener stopped; inspect its authorized local status", -32003)
        except Exception:
            failed.set()
            raise
        finally:
            stop.set()
            # Pessimistic before any fallible cleanup or SQLite metadata write.
            self.unsafe_shutdown = True
            self._retained_lock = descriptor
            stop_failed = False
            try:
                self.adapter.stop()
            except Exception:  # noqa: BLE001 - still join and retain ownership on cleanup failure
                stop_failed = True
            if thread:
                thread.join(timeout=10)
                if thread.is_alive():
                    failed.set()
            unsafe = (stop_failed or (thread is not None and thread.is_alive())
                      or not self.adapter.runner.children_exit_confirmed)
            self.unsafe_shutdown = unsafe
            try:
                self.heartbeat("unsafe_shutdown" if unsafe else "failed" if failed.is_set() else "stopped")
            finally:
                if not unsafe:
                    os.close(descriptor)
                    self._retained_lock = None
            # A stuck consumer retains both the DB and exclusive lock until process exit.
            if unsafe:
                raise BridgeError("CLI shutdown was not confirmed; operator action required", -32003)

    def close(self):
        if self.unsafe_shutdown:
            raise BridgeError("Unsafe worker still owns storage; terminate container before reconciliation", -32003)
        self.store.close()

