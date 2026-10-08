"""Durable single-user event delivery; no model inference or shell execution."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from cryptography.fernet import Fernet

from .security import SecurityError, TransportError, signed_headers, validate_secret

EVENT_NAME = "message.created"
MAX_ATTEMPTS = 8
ROTATION_SECONDS = 300
TIMING_SAMPLE_LIMIT = 64


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z")


class BridgeError(Exception):
    def __init__(self, message: str, code: int = -32602, reason: str | None = None):
        super().__init__(message)
        self.code, self.reason = code, reason


class Store:
    """One process, multiple threads. CLI ACK may precede SQLite commit."""

    def __init__(
        self,
        path: str | Path,
        encryption_key: bytes,
        *,
        recover_inflight: bool = True,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ):
        self.cipher = Fernet(encryption_key)
        self.monotonic_ns = monotonic_ns
        self.timing_run_id = secrets.token_hex(8)
        self._ingress_timings = OrderedDict()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.exists() and (path.is_symlink() or path.stat().st_mode & 0o077):
            raise ValueError("Database must be a private regular file (mode 0600)")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=5, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS messages(
                seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
                message_id TEXT UNIQUE NOT NULL, chat_id TEXT NOT NULL,
                occurred_at TEXT NOT NULL, body BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS subscriptions(
                id TEXT PRIMARY KEY, principal TEXT NOT NULL, chat_id TEXT NOT NULL,
                callback BLOB NOT NULL, secret BLOB NOT NULL, old_secret BLOB,
                rotation_until REAL NOT NULL DEFAULT 0,
                expires REAL NOT NULL, active INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS verification(
                identity TEXT PRIMARY KEY, valid_until REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS deliveries(
                subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
                seq INTEGER NOT NULL REFERENCES messages(seq),
                state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                next_at REAL NOT NULL DEFAULT 0, last_reason TEXT,
                PRIMARY KEY(subscription_id,seq));
            CREATE TABLE IF NOT EXISTS replies(
                message_id TEXT PRIMARY KEY REFERENCES messages(message_id),
                text_hash TEXT NOT NULL, request_id TEXT NOT NULL,
                state TEXT NOT NULL, reply_id TEXT, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS delivery_timings(
                sample_id INTEGER PRIMARY KEY AUTOINCREMENT, sample TEXT NOT NULL);
        """)
        # A process crash while posting may have delivered the event; redelivery uses same eventId.
        if recover_inflight:
            with self.db:
                self.db.execute("UPDATE deliveries SET state='pending' WHERE state='sending'")

    def seal(self, value: str) -> bytes:
        return self.cipher.encrypt(value.encode())

    def open(self, value: bytes) -> str:
        return self.cipher.decrypt(value).decode()

    def close(self):
        with self.lock:
            self.db.close()

    def ingest(self, message, *, now: float | None = None, record_received_ns: int | None = None) -> bool:
        now = time.time() if now is None else now
        values = asdict(message)
        with self.lock:
            with self.db:
                c = self.db.execute(
                    "INSERT OR IGNORE INTO messages(event_id,message_id,chat_id,occurred_at,body) VALUES(?,?,?,?,?)",
                    (
                        message.event_id,
                        message.message_id,
                        message.chat_id,
                        message.occurred_at,
                        self.seal(canonical(values)),
                    ),
                )
                if c.rowcount == 0:
                    return False
                self.db.execute(
                    """INSERT INTO deliveries(subscription_id,seq)
                    SELECT id,? FROM subscriptions WHERE active=1 AND expires>? AND chat_id=?""",
                    (c.lastrowid, now, message.chat_id),
                )
            # Commit is complete and the lock still excludes the delivery thread.
            committed_ns = self.monotonic_ns()
            if type(record_received_ns) is not int or not 0 <= record_received_ns <= committed_ns:
                record_received_ns = None
            self._ingress_timings[c.lastrowid] = (record_received_ns, committed_ns)
            while len(self._ingress_timings) > TIMING_SAMPLE_LIMIT:
                self._ingress_timings.popitem(last=False)
            return True

    def record_delivery_timing(
        self, *, sequence, attempt, claim_ns, post_start_ns, post_end_ns, http_status, outcome
    ):
        """Called under the existing final delivery transaction; metadata only.

        Absolute monotonic values never cross process boundaries. Missing ingress
        after restart or bounded-cache eviction stays unknown rather than mixing
        clocks. The delivery attempt itself is measured in this Store's run.
        """
        received_ns, committed_ns = self._ingress_timings.get(sequence, (None, None))

        def elapsed(start, end):
            return round((end - start) / 1_000_000, 3) if start is not None and end >= start else None

        sample = {
            "run_id": self.timing_run_id,
            "sequence": sequence,
            "attempt": attempt,
            "http_status": http_status,
            "outcome": outcome,
            "source_to_receiver_ms": None,
            "source_to_receiver": "unknown",
            "record_to_commit_ms": elapsed(received_ns, committed_ns) if committed_ns is not None else None,
            "commit_to_claim_ms": elapsed(committed_ns, claim_ns),
            "claim_to_post_ms": elapsed(claim_ns, post_start_ns),
            "post_ms": elapsed(post_start_ns, post_end_ns),
            "record_to_post_end_ms": elapsed(received_ns, post_end_ns),
        }
        # No delivery-state update has happened in this transaction yet. If
        # SQLite aborts it (including SQLITE_FULL), discard telemetry and let
        # the caller persist the authoritative callback result in a new one.
        try:
            self.db.execute("INSERT INTO delivery_timings(sample) VALUES(?)", (canonical(sample),))
            self.db.execute(
                """DELETE FROM delivery_timings WHERE sample_id NOT IN
                (SELECT sample_id FROM delivery_timings ORDER BY sample_id DESC LIMIT ?)""",
                (TIMING_SAMPLE_LIMIT,),
            )
        except sqlite3.Error:
            self.db.rollback()

    def delivery_timings(self):
        with self.lock:
            rows = self.db.execute(
                "SELECT sample FROM delivery_timings ORDER BY sample_id DESC LIMIT ?", (TIMING_SAMPLE_LIMIT,)
            ).fetchall()
        return {
            "clock": "same_process_monotonic",
            "source_to_receiver": "unknown",
            "sample_limit": TIMING_SAMPLE_LIMIT,
            "samples": [json.loads(row[0]) for row in rows],
        }

    def message(self, message_id: str) -> dict:
        with self.lock:
            row = self.db.execute(
                "SELECT seq,body FROM messages WHERE message_id=?", (message_id,)
            ).fetchone()
            if not row:
                raise BridgeError("Message not available", -32004)
            value = json.loads(self.open(row["body"]))
            value["sequence"] = row["seq"]
            return value

    def message_record(self, message_id: str):
        from .feishu import InboundMessage

        value = self.message(message_id)
        value.pop("sequence")
        return InboundMessage(**value)


class Bridge:
    def __init__(
        self,
        store: Store,
        transport,
        *,
        principal: str,
        chat_id: str,
        authorized: Callable[[str, str], bool] | None = None,
        clock: Callable[[], float] = time.time,
        replier=None,
        event_name: str = EVENT_NAME,
    ):
        self.event_name = event_name
        self.store, self.transport = store, transport
        self.principal, self.chat_id, self.clock, self.replier = principal, chat_id, clock, replier
        self.authorized = authorized or (lambda p, c: p == principal and c == chat_id)
        self.delivery_lock = threading.Lock()
        self.delivery_healthy = True

    def authorize(self, principal: str, chat_id: str):
        if principal != self.principal or chat_id != self.chat_id or not self.authorized(principal, chat_id):
            raise BridgeError("Access denied", -32001)

    def definition(self, principal: str) -> dict:
        self.authorize(principal, self.chat_id)
        props = {k: {"type": "string"} for k in ("message_id", "chat_id", "sender_id", "occurred_at")}
        props["sequence"] = {"type": "integer", "minimum": 1}
        return {
            "name": self.event_name,
            "description": "A text message from the verified user in the one authorized Feishu bot private chat.",
            "delivery": ["webhook"],
            "inputSchema": {
                "type": "object",
                "properties": {"chat_id": {"type": "string", "enum": [self.chat_id]}},
                "required": ["chat_id"],
                "additionalProperties": False,
            },
            "payloadSchema": {
                "type": "object",
                "properties": props,
                "required": list(props),
                "additionalProperties": False,
            },
        }

    def identity(self, principal: str, params: dict) -> str:
        if params.get("name") != self.event_name:
            raise BridgeError("Unknown event")
        args, delivery = params.get("arguments"), params.get("delivery")
        if not isinstance(args, dict) or set(args) != {"chat_id"}:
            raise BridgeError("Exactly one chat_id is required")
        self.authorize(principal, args["chat_id"])
        if (
            not isinstance(delivery, dict)
            or delivery.get("mode") != "webhook"
            or not isinstance(delivery.get("url"), str)
        ):
            raise BridgeError("Webhook delivery is required")
        # Canonical JSON makes property order irrelevant. Principal scopes ownership.
        raw = canonical([principal, delivery["url"], self.event_name, args])
        return "sub_" + hashlib.sha256(raw.encode()).hexdigest()

    def subscribe(self, principal: str, params: dict) -> dict:
        sid = self.identity(principal, params)
        if params.get("cursor") is not None:
            raise BridgeError("This Feishu live event source does not support replay cursors")
        delivery = params["delivery"]
        try:
            secret = delivery["secret"]
            validate_secret(secret)
        except (KeyError, ValueError, TypeError, SecurityError):
            raise BridgeError("Invalid webhook signing secret") from None
        ttl = params.get("ttlMs", 86400000)
        if ttl is None:
            ttl = 86400000  # Finite policy even when unbounded was requested.
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
            raise BridgeError("ttlMs must be a positive integer or null")
        expires = self.clock() + max(30_000, min(ttl, 7 * 86_400_000)) / 1000
        url = delivery["url"]
        verification_id = hashlib.sha256(canonical([principal, url]).encode()).hexdigest()
        with self.store.lock:
            row = self.store.db.execute(
                "SELECT valid_until FROM verification WHERE identity=?", (verification_id,)
            ).fetchone()
        if not row or row[0] <= self.clock():
            challenge = secrets.token_urlsafe(32)
            started = self.clock()
            body = canonical({"type": "verification", "challenge": challenge}).encode()
            headers = signed_headers(secret, "verify_" + secrets.token_hex(16), int(started), body, sid)
            try:
                result = self.transport.post(url, body, headers)
                echoed = json.loads(result.body).get("challenge")
                if (
                    not 200 <= result.status < 300
                    or not isinstance(echoed, str)
                    or self.clock() - started > 30
                    or not hmac.compare_digest(echoed, challenge)
                ):
                    raise BridgeError("Callback verification failed", -32015, "challenge_failed")
            except BridgeError:
                raise
            except TimeoutError:
                raise BridgeError("Callback verification failed", -32015, "timeout") from None
            except TransportError as exc:
                reason = "timeout" if exc.reason == "timeout" else "connection_failed"
                raise BridgeError("Callback verification failed", -32015, reason) from None
            except (ValueError, TypeError, AttributeError, SecurityError, OSError):
                raise BridgeError("Callback verification failed", -32015, "challenge_failed") from None
            with self.store.lock, self.store.db:
                self.store.db.execute(
                    "INSERT OR REPLACE INTO verification VALUES(?,?)", (verification_id, self.clock() + 300)
                )
        # Authorization may have changed while verification ran.
        self.authorize(principal, params["arguments"]["chat_id"])
        with self.store.lock, self.store.db:
            old = self.store.db.execute(
                "SELECT secret,old_secret,rotation_until FROM subscriptions WHERE id=?", (sid,)
            ).fetchone()
            previous, rotation = None, 0
            if old and not hmac.compare_digest(self.store.open(old["secret"]), secret):
                previous, rotation = old["secret"], self.clock() + ROTATION_SECONDS
            elif old:
                previous, rotation = old["old_secret"], old["rotation_until"]
            self.store.db.execute(
                """INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?,1)
                ON CONFLICT(id) DO UPDATE SET callback=excluded.callback,secret=excluded.secret,
                old_secret=excluded.old_secret,rotation_until=excluded.rotation_until,
                expires=excluded.expires,active=1""",
                (
                    sid,
                    principal,
                    self.chat_id,
                    self.store.seal(url),
                    self.store.seal(secret),
                    previous,
                    rotation,
                    expires,
                ),
            )
        return {"id": sid, "refreshBefore": iso(expires), "cursor": None, "truncated": False}

    def unsubscribe(self, principal: str, params: dict) -> dict:
        sid = self.identity(principal, params)
        with self.store.lock, self.store.db:
            self.store.db.execute(
                "UPDATE subscriptions SET active=0 WHERE id=? AND principal=?", (sid, principal)
            )
            self.store.db.execute(
                "UPDATE deliveries SET state='cancelled' WHERE subscription_id=? AND state='pending'", (sid,)
            )
        return {}

    def deliver_once(self) -> bool:
        # Single worker preserves accepted-arrival order per subscription, even under retries.
        if not self.delivery_lock.acquire(blocking=False):
            return False
        try:
            return self._deliver_once()
        finally:
            self.delivery_lock.release()

    def _deliver_once(self) -> bool:
        now = self.clock()
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE subscriptions SET active=0 WHERE expires<=?", (now,))
            self.store.db.execute(
                "UPDATE subscriptions SET old_secret=NULL,rotation_until=0 WHERE rotation_until>0 AND rotation_until<=?",
                (now,),
            )
            row = self.store.db.execute(
                """SELECT d.*,s.principal,s.chat_id,s.callback,s.secret,s.old_secret,s.rotation_until,m.body
                FROM deliveries d JOIN subscriptions s ON s.id=d.subscription_id JOIN messages m ON m.seq=d.seq
                WHERE d.state='pending' AND d.next_at<=? AND s.active=1 AND s.expires>?
                AND NOT EXISTS(SELECT 1 FROM deliveries prior WHERE prior.subscription_id=d.subscription_id
                    AND prior.seq<d.seq AND prior.state IN ('pending','sending'))
                ORDER BY d.seq LIMIT 1""",
                (now, now),
            ).fetchone()
            if not row:
                return False
            if not self.authorized(row["principal"], row["chat_id"]):
                self.store.db.execute(
                    "UPDATE subscriptions SET active=0 WHERE id=?", (row["subscription_id"],)
                )
                return True
            claimed_ns = self.store.monotonic_ns()
            self.store.db.execute(
                "UPDATE deliveries SET state='sending' WHERE subscription_id=? AND seq=?",
                (row["subscription_id"], row["seq"]),
            )
        message = json.loads(self.store.open(row["body"]))
        event_id = "evt_" + hashlib.sha256(message["message_id"].encode()).hexdigest()
        data = {k: message[k] for k in ("message_id", "chat_id", "sender_id", "occurred_at")}
        data["sequence"] = row["seq"]
        body = canonical(
            {
                "eventId": event_id,
                "name": self.event_name,
                "timestamp": message["occurred_at"],
                "data": data,
                "cursor": None,
            }
        ).encode()
        previous = (
            self.store.open(row["old_secret"]) if row["old_secret"] and row["rotation_until"] > now else None
        )
        headers = signed_headers(
            self.store.open(row["secret"]),
            event_id,
            int(now),
            body,
            row["subscription_id"],
            previous_secret=previous,
        )
        attempts = row["attempts"] + 1
        status, reason = 0, "transport_failure"
        post_start_ns = self.store.monotonic_ns()
        try:
            result = self.transport.post(self.store.open(row["callback"]), body, headers)
            status, reason = result.status, "http_" + str(result.status)
        except (TransportError, SecurityError, OSError, TimeoutError):
            pass
        post_end_ns = self.store.monotonic_ns()
        if 200 <= status < 300:
            state = "delivered"
        elif (
            status in (410, 413)
            or (400 <= status < 500 and status not in (408, 425, 429))
            or 300 <= status < 400
            or attempts >= MAX_ATTEMPTS
        ):
            state = "failed"
        else:
            state = "pending"
        with self.store.lock, self.store.db:
            # Diagnostics come first so they cannot roll back a delivery result.
            # Both writes share one normal-path commit; a telemetry error resets
            # only its work, and the authoritative update starts a new transaction.
            self.store.record_delivery_timing(
                sequence=row["seq"],
                attempt=attempts,
                claim_ns=claimed_ns,
                post_start_ns=post_start_ns,
                post_end_ns=post_end_ns,
                http_status=status,
                outcome=state,
            )
            self.store.db.execute(
                "UPDATE deliveries SET state=?,attempts=?,next_at=?,last_reason=? WHERE subscription_id=? AND seq=?",
                (
                    state,
                    attempts,
                    self.clock() + min(3600, 2**attempts),
                    reason,
                    row["subscription_id"],
                    row["seq"],
                ),
            )
            if status == 410:
                self.store.db.execute(
                    "UPDATE subscriptions SET active=0 WHERE id=?", (row["subscription_id"],)
                )
        return True

    def get_message(self, principal: str, message_id: str | None = None) -> dict:
        if message_id is not None:
            value = self.store.message(message_id)
            self.authorize(principal, value["chat_id"])
            return value
        # One bounded local read: no history fetch, claim, or mark-read mutation.
        with self.store.lock:
            self.authorize(principal, self.chat_id)
            row = self.store.db.execute(
                """SELECT m.message_id,m.seq,m.body,r.state AS reply_state
                FROM messages m LEFT JOIN replies r ON r.message_id=m.message_id
                WHERE m.chat_id=? AND (r.state IS NULL OR r.state!='sent')
                AND EXISTS(SELECT 1 FROM deliveries d JOIN subscriptions s ON s.id=d.subscription_id
                    WHERE d.seq=m.seq AND d.state='delivered' AND s.principal=? AND s.chat_id=?)
                ORDER BY m.seq LIMIT 1""",
                (self.chat_id, principal, self.chat_id),
            ).fetchone()
            if not row:
                self.authorize(principal, self.chat_id)
                return {"status": "empty", "message": None}
            if row["reply_state"] is not None:
                self.authorize(principal, self.chat_id)
                return {
                    "status": "blocked",
                    "message": None,
                    "message_id": row["message_id"],
                    "sequence": row["seq"],
                    "reply_state": row["reply_state"],
                    "reason": "operator_reconciliation_required",
                }
            value = json.loads(self.store.open(row["body"]))
            value["sequence"] = row["seq"]
            # A live config/binding change while reading must fail closed.
            self.authorize(principal, value["chat_id"])
            return {"status": "ready", "reply_state": "not_started", "message": value}

    def reply_to_message(self, principal: str, message_id: str, text: str) -> dict:
        self.get_message(principal, message_id)
        from .feishu import FeishuError, validate_reply_text

        try:
            validate_reply_text(text)
        except FeishuError:
            raise BridgeError(
                "Reply text is empty, malformed, or exceeds the Feishu text/encoded-content limit"
            ) from None
        if self.replier is None:
            raise BridgeError("Bot reply is not configured", -32003)
        digest = hashlib.sha256(text.encode()).hexdigest()
        request_id = str(uuid5(NAMESPACE_URL, "feishu-dot-reply:" + message_id))
        with self.store.lock, self.store.db:
            row = self.store.db.execute("SELECT * FROM replies WHERE message_id=?", (message_id,)).fetchone()
            if row:
                if row["text_hash"] != digest:
                    raise BridgeError(
                        "One reply is allowed per inbound message; existing reply differs", -32009
                    )
                if row["state"] == "sent":
                    return {"message_id": row["reply_id"], "duplicate": True}
                raise BridgeError(
                    "Previous send outcome is unknown; operator reconciliation is required", -32010
                )
            self.store.db.execute(
                "INSERT INTO replies VALUES(?,?,?,'sending',NULL,?)",
                (message_id, digest, request_id, self.clock()),
            )
        try:
            reply_id = self.replier.reply(message_id, text, request_id)
        except Exception:  # noqa: BLE001 - boundary must redact arbitrary SDK/transport exceptions
            # Do not echo SDK response bodies, tokens or user text. Fail closed on ambiguous sends.
            with self.store.lock, self.store.db:
                self.store.db.execute(
                    "UPDATE replies SET state='uncertain' WHERE message_id=?", (message_id,)
                )
            raise BridgeError(
                "Bot send outcome is uncertain; check the original chat before retrying", -32010
            ) from None
        with self.store.lock, self.store.db:
            self.store.db.execute(
                "UPDATE replies SET state='sent',reply_id=? WHERE message_id=?", (reply_id, message_id)
            )
        return {"message_id": reply_id, "duplicate": False}
