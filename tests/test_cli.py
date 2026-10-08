import hashlib
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from dot2feishu.cli import CLIConfig, FeishuCLIAdapter, FeishuCLIError, OfficialCLIRunner
from dot2feishu.feishu import FeishuPolicy, InboundMessage

POLICY = FeishuPolicy("cli_app", "verified-tenant", "ou_owner", "oc_private")
CONFIG = CLIConfig("/not-executed/cli", "a" * 64, "cli_app", "/not-read/config", "/not-read/data", "ou_bot")
WHO = {
    "profile": "cli_app",
    "appId": "cli_app",
    "brand": "feishu",
    "identity": "bot",
    "identitySource": "flag",
    "available": True,
    "tokenStatus": "ready",
}
BOT = {"ok": True, "identity": "bot", "data": {"open_id": "ou_bot", "activate_status": 2}}
ORIGINAL = InboundMessage(
    "event-1", "om_inbound", "oc_private", "ou_owner", "original", "2026-10-08T05:00:00Z"
)


class Runner:
    def __init__(self):
        self.calls = []
        self.responses = [WHO, BOT]
        self.events = []
        self.started = False

    def run_json(self, args, input_bytes=b""):
        self.calls.append((args, input_bytes))
        return self.responses.pop(0)

    def consume(self, callback):
        self.started = True
        for event in self.events:
            callback(event)

    def stop(self):
        pass


def event():
    now = str(int(datetime.now(UTC).timestamp() * 1000))
    return {
        "type": "im.message.receive_v1",
        "event_id": "event-1",
        "message_id": "om_inbound",
        "chat_id": "oc_private",
        "chat_type": "p2p",
        "sender_id": "ou_owner",
        "sender_type": "user",
        "message_type": "text",
        "content": "hello",
        "create_time": now,
        "timestamp": now,
    }


def test_verified_profile_bot_and_single_user_event_only():
    runner = Runner()
    runner.events = [event(), {**event(), "sender_id": "ou_other"}, {**event(), "sender_type": "bot"}]
    received = []
    adapter = FeishuCLIAdapter(CONFIG, POLICY, received.append, lambda _: ORIGINAL, runner=runner)
    adapter.start()
    assert len(received) == 1 and received[0].text == "hello"
    assert runner.calls == [
        (["whoami", "--as", "bot"], b""),
        (["api", "GET", "/open-apis/bot/v3/info", "--as", "bot"], b""),
    ]
    with pytest.raises(FeishuCLIError):
        adapter.start()


@pytest.mark.parametrize(
    "field,value",
    [
        ("profile", "other"),
        ("appId", "other"),
        ("brand", "lark"),
        ("identity", "user"),
        ("identitySource", "auto"),
        ("available", False),
        ("available", 1),
        ("tokenStatus", "expired"),
    ],
)
def test_wrong_identity_never_listens(field, value):
    runner = Runner()
    runner.responses[0] = {**WHO, field: value}
    adapter = FeishuCLIAdapter(CONFIG, POLICY, lambda _: None, lambda _: ORIGINAL, runner=runner)
    with pytest.raises(FeishuCLIError):
        adapter.start()
    assert not runner.started


@pytest.mark.parametrize(
    "value",
    [
        {"ok": False},
        {"ok": True, "identity": "user", "data": BOT["data"]},
        {"ok": True, "identity": "bot", "data": {"open_id": "ou_other", "activate_status": 2}},
        {"ok": True, "identity": "bot", "data": {"open_id": "ou_bot", "activate_status": False}},
        {"ok": True, "identity": "bot", "data": []},
    ],
)
def test_wrong_or_inactive_bot_never_listens(value):
    runner = Runner()
    runner.responses[1] = value
    with pytest.raises(FeishuCLIError):
        FeishuCLIAdapter(CONFIG, POLICY, lambda _: None, lambda _: ORIGINAL, runner=runner).start()
    assert not runner.started


def test_reply_fixed_arguments_stdin_and_original_chat():
    runner = Runner()
    runner.responses.append(
        {"ok": True, "identity": "bot", "data": {"message_id": "om_reply", "chat_id": "oc_private"}}
    )
    adapter = FeishuCLIAdapter(CONFIG, POLICY, lambda _: None, lambda _: ORIGINAL, runner=runner)
    text = "$(do not execute) --as user @/secret\n你好"
    assert adapter.reply("om_inbound", text, "stable-request-id") == "om_reply"
    args, data = runner.calls[-1]
    assert args == [
        "im",
        "+messages-reply",
        "--as",
        "bot",
        "--message-id",
        "om_inbound",
        "--text",
        "-",
        "--idempotency-key",
        "stable-request-id",
    ]
    assert data == text.encode() and text not in args


@pytest.mark.parametrize(
    "original",
    [
        None,
        replace(ORIGINAL, chat_id="oc_other"),
        replace(ORIGINAL, sender_id="ou_other"),
        replace(ORIGINAL, message_id="om_other"),
    ],
)
def test_reply_never_accepts_unverified_target(original):
    runner = Runner()
    adapter = FeishuCLIAdapter(CONFIG, POLICY, lambda _: None, lambda _: original, runner=runner)
    with pytest.raises(FeishuCLIError):
        adapter.reply("om_inbound", "reply", "uuid")
    assert not runner.calls


@pytest.mark.parametrize(
    "result",
    [
        {"ok": True, "identity": "user", "data": {"message_id": "om_reply", "chat_id": "oc_private"}},
        {"ok": True, "identity": "bot", "data": {"message_id": "om_reply", "chat_id": "oc_other"}},
        {"ok": True, "identity": "bot", "data": {"message_id": "om_inbound", "chat_id": "oc_private"}},
    ],
)
def test_reply_result_must_confirm_identity_and_original_chat(result):
    runner = Runner()
    runner.responses.append(result)
    with pytest.raises(FeishuCLIError):
        FeishuCLIAdapter(CONFIG, POLICY, lambda _: None, lambda _: ORIGINAL, runner=runner).reply(
            "om_inbound", "reply", "uuid"
        )


def test_persistence_exception_is_sanitized():
    runner = Runner()
    runner.events = [event()]

    def fail(_):
        raise RuntimeError("private content and credentials")

    with pytest.raises(FeishuCLIError) as exc:
        FeishuCLIAdapter(CONFIG, POLICY, fail, lambda _: ORIGINAL, runner=runner).start()
    assert "private content" not in str(exc.value)


def test_native_binary_hash_and_profile_pinning(tmp_path):
    binary = tmp_path / "native"
    binary.write_bytes(b"\x7fELFsynthetic-never-executed")
    binary.chmod(0o700)
    config = replace(
        CONFIG, binary=str(binary), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()
    )
    runner = OfficialCLIRunner(config)
    assert runner._command(["whoami", "--as", "bot"]) == [
        str(binary),
        "--profile",
        "cli_app",
        "whoami",
        "--as",
        "bot",
    ]
    binary.write_bytes(b"\x7fELFchanged")
    with pytest.raises(FeishuCLIError):
        runner._command(["whoami"])
    link = tmp_path / "link"
    link.symlink_to(binary)
    with pytest.raises(FeishuCLIError):
        OfficialCLIRunner(replace(config, binary=str(link)))._command(["whoami"])


def test_child_environment_does_not_copy_tokens_or_preloads(monkeypatch):
    monkeypatch.setenv("LARK_USER_ACCESS_TOKEN", "must-not-leak")
    monkeypatch.setenv("LD_PRELOAD", "must-not-execute")
    monkeypatch.setenv("HOME", "/test-home")
    env = OfficialCLIRunner(CONFIG)._environment()
    assert "LARK_USER_ACCESS_TOKEN" not in env and "LD_PRELOAD" not in env
    assert env["HOME"] == "/test-home" and env["LARKSUITE_CLI_CONFIG_DIR"] == "/not-read/config"


class SyntheticProcessRunner(OfficialCLIRunner):
    """Runs only inline offline Python fixtures, never Feishu or credentials."""

    def __init__(self, script):
        super().__init__(CONFIG)
        self.script = script
        self.args = None

    def _spawn(self, args):
        self.args = args
        return subprocess.Popen(
            [sys.executable, "-c", self.script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )


def test_bounded_process_reads_and_stdin():
    runner = SyntheticProcessRunner('import sys,json; print(json.dumps({"input":sys.stdin.read()}))')
    assert runner.run_json(["fixture"], b"hello") == {"input": "hello"}


@pytest.mark.parametrize(
    "script",
    [
        "print('x'*300000)",
        "import sys; print('x'*300000,file=sys.stderr)",
        "import sys;sys.exit(3)",
        "print('not-json')",
    ],
)
def test_bad_process_output_fails_without_raw_text(script):
    with pytest.raises(FeishuCLIError):
        SyntheticProcessRunner(script).run_json(["fixture"])


def test_consume_waits_for_ready_and_keeps_stdin_open():
    script = 'import sys,json; print(json.dumps({"id":"before-ready"}),flush=True); print("[event] ready event_key=im.message.receive_v1",file=sys.stderr,flush=True); sys.stdin.read()'
    runner = SyntheticProcessRunner(script)
    received = []

    def accept(value):
        received.append(value)
        runner.stop()

    runner.consume(accept)
    assert received == [{"id": "before-ready"}]
    assert runner.args == ["event", "consume", "im.message.receive_v1", "--as", "bot"]


@pytest.mark.parametrize(
    "script",
    [
        "print('not-json',flush=True)",
        "import sys; print('[event] ready event_key=wrong',file=sys.stderr,flush=True)",
        "import sys; print('WARN dropped 1 event',file=sys.stderr,flush=True)",
        "import sys; print('{\"ok\":false}',file=sys.stderr,flush=True)",
    ],
)
def test_bad_consumer_never_delivers(script):
    delivered = []
    with pytest.raises(FeishuCLIError):
        SyntheticProcessRunner(script).consume(delivered.append, startup_timeout=0.2)
    assert not delivered


def test_reply_rechecks_revocation_after_identity_lookup():
    runner = Runner()
    allowed = [True]
    original_run = runner.run_json
    def revoke_after_identity(args, input_bytes=b''):
        response = original_run(args, input_bytes)
        if args[:2] == ['api', 'GET']:
            allowed[0] = False
        return response
    runner.run_json = revoke_after_identity
    adapter = FeishuCLIAdapter(CONFIG, POLICY, lambda _: None, lambda _: ORIGINAL,
                               runner=runner, authorized=lambda: allowed[0])
    with pytest.raises(FeishuCLIError, match='revoked before sending'):
        adapter.reply('om_inbound', 'not sent', 'stable-request-id')
    assert all(args[:2] != ['im', '+messages-reply'] for args, _ in runner.calls)


def test_listener_rechecks_revocation_after_identity_lookup():
    runner = Runner()
    adapter = FeishuCLIAdapter(CONFIG, POLICY, lambda _: None, lambda _: ORIGINAL,
                               runner=runner, authorized=lambda: False)
    with pytest.raises(FeishuCLIError, match='revoked before listening'):
        adapter.start()
    assert not runner.started


def test_fake_bot_only_identity_envelope():
    # Hand-built fixtures preserve the CLI shape without production identity files.
    record = {
        "whoami": {**WHO, "user": None, "identity": "bot", "identitySource": "flag"},
        "bot_info": {**BOT, "data": {"open_id": "ou_bot", "activate_status": 2}},
    }
    runner = Runner()
    runner.responses = [record["whoami"], record["bot_info"]]
    adapter = FeishuCLIAdapter(CONFIG, POLICY, lambda _: None, lambda _: None, runner=runner)
    adapter.verify_identity()
    assert runner.calls == [(["whoami", "--as", "bot"], b""),
                            (["api", "GET", "/open-apis/bot/v3/info", "--as", "bot"], b"")]
    assert not runner.started


def test_consume_timing_preserves_record_read_before_ready():
    import time
    script = ('import sys,json,time; print(json.dumps({"id":"before-ready"}),flush=True); '
              'time.sleep(0.08); print("[event] ready event_key=im.message.receive_v1",'
              'file=sys.stderr,flush=True); sys.stdin.read()')
    runner = SyntheticProcessRunner(script)
    received = []
    def accept(value, received_ns):
        received.append((value, received_ns, time.monotonic_ns()))
        runner.stop()
    runner.consume(accept, include_timing=True)
    assert received[0][0] == {'id': 'before-ready'}
    assert received[0][2] - received[0][1] > 40_000_000


def test_adapter_forwards_only_separate_record_timestamp():
    class TimedRunner(Runner):
        def consume(self, callback, *, include_timing=False):
            assert include_timing
            callback(event(), 123456789)
    runner = TimedRunner()
    received = []
    def ingest(message, *, record_received_ns):
        received.append((message, record_received_ns))
    adapter = FeishuCLIAdapter(CONFIG, POLICY, ingest, lambda _: ORIGINAL,
                               runner=runner, record_timing=True)
    adapter.start()
    assert received[0][1] == 123456789
    assert not hasattr(received[0][0], 'record_received_ns')


def test_multiple_records_in_one_chunk_keep_same_read_timestamp():
    import time
    script = ('import sys,os,time; print("[event] ready event_key=im.message.receive_v1",'
              'file=sys.stderr,flush=True); time.sleep(0.02); '
              'os.write(sys.stdout.fileno(),b\'{"n":1}\\n{"n":2}\\n\'); sys.stdin.read()')
    runner = SyntheticProcessRunner(script)
    received = []
    def accept(value, received_ns):
        received.append((value, received_ns))
        if len(received) == 1:
            time.sleep(0.02)
        else:
            runner.stop()
    runner.consume(accept, include_timing=True)
    assert [item[0]['n'] for item in received] == [1, 2]
    assert received[0][1] == received[1][1]
