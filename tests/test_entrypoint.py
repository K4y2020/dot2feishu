"""Foreground service lifecycle tests with fake sockets and fake HTTP server."""

import threading
from types import SimpleNamespace

import pytest

from dot2feishu import __main__ as entrypoint
from dot2feishu import app
from dot2feishu.core import BridgeError
from dot2feishu.runtime import create_private


@pytest.fixture
def foreground(tmp_path, monkeypatch):
    root = tmp_path / 'private-data'
    root.mkdir(mode=0o700)
    create_private(root / 'mcp-bearer', b'offline-example-token-not-a-real-credential')
    calls = []

    class Socket:
        fail_bind = False
        closed = False

        def setsockopt(self, *_):
            calls.append('setsockopt')

        def bind(self, address):
            assert address == ('0.0.0.0', 8765)
            calls.append('bind')
            if self.fail_bind:
                raise OSError('fake port is unavailable')

        def listen(self, count):
            assert count == 128
            calls.append('listen')

        def close(self):
            self.closed = True
            calls.append('socket-close')

    class Runtime:
        def __init__(self):
            self.config = {'enabled': True, 'mcp_http_hosts': ['testserver'], 'port': 8765}
            self.bridge = SimpleNamespace(delivery_healthy=True)
            self.started = threading.Event()
            self.closed = False
            self.fail_run = False

        def run(self, stop):
            calls.append('runtime-start')
            self.started.set()
            if self.fail_run:
                raise RuntimeError('private-example-diagnostic')
            assert stop.wait(2), 'serve must stop the runtime before it closes storage'
            calls.append('runtime-stop')

        def close(self):
            self.closed = True
            calls.append('runtime-close')

    class Server:
        def __init__(self, config):
            self.started = True
            self.should_exit = False

        def run(self, *, sockets):
            assert sockets == [sock]
            assert runtime.started.wait(2)
            calls.append('http-run')

    sock, runtime = Socket(), Runtime()
    monkeypatch.setattr(entrypoint.socket, 'socket', lambda *_args, **_kwargs: sock)
    monkeypatch.setattr(app, 'build_app', lambda *_args, **_kwargs: lambda scope, receive, send: None)
    return root, runtime, sock, Server, calls


def test_failed_http_bind_never_starts_cli(foreground):
    root, runtime, sock, server, calls = foreground
    sock.fail_bind = True
    with pytest.raises(OSError, match='fake port'):
        entrypoint.serve(root, runtime_factory=lambda *_a, **_k: runtime, server_factory=server)
    assert not runtime.started.is_set()
    assert runtime.closed and sock.closed
    assert 'runtime-start' not in calls and 'http-run' not in calls


def test_foreground_binds_first_and_joins_worker_before_closing_storage(foreground):
    root, runtime, sock, server, calls = foreground
    entrypoint.serve(root, runtime_factory=lambda *_a, **_k: runtime, server_factory=server)
    assert calls.index('bind') < calls.index('listen') < calls.index('runtime-start')
    assert calls.index('runtime-stop') < calls.index('runtime-close')
    assert runtime.closed and sock.closed


def test_failed_runtime_stops_http_and_is_redacted(foreground):
    root, runtime, sock, server, _calls = foreground
    runtime.fail_run = True
    with pytest.raises(BridgeError, match='Bridge stopped') as caught:
        entrypoint.serve(root, runtime_factory=lambda *_a, **_k: runtime, server_factory=server)
    assert 'private-example-diagnostic' not in str(caught.value)
    assert runtime.bridge.delivery_healthy is False
    assert runtime.closed and sock.closed


def test_disabled_runtime_never_binds_or_starts(foreground):
    root, runtime, _sock, server, calls = foreground
    runtime.config['enabled'] = False
    with pytest.raises(BridgeError, match='disabled'):
        entrypoint.serve(root, runtime_factory=lambda *_a, **_k: runtime, server_factory=server)
    assert not runtime.started.is_set()
    assert calls == ['runtime-close']
    assert runtime.closed


def test_cli_boundary_redacts_unknown_exception(monkeypatch, capsys, tmp_path):
    canary = 'DO-NOT-PRINT-FAKE-PRIVATE-FAILURE'
    monkeypatch.setattr('sys.argv', ['dot2feishu', '--root', str(tmp_path), 'doctor'])

    def fail(_root):
        raise RuntimeError(canary)

    monkeypatch.setattr(entrypoint, 'doctor', fail)
    assert entrypoint.main() == 1
    output = capsys.readouterr()
    assert canary not in output.out + output.err
    assert 'operation_failed_check_private_configuration_and_local_status' in output.out


def test_real_uvicorn_sigterm_runs_cleanup_and_state_can_restart(tmp_path):
    """A real process is needed: Uvicorn replays captured process signals.

    Only this isolated child binds loopback. It has a fake adapter and blocks
    outbound DNS/connect, so it cannot log into or communicate with Feishu.
    """
    import json
    import os
    import select
    import signal
    import sqlite3
    import subprocess
    import sys
    import textwrap
    import time
    from pathlib import Path

    root = tmp_path / 'signal-state'
    script = textwrap.dedent('''
        import asyncio
        import json
        import socket
        import sys
        import threading
        from pathlib import Path
        from types import SimpleNamespace

        import uvicorn

        from dot2feishu.__main__ import serve
        from dot2feishu.runtime import Runtime, create_private

        root = Path(sys.argv[1])
        root.mkdir(mode=0o700, exist_ok=True)
        config_path = root / 'config.json'
        if not config_path.exists():
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            config = {
                'version': 1, 'enabled': True, 'principal': 'offline-signal-owner',
                'binding': {
                    'app_id': 'cli_signal_example', 'bot_open_id': 'ou_signal_example_bot',
                    'user_open_id': 'ou_signal_example_owner', 'tenant_key': 'tenant_signal_example',
                    'chat_id': 'oc_signal_example_private',
                },
                'cli': {
                    'binary': '/never-executed/lark-cli', 'binary_sha256': 'a' * 64,
                    'profile': 'cli_signal_example', 'expected_bot_open_id': 'ou_signal_example_bot',
                    'config_dir': str(root / 'config'), 'data_dir': str(root / 'data'),
                },
                'callback_hosts': ['receiver.example.com'], 'mcp_http_hosts': ['127.0.0.1:' + str(port)],
                'port': port,
            }
            create_private(config_path, json.dumps(config).encode())
            create_private(root / 'mcp-bearer', b'offline-example-signal-token-no-real-authentication')

        def denied(*_args, **_kwargs):
            raise AssertionError('Signal test cannot access external DNS or network')

        base_socket = socket.socket
        class LoopbackOnlySocket(base_socket):
            def bind(self, address):
                assert isinstance(address, tuple) and address[0] in {'127.0.0.1', '0.0.0.0'}
                return super().bind(('127.0.0.1', address[1]))
            connect = denied
            connect_ex = denied

        socket.socket = LoopbackOnlySocket
        socket.getaddrinfo = denied
        socket.create_connection = denied

        class FakeAdapter:
            def __init__(self, *args, **kwargs):
                self.runner = SimpleNamespace(ready=threading.Event(), children_exit_confirmed=True)
                self.stopped = threading.Event()
            def start(self):
                self.runner.ready.set()
                self.stopped.wait()
            def stop(self):
                self.stopped.set()
            def reply(self, *_args):
                raise AssertionError('Signal test must never send a message')

        def factory(path, *, root):
            return Runtime(path, root=root, adapter_factory=FakeAdapter)

        if not (root / 'bridge-state').exists():
            initial = Runtime(config_path, root=root, initialize=True, adapter_factory=FakeAdapter)
            initial.close()

        class ReadyServer(uvicorn.Server):
            async def startup(self, sockets=None):
                await super().startup(sockets=sockets)
                assert self.started
                print('HTTP_READY', flush=True)

        serve(root, runtime_factory=factory, server_factory=ReadyServer)
        print('CLEAN_EXIT', flush=True)
    ''')
    project = Path(__file__).resolve().parents[1]
    for _attempt in range(2):
        process = subprocess.Popen(
            [sys.executable, '-c', script, str(root)], cwd=project,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, 'PYTHONPATH': str(project)},
        )
        ready = False
        observed = []
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                readable, _, _ = select.select([process.stdout], [], [], 0.1)
                if readable:
                    line = process.stdout.readline()
                    observed.append(line)
                    if line.strip() == 'HTTP_READY':
                        ready = True
                        break
            if not ready:
                process.kill()
                out, err = process.communicate(timeout=5)
                pytest.fail('Fake loopback server did not become ready: ' + ''.join(observed) + out + err)
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=15)
            assert process.returncode == 0, ''.join(observed) + out + err
            assert 'CLEAN_EXIT' in out
            with sqlite3.connect(root / 'bridge-state' / 'bridge.sqlite3') as database:
                row = database.execute("SELECT value FROM bridge_meta WHERE key='listener'").fetchone()
            assert json.loads(row[0])['state'] == 'stopped'
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
