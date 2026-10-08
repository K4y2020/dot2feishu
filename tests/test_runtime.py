"""Offline standalone runtime tests: fake identities, CLI and callback transport."""
import base64
import dataclasses
import json
import os
import threading
import time
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from dot2feishu.core import BridgeError
from dot2feishu.feishu import InboundMessage
from dot2feishu.runtime import EVENT_NAME, Runtime, create_private

SECRET = 'whsec_' + base64.b64encode(b'offline-only-synthetic-signing-key').decode()
BINDING = {
    'app_id': 'cli_example_test',
    'bot_open_id': 'ou_example_bot',
    'user_open_id': 'ou_example_user',
    'tenant_key': 'tenant_example_test',
    'chat_id': 'oc_example_private',
}


class Transport:
    def __init__(self):
        self.calls = []
        self.status = 200

    def post(self, url, body, headers):
        value = json.loads(body)
        self.calls.append((value, headers))
        return SimpleNamespace(status=self.status, body=json.dumps({'challenge': value.get('challenge')}).encode())


class Adapter:
    def __init__(self, config, policy, ingest, lookup, authorized=None, record_timing=False):
        self.config, self.policy, self.ingest, self.lookup = config, policy, ingest, lookup
        self.runner = SimpleNamespace(ready=threading.Event(), children_exit_confirmed=True)
        self.stop_event = threading.Event()
        self.started = threading.Event()
        self.replies = []
        self.error = False

    def start(self):
        self.started.set()
        self.runner.ready.set()
        if self.error:
            raise RuntimeError('must-never-leak-private-diagnostic')
        self.stop_event.wait(10)

    def stop(self):
        self.stop_event.set()

    def reply(self, message_id, text, request_id):
        self.replies.append((message_id, text, request_id))
        return 'om_verified_reply'


@pytest.fixture
def deployment(tmp_path):
    root = tmp_path / 'bridge'
    root.mkdir(mode=0o700)
    config = {'version': 1, 'enabled': True, 'principal': 'offline-owner', 'binding': dict(BINDING),
              'callback_hosts': ['receiver.example.com'], 'mcp_http_hosts': ['testserver'], 'port': 8765,
              'cli': {'binary': str(root / 'prefix/lib/node_modules/@larksuite/cli/bin/lark-cli'),
                      'binary_sha256': 'a' * 64, 'profile': BINDING['app_id'],
                      'config_dir': str(root / 'config'), 'data_dir': str(root / 'data'),
                      'expected_bot_open_id': BINDING['bot_open_id']}}
    path = root / 'bridge-config.json'
    create_private(path, json.dumps(config).encode())
    transport = Transport()
    runtime = Runtime(path, root=root, owner='offline-owner', initialize=True,
                      transport=transport, adapter_factory=Adapter)
    yield runtime, path, config, transport
    runtime.close()


def subscription():
    return {'name': EVENT_NAME, 'arguments': {'chat_id': BINDING['chat_id']},
            'delivery': {'mode': 'webhook', 'url': 'https://receiver.example.com/events',
                         'secret': SECRET}, 'cursor': None, 'ttlMs': 60000}


def msg(**changes):
    message = InboundMessage('ev_offline_1', 'om_offline_1', BINDING['chat_id'], BINDING['user_open_id'],
                             'private text remains only in encrypted SQLite', datetime.now(UTC).isoformat())
    return dataclasses.replace(message, **changes)


def accept(runtime, message=None):
    runtime.bridge.subscribe(runtime.principal, subscription())
    runtime.cutoff = time.time() - 0.1
    message = message or msg()
    assert runtime.ingest(message)
    return message


def test_durable_event_metadata_only_and_idempotent_reply(deployment):
    runtime, _path, _, transport = deployment
    message = accept(runtime)
    assert not runtime.ingest(message)
    assert runtime.bridge.deliver_once()
    event, headers = transport.calls[-1]
    assert event['name'] == EVENT_NAME
    assert event['data']['message_id'] == message.message_id
    assert message.text not in json.dumps(event)
    assert 'text' not in event['data'] and 'webhook-signature' in headers
    assert runtime.bridge.get_message(runtime.principal, message.message_id)['text'] == message.text
    first = runtime.bridge.reply_to_message(runtime.principal, message.message_id, 'approved reply')
    assert first['duplicate'] is False
    assert runtime.bridge.reply_to_message(runtime.principal, message.message_id, 'approved reply')['duplicate']
    assert len(runtime.adapter.replies) == 1
    with pytest.raises(BridgeError):
        runtime.bridge.reply_to_message(runtime.principal, message.message_id, 'different reply')
    for file in runtime.state.glob('*'):
        if file.is_file():
            assert message.text.encode() not in file.read_bytes()
            assert SECRET.encode() not in file.read_bytes()
    assert runtime.status()['deliveries'] == {'delivered': 1}
    assert 'approved reply' not in json.dumps(runtime.status())


@pytest.mark.parametrize('changes', [
    {'chat_id': 'oc_other'}, {'sender_id': 'ou_other'}, {'sender_id': BINDING['bot_open_id']},
    {'occurred_at': '2020-01-01T00:00:00+00:00'},
])
def test_ingress_scope_and_session_start_cutoff(deployment, changes):
    runtime, *_ = deployment
    runtime.bridge.subscribe(runtime.principal, subscription())
    runtime.cutoff = time.time() - 1
    assert not runtime.ingest(msg(**changes))
    assert runtime.status()['accepted_messages'] == 0


def test_no_ingest_without_subscription_or_explicit_start(deployment):
    runtime, *_ = deployment
    assert not runtime.ingest(msg())
    runtime.cutoff = time.time() - 1
    assert not runtime.ingest(msg())
    assert runtime.status()['accepted_messages'] == 0


@pytest.mark.parametrize('field', ['app_id', 'bot_open_id', 'user_open_id', 'tenant_key', 'chat_id'])
def test_each_identity_mutation_revokes_without_rebinding(deployment, field):
    runtime, path, config, _ = deployment
    config['binding'] = {**BINDING, field: 'unapproved'}
    path.write_text(json.dumps(config))
    assert not runtime.authorized(runtime.principal, BINDING['chat_id'])
    with pytest.raises(BridgeError):
        Runtime(path, root=runtime.root, adapter_factory=Adapter)


@pytest.mark.parametrize('field,value', [('enabled', False), ('principal', 'someone-else')])
def test_runtime_revocation(deployment, field, value):
    runtime, path, config, _ = deployment
    message = accept(runtime)
    config[field] = value
    path.write_text(json.dumps(config))
    assert not runtime.authorized(runtime.principal, BINDING['chat_id'])
    with pytest.raises(BridgeError):
        runtime.bridge.get_message(runtime.principal, message.message_id)
    with pytest.raises(BridgeError):
        runtime.bridge.reply_to_message(runtime.principal, message.message_id, 'no')
    assert not runtime.adapter.replies


@pytest.mark.parametrize('field,value', [('config_dir', '/tmp/auth'), ('data_dir', '/tmp/auth'),
                                       ('binary', '/tmp/other'), ('profile', 'cli_other'),
                                       ('expected_bot_open_id', 'ou_other')])
def test_cli_mutations_fail_closed(deployment, field, value):
    runtime, path, config, _ = deployment
    config['cli'][field] = value
    path.write_text(json.dumps(config))
    assert not runtime.authorized(runtime.principal, BINDING['chat_id'])


def test_binding_sha_change_does_not_adopt_existing_state(deployment):
    runtime, path, config, _ = deployment
    config['cli']['binary_sha256'] = 'b' * 64
    path.write_text(json.dumps(config))
    assert not runtime.authorized(runtime.principal, BINDING['chat_id'])
    with pytest.raises(BridgeError, match='another binding'):
        Runtime(path, root=runtime.root, adapter_factory=Adapter)


def test_mcp_reopen_does_not_reset_inflight_or_start_cli(deployment):
    runtime, path, _, transport = deployment
    accept(runtime)
    with runtime.store.db:
        runtime.store.db.execute("UPDATE deliveries SET state='sending'")
    reopened = Runtime(path, root=runtime.root, owner=runtime.principal, transport=transport,
                       adapter_factory=Adapter)
    try:
        assert reopened.store.db.execute('SELECT state FROM deliveries').fetchone()[0] == 'sending'
        assert not reopened.adapter.started.is_set()
        assert not runtime.adapter.started.is_set()
        assert reopened.status()['listener_state'] == 'not_started'
    finally:
        reopened.close()


def test_other_owner_cannot_attach(deployment):
    runtime, path, *_ = deployment
    with pytest.raises(BridgeError, match='owner'):
        Runtime(path, root=runtime.root, owner='other', adapter_factory=Adapter)


def test_single_listener_lock_and_independent_mcp_restart(deployment):
    runtime, path, _, transport = deployment
    stop = threading.Event()
    errors = []
    def run():
        try:
            runtime.run(stop)
        except Exception as exc:  # noqa: BLE001 - capture thread test failure
            errors.append(exc)
    thread = threading.Thread(target=run)
    thread.start()
    assert runtime.adapter.started.wait(2)
    reopened = Runtime(path, root=runtime.root, transport=transport, adapter_factory=Adapter)
    try:
        with pytest.raises(BridgeError, match='Another listener'):
            reopened.run(threading.Event())
        assert runtime.adapter.started.is_set() and not reopened.adapter.started.is_set()
        assert runtime.status()['listener_state'] in {'starting', 'running'}
    finally:
        reopened.close()
        stop.set()
        thread.join(3)
    assert not errors and not thread.is_alive()
    assert runtime.status()['listener_state'] == 'stopped'


def test_listener_failure_is_redacted_and_terminal(deployment):
    runtime, *_ = deployment
    runtime.adapter.error = True
    with pytest.raises(BridgeError, match='listener stopped') as exc:
        runtime.run()
    assert 'private-diagnostic' not in str(exc.value)
    assert runtime.status()['listener_state'] == 'failed'


@pytest.mark.parametrize('target', ['config', 'state', 'key', 'database', 'root', 'cli_config', 'cli_data'])
def test_private_storage_enforced(deployment, target):
    runtime, path, *_ = deployment
    selected = {'config': path, 'state': runtime.state, 'key': runtime.state / 'storage.key',
                'database': runtime.state / 'bridge.sqlite3', 'root': runtime.root,
                'cli_config': runtime.root / 'config', 'cli_data': runtime.root / 'data'}[target]
    is_directory = selected.is_dir()
    selected.chmod(0o755 if is_directory else 0o644)
    with pytest.raises(BridgeError, match='permissions'):
        Runtime(path, root=runtime.root, adapter_factory=Adapter)
    selected.chmod(0o700 if is_directory else 0o600)


def test_previous_unconfirmed_exit_blocks_restart(deployment):
    runtime, *_ = deployment
    runtime.heartbeat('running')
    with pytest.raises(BridgeError, match='exit is unconfirmed'):
        runtime.run()
    assert not runtime.adapter.started.is_set()


def test_unsafe_child_shutdown_poison_prevents_new_listener(deployment):
    runtime, path, _config, transport = deployment
    runtime.adapter.error = True
    runtime.adapter.runner.children_exit_confirmed = False
    try:
        with pytest.raises(BridgeError, match='shutdown was not confirmed'):
            runtime.run()
        assert runtime.status()['listener_state'] == 'unsafe_shutdown'
        assert runtime.unsafe_shutdown
        with pytest.raises(BridgeError, match='Another listener'):
            runtime.run()
        reopened = Runtime(path, root=runtime.root, transport=transport, adapter_factory=Adapter)
        try:
            with pytest.raises(BridgeError, match='Another listener'):
                reopened.run()
            assert not reopened.adapter.started.is_set()
        finally:
            reopened.close()
        with pytest.raises(BridgeError, match='Unsafe worker still owns storage'):
            runtime.close()
        # Closing an unsafe runtime must leave storage intact for a live worker.
        assert runtime.store.db.execute('SELECT 1').fetchone()[0] == 1
    finally:
        # There are no real children in this test: the fake adapter exited by
        # raising. Undo the deliberately fabricated poison only for cleanup.
        if hasattr(runtime, '_retained_lock'):
            os.close(runtime._retained_lock)
        runtime.unsafe_shutdown = False


def test_pending_status_metadata_no_decrypt_and_sent_reply_removed(deployment, monkeypatch):
    runtime, *_ = deployment
    message = accept(runtime)
    assert runtime.status()['pending_events'] == []
    assert runtime.bridge.deliver_once()
    def forbidden(*_args):
        raise AssertionError('Status must not decrypt message/callback/secret data')
    with monkeypatch.context() as patch:
        patch.setattr(runtime.store, 'open', forbidden)
        status = runtime.status()
    assert status['pending_events'] == [{
        'event_id': 'evt_' + __import__('hashlib').sha256(message.message_id.encode()).hexdigest(),
        'message_id': message.message_id, 'chat_id': BINDING['chat_id'],
        'sender_id': BINDING['user_open_id'], 'occurred_at': message.occurred_at,
        'sequence': 1, 'reply_state': 'not_started',
    }]
    assert not status['pending_events_truncated']
    assert message.text not in json.dumps(status) and SECRET not in json.dumps(status)
    runtime.bridge.reply_to_message(runtime.principal, message.message_id, 'approved reply')
    assert runtime.status()['pending_events'] == []


def test_pending_status_bounded_oldest_first_and_uncertain_visible(deployment):
    runtime, *_ = deployment
    for n in range(12):
        accept(runtime, msg(event_id=f'ev_{n}', message_id=f'om_{n}'))
    with runtime.store.db:
        runtime.store.db.execute("UPDATE deliveries SET state='delivered'")
        runtime.store.db.execute("INSERT INTO replies VALUES('om_0','hash','request','uncertain',NULL,0)")
    status = runtime.status()
    assert len(status['pending_events']) == 10 and status['pending_events_truncated']
    assert [item['sequence'] for item in status['pending_events']] == list(range(1, 11))
    assert status['pending_events'][0]['reply_state'] == 'uncertain'


def test_pending_status_hides_revoked_metadata(deployment):
    runtime, path, config, _ = deployment
    accept(runtime)
    runtime.bridge.deliver_once()
    config['enabled'] = False
    path.write_text(json.dumps(config))
    status = runtime.status()
    assert status['enabled'] is False and status['pending_events'] == []


def test_pending_status_enforces_chat_and_subscription_owner(deployment):
    runtime, *_ = deployment
    message = accept(runtime)
    runtime.bridge.deliver_once()
    with runtime.store.db:
        runtime.store.db.execute("UPDATE messages SET chat_id='oc_other' WHERE message_id=?", (message.message_id,))
    assert runtime.status()['pending_events'] == []
    with runtime.store.db:
        runtime.store.db.execute('UPDATE messages SET chat_id=?', (BINDING['chat_id'],))
        runtime.store.db.execute("UPDATE subscriptions SET principal='other-owner'")
    assert runtime.status()['pending_events'] == []


def test_status_reports_bounded_monotonic_timing_without_message_data(deployment):
    runtime, path, _, transport = deployment
    runtime.bridge.subscribe(runtime.principal, subscription())
    runtime.cutoff = time.time() - 1
    message = msg()
    assert runtime.ingest(message, record_received_ns=time.monotonic_ns())
    assert runtime.bridge.deliver_once()
    timing = runtime.status()['delivery_timings']
    assert timing['source_to_receiver'] == 'unknown'
    assert timing['samples'][0]['record_to_commit_ms'] is not None
    assert message.text not in json.dumps(timing)
    reopened = Runtime(path, root=runtime.root, owner=runtime.principal, transport=transport,
                       adapter_factory=Adapter)
    try:
        assert reopened.status()['delivery_timings'] == timing
    finally:
        reopened.close()


def test_pending_get_empty_until_delivered_and_repeated_read_has_no_mutation(deployment):
    runtime, *_ = deployment
    assert runtime.bridge.get_message(runtime.principal) == {'status': 'empty', 'message': None}
    message = accept(runtime)
    assert runtime.bridge.get_message(runtime.principal) == {'status': 'empty', 'message': None}
    assert runtime.bridge.deliver_once()
    changes = runtime.store.db.total_changes
    result = runtime.bridge.get_message(runtime.principal)
    assert result == {'status': 'ready', 'reply_state': 'not_started',
                      'message': runtime.bridge.get_message(runtime.principal, message.message_id)}
    assert result['message']['text'] == message.text
    assert result['message']['sequence'] == 1
    assert runtime.bridge.get_message(runtime.principal) == result
    assert runtime.store.db.total_changes == changes
    assert not runtime.adapter.replies


def test_pending_get_orders_by_sequence_and_excludes_sent(deployment):
    runtime, *_ = deployment
    for n in range(3):
        accept(runtime, msg(event_id=f'ev_{n}', message_id=f'om_{n}'))
    with runtime.store.db:
        runtime.store.db.execute("UPDATE deliveries SET state='delivered'")
        runtime.store.db.execute("INSERT INTO replies VALUES('om_0','hash','request','sent','reply',0)")
    result = runtime.bridge.get_message(runtime.principal)
    assert result['message']['message_id'] == 'om_1'
    assert result['message']['sequence'] == 2


@pytest.mark.parametrize('state', ['sending', 'uncertain', 'unexpected-state'])
def test_pending_get_blocks_oldest_ambiguous_reply_without_decryption_or_skip(deployment, monkeypatch, state):
    runtime, *_ = deployment
    for n in range(2):
        accept(runtime, msg(event_id=f'ev_{n}', message_id=f'om_{n}'))
    with runtime.store.db:
        runtime.store.db.execute("UPDATE deliveries SET state='delivered'")
        runtime.store.db.execute("INSERT INTO replies VALUES('om_0','hash','request',?,NULL,0)", (state,))
    def forbidden(*_):
        raise AssertionError('Blocked getter must not decrypt message data')
    monkeypatch.setattr(runtime.store, 'open', forbidden)
    changes = runtime.store.db.total_changes
    result = runtime.bridge.get_message(runtime.principal)
    assert result == {'status': 'blocked', 'message': None, 'message_id': 'om_0',
                      'sequence': 1, 'reply_state': state, 'reason': 'operator_reconciliation_required'}
    assert not runtime.adapter.replies
    assert runtime.store.db.total_changes == changes


@pytest.mark.parametrize('field', ['enabled', 'binding'])
def test_pending_get_checks_live_revocation_and_binding_before_decrypt(deployment, monkeypatch, field):
    runtime, path, config, _ = deployment
    accept(runtime)
    runtime.bridge.deliver_once()
    if field == 'enabled':
        config['enabled'] = False
    else:
        config['binding'] = {**BINDING, 'chat_id': 'oc_other'}
    path.write_text(json.dumps(config))
    def forbidden(*_):
        raise AssertionError('Revoked getter must not decrypt message data')
    monkeypatch.setattr(runtime.store, 'open', forbidden)
    with pytest.raises(BridgeError, match='Access denied'):
        runtime.bridge.get_message(runtime.principal)


@pytest.mark.parametrize('mutation', ["UPDATE subscriptions SET principal='other-owner'",
                                     "UPDATE subscriptions SET chat_id='oc_other'",
                                     "UPDATE messages SET chat_id='oc_other'"])
def test_pending_get_enforces_subscription_owner_and_both_chat_bindings(deployment, monkeypatch, mutation):
    runtime, *_ = deployment
    accept(runtime)
    runtime.bridge.deliver_once()
    with runtime.store.db:
        runtime.store.db.execute(mutation)
    def forbidden(*_):
        raise AssertionError('Out-of-scope row must not be decrypted')
    monkeypatch.setattr(runtime.store, 'open', forbidden)
    assert runtime.bridge.get_message(runtime.principal) == {'status': 'empty', 'message': None}


def test_pending_get_rejects_other_owner_before_decryption(deployment, monkeypatch):
    runtime, *_ = deployment
    accept(runtime)
    runtime.bridge.deliver_once()
    def forbidden(*_):
        raise AssertionError('Wrong owner must not decrypt message data')
    monkeypatch.setattr(runtime.store, 'open', forbidden)
    with pytest.raises(BridgeError, match='Access denied'):
        runtime.bridge.get_message('other-owner')


def test_pending_get_rechecks_authorization_inside_lock_after_decryption(deployment, monkeypatch):
    runtime, path, config, _ = deployment
    accept(runtime)
    runtime.bridge.deliver_once()
    original = runtime.store.open
    def revoke_after_read(value):
        assert runtime.store.lock._is_owned()
        result = original(value)
        config['enabled'] = False
        path.write_text(json.dumps(config))
        return result
    monkeypatch.setattr(runtime.store, 'open', revoke_after_read)
    with pytest.raises(BridgeError, match='Access denied'):
        runtime.bridge.get_message(runtime.principal)
    assert not runtime.adapter.replies


def test_pending_get_both_authorization_checks_hold_store_lock(deployment, monkeypatch):
    runtime, *_ = deployment
    accept(runtime)
    runtime.bridge.deliver_once()
    checks = []
    authorized = runtime.bridge.authorized
    def checking(principal, chat_id):
        checks.append(runtime.store.lock._is_owned())
        return authorized(principal, chat_id)
    monkeypatch.setattr(runtime.bridge, 'authorized', checking)
    assert runtime.bridge.get_message(runtime.principal)['status'] == 'ready'
    assert checks == [True, True]


def test_pending_get_explicit_id_response_and_unknown_id_are_unchanged(deployment):
    runtime, *_ = deployment
    message = accept(runtime)
    result = runtime.bridge.get_message(runtime.principal, message.message_id)
    assert result == {**dataclasses.asdict(message), 'sequence': 1}
    with pytest.raises(BridgeError, match='Message not available') as caught:
        runtime.bridge.get_message(runtime.principal, 'om_unknown')
    assert caught.value.code == -32004




@pytest.mark.parametrize('field,value', [
    ('callback_hosts', ['other.example.com']),
    ('mcp_http_hosts', ['other.example.com']),
    ('port', 8766),
])
def test_network_policy_changes_revoke_existing_state(deployment, field, value):
    runtime, path, config, _ = deployment
    config[field] = value
    path.write_text(json.dumps(config))
    assert not runtime.authorized(runtime.principal, BINDING['chat_id'])
    with pytest.raises(BridgeError, match='another binding'):
        Runtime(path, root=runtime.root, adapter_factory=Adapter)


@pytest.mark.parametrize('field,value', [
    ('version', True), ('version', 2), ('enabled', 1), ('principal', ''),
    ('port', True), ('port', 80), ('port', 65536), ('port', '8765'),
    ('callback_hosts', []), ('callback_hosts', ['*.example.com']),
    ('callback_hosts', ['https://receiver.example.com/events']),
    ('callback_hosts', ['Receiver.Example.Com']),
    ('mcp_http_hosts', []), ('mcp_http_hosts', 'testserver'),
])
def test_config_rejects_ambiguous_or_unbounded_values(deployment, field, value):
    runtime, path, config, _ = deployment
    config[field] = value
    path.write_text(json.dumps(config))
    assert not runtime.authorized(runtime.principal, BINDING['chat_id'])
    with pytest.raises((BridgeError, TypeError, ValueError)):
        Runtime(path, root=runtime.root, adapter_factory=Adapter)


def test_new_deployment_uses_only_its_parameterized_binding(tmp_path):
    root = tmp_path / 'independent-example'
    root.mkdir(mode=0o700)
    binding = {
        'app_id': 'cli_second_example', 'bot_open_id': 'ou_second_example_bot',
        'user_open_id': 'ou_second_example_user', 'tenant_key': 'tenant_second_example',
        'chat_id': 'oc_second_example_private',
    }
    config = {
        'version': 1, 'enabled': True, 'principal': 'another-offline-owner', 'binding': binding,
        'cli': {
            'binary': '/opt/example/lark-cli', 'binary_sha256': 'b' * 64, 'profile': binding['app_id'],
            'config_dir': str(root / 'config'), 'data_dir': str(root / 'data'),
            'expected_bot_open_id': binding['bot_open_id'],
        },
        'callback_hosts': ['receiver.example.com'], 'mcp_http_hosts': ['testserver'], 'port': 8766,
    }
    path = root / 'config.json'
    create_private(path, json.dumps(config).encode())
    runtime = Runtime(path, root=root, initialize=True, transport=Transport(), adapter_factory=Adapter)
    try:
        assert runtime.authorized(config['principal'], binding['chat_id'])
        assert not runtime.authorized('offline-owner', BINDING['chat_id'])
        params = subscription()
        params['arguments']['chat_id'] = binding['chat_id']
        runtime.bridge.subscribe(runtime.principal, params)
        runtime.cutoff = time.time() - 1
        assert runtime.ingest(msg(chat_id=binding['chat_id'], sender_id=binding['user_open_id']))
        assert not runtime.ingest(msg())
        assert runtime.bridge.get_message(runtime.principal, 'om_offline_1')['chat_id'] == binding['chat_id']
    finally:
        runtime.close()


@pytest.mark.parametrize('failure', ['stop', 'heartbeat'])
def test_cleanup_exception_preserves_storage_and_listener_ownership(deployment, monkeypatch, failure):
    runtime, path, _config, transport = deployment
    runtime.adapter.error = True
    if failure == 'stop':
        def fail_stop():
            raise RuntimeError('fake stop failure')
        monkeypatch.setattr(runtime.adapter, 'stop', fail_stop)
        error = BridgeError
    else:
        runtime.adapter.runner.children_exit_confirmed = False
        heartbeat = runtime.heartbeat

        def fail_unsafe_heartbeat(state):
            if state == 'unsafe_shutdown':
                raise RuntimeError('fake final metadata failure')
            return heartbeat(state)

        monkeypatch.setattr(runtime, 'heartbeat', fail_unsafe_heartbeat)
        error = RuntimeError
    try:
        with pytest.raises(error):
            runtime.run()
        assert runtime.unsafe_shutdown
        assert type(runtime._retained_lock) is int
        with pytest.raises(BridgeError, match='Unsafe worker still owns storage'):
            runtime.close()
        assert runtime.store.db.execute('SELECT 1').fetchone()[0] == 1
        reopened = Runtime(path, root=runtime.root, transport=transport, adapter_factory=Adapter)
        try:
            with pytest.raises(BridgeError, match='Another listener'):
                reopened.run()
        finally:
            reopened.close()
    finally:
        # The fake adapter raises immediately, so no real child remains alive.
        if runtime._retained_lock is not None:
            os.close(runtime._retained_lock)
            runtime._retained_lock = None
        runtime.unsafe_shutdown = False
