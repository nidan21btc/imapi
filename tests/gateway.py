#!/usr/bin/env python3
"""Smoke-test the local HTTPS gateway without using a real mailbox.

IMAPI_TEST_KEY=... python3 tests/gateway.py
Never prints request headers or response bodies.
"""
import http.client
import json
import os
from pathlib import Path
import ssl

root = Path(__file__).resolve().parent.parent
key = os.environ['IMAPI_TEST_KEY']
context = ssl.create_default_context(cafile=str(root / '.dev/imapi.test.crt'))
count = 0


def request(method='POST', body=None, status=400, code=None, tls=True, **headers):
    global count
    cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    conn = cls('imapi.test', timeout=10, **({'context': context} if tls else {}))
    base = {'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json',
            'X-Mail-User': 'fixture@sann.gmbh', 'X-Mail-Password': 'fixture-only'}
    if not tls:
        # Test HTTPS rejection without ever sending credentials over plaintext HTTP.
        base = {'Content-Type': 'application/json'}
    base.update(headers)
    data = json.dumps(body) if isinstance(body, dict) else body
    conn.request(method, '/', data, base)
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    assert response.status == status, f'Check {count + 1}: expected {status}, got {response.status}'
    parsed = json.loads(raw)
    assert parsed['ok'] is False
    if code:
        assert parsed['error']['code'] == code, f'Check {count + 1}: unexpected error code'
    assert b'fixture-only' not in raw and b'fixture@sann.gmbh' not in raw
    assert response.getheader('Cache-Control') == 'no-store'
    count += 1


request(tls=False, status=426, code='https_required', **{'X-Forwarded-Proto': 'https'})
request(method='GET', status=405, code='method_not_allowed')
request(status=401, code='unauthorized', Authorization='Bearer ' + 'x' * 64)
request(body={}, status=415, code='json_required', **{'Content-Type': 'text/plain'})
request(body='{', code='invalid_json')
request(body='[]', code='invalid_json')
request(body={'action': 'folders'}, status=403, code='mailbox_forbidden', **{'X-Mail-User': 'user@evil.test'})
request(body={'action': 'folders'}, status=403, code='mail_auth_failed', **{'X-Mail-Password': ''})
request(body={'action': 'delete'}, code='invalid_action')
request(body={'action': 'get', 'uid': '42'}, code='invalid_parameter')
request(body={'action': 'list', 'limit': 101}, code='invalid_parameter')
request(body={'action': 'list', 'since': '2026-02-30'}, code='invalid_parameter')
request(body={'action': 'flag', 'uid': 42, 'seen': 'false'}, code='invalid_parameter')
request(body={'action': 'flag', 'uid': 42}, code='invalid_parameter')
request(body={'action': 'create_folder', 'folder': ''}, code='invalid_parameter')
request(body={'action': 'create_folder', 'folder': 'Archiv//2026'}, code='invalid_parameter')
request(body={'action': 'send', 'to': 'a@foreign.example', 'subject': 'Test', 'text': 'Test'}, status=403, code='recipient_not_allowed')
request(body={'action': 'send', 'to': [], 'subject': 'Test', 'text': 'Test'}, code='invalid_parameter')
print(f'{count} HTTPS/HTTP gateway checks passed; no real mailbox accessed.')
