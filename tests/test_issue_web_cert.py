# Copyright 2026 uds-takserver authors
# SPDX-License-Identifier: GPL-3.0-only

"""Exercise renewal, Secret publication, reload, and real backend TLS."""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from tests.test_issue_health_cert import CAPASS, NS, b64, make_ca, run


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'charts/takserver/files/scripts'
KEY = 'takserver-web.jks'
FQDN = 'takserver-web.takserver.svc.cluster.local'
ANNOTATION = 'uds.dev/web-keystore-sha256'


class FakeApi:
    def __init__(self, directory, ca, key, store=None, location='Secret', deployment=True):
        self.cm = {'binaryData': {'ca.pem': b64(ca)}}
        self.secret = {'admin.pem': base64.b64encode(b'preserve-admin').decode()}
        if store is not None:
            (self.cm['binaryData'] if location == 'ConfigMap' else self.secret)[KEY] = store
        self.ca_key = b64(key)
        self.deployment = deployment
        self.annotations = {'unrelated': 'keep'}
        self.writes = []
        self.restarts = 0
        self.fail_reload = False
        self.secret_error = None
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def reply(self, code, body):
                data = json.dumps(body, indent=2).encode()
                self.send_response(code)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path.endswith('/configmaps/cert-migration'):
                    self.reply(200, api.cm)
                elif self.path.endswith('/secrets/takserver-certs'):
                    self.reply(api.secret_error or 200, {'data': api.secret})
                elif self.path.endswith('/secrets/takserver-ca-key'):
                    self.reply(200, {'data': {'ca-do-not-share.key': api.ca_key}})
                elif self.path.endswith('/deployments/takserver-api'):
                    self.reply(200 if api.deployment else 404,
                               {'spec': {'template': {'metadata': {'annotations': api.annotations}}}})
                else:
                    self.reply(404, {})

            def write(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if self.path.endswith('/secrets'):
                    self.reply(409, {})
                    return
                if self.path.endswith('/deployments/takserver-api') and api.fail_reload:
                    self.reply(403, {})
                    return
                if self.path.endswith('/deployments/takserver-api') and not api.deployment:
                    self.reply(404, {})
                    return
                api.writes.append((self.path, body))
                if self.path.endswith('/configmaps/cert-migration'):
                    for name, value in body['binaryData'].items():
                        if value is None:
                            api.cm['binaryData'].pop(name, None)
                        else:
                            api.cm['binaryData'][name] = value
                elif self.path.endswith('/secrets/takserver-certs'):
                    api.secret = body['data']
                else:
                    annotations = body['spec']['template']['metadata']['annotations']
                    if any(api.annotations.get(name) != value for name, value in annotations.items()):
                        api.restarts += 1
                    api.annotations.update(annotations)
                self.reply(200, body)

            do_PATCH = write
            do_POST = write
            do_PUT = write

        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / 'server.pem', directory / 'server.key')
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f'https://127.0.0.1:{self.server.server_address[1]}'


@unittest.skipUnless(shutil.which('keytool') and shutil.which('openssl'), 'JDK and OpenSSL required')
class WebCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.fixtures = Path(cls.temporary.name)
        cls.ca_key, cls.ca = make_ca(cls.fixtures, 'ca')
        cls.other_key, cls.other_ca = make_ca(cls.fixtures, 'other')
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
             '-keyout', str(cls.fixtures / 'server.key'), '-out', str(cls.fixtures / 'server.pem')])
        cls.stores = {}
        for name, days, host, other in (
            ('current', 365, FQDN, False), ('expired', -1, FQDN, False),
            ('near-expiry', 1, FQDN, False), ('wrong-san', 365, 'wrong.example.test', False),
            ('wrong-ca', 365, FQDN, True),
        ):
            key, csr, pem = (cls.fixtures / f'{name}.{suffix}' for suffix in ('key', 'csr', 'pem'))
            run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', f'/CN={host}',
                 '-keyout', str(key), '-out', str(csr)])
            ext = cls.fixtures / 'extensions'
            ext.write_text(f'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{host}\n')
            run(['openssl', 'x509', '-req', '-in', str(csr), '-days', str(days), '-set_serial', '10',
                 '-CA', str(cls.other_ca if other else cls.ca),
                 '-CAkey', str(cls.other_key if other else cls.ca_key), '-passin', f'pass:{CAPASS}',
                 '-extfile', str(ext), '-out', str(pem)])
            store = cls.fixtures / f'{name}.p12'
            run(['openssl', 'pkcs12', '-export', '-in', str(pem), '-inkey', str(key),
                 '-name', 'takserver-web', '-out', str(store), '-passout', f'pass:{CAPASS}'])
            cls.stores[name] = b64(store)
        cls.stores['unreadable'] = base64.b64encode(b'not a keystore').decode()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.sa = self.directory / 'sa'
        self.sa.mkdir()
        (self.sa / 'namespace').write_text(NS)
        (self.sa / 'token').write_text('synthetic-token')
        (self.sa / 'ca.crt').write_bytes((self.fixtures / 'server.pem').read_bytes())

    def api(self, *args, **kwargs):
        api = FakeApi(self.fixtures, self.ca, self.ca_key, *args, **kwargs)
        self.addCleanup(api.server.server_close)
        self.addCleanup(api.server.shutdown)
        return api

    def execute(self, api, name, ca_file=True):
        result = subprocess.run(['bash', str(SCRIPTS / name)], text=True, capture_output=True, timeout=45,
                                env={**os.environ, 'CAPASS': CAPASS, 'SA_DIR': str(self.sa),
                                     'KUBE_API': api.url, 'WEB_SERVICE': 'takserver-web',
                                     'CA_KEY_FILE': str(self.ca_key if ca_file else self.directory / 'absent')})
        self.assertNotIn(CAPASS, result.stdout + result.stderr)
        return result

    def renew_and_publish(self, api):
        for name in ('issue-web-cert.sh', 'split-key-material.sh'):
            result = self.execute(api, name)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def certificate(self, api):
        store, pem = self.directory / 'issued.p12', self.directory / 'issued.pem'
        store.write_bytes(base64.b64decode(api.secret[KEY]))
        pem.write_text(run(['keytool', '-exportcert', '-rfc', '-alias', 'takserver-web',
                            '-keystore', str(store), '-storepass', CAPASS]).stdout)
        run(['openssl', 'verify', '-CAfile', str(self.ca), '-purpose', 'sslserver',
             '-verify_hostname', FQDN, str(pem)])
        run(['openssl', 'x509', '-in', str(pem), '-noout', '-checkend', '2592000'])
        return store, pem

    def test_current_keystore_is_preserved_in_both_locations(self):
        for location in ('ConfigMap', 'Secret'):
            with self.subTest(location=location):
                api = self.api(store=self.stores['current'], location=location)
                api.annotations[ANNOTATION] = hashlib.sha256(self.stores['current'].encode()).hexdigest()
                self.renew_and_publish(api)
                self.assertEqual(api.secret[KEY], self.stores['current'])
                self.assertEqual(api.restarts, 0)

    def test_invalid_keystores_are_replaced_in_both_locations(self):
        for location in ('ConfigMap', 'Secret'):
            for fixture in ('expired', 'near-expiry', 'wrong-san', 'wrong-ca', 'unreadable'):
                with self.subTest(location=location, fixture=fixture):
                    api = self.api(store=self.stores[fixture], location=location)
                    self.renew_and_publish(api)
                    self.assertNotEqual(api.secret[KEY], self.stores[fixture])
                    self.certificate(api)
                    self.assertNotIn(KEY, api.cm['binaryData'])
                    self.assertEqual(base64.b64decode(api.secret['admin.pem']), b'preserve-admin')
                    self.assertEqual(api.annotations['unrelated'], 'keep')
                    self.assertEqual(api.annotations[ANNOTATION], hashlib.sha256(api.secret[KEY].encode()).hexdigest())
                    paths = [path for path, _ in api.writes]
                    self.assertLess(next(i for i, path in enumerate(paths) if path.endswith('/secrets/takserver-certs')),
                                    next(i for i, path in enumerate(paths) if '/deployments/' in path))

    def test_initial_install_uses_ca_key_secret_and_tolerates_no_deployment(self):
        api = self.api(deployment=False)
        result = self.execute(api, 'issue-web-cert.sh', ca_file=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.execute(api, 'split-key-material.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.certificate(api)

    def test_stale_configmap_cannot_overwrite_a_current_secret(self):
        api = self.api(store=self.stores['expired'], location='ConfigMap')
        api.secret[KEY] = self.stores['current']
        self.renew_and_publish(api)
        self.assertNotEqual(api.secret[KEY], self.stores['expired'])
        self.certificate(api)

    def test_secret_read_failure_does_not_overwrite_credentials(self):
        api = self.api(store=self.stores['current'])
        api.secret_error = 403
        result = self.execute(api, 'issue-web-cert.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(api.writes, [])

    def test_reload_failure_is_retried_without_reissuing(self):
        api = self.api(store=self.stores['expired'])
        result = self.execute(api, 'issue-web-cert.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        api.fail_reload = True
        self.assertNotEqual(self.execute(api, 'split-key-material.sh').returncode, 0)
        published = api.secret[KEY]
        api.fail_reload = False
        self.renew_and_publish(api)
        self.assertEqual(api.secret[KEY], published)
        count = api.restarts
        self.renew_and_publish(api)
        self.assertEqual(api.restarts, count)

    def test_renewed_certificate_completes_a_verified_tls_handshake(self):
        api = self.api(store=self.stores['expired'])
        self.renew_and_publish(api)
        store, pem = self.certificate(api)
        key = self.directory / 'issued.key'
        run(['openssl', 'pkcs12', '-in', str(store), '-passin', f'pass:{CAPASS}',
             '-nocerts', '-nodes', '-out', str(key)])
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.settimeout(5)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(pem, key)
        errors = []

        def serve():
            try:
                conn, _ = server.accept()
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.sendall(b'backend verified')
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        client = ssl.create_default_context(cafile=str(self.ca))
        with socket.create_connection(server.getsockname(), timeout=5) as conn:
            with client.wrap_socket(conn, server_hostname=FQDN) as tls:
                self.assertEqual(tls.recv(100), b'backend verified')
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
