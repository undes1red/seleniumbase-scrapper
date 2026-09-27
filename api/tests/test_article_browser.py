"""Real local-browser coverage for CDP-backed article options."""
import http.server
import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

from flask import Flask

from endpoints import article


@unittest.skipUnless(os.getenv('RUN_BROWSER_TESTS') == '1', 'set RUN_BROWSER_TESTS=1')
class LocalBrowserTest(unittest.TestCase):
    def setUp(self):
        self.observed = {'requests': [], 'resources': {}}
        observed = self.observed

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                resource = self.path.split('?', 1)[0]
                observed['requests'].append({
                    'path': resource,
                    'ua': self.headers.get('User-Agent'),
                    'x': self.headers.get('X-Local-Test'),
                    'language': self.headers.get('Accept-Language'),
                    'cookie': self.headers.get('Cookie', ''),
                    'authorization': self.headers.get('Authorization', ''),
                })
                observed['resources'][resource] = observed['resources'].get(resource, 0) + 1

                if resource == '/slow-commit':
                    time.sleep(.2)
                if resource == '/ping':
                    time.sleep(.1)
                    self.send_response(204)
                    self.end_headers()
                    return
                if resource == '/blocked.png':
                    self.send_response(200)
                    self.send_header('Content-Type', 'image/png')
                    self.end_headers()
                    return
                if resource == '/allowed.js':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/javascript')
                    self.end_headers()
                    self.wfile.write(b'document.body.dataset.allowed = "yes";')
                    return
                if resource == '/auth' and self.headers.get('Authorization') != 'Basic cmVhZGVyOnJlZGFjdGVk':
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="local"')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return

                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Set-Cookie', 'session=rotated; Path=/; HttpOnly; SameSite=Lax')
                self.end_headers()
                delayed_fetch = (
                    "setTimeout(() => fetch('/ping'), 100);"
                    if resource == '/networkidle' else ''
                )
                self.wfile.write((f"""<html><body>
                    <div id="browser-data"></div>
                    <script src="/allowed.js"></script>
                    <img src="/blocked.png">
                    <script>
                    document.getElementById('browser-data').textContent = [
                        navigator.userAgent, navigator.language,
                        Intl.DateTimeFormat().resolvedOptions().timeZone
                    ].join('|');
                    {delayed_fetch}
                    </script>
                    local article
                    </body></html>""").encode())

            def log_message(self, *_):
                pass

        self.http = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.root = Path(tempfile.mkdtemp())
        for name in ('cache', 'scripts', 'shots'):
            (self.root / name).mkdir()
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        article.register_routes(
            self.app, self.root / 'cache', self.root / 'scripts', self.root / 'shots',
            False, False, False, '', 0, True, 60000, 'domcontentloaded', 0, '',
            None, None, None, None, 'Desktop Chrome', 0, True, '', '', '', '', '', 3600,
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=2)
        shutil.rmtree(self.root, ignore_errors=True)

    def test_local_cookie_rotation_headers_locale_timezone_and_basic_auth(self):
        port = self.http.server_address[1]
        user_agent = 'PriceBuddyLocal/1.0'
        response = self.client.post('/api/article', json={
            'url': f'http://127.0.0.1:{port}/auth',
            'cookies': [{'name': 'session', 'value': 'initial', 'hostOnly': True}],
            'extra-http-headers': 'Cookie:legacy=two; X-Local-Test:yes',
            'http-credentials': {'username': 'reader', 'password': 'redacted'},
            'user-agent': user_agent, 'locale': 'en-GB',
            'timezone': 'Europe/London', 'resource': ['document', 'script'],
            'full-content': True, 'return-cookies': True,
        })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        data = response.get_json()
        requests = [item for item in self.observed['requests'] if item['path'] == '/auth']
        self.assertTrue(requests)
        observed = next((item for item in requests if item['authorization']), requests[-1])
        self.assertEqual(observed['ua'], user_agent, requests)
        self.assertEqual(observed['x'], 'yes', requests)
        self.assertTrue(observed['language'].startswith('en-GB'))
        self.assertIn('session=initial', observed['cookie'])
        self.assertIn('legacy=two', observed['cookie'])
        self.assertEqual(observed['authorization'], 'Basic cmVhZGVyOnJlZGFjdGVk')

        browser_data = data['textContent'] or ''
        self.assertIn(user_agent, browser_data)
        self.assertIn('en-GB', browser_data)
        self.assertIn('Europe/London', browser_data)
        self.assertEqual(self.observed['resources'].get('/allowed.js'), 1)
        self.assertEqual(self.observed['resources'].get('/blocked.png', 0), 0)
        self.assertTrue(any(cookie['name'] == 'session' and cookie['value'] == 'rotated'
                            for cookie in data['cookies']))
        self.assertIn('local article', data['textContent'])

        replay = self.client.post('/api/article', json={
            'url': f'http://127.0.0.1:{port}/auth',
            'cookies': data['cookies'], 'return-cookies': True,
            'http-credentials': {'username': 'reader', 'password': 'redacted'},
        })
        self.assertEqual(replay.status_code, 200)
        self.assertIn('session=rotated', self.observed['requests'][-1]['cookie'])

    def test_commit_waits_for_main_document_response_with_timeout_disabled(self):
        port = self.http.server_address[1]
        started = time.monotonic()
        response = self.client.post('/api/article', json={
            'url': f'http://127.0.0.1:{port}/slow-commit',
            'wait-until': 'commit', 'timeout': 0,
        })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertGreaterEqual(time.monotonic() - started, .2)
        self.assertEqual(self.observed['resources'].get('/slow-commit'), 1)

    def test_networkidle_waits_for_delayed_request(self):
        port = self.http.server_address[1]
        started = time.monotonic()
        response = self.client.post('/api/article', json={
            'url': f'http://127.0.0.1:{port}/networkidle',
            'wait-until': 'networkidle', 'timeout': 5000,
        })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertGreaterEqual(time.monotonic() - started, .5)
        self.assertEqual(self.observed['resources'].get('/ping'), 1)


if __name__ == '__main__':
    unittest.main()
