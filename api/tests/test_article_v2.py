import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from flask import Flask

import server
from endpoints import article


class ArticleV2Test(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.root = Path(tempfile.mkdtemp())
        article.register_routes(
            self.app, self.root / 'cache', self.root / 'scripts', self.root / 'shots',
            False, False, False, '', 0, True, 60000, 'domcontentloaded', 0, '',
            None, None, None, None, 'Desktop Chrome', 0, True, '', '', '', '', '', 3600,
        )
        (self.root / 'cache').mkdir()
        (self.root / 'scripts').mkdir()
        (self.root / 'shots').mkdir()
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _driver(self):
        driver = MagicMock()
        driver.current_url = 'http://example.test/'
        driver.page_source = '<html><head><title>ok</title></head><body>ok</body></html>'
        driver.execute_cdp_cmd.side_effect = lambda method, params: (
            {'cookies': [
                {'name': 'sid', 'value': 'rotated', 'domain': 'example.test',
                 'path': '/', 'secure': True, 'httpOnly': True, 'expires': 42,
                 'sameSite': 'Lax', 'session': False},
                {'name': 'sid', 'value': 'second', 'domain': 'example.test',
                 'path': '/other', 'secure': False, 'httpOnly': False,
                 'expires': -1, 'sameSite': 'None', 'session': True},
            ]} if method == 'Storage.getCookies' else {})
        return driver

    def test_post_precedence_and_redaction(self):
        driver = self._driver()
        with patch('endpoints.article.Driver', return_value=driver), patch('endpoints.article._install_fetch'):
            response = self.client.post(
                '/api/article?url=http://example.test/&full-content=false',
                json={'full-content': True, 'cookies': [{'name': 'sid', 'value': 'secret'}],
                      'extra-http-headers': {'X-Test': 'secret'},
                      'http-credentials': {'username': 'u', 'password': 'secret'},
                      'return-cookies': True},
            )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsNotNone(data['fullContent'])
        self.assertIn('cookies', data)
        self.assertEqual(len(data['cookies']), 2)
        self.assertNotIn('cookies', data['query'])
        self.assertNotIn('secret', json.dumps(data['query']))
        self.assertNotIn('Cookie', [call.args[0] for call in driver.execute_cdp_cmd.call_args_list])

    def test_sensitive_post_never_reads_or_writes_cache(self):
        driver = self._driver()
        with patch('endpoints.article.Driver', return_value=driver), \
             patch('endpoints.article.get_cached_result') as read, \
             patch('endpoints.article.save_to_cache') as write:
            response = self.client.post(
                '/api/article?cache=true',
                json={'url': 'http://example.test/', 'extra-http-headers': {'X-Test': 'redacted'}},
            )
        self.assertEqual(response.status_code, 200)
        read.assert_not_called()
        write.assert_not_called()

    def test_unknown_option_and_conflicting_url_are_rejected(self):
        response = self.client.post('/api/article', json={'url': 'http://example.test/', 'secret': 'x'})
        self.assertEqual(response.status_code, 400)
        response = self.client.post('/api/article?url=http://one.test/', json={'url': 'http://two.test/'})
        self.assertEqual(response.status_code, 400)

    def test_script_path_containment(self):
        with self.assertRaises(article.RequestError):
            article._script_path(self.root / 'scripts', '../outside.js')

    def test_sensitive_options_are_rejected_in_query_strings(self):
        for option in ('cookies', 'http-credentials', 'extra-http-headers'):
            response = self.client.get(
                '/api/article',
                query_string={'url': 'http://example.test/', option: 'redacted'},
            )
            self.assertEqual(response.status_code, 400)
            self.assertNotIn('redacted', response.get_data(as_text=True))

    def test_get_query_keeps_legacy_supplied_option_shape(self):
        driver = self._driver()
        with patch('endpoints.article.Driver', return_value=driver):
            response = self.client.get(
                '/api/article',
                query_string={'url': 'http://example.test/', 'sleep': '0'},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['query'], {
            'url': 'http://example.test/', 'sleep': '0',
        })

    def test_incomplete_dimensions_are_rejected(self):
        for dimensions in (
            {'viewport-width': 800},
            {'viewport-height': 600},
            {'screen-width': 800},
            {'screen-width': 800, 'screen-height': 600},
        ):
            response = self.client.post(
                '/api/article', json={'url': 'http://example.test/', **dimensions},
            )
            self.assertEqual(response.status_code, 400)


class CookieMappingTest(unittest.TestCase):
    def test_host_only_cookie_uses_url_and_header_cookie_is_real_cookie(self):
        cookies = article.cookies_to_cdp(
            [{'name': 'a', 'value': '1', 'domain': 'example.test', 'hostOnly': True}],
            'http://example.test/path', ['b=2'],
        )
        self.assertEqual(cookies[0]['url'], 'http://example.test/')
        self.assertNotIn('domain', cookies[0])
        self.assertEqual(cookies[1]['name'], 'b')
        self.assertNotIn('Cookie', cookies[1])

    def test_export_keeps_duplicate_cookie_names(self):
        driver = MagicMock()
        driver.execute_cdp_cmd.return_value = {'cookies': [
            {'name': 'x', 'value': '1', 'domain': 'a', 'path': '/', 'httpOnly': True},
            {'name': 'x', 'value': '2', 'domain': 'a', 'path': '/other', 'secure': True},
        ]}
        exported = article.export_cookies(driver)
        self.assertEqual([cookie['value'] for cookie in exported], ['1', '2'])
        self.assertTrue(exported[0]['httpOnly'])
        self.assertTrue(exported[1]['secure'])
        self.assertTrue(exported[0]['hostOnly'])

    def test_export_session_cookie_omits_chrome_minus_one_expiry(self):
        driver = MagicMock()
        driver.execute_cdp_cmd.return_value = {'cookies': [
            {'name': 'session', 'value': 'rotated', 'domain': 'example.test',
             'path': '/', 'session': True, 'expires': -1},
        ]}
        exported = article.export_cookies(driver)
        self.assertTrue(exported[0]['session'])
        self.assertNotIn('expires', exported[0])

    def test_export_falls_back_to_network_cookie_store(self):
        driver = MagicMock()
        driver.execute_cdp_cmd.side_effect = [
            {'cookies': []},
            {'cookies': [
                {'name': 'x', 'value': 'network', 'domain': '.example.test',
                 'path': '/', 'expires': 42},
            ]},
        ]
        self.assertEqual(article.export_cookies(driver)[0]['value'], 'network')
        self.assertEqual(driver.execute_cdp_cmd.call_args_list[1].args[0],
                         'Network.getAllCookies')

    def test_cookie_params_use_cdp_expires_and_no_opaque_partition_field(self):
        params = article.cookies_to_cdp([{
            'name': 'x', 'value': '1', 'domain': '.example.test',
            'expires': 42, 'partitionKeyOpaque': True,
        }], 'https://example.test/')
        self.assertEqual(params[0]['expires'], 42)
        self.assertNotIn('expirationDate', params[0])
        self.assertNotIn('partitionKeyOpaque', params[0])


if __name__ == '__main__':
    unittest.main()
