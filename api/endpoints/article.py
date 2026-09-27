#!/usr/bin/env python3
"""The article endpoint and the small browser configuration layer it needs."""
import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from bs4 import BeautifulSoup
from flask import jsonify, request
from seleniumbase import Driver

from helpers import (
    extract_article_content, extract_meta_tags, extract_published_time,
    extract_text_content, get_cached_result, get_cache_key,
    reap_abandoned_child_processes, save_to_cache,
)

logger = logging.getLogger(__name__)

PUBLIC_OPTIONS = {
    'cache', 'full-content', 'screenshot', 'user-scripts',
    'user-scripts-timeout', 'incognito', 'timeout', 'wait-until', 'sleep',
    'resource', 'viewport-width', 'viewport-height', 'screen-width',
    'screen-height', 'device', 'scroll-down', 'ignore-https-errors',
    'user-agent', 'locale', 'timezone', 'http-credentials',
    'extra-http-headers', 'cookies', 'return-cookies', 'url',
}
WAIT_UNTIL = {'load', 'domcontentloaded', 'commit', 'networkidle'}
SECRET_OPTIONS = {'cookies', 'http-credentials', 'extra-http-headers'}
RESOURCE_TYPES = {
    'document', 'stylesheet', 'image', 'media', 'font', 'script', 'texttrack',
    'xhr', 'fetch', 'eventsource', 'websocket', 'manifest', 'other',
}
DEVICE_PRESETS = {
    # Keep Desktop Chrome as the documented no-op baseline.
    'Desktop Chrome': {},
    'iPhone 12': {'width': 390, 'height': 844, 'dpr': 3, 'mobile': True,
                  'user_agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'},
    'iPhone 13': {'width': 390, 'height': 844, 'dpr': 3, 'mobile': True,
                  'user_agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1'},
    'Pixel 5': {'width': 393, 'height': 851, 'dpr': 2.75, 'mobile': True,
                'user_agent': 'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'},
}
COOKIE_KEYS = {'name', 'value', 'domain', 'path', 'hostOnly', 'secure', 'httpOnly',
               'expires', 'session', 'sameSite', 'priority', 'sourceScheme',
               'sourcePort', 'partitionKey', 'partitionKeyOpaque'}


class RequestError(ValueError):
    """A safe, client-facing request validation error."""


def _error(kind, message, status=400, cookies=None):
    body = {'detail': [{'type': kind, 'msg': message}]}
    if cookies is not None:
        body['cookies'] = cookies
    return jsonify(body), status


def _bool(value, default):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {'true', '1', 'yes'}:
        return True
    if isinstance(value, str) and value.lower() in {'false', '0', 'no'}:
        return False
    raise RequestError('invalid boolean value')


def _int(value, default, minimum=0, maximum=10_000_000):
    if value is None or value == '':
        value = default
    if isinstance(value, bool):
        raise RequestError('invalid integer value')
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise RequestError('invalid integer value')
    if result < minimum or result > maximum:
        raise RequestError('integer value is out of range')
    return result


def _list(value, default=''):
    if value is None or value == '':
        value = default
    if isinstance(value, list):
        if not all(isinstance(item, str) and item.strip() for item in value):
            raise RequestError('list values must be non-empty strings')
        return [item.strip() for item in value]
    if not isinstance(value, str):
        raise RequestError('list value must be a string or list')
    return [item.strip() for item in value.split(',') if item.strip()]


def _url(value):
    if not isinstance(value, str) or not value:
        raise RequestError('url is required')
    parsed = urlparse(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise RequestError('url must use http or https')
    if parsed.username or parsed.password:
        raise RequestError('URL credentials are not supported')
    return value


def _origin(url):
    parsed = urlparse(url)
    return f'{parsed.scheme}://{parsed.hostname}' + (f':{parsed.port}' if parsed.port else '')


def _parse_headers(value):
    if value is None or value == '':
        return {}, []
    if isinstance(value, dict):
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
            raise RequestError('extra-http-headers must contain string values')
        pairs = list(value.items())
    elif isinstance(value, str):
        pairs = []
        cookie_value = None
        for part in value.split(';'):
            part = part.strip()
            if not part:
                continue
            if ':' in part:
                key, val = part.split(':', 1)
                cookie_value = val if key.strip().lower() == 'cookie' else None
                pairs.append((key, val))
            elif cookie_value is not None:
                pairs[-1] = (pairs[-1][0], f'{pairs[-1][1]}; {part}')
            else:
                raise RequestError('extra-http-headers must use name:value pairs')
    else:
        raise RequestError('extra-http-headers must be an object or string')
    headers, cookie_headers = {}, []
    for key, val in pairs:
        key, val = key.strip(), val.strip()
        if not key or '\n' in key or '\n' in val or '\r' in key or '\r' in val:
            raise RequestError('invalid HTTP header')
        if key.lower() == 'cookie':
            cookie_headers.append(val)
        else:
            headers[key] = val
    return headers, cookie_headers


def _parse_credentials(value):
    if value is None or value == '':
        return None
    if isinstance(value, dict):
        if set(value) != {'username', 'password'} or not all(isinstance(v, str) for v in value.values()):
            raise RequestError('http-credentials must contain username and password')
        return dict(value)
    if isinstance(value, str) and ':' in value:
        username, password = value.split(':', 1)
        if username:
            return {'username': username, 'password': password}
    raise RequestError('invalid http-credentials')


def _parse_expiry(value):
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < 0:
            raise RequestError('invalid cookie expiry')
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
        except ValueError:
            raise RequestError('invalid cookie expiry')
    raise RequestError('invalid cookie expiry')


def _parse_cookies(value):
    if value in (None, ''):
        return []
    if not isinstance(value, list):
        raise RequestError('cookies must be a list')
    result = []
    for cookie in value:
        if not isinstance(cookie, dict) or not isinstance(cookie.get('name'), str) or not isinstance(cookie.get('value'), str):
            raise RequestError('each cookie needs a string name and value')
        if set(cookie) - COOKIE_KEYS:
            raise RequestError('unsupported cookie field')
        item = dict(cookie)
        for key in ('hostOnly', 'secure', 'httpOnly', 'session', 'partitionKeyOpaque'):
            if key in item and not isinstance(item[key], bool):
                raise RequestError('cookie flags must be boolean')
        if 'path' in item and not isinstance(item['path'], str):
            raise RequestError('cookie path must be a string')
        if 'domain' in item and not isinstance(item['domain'], str):
            raise RequestError('cookie domain must be a string')
        if 'sameSite' in item and item['sameSite'] not in {'Strict', 'Lax', 'None'}:
            raise RequestError('invalid cookie SameSite value')
        if 'expires' in item and item['expires'] is not None:
            item['expires'] = _parse_expiry(item['expires'])
        result.append(item)
    return result


def _cookie_from_header(value, url):
    return [{'name': name.strip(), 'value': cookie_value.strip(),
             'url': _origin(url) + '/', 'path': '/'}
            for part in value.split(';')
            if '=' in part
            for name, cookie_value in [part.split('=', 1)]
            if name.strip()]


CDP_COOKIE_KEYS = {
    'name', 'value', 'url', 'domain', 'path', 'secure', 'httpOnly', 'sameSite',
    'expires', 'priority', 'sourcePort', 'partitionKey',
}


def cookies_to_cdp(cookies, url, cookie_headers=()):
    """Convert API cookies to Network.setCookies entries without broad domains."""
    converted = []
    all_cookies = cookies + sum((_cookie_from_header(header, url) for header in cookie_headers), [])
    for cookie in all_cookies:
        item = {key: value for key, value in cookie.items()
                if key in CDP_COOKIE_KEYS and value is not None}
        item.setdefault('path', '/')
        domain = cookie.get('domain')
        host_only = cookie.get('hostOnly')
        if host_only is None and domain:
            host_only = not domain.startswith('.')
        if host_only or not domain:
            item.pop('domain', None)
            host = (domain or urlparse(url).hostname).lstrip('.')
            try:
                if urlparse('https://' + host).hostname != host:
                    raise RequestError('invalid cookie domain')
            except ValueError:
                raise RequestError('invalid cookie domain')
            item['url'] = f'{urlparse(url).scheme}://{host}' + item['path']
        else:
            item.pop('url', None)
        if cookie.get('session') or item.get('expires', 0) == -1:
            item.pop('expires', None)
        converted.append(item)
    return converted


def _cookie_snapshot(result):
    return result.get('cookies', []) if isinstance(result, dict) else []


def export_cookies(driver):
    """Return Chrome's store, retaining duplicate names and cookie scope."""
    try:
        cookies = _cookie_snapshot(driver.execute_cdp_cmd('Storage.getCookies', {}))
    except Exception:
        cookies = []
    if not cookies:
        try:
            cookies = _cookie_snapshot(driver.execute_cdp_cmd('Network.getAllCookies', {}))
        except Exception:
            cookies = []
    exported = []
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        item = {key: cookie[key] for key in (
            'name', 'value', 'domain', 'path', 'expires', 'secure', 'httpOnly',
            'sameSite', 'session', 'priority', 'sourceScheme', 'sourcePort',
            'partitionKey'
        ) if key in cookie}
        if item.get('session') or item.get('expires') == -1:
            item.pop('expires', None)
        if 'domain' in item and 'hostOnly' not in cookie:
            item['hostOnly'] = not item['domain'].startswith('.')
        elif 'hostOnly' in cookie:
            item['hostOnly'] = cookie['hostOnly']
        exported.append(item)
    return exported


def _cdp(driver, method, params=None):
    command = getattr(driver, 'execute_cdp_cmd', None)
    if not callable(command):
        raise RequestError(f'unsupported browser feature: {method}')
    command(method, params or {})


def _event_value(event, key, default=None):
    if isinstance(event, dict):
        return event.get(key, default)
    return getattr(event, key, default)


def _install_fetch(driver, allowed, credentials, target_url):
    """Install Fetch callbacks when Selenium exposes event-capable DevTools."""
    if not hasattr(driver, 'start_devtools'):
        raise RequestError('unsupported browser feature: event-capable CDP Fetch')
    try:
        devtools, connection = driver.start_devtools()
        fetch = devtools.fetch
        network = devtools.network
        origin = _origin(target_url)
        def paused(event):
            request_id = _event_value(event, 'request_id') or _event_value(event, 'requestId')
            resource = _event_value(event, 'resource_type') or _event_value(event, 'resourceType')
            resource = getattr(resource, 'value', resource)
            resource = str(resource).lower().split('.')[-1] if resource else resource
            if allowed and resource and resource not in allowed:
                connection.execute(fetch.fail_request(
                    request_id, network.ErrorReason.BLOCKED_BY_CLIENT))
            else:
                connection.execute(fetch.continue_request(request_id))
        def auth(event):
            request_id = _event_value(event, 'request_id') or _event_value(event, 'requestId')
            req = _event_value(event, 'request', {})
            req_url = _event_value(req, 'url', '')
            if credentials and _origin(req_url) == origin:
                response = fetch.AuthChallengeResponse(
                    response='ProvideCredentials', username=credentials['username'],
                    password=credentials['password'])
            else:
                response = fetch.AuthChallengeResponse(response='Default')
            connection.execute(fetch.continue_with_auth(request_id, response))
        connection.add_callback(fetch.RequestPaused, paused)
        if credentials:
            connection.add_callback(fetch.AuthRequired, auth)
        connection.execute(fetch.enable(handle_auth_requests=bool(credentials)))
        return connection
    except RequestError:
        raise
    except Exception as exc:
        raise RequestError('unsupported browser feature: event-capable CDP Fetch') from exc


def _configure_network_wait(driver):
    if not hasattr(driver, 'start_devtools'):
        raise RequestError('unsupported browser feature: event-capable CDP Network')
    try:
        devtools, connection = driver.start_devtools()
        network = devtools.network
        state = {'inflight': set(), 'last': time.monotonic()}
        def sent(event):
            rid = _event_value(event, 'request_id') or _event_value(event, 'requestId')
            state['inflight'].add(rid); state['last'] = time.monotonic()
        def done(event):
            rid = _event_value(event, 'request_id') or _event_value(event, 'requestId')
            state['inflight'].discard(rid); state['last'] = time.monotonic()
        connection.add_callback(network.RequestWillBeSent, sent)
        connection.add_callback(network.LoadingFinished, done)
        connection.add_callback(network.LoadingFailed, done)
        connection.execute(network.enable())
        return state
    except Exception as exc:
        raise RequestError('unsupported browser feature: event-capable CDP Network') from exc


def _configure_commit_wait(driver):
    if not hasattr(driver, 'start_devtools'):
        raise RequestError('unsupported browser feature: event-capable CDP Network')
    try:
        devtools, connection = driver.start_devtools()
        network = devtools.network
        state = {'committed': False}

        def received(event):
            resource = _event_value(event, 'type_') or _event_value(event, 'type')
            resource = getattr(resource, 'value', resource)
            if str(resource).lower().split('.')[-1] == 'document':
                state['committed'] = True

        connection.add_callback(network.ResponseReceived, received)
        connection.execute(network.enable())
        return state
    except Exception as exc:
        raise RequestError('unsupported browser feature: event-capable CDP Network') from exc


def _normalize(params, defaults, url):
    get = params.get
    device = get('device', defaults['device'])
    if not isinstance(device, str) or device not in DEVICE_PRESETS:
        raise RequestError('unsupported device name')
    result = {
        'url': _url(url),
        'cache': _bool(get('cache'), defaults['cache']),
        'full-content': _bool(get('full-content'), defaults['full_content']),
        'screenshot': _bool(get('screenshot'), defaults['screenshot']),
        'user-scripts': _list(get('user-scripts'), defaults['user_scripts']),
        'user-scripts-timeout': _int(get('user-scripts-timeout'), defaults['user_scripts_timeout']),
        'incognito': _bool(get('incognito'), defaults['incognito']),
        'timeout': _int(get('timeout'), defaults['timeout']),
        'wait-until': get('wait-until', defaults['wait_until']),
        'sleep': _int(get('sleep'), defaults['sleep']),
        'resource': _list(get('resource'), defaults['resource']),
        'viewport-width': _int(get('viewport-width'), defaults['viewport_width'], 1, 10000) if get('viewport-width', defaults['viewport_width']) not in (None, '') else None,
        'viewport-height': _int(get('viewport-height'), defaults['viewport_height'], 1, 10000) if get('viewport-height', defaults['viewport_height']) not in (None, '') else None,
        'screen-width': _int(get('screen-width'), defaults['screen_width'], 1, 20000) if get('screen-width', defaults['screen_width']) not in (None, '') else None,
        'screen-height': _int(get('screen-height'), defaults['screen_height'], 1, 20000) if get('screen-height', defaults['screen_height']) not in (None, '') else None,
        'device': device,
        'scroll-down': _int(get('scroll-down'), defaults['scroll_down']),
        'ignore-https-errors': _bool(get('ignore-https-errors'), defaults['ignore_https_errors']),
        'user-agent': get('user-agent', defaults['user_agent']) or None,
        'locale': get('locale', defaults['locale']) or None,
        'timezone': get('timezone', defaults['timezone']) or None,
        'return-cookies': _bool(get('return-cookies'), False),
        'cookies': _parse_cookies(get('cookies')),
    }
    if result['wait-until'] not in WAIT_UNTIL:
        raise RequestError('invalid wait-until value')
    if result['resource'] and not set(result['resource']) <= RESOURCE_TYPES:
        raise RequestError('invalid resource type')
    if result['user-agent'] is not None and not isinstance(result['user-agent'], str):
        raise RequestError('user-agent must be a string')
    if result['locale'] is not None and not isinstance(result['locale'], str):
        raise RequestError('locale must be a string')
    if result['timezone'] is not None and not isinstance(result['timezone'], str):
        raise RequestError('timezone must be a string')
    has_viewport_width = result['viewport-width'] is not None
    has_viewport_height = result['viewport-height'] is not None
    if has_viewport_width != has_viewport_height:
        raise RequestError('viewport width and height must be specified together')
    has_screen_width = result['screen-width'] is not None
    has_screen_height = result['screen-height'] is not None
    if has_screen_width != has_screen_height:
        raise RequestError('screen width and height must be specified together')
    preset = DEVICE_PRESETS[result['device']]
    if has_screen_width and not (has_viewport_width or preset.get('width')):
        raise RequestError('screen dimensions require viewport dimensions or a mobile device')
    result['headers'], cookie_headers = _parse_headers(get('extra-http-headers', defaults['extra_http_headers']))
    result['cookie_headers'] = cookie_headers
    result['credentials'] = _parse_credentials(get('http-credentials', defaults['http_credentials']))
    return result


def _safe_query(options):
    return {key: options[key] for key in (
        'url', 'full-content', 'screenshot', 'user-scripts',
        'user-scripts-timeout', 'incognito', 'timeout', 'wait-until', 'sleep',
        'resource', 'viewport-width', 'viewport-height', 'screen-width',
        'screen-height', 'device', 'scroll-down', 'ignore-https-errors',
        'user-agent', 'locale', 'timezone'
    )}


def _response_query(query, body, target_url):
    """Preserve the legacy supplied-option shape without reflecting secrets."""
    result = {'url': target_url}
    for source in (query, body):
        result.update({
            key: value for key, value in source.items()
            if key not in SECRET_OPTIONS | {'url'}
        })
    return result


def _script_path(root, name):
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise RequestError('invalid user script name')
    root = Path(root).resolve()
    path = (root / name).resolve()
    if path.parent != root or not path.is_file():
        raise RequestError('user script not found')
    return path


def _apply_options(driver, options, target_url):
    preset = DEVICE_PRESETS[options['device']]
    if options['timeout'] > 0:
        driver.set_page_load_timeout(options['timeout'] / 1000.0)
    if (options['headers'] or options['user-agent'] or options['locale']
            or options['cookies'] or options['cookie_headers']):
        _cdp(driver, 'Network.enable')
    width = options['viewport-width'] or preset.get('width')
    height = options['viewport-height'] or preset.get('height')
    if width and height:
        driver.set_window_size(width, height)
        _cdp(driver, 'Emulation.setDeviceMetricsOverride', {
            'width': width, 'height': height, 'deviceScaleFactor': preset.get('dpr', 1),
            'mobile': preset.get('mobile', False),
            **({'screenWidth': options['screen-width']} if options['screen-width'] else {}),
            **({'screenHeight': options['screen-height']} if options['screen-height'] else {}),
        })
    _cdp(driver, 'Security.setIgnoreCertificateErrors', {'ignore': options['ignore-https-errors']})
    headers = dict(options['headers'])
    if options['locale'] and not any(key.lower() == 'accept-language' for key in headers):
        headers['Accept-Language'] = options['locale']
    if headers:
        _cdp(driver, 'Network.setExtraHTTPHeaders', {'headers': headers})
    ua = options['user-agent'] or preset.get('user_agent')
    if ua:
        args = {'userAgent': ua}
        if options['locale']:
            args['acceptLanguage'] = options['locale']
        _cdp(driver, 'Network.setUserAgentOverride', args)
    if options['locale']:
        _cdp(driver, 'Emulation.setLocaleOverride', {'locale': options['locale']})
    if options['timezone']:
        _cdp(driver, 'Emulation.setTimezoneOverride', {'timezoneId': options['timezone']})
    if options['cookies'] or options['cookie_headers']:
        _cdp(driver, 'Network.enable')
        _cdp(driver, 'Network.setCookies', {'cookies': cookies_to_cdp(options['cookies'], target_url, options['cookie_headers'])})


def _wait_for_commit(state, timeout):
    """Wait for the main document's response to commit."""
    deadline = time.monotonic() + timeout / 1000 if timeout else None
    while not state['committed']:
        if deadline is not None and time.monotonic() > deadline:
            raise RequestError('commit wait timed out')
        time.sleep(.05)


def register_routes(app, cache_dir, user_scripts_dir, screenshots_dir,
                    default_cache, default_full_content, default_screenshot,
                    default_user_scripts, default_user_scripts_timeout,
                    default_incognito, default_timeout, default_wait_until,
                    default_sleep, default_resource, default_viewport_width,
                    default_viewport_height, default_screen_width, default_screen_height,
                    default_device, default_scroll_down, default_ignore_https_errors,
                    default_user_agent, default_locale, default_timezone,
                    default_http_credentials, default_extra_http_headers,
                    default_cache_ttl):
    defaults = dict(cache=default_cache, full_content=default_full_content,
                    screenshot=default_screenshot, user_scripts=default_user_scripts,
                    user_scripts_timeout=default_user_scripts_timeout, incognito=default_incognito,
                    timeout=default_timeout, wait_until=default_wait_until, sleep=default_sleep,
                    resource=default_resource, viewport_width=default_viewport_width,
                    viewport_height=default_viewport_height, screen_width=default_screen_width,
                    screen_height=default_screen_height, device=default_device,
                    scroll_down=default_scroll_down, ignore_https_errors=default_ignore_https_errors,
                    user_agent=default_user_agent, locale=default_locale, timezone=default_timezone,
                    http_credentials=default_http_credentials, extra_http_headers=default_extra_http_headers)

    @app.route('/api/article', methods=['GET', 'POST'])
    def article():
        body = {}
        if request.method == 'POST':
            body = request.get_json(silent=True)
            if not isinstance(body, dict):
                return _error('invalid_request', 'POST body must be a JSON object')
        query = request.args.to_dict(flat=True)
        unknown = (set(query) | set(body)) - PUBLIC_OPTIONS
        if unknown:
            return _error('invalid_option', 'unsupported option')
        if set(query) & SECRET_OPTIONS:
            return _error(
                'invalid_option',
                'cookies, credentials, and extra headers require POST JSON',
            )
        # URL is selected independently, so ordinary body options cannot replace it.
        target_url = query.get('url') or body.get('url')
        if not target_url:
            return _error('missing_parameter', 'Missing required parameter: url')
        if query.get('url') and body.get('url') and query['url'] != body['url']:
            return _error('invalid_option', 'url may only be specified once')
        try:
            options = _normalize({**query, **body, 'url': target_url}, defaults, target_url)
        except RequestError as exc:
            return _error('invalid_option', str(exc))
        response_query = _response_query(query, body, target_url)

        sensitive = any(key in query or key in body for key in (
            'cookies', 'http-credentials', 'extra-http-headers', 'return-cookies',
            'user-scripts'
        )) or bool(options['cookies'] or options['cookie_headers'] or options['credentials'] or options['headers'] or options['user-scripts'] or options['return-cookies'])
        cacheable = not sensitive
        cache_key = get_cache_key(options['url'], _safe_query(options))
        if cacheable and options['cache']:
            cached = get_cached_result(cache_key, cache_dir, default_cache_ttl)
            if cached:
                return jsonify(cached), 200

        driver = None
        exported = None
        html_content = ''
        final_url = options['url']
        try:
            is_chromium = os.path.exists('/usr/bin/chromium-browser')
            # SeleniumBase UC uses a separate CDP connection that cannot service
            # Fetch/Network events. Use standard Chrome only for options that need
            # event callbacks; ordinary anti-bot/cookie scrapes keep UC mode.
            needs_event_cdp = bool(
                options['resource'] or options['credentials']
                or options['wait-until'] in {'commit', 'networkidle'}
            )
            driver_kwargs = {
                'browser': 'chrome', 'headless': True,
                'uc': not is_chromium and not needs_event_cdp,
                'incognito': options['incognito'],
                'page_load_strategy': {
                    'load': 'normal', 'domcontentloaded': 'eager',
                    'commit': 'none', 'networkidle': 'none',
                }[options['wait-until']],
            }
            preset = DEVICE_PRESETS[options['device']]
            if options['user-agent'] or preset.get('user_agent'):
                driver_kwargs['agent'] = options['user-agent'] or preset['user_agent']
            if options['locale']:
                driver_kwargs['locale_code'] = options['locale']
            driver = Driver(**driver_kwargs)
            _apply_options(driver, options, options['url'])
            if options['resource'] or options['credentials']:
                _install_fetch(driver, set(options['resource']), options['credentials'], options['url'])
            network_state = _configure_network_wait(driver) if options['wait-until'] == 'networkidle' else None
            commit_state = _configure_commit_wait(driver) if options['wait-until'] == 'commit' else None
            driver.get(options['url'])
            if commit_state is not None:
                _wait_for_commit(commit_state, options['timeout'])
            if network_state is not None:
                deadline = time.monotonic() + options['timeout'] / 1000 if options['timeout'] else None
                while network_state['inflight'] or time.monotonic() - network_state['last'] < .5:
                    if deadline is not None and time.monotonic() > deadline:
                        raise RequestError('networkidle wait timed out')
                    time.sleep(.05)
            for script in options['user-scripts']:
                with open(_script_path(user_scripts_dir, script), encoding='utf-8') as handle:
                    driver.execute_script(handle.read())
            if options['user-scripts-timeout']:
                time.sleep(options['user-scripts-timeout'] / 1000)
            if options['sleep']:
                time.sleep(options['sleep'] / 1000)
            if options['scroll-down']:
                driver.execute_script(f"window.scrollBy(0, {options['scroll-down']});")
                time.sleep(.5)
            final_url = driver.current_url
            html_content = driver.page_source
            screenshot_uri = None
            if options['screenshot']:
                filename = f'{cache_key}.png'
                try:
                    driver.save_screenshot(str(Path(screenshots_dir) / filename))
                    screenshot_uri = f'file://screenshots/{filename}'
                except Exception:
                    logger.warning('Failed to save screenshot')
            result = _build_response(
                final_url, html_content, options, response_query, screenshot_uri,
            )
            exported = export_cookies(driver)
            if options['return-cookies']:
                result['cookies'] = exported
            if cacheable:
                save_to_cache(cache_key, result, cache_dir)
            return jsonify(result), 200
        except RequestError as exc:
            if driver is not None:
                exported = export_cookies(driver)
            return _error('unsupported' if str(exc).startswith('unsupported') else 'fetch_error', str(exc), 400 if str(exc).startswith('unsupported') else 500, exported if options['return-cookies'] else None)
        except Exception:
            if driver is not None:
                exported = export_cookies(driver)
            return _error('fetch_error', 'Failed to fetch URL', 500, exported if options['return-cookies'] else None)
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    logger.warning('driver.quit() failed')
            reap_abandoned_child_processes()


def _build_response(final_url, html_content, options, response_query, screenshot_uri):
    soup = BeautifulSoup(html_content, 'html.parser')
    title = soup.find('title')
    title = title.get_text(strip=True) if title else None
    if not title and (tag := soup.find('meta', property='og:title')):
        title = tag.get('content')
    desc = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', property='og:description')
    author = soup.find('meta', attrs={'name': 'author'}) or soup.find('meta', property='article:author')
    html_tag = soup.find('html')
    text = extract_text_content(soup)
    result_id = hashlib.md5(final_url.encode()).hexdigest()
    parsed = urlparse(final_url)
    safe_netloc = parsed.hostname or ''
    if parsed.port:
        safe_netloc += f':{parsed.port}'
    safe_url = urlunparse(parsed._replace(netloc=safe_netloc))
    return {'id': result_id, 'url': safe_url,
            'domain': safe_netloc, 'title': title, 'byline': author.get('content') if author else None,
            'excerpt': desc.get('content') if desc else None,
            'siteName': (soup.find('meta', property='og:site_name') or {}).get('content') if soup.find('meta', property='og:site_name') else None,
            'content': extract_article_content(soup), 'textContent': text,
            'length': len(text) if text else None, 'lang': html_tag.get('lang') if html_tag else None,
            'dir': html_tag.get('dir') if html_tag else None, 'publishedTime': extract_published_time(soup),
            'fullContent': html_content if options['full-content'] else None,
            'date': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'query': response_query, 'meta': extract_meta_tags(soup),
            'resultUri': f'api://article/{result_id}', 'screenshotUri': screenshot_uri}
