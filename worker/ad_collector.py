"""Read-only AD Security log collector. Secrets and raw WinRM errors are never logged."""
import base64
import ipaddress
import json
import os
from pathlib import Path
import signal
import stat
import time
from urllib.parse import urlparse

EVENT_IDS = {4624, 4625, 4672, 4728, 4732, 4740, 4756, 4768, 4769, 4771, 4776, 1102, 4719}
STOP = False


def configuration(path, controller):
    info = path.stat()
    if os.name != 'nt' and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o037):
        raise ValueError('CONFIG_INVALID')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, OSError, UnicodeError):
        raise ValueError('CONFIG_INVALID') from None
    if not isinstance(value, dict) or not isinstance(value.get('enabled'), bool):
        raise ValueError('CONFIG_INVALID')
    endpoint = urlparse(value.get('endpoint', ''))
    if endpoint.scheme not in ('http', 'https') or endpoint.hostname != controller or endpoint.port != (5986 if endpoint.scheme == 'https' else 5985) or endpoint.path != '/wsman' or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError('CONFIG_INVALID')
    if endpoint.scheme == 'http' and not ipaddress.ip_address(controller).is_private:
        raise ValueError('CONFIG_INVALID')
    for field in ('username', 'password'):
        if not isinstance(value.get(field), str) or len(value[field]) > 1024:
            raise ValueError('CONFIG_INVALID')
    return value


def query(session, cursor, script):
    if not isinstance(cursor, int) or cursor < 0 or cursor > 9007199254740991:
        raise ValueError('CONFIG_INVALID')
    params = base64.b64encode(json.dumps({'cursor': cursor}).encode()).decode()
    response = session.run_ps(script.replace('__PARAMS__', params))
    if len(response.std_out) > 1500000:
        raise ValueError('INVALID_RESPONSE')
    try:
        result = json.loads(response.std_out.decode('utf-8-sig'))
    except (ValueError, UnicodeError):
        raise ValueError('EVENT_QUERY_FAILED') from None
    if response.status_code or result.get('error'):
        raise ValueError(result.get('error') if result.get('error') in ('ACCESS_DENIED', 'EVENT_QUERY_FAILED') else 'EVENT_QUERY_FAILED')
    if not isinstance(result.get('events'), list) or len(result['events']) > 500 or not isinstance(result.get('cursor'), int) or result['cursor'] < 0 or result['cursor'] > 9007199254740991 or not isinstance(result.get('backlog'), bool) or result.get('warning', '') not in ('', 'LOG_GAP', 'LOG_RESET'):
        raise ValueError('INVALID_RESPONSE')
    for event in result['events']:
        if not isinstance(event, dict) or event.get('eventId') not in EVENT_IDS:
            raise ValueError('INVALID_RESPONSE')
    return result


def save_cursor(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value), encoding='utf-8')
    temporary.chmod(0o600)
    temporary.replace(path)


def stop(*_):
    global STOP
    STOP = True


def new_session(config):
    import winrm
    return winrm.Session(config['endpoint'], auth=(config['username'], config['password']), transport='ntlm', message_encryption='always', server_cert_validation='validate', operation_timeout_sec=20, read_timeout_sec=30)


def main():
    import requests
    from winrm.exceptions import InvalidCredentialsError
    controller = os.environ['AD_CONTROLLER'].lower()
    origin = urlparse(os.environ['AD_APP_URL'])
    secret = os.environ['AD_TOKEN']
    if origin.scheme != 'https' or origin.username or origin.password or origin.path not in ('', '/') or origin.query or origin.fragment or len(secret) < 32:
        raise ValueError('CONFIG_INVALID')
    config_path = Path('/etc/sechub-ad/credentials.json')
    state_path = Path('/var/lib/sechub-ad/cursor.json')
    script = Path(__file__).with_name('ad-events.ps1').read_text(encoding='utf-8')
    cursor = json.loads(state_path.read_text(encoding='utf-8')) if state_path.exists() else {'cursor': 0}
    http = requests.Session()
    http.trust_env = False
    last_state = None
    auth_blocked = None

    def post(payload):
        response = http.post(origin.geturl().rstrip('/') + '/api/ad/ingest', json=payload, headers={'Authorization': 'Bearer ' + secret}, timeout=(5, 20), allow_redirects=False)
        if response.status_code != 200 or len(response.content) > 65536 or response.json().get('ok') is not True:
            raise RuntimeError('CONTROLLER_UNAVAILABLE')

    while not STOP:
        state, code, backlog = 'error', 'CONFIG_INVALID', False
        try:
            config = configuration(config_path, controller)
            signature = (config_path.stat().st_mtime_ns, config_path.stat().st_size)
            if not config['enabled'] or not config['username'] or not config['password']:
                state, code = 'credentials_pending', 'CREDENTIALS_PENDING'
                post({'status': state, 'error': code, 'events': []})
            elif auth_blocked == signature:
                # A bad password must not lock out the service account through retries.
                code = 'AUTH_FAILED'
                post({'status': 'error', 'error': code, 'events': []})
            else:
                # Password is only held in memory; never passed as an argument or posted.
                session = new_session(config)
                try:
                    result = query(session, cursor['cursor'], script)
                except InvalidCredentialsError:
                    auth_blocked = signature
                    raise ValueError('AUTH_FAILED') from None
                state, code, backlog = 'ok', result.get('warning', ''), result['backlog']
                post({'status': state, 'error': code, 'backlog': backlog, 'events': result['events']})
                # Cursor advances only after the server commits the batch; replay is deduplicated.
                cursor = {'cursor': result['cursor']}
                save_cursor(state_path, cursor)
        except Exception as error:
            code = str(error) if isinstance(error, ValueError) and str(error) in ('CONFIG_INVALID', 'AUTH_FAILED', 'ACCESS_DENIED', 'EVENT_QUERY_FAILED', 'INVALID_RESPONSE') else 'WINRM_UNAVAILABLE'
            try:
                post({'status': 'error', 'error': code, 'events': []})
            except Exception:
                code = 'CONTROLLER_UNAVAILABLE'
        if (state, code) != last_state:
            print('AD_COLLECTOR', state, code or 'OK', flush=True)
            last_state = (state, code)
        for _ in range(5 if backlog else 60):
            if STOP:
                break
            time.sleep(1)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    main()
