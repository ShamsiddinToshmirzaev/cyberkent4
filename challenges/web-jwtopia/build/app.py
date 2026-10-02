# app.py — JWTopia Analytics API
from flask import Flask, request, jsonify, render_template_string
import jwt
import os

app = Flask(__name__)

with open('/app/keys/private.pem', 'rb') as f:
    PRIVATE_KEY = f.read()

with open('/app/keys/public.pem', 'rb') as f:
    PUBLIC_KEY = f.read()

FLAG = os.environ.pop('FLAG', 'ctf4{test_flag}')

USERS = {
    'guest': {'password': 'guest123',          'role': 'user'},
    'alice': {'password': 'al!c3_s3cr3t_2024', 'role': 'user'},
}


def parse_token(token):
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get('alg', 'RS256')
        if alg not in ('RS256', 'HS256'):
            return None
        # BUG: ikki xil algoritmda ham PUBLIC_KEY ishlatiladi
        key = PUBLIC_KEY
        if alg == 'HS256':
            import hmac as _hmac, hashlib as _hs, base64 as _b64, json as _json
            h, p, s = token.split('.')
            expected = _hmac.new(key, f"{h}.{p}".encode(), _hs.sha256).digest()
            if not _hmac.compare_digest(expected, _b64.urlsafe_b64decode(s + '==')):
                return None
            return _json.loads(_b64.urlsafe_b64decode(p + '=='))
        return jwt.decode(token, key, algorithms=[alg])
    except Exception:
        return None


@app.route('/')
def index():
    return jsonify({
        'service': 'JWTopia Analytics API',
        'version': '2.1.0',
    })


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    user = USERS.get(data.get('username', ''))
    if not user or user['password'] != data.get('password', ''):
        return jsonify({'error': 'Invalid credentials'}), 401
    token = jwt.encode(
        {'sub': data['username'], 'role': user['role']},
        PRIVATE_KEY,
        algorithm='RS256'
    )
    return jsonify({'token': token})


@app.route('/public.pem')
def serve_pubkey():
    # Client-side verification uchun ochiq kalit
    return PUBLIC_KEY, 200, {'Content-Type': 'application/x-pem-file'}


@app.route('/api/profile')
def profile():
    token = request.headers.get('Authorization', '').removeprefix('Bearer ')
    claims = parse_token(token)
    if not claims:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'username': claims['sub'], 'role': claims['role']})


@app.route('/admin/report', methods=['POST'])
def admin_report():
    token = request.headers.get('Authorization', '').removeprefix('Bearer ')
    claims = parse_token(token)
    if not claims or claims.get('role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403

    data = request.get_json(silent=True) or {}
    template = data.get('template', '')

    # BUG: foydalanuvchi kiritgan template to'g'ridan-to'g'ri render qilinadi
    output = render_template_string(template, user=claims['sub'])
    return jsonify({'output': output})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
