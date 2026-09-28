# main_app.py — InvoiceFlow API (port 5000)
from flask import Flask, request, jsonify
from lxml import etree
import hashlib, os, urllib.request

app = Flask(__name__)

INTERNAL_URL = os.environ.get('INTERNAL_URL', 'http://127.0.0.1:7777')

USERS = {
    'testuser': hashlib.sha256(b'test1234').hexdigest()[:16],
    'alice':    hashlib.sha256(b'al!c3pw').hexdigest()[:16],
}
VALID_KEYS = set(USERS.values())


class HTTPResolver(etree.Resolver):
    # XXE ZAIFLIK: HTTP entity'larni resolve qiladi — SSRF imkoni beradi
    def resolve(self, url, id, context):
        if url.startswith('http://') or url.startswith('https://'):
            try:
                data = urllib.request.urlopen(url, timeout=5).read()
                return self.resolve_string(data, context)
            except Exception:
                return None
        return None


def parse_invoice(xml_bytes: bytes) -> dict:
    # XXE ZAIFLIK: resolve_entities=True, no_network=False
    parser = etree.XMLParser(
        resolve_entities=True,
        no_network=False,
        load_dtd=True,
    )
    parser.resolvers.add(HTTPResolver())
    root = etree.fromstring(xml_bytes, parser)
    return {
        'vendor': root.findtext('vendor') or '',
        'amount': root.findtext('amount') or '0',
        'date':   root.findtext('date')   or '',
        'status': 'processed',
    }


@app.route('/')
def index():
    return jsonify({'service': 'InvoiceFlow API', 'version': '2.1.0'})


@app.route('/api/auth', methods=['POST'])
def auth():
    d = request.get_json(silent=True) or {}
    u, p = d.get('username', ''), d.get('password', '')
    stored = USERS.get(u)
    given  = hashlib.sha256(p.encode()).hexdigest()[:16]
    if not stored or stored != given:
        return jsonify({'error': 'Invalid credentials'}), 401
    return jsonify({'api_key': stored, 'hint': 'Use X-API-Key header'})


@app.route('/api/invoice', methods=['POST'])
def invoice():
    key = request.headers.get('X-API-Key', '')
    if key not in VALID_KEYS:
        return jsonify({'error': 'Unauthorized'}), 401

    xml_data = request.get_data()
    if not xml_data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        result = parse_invoice(xml_data)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
