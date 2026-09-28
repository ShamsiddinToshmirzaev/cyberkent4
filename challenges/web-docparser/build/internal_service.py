# internal_service.py — Admin service (port 7777, localhost only)
from flask import Flask, jsonify
import os

app = Flask(__name__)

FLAG = os.environ.get('FLAG', 'ctf4{test_flag}')


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'internal-admin'})


@app.route('/flag')
def flag():
    return jsonify({'flag': FLAG})


if __name__ == '__main__':
    # Faqat localhost dan so'rovlar qabul qilinadi
    app.run(host='127.0.0.1', port=7777)
