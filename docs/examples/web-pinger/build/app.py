# app.py — Pinger network diagnostics
import os
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Flag is injected at runtime via flags.env — NEVER hardcode it here.
FLAG = os.environ.get("FLAG", "CTF4{local_test_flag}")

PAGE = """
<!doctype html>
<title>Pinger</title>
<h1>Network diagnostics</h1>
<form action="/ping" method="get">
  <input name="host" placeholder="8.8.8.8" value="{{ host }}">
  <button>Ping</button>
</form>
<pre>{{ output }}</pre>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, host="", output="")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # BUG (intended): user input is concatenated into a shell command.
    # `ping -c 1 <host>` becomes injectable, e.g. host = "8.8.8.8; printenv FLAG".
    cmd = "ping -c 1 " + host
    try:
        output = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        ).stdout
    except subprocess.TimeoutExpired:
        output = "timed out"
    return render_template_string(PAGE, host=host, output=output)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
