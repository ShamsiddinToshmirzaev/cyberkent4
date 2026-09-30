# app.py — placeholder. Replace with your challenge. The only rule that MUST survive:
# read the flag from the environment, never hardcode it.
import os

from flask import Flask, render_template_string, request

app = Flask(__name__)

# Injected at runtime from flags.env. The fallback is only for local dev.
FLAG = os.environ.get("FLAG", "CTF{local_dev_flag}")

PAGE = """
<!doctype html>
<title>Example challenge</title>
<h1>It runs.</h1>
<p>Replace this app with your challenge. Put the intended vulnerability here.</p>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


if __name__ == "__main__":
    # Must listen on 0.0.0.0:5000 to match the compose port mapping and healthcheck.
    app.run(host="0.0.0.0", port=5000)
