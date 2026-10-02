# app.py — PLACEHOLDER challenge. Replace with your own vulnerability.
# The only rule that MUST survive: read the flag from the environment, never hardcode it.
import os
from flask import Flask, render_template_string

app = Flask(__name__)

# Injected at runtime from flags.env. The fallback is only for local dev.
FLAG = os.environ.get("FLAG", "CTF4{local_dev_flag}")

# PLACEHOLDER "vuln": the flag is disclosed in an HTML comment so the scaffold is solvable
# out of the box. DELETE this and build a real vulnerability whose intended solve yields FLAG.
PAGE = """
<!doctype html>
<title>__SLUG__</title>
<h1>Replace me</h1>
<p>This is a scaffold. Put your challenge here; the intended solve must reveal FLAG.</p>
<!-- FLAG: {{ flag }} -->
"""


@app.route("/")
def index():
    return render_template_string(PAGE, flag=FLAG)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
