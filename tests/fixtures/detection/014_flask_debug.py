"""
Fixture: Flask app started with debug=True.

CWE-489 / CWE-94: Werkzeug's debugger console allows arbitrary code
execution via the browser when an exception fires. Never run with
debug=True in production. Engine should rewrite to debug=False.
"""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "hello"


if __name__ == "__main__":
    app.run(debug=True)
