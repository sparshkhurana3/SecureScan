"""Deliberately vulnerable. Do not use."""
import pickle
import subprocess

from flask import Flask, request

app = Flask(__name__)
# Planted: hard-coded secret (fake).
SECRET_KEY = "k8Jd93hFq02LsmZx81VbQe7TnPo4RwUy"
app.config["SECRET_KEY"] = SECRET_KEY


@app.route("/lookup")
def lookup():
    # Planted: shell injection.
    out = subprocess.check_output("nslookup " + request.args["host"], shell=True)
    return out


@app.route("/load", methods=["POST"])
def load():
    # Planted: unsafe deserialisation.
    return str(pickle.loads(request.data))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")  # Planted: debug server on all interfaces.
