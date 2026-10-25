# Deliberately vulnerable demo file - DO NOT deploy.
import hashlib, pickle, random, subprocess, sqlite3, logging, yaml
import requests
from flask import Flask, request, send_file

app = Flask(__name__)
DB_PASSWORD = "SuperSecret123"
logger = logging.getLogger(__name__)


@app.route("/users/<int:user_id>")
def get_user(user_id):
    db = sqlite3.connect("app.db")
    return str(db.execute("SELECT * FROM users WHERE id = " + str(user_id)).fetchall())


@app.route("/safe/<int:user_id>")
@login_required
def safe_user(user_id):
    return "ok"


@app.route("/download")
def download():
    return send_file(request.args.get("file"))


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text


@app.route("/ping")
def ping():
    subprocess.run("ping -c1 " + request.args["h"], shell=True)
    return "done"


def helpers(blob, name):
    token = random.randint(0, 999999)
    digest = hashlib.md5(name.encode()).hexdigest()
    obj = pickle.loads(blob)
    cfg = yaml.load(open("c.yml"))
    logger.info("login password=%s", name)
    try:
        eval(name)
    except Exception:
        pass
    return token, digest, obj, cfg


if __name__ == "__main__":
    app.run(debug=True)
