from flask import Flask, session, request, abort, redirect, Response, render_template
from urllib.parse import urlencode, urljoin
from urllib.request import urlopen
from urllib import request as url_request
from xml.etree import ElementTree
from Crypto.Cipher import AES
import uuid
import secrets
import json
import base64
import config
import traceback

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# github auth
github_url = "https://github.com/login/oauth/authorize"
github_validate = "https://github.com/login/oauth/access_token"
github_user_api = "https://api.github.com/user"
client_id = config.CLIENT_ID
client_secret = config.CLIENT_SECRET
passphrase = config.PASSPHRASE

# cas auth
cas_url = config.CAS_URL
cas_validate = config.CAS_VALIDATE
cas_redirect = config.CAS_REDIRECT
cas_logout = config.CAS_LOGOUT

host = config.HOST
admin_list = config.ADMIN


def check_ticket(ticket, service):
    validate = cas_validate + "?" + urlencode({"service": service, "ticket": ticket})
    with urlopen(validate) as req:
        tree = ElementTree.fromstring(req.read())[0]
    cas = "{http://www.yale.edu/tp/cas}"
    if tree.tag != cas + "authenticationSuccess":
        return None
    # gid = tree.find("attributes").find(cas + "gid").text.strip()
    user = tree.find(cas + "user").text.strip()
    return user


def check_gh(code):
    validate = url_request.Request(
        github_validate
        + "?"
        + urlencode(
            {"client_id": client_id, "client_secret": client_secret, "code": code}
        ),
        method="POST",
        headers={"Accept": "application/json"},
    )
    with urlopen(validate) as req:
        data = json.loads(req.read())
        access_token = data["access_token"]
    with urlopen(
        url_request.Request(
            github_user_api, headers={"Authorization": "token " + access_token}
        )
    ) as req:
        data = json.loads(req.read())
        return data["login"]  # username


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return """This app authorizes USTC students with their GitHub account. 
    The implementation is database-less and we DO NOT store any personal information."""


@app.route("/logout")
def logout():
    session.clear()
    return """Your session is now cleared. 
    Please also remember to logout from CAS and GitHub if you are using a public computer."""


@app.route("/auth")
def auth():
    if "cas" not in session:
        # drive user to CAS
        # ref: https://github.com/zzh1996/ustccas-revproxy/blob/master/auth/auth_server.py
        if "id" not in session:
            session["id"] = uuid.uuid4().hex
        jump = request.base_url + "?" + urlencode({"cas_id": session["id"]})
        service = cas_redirect + "?" + urlencode({"jump": jump})
        ticket = request.args.get("ticket")
        if not ticket:
            return redirect(cas_url + "?" + urlencode({"service": service}))
        if request.args.get("cas_id") != session["id"]:
            abort(Response("cas_id does not match the id in session", status=401))
        user = check_ticket(ticket, service)
        if user:
            session["cas"] = user
        else:
            abort(Response("CAS ticket validation failed", status=401))
    if "github" not in session:
        # drive user to GitHub (Now user has been authenticated by CAS)
        # ref: https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps#web-application-flow
        jump = urljoin(host, "/ghcallback")

        session["state"] = secrets.token_hex()
        state = session["state"]

        return redirect(
            github_url
            + "?"
            + urlencode({"client_id": client_id, "redirect_uri": jump, "state": state})
        )
    return redirect("generate")


@app.route("/ghcallback")
def gh_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if request.args.get("error"):
        return (
            render_template(
                "gherror.html",
                error=request.args["error"],
                reason=request.args["error_description"],
            ),
            401,
        )
    if not code or not state:
        return redirect("auth")
    if session["state"] != request.args.get("state"):
        return redirect("auth")
    user = check_gh(code)
    if user:
        session["github"] = user
    else:
        abort(Response("GitHub code validation failed", status=401))
    return redirect("generate")


@app.route("/generate")
def generate():
    if "github" not in session or "cas" not in session:
        return redirect("auth")
    aes = AES.new(passphrase.encode("utf-8"), AES.MODE_EAX)
    s = f"{session['github']}:{session['cas']}".encode("utf-8")
    ciphertext, tag = aes.encrypt_and_digest(s)
    json_k = ["nonce", "ciphertext", "tag"]
    json_v = [base64.b64encode(x).decode("utf-8") for x in (aes.nonce, ciphertext, tag)]
    info = json.dumps(dict(zip(json_k, json_v)))
    return render_template(
        "generate.html", token=base64.b64encode(info.encode("utf-8")).decode("utf-8")
    )


@app.route("/check", methods=["GET", "POST"])
def check():
    if "cas" not in session:
        return redirect("auth")
    if session["cas"] not in admin_list:
        abort(403)
    if request.method == "GET":
        return render_template("check.html")
    elif request.method == "POST":
        try:
            cipher = request.form.get("cipher")
            info = json.loads(base64.b64decode(cipher))
            json_k = ["nonce", "ciphertext", "tag"]
            jv = {k: base64.b64decode(info[k]) for k in json_k}
            aes = AES.new(passphrase.encode("utf-8"), AES.MODE_EAX, nonce=jv["nonce"])
            plaintext = aes.decrypt_and_verify(jv["ciphertext"], jv["tag"])
            return plaintext.decode("utf-8")
        except Exception as e:
            traceback.print_exc()
            return Response(f"decrypt failed: {e}", status=400)
