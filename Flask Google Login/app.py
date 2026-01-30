from flask import Flask, session, abort, redirect, url_for, request
from google_auth_oauthlib.flow import Flow
import os
import pathlib
import requests
import google.auth.transport.requests
from google.oauth2 import id_token
import cachecontrol


app = Flask("Google Login App")
app.secret_key = "pranav"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Allow insecure HTTP for OAuthlib

GOOGLE_CLIENT_ID = "172960066875-ej7er8kmdvo9gjvg7olpmqrro53r5qh9.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(client_secrets_file=client_secrets_file, scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"], redirect_uri="http://127.0.0.1:5000/callback")

def login_is_required(f):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401) # Authorization required
        else:
            return f()
        
    return wrapper

@app.route("/login")
def login():
    authoriaztion_url, state, = flow.authorization_url()
    session["state"] = state
    return redirect(authoriaztion_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")

    return redirect("/protected")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    return "&nbsp; &nbsp; &nbsp;Hello World! <br> <br> &nbsp; &nbsp; &nbsp; <a href='/login'><button> Login </button></a>"

@app.route("/protected")
@login_is_required
def protected_area():
    return "This is a protected area. <br> <br> &nbsp; &nbsp; &nbsp; <a href='/logout'><button> Logout </button></a>"

if __name__ == "__main__":
    app.run(debug=True)
