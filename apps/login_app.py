from flask import Flask, request, render_template, redirect, make_response, jsonify
import redis
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_raw_jwt, set_access_cookies, set_refresh_cookies, create_refresh_token, get_jwt_identity, jwt_refresh_token_required 
import os
import hashlib
import sys
import datetime
import bcrypt
import string
import random

#update

GET = "GET"
POST = "POST"
SECRET_KEY = "LAB_5_SECRET"
TOKEN_EXPIRES_IN_SECONDS = 300

USERS = "users"
SESSION_ID = "session-id"

app = Flask(__name__, static_url_path = "")
db = redis.Redis(host = "redis", port = 6379, decode_responses = True)

app.config['JWT_SECRET_KEY'] = os.environ.get(SECRET_KEY)

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = TOKEN_EXPIRES_IN_SECONDS
app.config['JWT_TOKEN_LOCATION'] = ['cookies','headers']
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['JWT_REFRESH_COOKIE_PATH'] = 'https://localhost:80/token/refresh'
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
jwt = JWTManager(app)

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods = [POST])
def login():
    login = request.form["login"]
    password = request.form["password"]
    if check_if_valid(login) and check_if_valid(password):
        passwd = db.hget(USERS,login)
        if bcrypt.checkpw(password.encode(),passwd.encode()):
            print('poprawnie zalogowano', file=sys.stderr)
            name_hash = hashlib.sha512(login.encode('utf-8')).hexdigest()
            db.set(SESSION_ID, name_hash)
            expires = datetime.timedelta(seconds=300)
            access_token = create_access_token(identity=login, expires_delta = expires)
            refresh_token = create_refresh_token(identity=login)
            resp = make_response(redirect('https://localhost:81'))
            resp.set_cookie(SESSION_ID, name_hash, max_age = 300, secure = True, httponly = True)
            set_access_cookies(resp, access_token, max_age = 300)
            set_refresh_cookies(resp, refresh_token)
            return resp, 200
    return 'błąd podczas logowania', 400



@app.route("/registration")
def registration():
    return render_template("registration.html")

@app.route("/change_password")
@jwt_required
def change_password():
    return render_template("change_password.html", csrf_token=(get_raw_jwt() or {}).get("csrf"))
    

@app.route('/token/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    cookie = request.cookies
    if cookie["session-id"] in db.get(SESSION_ID):
        current_user = get_jwt_identity()
        expires = datetime.timedelta(seconds=30)
        access_token = create_access_token(identity=current_user, expires_delta=expires)
        resp = jsonify({'refresh': True})
        set_access_cookies(resp, access_token)
        return resp, 200
    else:
        resp = jsonify({'refresh': True})
        return resp, 400

@app.route("/register", methods = [POST])
def register():
    try:
        login = request.form["login"]
        password = request.form["password"]
        if check_if_valid(login) and check_if_valid(password):
            pass_hash = bcrypt.hashpw(str.encode(password),bcrypt.gensalt(14))
            db.hset(USERS, login, pass_hash)
            return 'pomyślnie stworzono użytkownika',201
        return 'niepoprawne hasło lub login', 400
    except Exception as e:
        print(e, file = sys.stderr)
        return 'nie udało się stworzyć użytkownika', 400


@app.route("/change_pass", methods = [POST])
@jwt_required
def change_pass():
    try:
        login = get_jwt_identity()
        password = request.form["password"]
        new_password = request.form["new_password"]
        new_password2 = request.form["new_password2"]
        if check_if_valid(login) and check_if_valid(password) and check_if_valid(new_password) and check_if_valid(new_password2):
            passwd = db.hget(USERS,login)
            if new_password == new_password2 and bcrypt.checkpw(password.encode(),passwd.encode()):
                pass_hash2 = bcrypt.hashpw(new_password.encode(),bcrypt.gensalt(14))
                x=db.hdel(USERS, login)
                print(x, file=sys.stderr)
                db.hset(USERS, login, pass_hash2)
                
                return 'pomyślnie zmieniono hasło', 201
        return 'hasła nie są identyczne', 400
    except Exception as e:
        print(e, file = sys.stderr)
        return 'nie udało się zmienić hasła', 400

@app.route("/logout")
def logout():
    try:
        cookie = request.cookies
        resp = jsonify({'logout': True})
        unset_jwt_cookies(resp)
        db.delete(SESSION_ID,cookie["session-id"])
        return redirect('https://localhost:80')
    except:
        return redirect('https://localhost:80')

@app.errorhandler(400)
def page_wrong_request(error):
    return render_template("errors/400.html", error = error)

@app.errorhandler(401)
def page_unauthorized(error):
    return render_template("errors/401.html", error = error)

@app.errorhandler(403)
def page_forbidden(error):
    return render_template("errors/403.html", error = error)

@app.errorhandler(404)
def page_not_found(error):
    return render_template("errors/404.html", error = error)


def check_if_valid(test_str):
    if len(test_str) > 7 and len(test_str) < 33 and test_str.isalnum():
        return True
    False

