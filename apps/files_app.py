from flask import Flask, request, render_template, send_file, url_for, send_file, redirect, jsonify, make_response
import redis
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, set_access_cookies, set_refresh_cookies, create_refresh_token, get_jwt_identity, jwt_refresh_token_required, get_raw_jwt
import os, sys
from werkzeug.utils import secure_filename
import string


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


GET = "GET"
SECRET_KEY = "LAB_5_SECRET"
SESSION_ID = "session-id"
DIR_PATH = "files/"
FILE_COUNTER = "file_counter"
ORG_FILENAME = "org_filename"
NEW_FILENAME = "new_filename"
PATH_TO_FILE = "path_to_file"
FILENAMES = "filenames"
OWNERS = "owners"
ALL = "all"

TOKEN_EXPIRES_IN_SECONDS = 300

app = Flask(__name__, static_url_path = "")
db = redis.Redis(host = "redis", port = 6379, decode_responses = True)

app.config['JWT_SECRET_KEY'] = os.environ.get(SECRET_KEY)

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = TOKEN_EXPIRES_IN_SECONDS
app.config['JWT_TOKEN_LOCATION'] = ['cookies','headers']
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['JWT_REFRESH_COOKIE_PATH'] = 'https://localhost:80/token/refresh'
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
jwt = JWTManager(app)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/list')
@jwt_required
def show_articles():
    try:
        cookie = request.cookies
        if cookie["session-id"] in db.get(SESSION_ID):
            user = get_jwt_identity()
            files = db.hgetall(FILENAMES)
            owners = db.hgetall(OWNERS)
            print(files, file = sys.stderr)
            keys_to_pop = []
            for k in files.keys():
                if owners[k] != user and owners[k] != ALL:
                    keys_to_pop.append(k)
            for k in keys_to_pop:
                files.pop(k, None)
            return render_template("index_file_list.html", my_files = files)
        else:
            return redirect("https://localhost:80")
    except Exception as e:
        print(e, file = sys.stderr)
        return redirect("https://localhost:80")


@app.route("/add-article")
@jwt_required
def add_article():
    return render_template("add_article.html", csrf_token=(get_raw_jwt() or {}).get("csrf"))


@app.route("/article-manager", methods=["POST"])
@jwt_required
def upload_article():
    user = get_jwt_identity()
    f = request.files["article"]
    if check_filename(f.filename):
        save_file(f, user)
        return redirect("https://localhost:81/list")
    return redirect("https://localhost:81/add-article")

@app.route("/article-manager-all", methods=["POST"])
@jwt_required
def upload_article_for_all():
    user = "all"
    f = request.files["article"]
    if check_filename(f.filename):
        save_file(f, user)
        return redirect("https://localhost:81/list")
    return redirect("https://localhost:81/add-article")

@app.route("/article-manager/<string:id>", methods=["GET"])
@jwt_required
def download_article(id):
    user = get_jwt_identity()
    full_name = db.hget(id, PATH_TO_FILE)
    org_filename = db.hget(id, ORG_FILENAME)
    owner = db.hget(OWNERS, id)
    if user == owner or owner == ALL:
        if(full_name != None):
            try:
                print(org_filename, file = sys.stderr)
                return send_file(full_name, attachment_filename = org_filename)
            except Exception as e:
                print(e, file = sys.stderr)
            return org_filename, 200
    return "nie masz dostepu do zasobu", 400

def save_file(file_to_save, user):
    if(len(file_to_save.filename) > 0):
        id = str(db.incr(FILE_COUNTER))
        org_filename = file_to_save.filename
        new_filename = id + org_filename
        path_to_file = DIR_PATH + new_filename
        file_to_save.save(path_to_file)
        print(org_filename, file = sys.stderr)
        db.hset(id, ORG_FILENAME, org_filename)
        db.hset(id, PATH_TO_FILE, path_to_file)
        db.hset(FILENAMES, id, file_to_save.filename)
        db.hset(OWNERS, id, user)
    else:
        print("\n\t\t[WARN] Empty content of file\n", file = sys.stderr)


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

@jwt.expired_token_loader
def my_expired_token_callback(expired_token):
    resp = make_response(redirect('https://localhost:81/logout'))
    return resp

@app.route("/login")
def login():
    return redirect('https://localhost:80')

@app.route("/logout")
def logout():
    return redirect('https://localhost:80/logout')

@app.route("/register")
def register():
    return redirect('https://localhost:80/registration')

@app.route("/change_password")
def change_password():
    return redirect('https://localhost:80/change_password')

def check_filename(filename):
    l=filename.split(".")

    if len(l)>2:
        return False
    
    if l[-1] not in ALLOWED_EXTENSIONS:
        return False
    return True